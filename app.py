from gevent import monkey
monkey.patch_all()

from flask import Flask, render_template, session, request, jsonify, redirect, url_for, g
from flask_socketio import join_room, leave_room, SocketIO, emit
import os
import sqlite3
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import logging
import time
import secrets
import string
from dotenv import load_dotenv  # FIXED: Load env for FLASK_SECRET_KEY

# Load env vars (for Render/prod)
load_dotenv()

# Suppress SocketIO logs
logging.getLogger('socketio').setLevel(logging.WARNING)
logging.getLogger('engineio').setLevel(logging.WARNING)

app = Flask(__name__)
# FIXED: Prioritize env var, fallback to file/gen for local
app.secret_key = os.getenv('FLASK_SECRET_KEY') or None
if not app.secret_key:
    SECRET_KEY_FILE = '.flask_secret_key'
    if os.path.exists(SECRET_KEY_FILE):
        with open(SECRET_KEY_FILE, 'rb') as f:
            app.secret_key = f.read()
    else:
        new_key = os.urandom(24)
        with open(SECRET_KEY_FILE, 'wb') as f:
            f.write(new_key)
        app.secret_key = new_key
        logging.info("Generated new secret key.")

socketio = SocketIO(app, cors_allowed_origins="*", async_mode='gevent')

# Globals
active_users_in_rooms = {}
sid_username = {}
dev_mode_users = set()

DB_FILE = "chat1.db"

# DB Helpers
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DB_FILE)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(exception):
    db = g.pop('db', None)
    if db:
        db.close()

def init_db():
    try:
        with app.app_context():
            db = get_db()
            c = db.cursor()
            # FIXED: Check/init core tables
            tables = ['users', 'rooms', 'messages', 'room_members', 'banned_users']
            missing = []
            for table in tables:
                c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table,))
                if not c.fetchone():
                    missing.append(table)
            if missing:
                with app.open_resource('schema.sql', mode='r') as f:
                    db.executescript(f.read())
                db.commit()
                logging.info(f"Initialized tables: {missing}")

            # NEW: Add plain_password column if missing (for admin plaintext view)
            c.execute("PRAGMA table_info(users)")
            columns = [col[1] for col in c.fetchall()]
            if 'plain_password' not in columns:
                db.execute("ALTER TABLE users ADD COLUMN plain_password TEXT")
                db.commit()
                logging.info("Added plain_password column.")
    except Exception as e:
        logging.error(f"DB init error: {e}")
        raise

# Run init on startup
init_db()

def load_messages(room_unique_id, limit=50, order='ASC'):  # FIXED: Keep ASC default (reverse in template for chronological)
    try:
        c = get_db().cursor()
        c.execute(f"""
            SELECT id, user, message, timestamp 
            FROM messages 
            WHERE room_unique_id = ? 
            ORDER BY timestamp {order} 
            LIMIT ?
        """, (room_unique_id, limit))
        rows = c.fetchall()
        # FIXED: Convert Row objects to plain dicts (safe for Jinja—no attribute errors)
        return [dict(row) for row in rows]
    except Exception as e:
        logging.error(f"Load messages error for {room_unique_id}: {e}")
        return []  # Return empty on error (prevents 500)

def save_message(room_unique_id, user, message):
    db = get_db()
    db.execute("INSERT INTO messages (room_unique_id, user, message) VALUES (?, ?, ?)", (room_unique_id, user, message))
    db.commit()

def load_rooms():
    c = get_db().cursor()
    c.execute("SELECT unique_id, name, password FROM rooms WHERE hidden = 0 ORDER BY name ASC")
    return [{"unique_id": row["unique_id"], "name": row["name"], "protected": bool(row["password"])} for row in c.fetchall()]

def create_room(name, password="", description=""):
    db = get_db()
    unique_id = uuid.uuid4().hex[:8]
    db.execute("INSERT INTO rooms (unique_id, name, password, description, hidden) VALUES (?, ?, ?, ?, 0)",
               (unique_id, name, password, description))
    db.commit()
    return unique_id

def get_room_details(unique_id):
    c = get_db().cursor()
    c.execute("SELECT * FROM rooms WHERE unique_id = ?", (unique_id,))
    return c.fetchone()

def add_user_to_room_members(room_unique_id, username):
    db = get_db()
    db.execute("""
        INSERT OR IGNORE INTO room_members (room_unique_id, username, last_seen) 
        VALUES (?, ?, CURRENT_TIMESTAMP)
    """, (room_unique_id, username))
    db.commit()

def get_room_members(room_unique_id):
    c = get_db().cursor()
    c.execute("SELECT username FROM room_members WHERE room_unique_id = ?", (room_unique_id,))
    return [row['username'] for row in c.fetchall()]

# NEW: Helper to get all users for the admin panel
def get_all_users():
    c = get_db().cursor()
    c.execute("SELECT id, username, is_verified FROM users WHERE username_lower != 'pratotasrik72'")
    return c.fetchall()

# NEW: Helper to get all rooms for the admin panel
def get_all_rooms_with_members():
    db = get_db()
    rooms = db.execute("SELECT unique_id, name, description, password, hidden FROM rooms").fetchall()
    rooms_data = []
    for room in rooms:
        room_dict = dict(room)
        room_dict['members'] = get_room_members(room['unique_id'])
        # NEW: Fetch banned users for the unban feature
        banned = db.execute("SELECT username FROM banned_users WHERE room_unique_id = ?", (room['unique_id'],)).fetchall()
        room_dict['banned_users'] = [row['username'] for row in banned]
        rooms_data.append(room_dict)
    return rooms_data

# NEW: Helper to get a user's public profile data
def get_user_profile(username):
    c = get_db().cursor()
    c.execute("SELECT username, bio, is_verified FROM users WHERE username_lower = ?", (username.lower(),))
    return c.fetchone()

# NEW: This hook runs before every request to keep DEV mode state in sync.
@app.before_request
def sync_dev_mode_state():
    admin_username_lower = 'pratotasrik72'
    # Check if the current user is the admin
    if session.get('username', '').lower() == admin_username_lower:
        # If their session says dev mode is on...
        if session.get('dev_mode', False):
            # ...ensure they are in the global set for invisibility.
            dev_mode_users.add(admin_username_lower)
        else:
            # ...otherwise, ensure they are NOT in the global set.
            dev_mode_users.discard(admin_username_lower)

# NEW: Context processor to make impersonation status available in all templates
@app.context_processor
def inject_impersonation_status():
    return dict(is_impersonating=session.get('impersonating_from') is not None)

# Routes
@app.route("/")
def main_redirect():
    # FIXED: Redirect to the main rooms page if logged in
    if "username" in session:
        return redirect(url_for("index"))
    return redirect(url_for("login"))

# REMOVED: The separate /profile route is no longer needed.

# NEW: Dummy route for the control panel button
@app.route("/control_panel", methods=["GET", "POST"])
def control_panel():
    admin_username_lower = 'pratotasrik72'
    if session.get('username', '').lower() != admin_username_lower:
        return "Access Denied", 403

    CONTROL_PANEL_PASSWORD = "kuttashopno"
    if not session.get('control_access'):
        if request.method == "POST" and request.form.get('password') == CONTROL_PANEL_PASSWORD:
            session['control_access'] = True
        else:
            error = "Incorrect password." if request.method == "POST" else None
            return render_template("control.html", access_granted=False, error=error)

    # FIXED: Robust DEV Mode toggle logic
    if request.method == "POST" and 'toggle_dev_mode' in request.form:
        # The form was submitted. Check if the checkbox was checked.
        if 'dev_mode' in request.form:
            # Checkbox is checked -> Turn ON
            session['dev_mode'] = True
            dev_mode_users.add(admin_username_lower)
        else:
            # Checkbox is unchecked -> Turn OFF
            session['dev_mode'] = False
            dev_mode_users.discard(admin_username_lower)
        return redirect(url_for('control_panel'))

    all_users = get_all_users()
    all_rooms = get_all_rooms_with_members()
    return render_template("control.html", access_granted=True, users=all_users, rooms=all_rooms)

@app.route("/rooms")
def index():
    if "username" not in session:
        return redirect(url_for("login"))
    # FIXED: Use case-insensitive check for the admin username
    is_admin = session.get('username', '').lower() == 'pratotasrik72'
    # NEW: Get user's own profile data for the sidebar
    user_profile = get_user_profile(session['username'])
    return render_template("index.html", is_admin=is_admin, user_profile=user_profile)

# NEW: Public user profile page
@app.route("/user/<username>")
def user_profile_page(username):
    if "username" not in session:
        return redirect(url_for("login"))
    
    profile_data = get_user_profile(username)
    if not profile_data:
        return "User not found", 404
    
    return render_template("user_profile.html", profile=profile_data)

@app.route("/chat/<unique_id>")
def chat(unique_id):
    if "username" not in session:
        return redirect(url_for("login"))
    
    room = get_room_details(unique_id)
    if not room:
        logging.warning(f"Invalid room access: {unique_id}")
        return redirect(url_for("index"))
    
    try:
        add_user_to_room_members(unique_id, session['username'])
        session_username = session['username']
        active_users_in_rooms[session_username] = unique_id
        
        messages = load_messages(unique_id, limit=50, order='ASC')  # FIXED: ASC + dicts
        logging.info(f"Rendering chat for {session_username} in {unique_id} ({len(messages)} messages)")
        
        # FIXED: Pass explicit vars (username for loop, room as dict)
        return render_template("chat_v2.html", 
                               room=dict(room), 
                               messages=messages, 
                               username=session_username)  # Explicit username (safer than session in template)
    except Exception as e:
        logging.error(f"Chat render error for {unique_id}: {e}")
        return "Chat unavailable - try refreshing.", 500

@app.route("/login", methods=["GET", "POST"])
def login():
    if "username" in session:
        return redirect(url_for("index"))
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        if not username or not password:
            return render_template("account.html", page="login", error="Username and password are required.")
        if len(password) < 6:
            return render_template("account.html", page="login", error="Password must be at least 6 characters.")

        db = get_db()
        user = db.execute("SELECT username, password FROM users WHERE username_lower = ?", (username.lower(),)).fetchone()

        if user:
            if check_password_hash(user['password'], password):
                session["username"] = user['username']
                return redirect(url_for("index"))
            else:
                return render_template("account.html", page="login", error="Incorrect password for this username.")
        else:
            # Auto-create: Store PLAIN password for admin view
            try:
                hashed = generate_password_hash(password)
                db.execute("INSERT INTO users (username, username_lower, password, plain_password) VALUES (?, ?, ?, ?)",
                           (username, username.lower(), hashed, password))  # NEW: Store plaintext
                db.commit()
                session["username"] = username
                return redirect(url_for("index"))
            except sqlite3.IntegrityError:
                return render_template("account.html", page="login", error="An error occurred. Please try again.")

    return render_template("account.html", page="login")

@app.route("/register", methods=["GET", "POST"])
def register():
    # FIXED: Redirect to rooms page if already logged in
    if "username" in session:
        return redirect(url_for("index"))
    if request.method == "POST":
        username, password = request.form.get("username"), request.form.get("password")
        if len(password) < 6:
            return render_template("account.html", page="register", error="Password too short.")
        
        db = get_db()
        c = db.cursor()
        c.execute("SELECT 1 FROM users WHERE username_lower = ?", (username.lower(),))
        if c.fetchone():
            return render_template("account.html", page="register", error="Username exists.")
        
        hashed = generate_password_hash(password)
        c.execute("INSERT INTO users (username, username_lower, password, plain_password) VALUES (?, ?, ?, ?)", 
                  (username, username.lower(), hashed, password))  # NEW: Store plaintext
        db.commit()
        session["username"] = username
        return redirect(url_for("index"))
    return render_template("account.html", page="register")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# API: Users in room (for sidebar)
@app.route('/api/rooms/<room_id>/users')
def get_room_users(room_id):
    if 'username' not in session:
        return jsonify([]), 401
    try:
        members = get_room_members(room_id)
        users = []
        for username in members:
            if username.lower() in dev_mode_users:
                continue
            active_in_room = active_users_in_rooms.get(username) == room_id
            users.append({'username': username, 'active_in_room': active_in_room})
        return jsonify(users)
    except Exception as e:
        logging.error(f"Users API error: {e}")
        return jsonify([]), 500

# API: Create room (simple)
@app.route("/api/create_room", methods=["POST"])
def api_create_room():
    if "username" not in session:
        return jsonify({"error": "Login required"}), 401
    
    data = request.json
    name = data.get('name')
    if not name or len(name) > 50:
        return jsonify({"error": "Invalid room name"}), 400
        
    password = data.get('password', '')  # FIXED: Room passwords stored as plain text (not hashed, as requested)
    hidden = bool(data.get('hidden', False))
    
    db = get_db()
    
    existing_room = db.execute("SELECT 1 FROM rooms WHERE LOWER(name) = ?", (name.lower(),)).fetchone()
    if existing_room:
        return jsonify({"error": "A room with this name already exists."}), 409

    # FIXED: Shorter room ID (6 characters from UUID hex)
    unique_id = str(uuid.uuid4().hex)[:6]
    
    db.execute("INSERT INTO rooms (unique_id, name, password, description, hidden) VALUES (?, ?, ?, ?, ?)",
               (unique_id, name, password, f"Welcome to {name}!", hidden))
    db.commit()
    
    add_user_to_room_members(unique_id, session['username'])
    
    return jsonify({"success": True, "unique_id": unique_id})

# API: Public rooms (for index.html fetch)
@app.route('/api/rooms')
def api_rooms():
    # FIXED: DEV mode now shows hidden rooms
    is_dev_mode = session.get('dev_mode', False)
    is_admin = session.get('username', '').lower() == 'pratotasrik72'
    
    query = "SELECT unique_id, name, password FROM rooms"
    if not (is_admin and is_dev_mode):
        query += " WHERE hidden = 0"
    query += " ORDER BY name ASC"
    
    c = get_db().cursor()
    c.execute(query)
    rooms = [{"unique_id": row["unique_id"], "name": row["name"], "protected": bool(row["password"])} for row in c.fetchall()]
    return jsonify(rooms)

# API: Join room (handles password check)
@app.route('/api/join_room', methods=['POST'])
def api_join_room():
    if "username" not in session:
        return jsonify({"error": "Login required"}), 401
    
    data = request.json
    unique_id = data.get('unique_id')
    password = data.get('password', '')
    username = session['username']
    
    # FIXED: Cache room details if possible (but simple query is fast)
    room = get_room_details(unique_id)
    if not room:
        return jsonify({"error": "Room not found"}), 404

    # Ban check (quick index query)
    db = get_db()
    is_banned = db.execute("SELECT 1 FROM banned_users WHERE room_unique_id = ? AND username = ?", 
                           (unique_id, username)).fetchone()
    if is_banned:
        return jsonify({"error": "You are banned from this room."}), 403

    # DEV mode bypass (no DB hit)
    is_dev_mode = session.get('dev_mode', False)
    is_admin = username.lower() == 'pratotasrik72'
    if not (is_dev_mode and is_admin) and room['password'] and room['password'] != password:
        return jsonify({"error": "Wrong password"}), 403
    
    # FIXED: Use INSERT OR IGNORE to avoid duplicate checks (faster)
    db.execute('INSERT OR IGNORE INTO room_members (room_unique_id, username, last_seen) VALUES (?, ?, CURRENT_TIMESTAMP)', 
               (unique_id, username))
    db.commit()
    
    return jsonify({"success": True})  # No extra data needed

# FIXED: Admin APIs (add plain_password to details)
@app.route('/api/admin/get_user_details', methods=['POST'])
def admin_get_user_details():
    if session.get('username', '').lower() != 'pratotasrik72': 
        return jsonify(success=False), 403
    username = request.json.get('username')
    user = get_db().execute("SELECT username, password, bio, plain_password FROM users WHERE username = ?", (username,)).fetchone()
    if user:
        details = dict(user)
        details['password'] = details['password'][:10] + '...'  # Show truncated hash (for security note)
        return jsonify(success=True, details=details)  # Includes plain_password
    return jsonify(success=False, error="User not found"), 404

@app.route('/api/admin/toggle_verify', methods=['POST'])
def admin_toggle_verify():
    if session.get('username', '').lower() != 'pratotasrik72': return jsonify(success=False), 403
    username = request.json.get('username')
    db = get_db()
    current_status = db.execute("SELECT is_verified FROM users WHERE username = ?", (username,)).fetchone()
    if not current_status: return jsonify(success=False, error="User not found"), 404
    new_status = 0 if current_status['is_verified'] else 1
    db.execute("UPDATE users SET is_verified = ? WHERE username = ?", (new_status, username))
    db.commit()
    return jsonify(success=True, is_verified=bool(new_status))

@app.route('/api/admin/delete_user', methods=['POST'])
def admin_delete_user():
    if session.get('username', '').lower() != 'pratotasrik72': return jsonify(success=False), 403
    username = request.json.get('username')
    db = get_db()
    db.execute("DELETE FROM users WHERE username = ?", (username,))
    db.execute("DELETE FROM messages WHERE user = ?", (username,))
    db.execute("DELETE FROM room_members WHERE username = ?", (username,))
    db.commit()
    return jsonify(success=True)

@app.route('/api/admin/login_as', methods=['POST'])
def admin_login_as():
    if session.get('username', '').lower() != 'pratotasrik72': return jsonify(success=False), 403
    admin_username = session['username'] # Store current admin username
    username_to_impersonate = request.json.get('username')
    session.clear()
    session['username'] = username_to_impersonate
    # FIXED: Set a flag to indicate impersonation and store who is doing it
    session['impersonating_from'] = admin_username
    return jsonify(success=True)

# NEW: Route to return to the admin account after impersonating
@app.route('/admin/return_to_admin')
def return_to_admin():
    admin_username = session.get('impersonating_from')
    if not admin_username:
        return redirect(url_for('index')) # Not impersonating, just go to index
    
    session.clear()
    session['username'] = admin_username
    session['control_access'] = True # Restore control panel access
    return redirect(url_for('control_panel'))

@app.route('/api/admin/update_room', methods=['POST'])
def admin_update_room():
    if session.get('username', '').lower() != 'pratotasrik72': return jsonify(success=False), 403
    data = request.json
    db = get_db()
    db.execute("UPDATE rooms SET description = ?, password = ? WHERE unique_id = ?", 
               (data.get('description'), data.get('password'), data.get('room_id')))
    db.commit()
    return jsonify(success=True)

@app.route('/api/admin/ban_user', methods=['POST'])
def admin_ban_user():
    if session.get('username', '').lower() != 'pratotasrik72': return jsonify(success=False), 403
    data = request.json
    db = get_db()
    db.execute("INSERT OR IGNORE INTO banned_users (room_unique_id, username) VALUES (?, ?)", (data.get('room_id'), data.get('username')))
    db.execute("DELETE FROM room_members WHERE room_unique_id = ? AND username = ?", (data.get('room_id'), data.get('username')))
    db.commit()
    # You could also emit a socket event to kick the user out in real-time
    return jsonify(success=True)

@app.route('/api/admin/delete_room', methods=['POST'])
def admin_delete_room():
    # FIXED: Corrected typo from 'pratotasrik7t2' to 'pratotasrik72'
    if session.get('username', '').lower() != 'pratotasrik72': return jsonify(success=False), 403
    room_id = request.json.get('room_id')
    db = get_db()
    db.execute("DELETE FROM rooms WHERE unique_id = ?", (room_id,))
    db.execute("DELETE FROM messages WHERE room_unique_id = ?", (room_id,))
    db.execute("DELETE FROM room_members WHERE room_unique_id = ?", (room_id,))
    db.execute("DELETE FROM banned_users WHERE room_unique_id = ?", (room_id,))
    db.commit()
    return jsonify(success=True)

# NEW: API to toggle room visibility
@app.route('/api/admin/toggle_room_visibility', methods=['POST'])
def admin_toggle_room_visibility():
    if session.get('username', '').lower() != 'pratotasrik72': return jsonify(success=False), 403
    room_id = request.json.get('room_id')
    db = get_db()
    current = db.execute("SELECT hidden FROM rooms WHERE unique_id = ?", (room_id,)).fetchone()
    if not current: return jsonify(success=False, error="Room not found"), 404
    new_hidden_status = 0 if current['hidden'] else 1
    db.execute("UPDATE rooms SET hidden = ? WHERE unique_id = ?", (new_hidden_status, room_id))
    db.commit()
    return jsonify(success=True, is_hidden=bool(new_hidden_status))

# NEW: API to unban a user from a room
@app.route('/api/admin/unban_user', methods=['POST'])
def admin_unban_user():
    if session.get('username', '').lower() != 'pratotasrik72': return jsonify(success=False), 403
    data = request.json
    db = get_db()
    db.execute("DELETE FROM banned_users WHERE room_unique_id = ? AND username = ?", (data.get('room_id'), data.get('username')))
    db.commit()
    return jsonify(success=True)

# NEW: API to reset a user's password from the admin panel
@app.route('/api/admin/reset_password', methods=['POST'])
def admin_reset_password():
    if session.get('username', '').lower() != 'pratotasrik72': 
        return jsonify(success=False, error="Unauthorized"), 403
    
    username = request.json.get('username')
    if not username:
        return jsonify(success=False, error="Username required"), 400

    # Generate a secure, random 8-character password
    alphabet = string.ascii_letters + string.digits
    new_password = ''.join(secrets.choice(alphabet) for i in range(8))
    
    db = get_db()
    user = db.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone()
    if not user:
        return jsonify(success=False, error="User not found"), 404

    # Hash the new password and update the database
    hashed_password = generate_password_hash(new_password)
    db.execute("UPDATE users SET password = ? WHERE username = ?", (hashed_password, username))
    db.commit()
    
    # Return the new plain-text password to the admin
    return jsonify(success=True, new_password=new_password)

# NEW: API endpoints for profile page
@app.route('/api/update_bio', methods=['POST'])
def api_update_bio():
    if "username" not in session:
        return jsonify({"success": False, "error": "Not logged in"}), 401
    
    new_bio = request.json.get('bio', '').strip()
    if len(new_bio) > 150:
        return jsonify({"success": False, "error": "Bio cannot exceed 150 characters."}), 400

    db = get_db()
    db.execute("UPDATE users SET bio = ? WHERE username = ?", (new_bio, session['username']))
    db.commit()
    return jsonify({"success": True, "message": "Bio updated!"})

@app.route('/api/change_username', methods=['POST'])
def api_change_username():
    if "username" not in session:
        return jsonify({"success": False, "error": "Not logged in"}), 401

    new_username = request.json.get('new_username', '').strip()
    password = request.json.get('password')
    old_username = session['username']

    if not new_username or not password or len(new_username) < 3:
        return jsonify({"success": False, "error": "Invalid input."}), 400

    db = get_db()
    user = db.execute("SELECT password FROM users WHERE username = ?", (old_username,)).fetchone()

    if not user or not check_password_hash(user['password'], password):
        return jsonify({"success": False, "error": "Password is incorrect."}), 403

    # Check if new username already exists (case-insensitive)
    existing_user = db.execute("SELECT 1 FROM users WHERE username_lower = ? AND username_lower != ?", 
                               (new_username.lower(), old_username.lower())).fetchone()
    if existing_user:
        return jsonify({"success": False, "error": "Username is already taken."}), 409

    # Update username across all tables
    db.execute("UPDATE users SET username = ?, username_lower = ? WHERE username = ?", (new_username, new_username.lower(), old_username))
    db.execute("UPDATE messages SET user = ? WHERE user = ?", (new_username, old_username))
    db.execute("UPDATE room_members SET username = ? WHERE username = ?", (new_username, old_username))
    db.commit()

    # Update session and notify clients
    session['username'] = new_username
    socketio.emit('username_changed', {'old_username': old_username, 'new_username': new_username}, broadcast=True)
    return jsonify({"success": True, "message": "Username changed successfully!"})

@app.route('/api/user_rooms')
def api_user_rooms():
    if "username" not in session:
        return jsonify({"error": "Not logged in"}), 401
    db = get_db()
    c = db.cursor()
    c.execute("""
        SELECT r.unique_id, r.name, r.password 
        FROM rooms r
        JOIN room_members rm ON r.unique_id = rm.room_unique_id
        WHERE rm.username = ?
    """, (session['username'],))
    rooms = [{"unique_id": row["unique_id"], "name": row["name"], "protected": bool(row["password"])} for row in c.fetchall()]
    return jsonify(rooms)

@app.route('/api/change_password', methods=['POST'])
def api_change_password():
    if "username" not in session:
        return jsonify({"success": False, "error": "Not logged in"}), 401
    
    data = request.json
    current_password = data.get('current_password')
    new_password = data.get('new_password')
    username = session['username']

    if not current_password or not new_password or len(new_password) < 6:
        return jsonify({"success": False, "error": "Invalid input."}), 400

    db = get_db()
    user = db.execute("SELECT password FROM users WHERE username = ?", (username,)).fetchone()

    if not user or not check_password_hash(user['password'], current_password):
        return jsonify({"success": False, "error": "Current password is incorrect."}), 403

    db.execute("UPDATE users SET password = ? WHERE username = ?", (generate_password_hash(new_password), username))
    db.commit()
    return jsonify({"success": True, "message": "Password updated successfully!"})

@app.route('/api/delete_account', methods=['POST'])
def api_delete_account():
    if "username" not in session:
        return jsonify({"success": False, "error": "Not logged in"}), 401

    password = request.json.get('password')
    username = session['username']
    db = get_db()
    user = db.execute("SELECT password FROM users WHERE username = ?", (username,)).fetchone()

    if not user or not check_password_hash(user['password'], password):
        return jsonify({"success": False, "error": "Password is incorrect."}), 403

    # Perform deletion
    db.execute("DELETE FROM users WHERE username = ?", (username,))
    db.execute("DELETE FROM messages WHERE user = ?", (username,))
    db.execute("DELETE FROM room_members WHERE username = ?", (username,))
    db.commit()
    session.clear()
    return jsonify({"success": True, "message": "Account deleted successfully."})

# FIXED: Add missing profile APIs (prevent 500s from account.html JS)
@app.route('/api/user_code', methods=['GET'])
def api_user_code():
    if 'username' not in session:
        return jsonify({'error': 'Login required'}), 401
    try:
        db = get_db()
        c = db.cursor()
        username_lower = session['username'].lower()
        # Generate or fetch unique code (8 chars, alphanumeric)
        c.execute("SELECT user_code FROM users WHERE username_lower = ?", (username_lower,))
        row = c.fetchone()
        if row and row['user_code']:
            user_code = row['user_code']
        else:
            user_code = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(8))
            db.execute("UPDATE users SET user_code = ? WHERE username_lower = ?", (user_code, username_lower))
            db.commit()
        return jsonify({'user_code': user_code})
    except Exception as e:
        logging.error(f"User code error: {e}")
        return jsonify({'error': 'Internal error'}), 500

@app.route('/api/hide_profile', methods=['POST'])
def api_hide_profile():
    if 'username' not in session:
        return jsonify({'success': False, 'error': 'Login required'}), 401
    try:
        data = request.json
        hidden = int(data.get('hidden', 0))  # 1=hidden, 0=visible
        db = get_db()
        db.execute("UPDATE users SET hidden = ? WHERE username_lower = ?", (hidden, session['username'].lower()))
        db.commit()
        return jsonify({'success': True, 'hidden': bool(hidden)})
    except Exception as e:
        logging.error(f"Hide profile error: {e}")
        return jsonify({'success': False, 'error': 'Internal error'}), 500

# FIXED: Wrap all routes in try-except to prevent 500 crashes (return JSON errors)
def safe_route(f):
    def wrapper(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except Exception as e:
            logging.error(f"Route error in {request.path}: {e}")
            if request.path.startswith('/api/'):
                return jsonify({'error': 'Internal server error'}), 500
            return "Internal server error", 500
    wrapper.__name__ = f.__name__
    return wrapper

# Apply to existing routes (after definition)
for rule in list(app.url_map.iter_rules()):
    if rule.endpoint != 'static' and rule.endpoint not in app.view_functions:  # Avoid re-wrap
        continue
    if rule.endpoint != 'static':
        view_func = app.view_functions[rule.endpoint]
        if not hasattr(view_func, '_safe_wrapped'):  # Prevent double-wrap
            app.view_functions[rule.endpoint] = safe_route(view_func)
            app.view_functions[rule.endpoint]._safe_wrapped = True

# SocketIO Events (add error handling)
@socketio.on('connect')
def on_connect():
    logging.info(f"Connect: SID {request.sid}")

@socketio.on('identify')
def on_identify(data):
    try:
        username = data.get('username')
        if username:
            sid_username[request.sid] = username
            logging.info(f"Identified: {username} (SID: {request.sid})")
    except Exception as e:
        logging.error(f"Identify error: {e}")

@socketio.on('disconnect')
def on_disconnect():
    username = sid_username.pop(request.sid, None)
    if username and username in active_users_in_rooms:
        room_id = active_users_in_rooms.pop(username)
        emit("user_list_updated", {}, room=room_id)
        print(f"Disconnect: {username} from {room_id}")

@socketio.on("join")
def on_join(data):
    username = sid_username.get(request.sid)
    room_id = data.get('room')
    if not username or not room_id:
        print(f"Join failed: Missing data (username: {username}, room: {room_id})")  # FIXED: Debug why fails
        return
    print(f"Join: {username} to {room_id} (SID: {request.sid})")  # FIXED: Debug success
    add_user_to_room_members(room_id, username)
    active_users_in_rooms[username] = room_id
    join_room(room_id)
    emit("user_list_updated", {}, room=room_id)
    print(f"Active in {room_id}: {list(active_users_in_rooms.keys())}")

@socketio.on("send_message")
def handle_message(data):
    username = sid_username.get(request.sid)
    if not username or username != data.get('user'):
        print(f"Rejected: Mismatch {data.get('user')} vs {username} (SID: {request.sid})")  # FIXED: Debug rejection
        return
    room_id = data['room']
    message = data['message'].strip()
    if not message or len(message) > 500:
        return
    print(f"Saving: {username} in {room_id}: {message} (SID: {request.sid})")
    save_message(room_id, username, message)
    # Verify save
    db = get_db()
    count = db.execute("SELECT COUNT(*) FROM messages WHERE room_unique_id = ? AND user = ? AND message = ?", 
                       (room_id, username, message)).fetchone()[0]
    if count == 0:
        print(f"WARNING: Not saved for {username}")
    data['user'] = username
    emit("receive_message", data, room=room_id, include_self=True)
    active_count = sum(1 for u, r in active_users_in_rooms.items() if r == room_id)
    print(f"Broadcast to {room_id} ({active_count} active)")

# FIXED: Prod-safe startup (Gunicorn for Render, socketio.run for local dev)
if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 5000))
    if not os.environ.get("PORT"):  # Local dev only
        logging.info("Starting dev server on http://0.0.0.0:5000")
        socketio.run(app, host="0.0.0.0", port=5000, debug=False, allow_unsafe_werkzeug=True)
    else:
        logging.info(f"App imported for production (Gunicorn) on port {port}")
        # Gunicorn handles running 'app'
