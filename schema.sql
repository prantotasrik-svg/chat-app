-- Users table: Stores user accounts with hashed passwords, online status, hiding, and user code
DROP TABLE IF EXISTS users;
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    username_lower TEXT UNIQUE NOT NULL, -- For case-insensitive checks
    password TEXT NOT NULL,
    bio TEXT DEFAULT 'No bio yet.', -- User biography
    is_verified INTEGER DEFAULT 0 -- For the blue tick
);

-- Rooms table: Stores chat rooms with unique IDs, names, optional passwords, and visibility
DROP TABLE IF EXISTS rooms;
CREATE TABLE rooms (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    unique_id TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    description TEXT,
    password TEXT,
    hidden INTEGER NOT NULL DEFAULT 0
);

-- Messages table: Stores chat messages linked to rooms and users
CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    room_unique_id TEXT NOT NULL,
    user TEXT NOT NULL,
    message TEXT NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- FIXED: Add indexes for faster queries (room + id; timestamp; user for bans)
CREATE INDEX IF NOT EXISTS idx_messages_room_id ON messages (room_unique_id, id);
CREATE INDEX IF NOT EXISTS idx_messages_timestamp ON messages (timestamp);
CREATE INDEX IF NOT EXISTS idx_messages_room_user ON messages (room_unique_id, user);

-- Room Members table: Tracks which users have joined which rooms (for history, lists, and unread counts)
DROP TABLE IF EXISTS room_members;
CREATE TABLE room_members (
    room_unique_id TEXT NOT NULL,
    username TEXT NOT NULL,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (room_unique_id, username)
);

-- FIXED: Index for room_members queries (room + user)
CREATE INDEX IF NOT EXISTS idx_room_members_room ON room_members (room_unique_id);
CREATE INDEX IF NOT EXISTS idx_room_members_user ON room_members (username);

-- NEW: Table to store banned users for specific rooms
DROP TABLE IF EXISTS banned_users;
CREATE TABLE banned_users (
    room_unique_id TEXT NOT NULL,
    username TEXT NOT NULL,
    PRIMARY KEY (room_unique_id, username)
);

-- Index for bans (room + user)
CREATE INDEX IF NOT EXISTS idx_banned_users_room ON banned_users (room_unique_id);

-- Private Messages table: Unchanged
CREATE TABLE IF NOT EXISTS private_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    from_user TEXT NOT NULL,
    to_user TEXT NOT NULL,
    message TEXT NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(from_user, to_user, id)  -- Prevent duplicates
);

-- Friends table: Unchanged
CREATE TABLE IF NOT EXISTS friends (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user1 TEXT NOT NULL,
    user2 TEXT NOT NULL,
    status INTEGER DEFAULT 0,  -- 0=pending, 1=accepted
    UNIQUE(user1, user2),
    UNIQUE(user2, user1)
);

-- NEW: Index for rooms (name for searches, unique_id for joins)
CREATE INDEX IF NOT EXISTS idx_rooms_name_lower ON rooms (LOWER(name));
CREATE INDEX IF NOT EXISTS idx_rooms_unique_id ON rooms (unique_id);