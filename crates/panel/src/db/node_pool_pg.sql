CREATE TABLE IF NOT EXISTS node_pool_nodes (
    identity_group_id BIGINT NOT NULL REFERENCES device_groups(id) ON DELETE CASCADE,
    node_id TEXT NOT NULL CHECK (char_length(node_id) BETWEEN 1 AND 128 AND node_id !~ '[^A-Za-z0-9_-]'),
    display_name TEXT NOT NULL DEFAULT '' CHECK (char_length(display_name) <= 128),
    created_at TEXT NOT NULL DEFAULT (to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS')),
    updated_at TEXT NOT NULL DEFAULT (to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS')),
    PRIMARY KEY (identity_group_id, node_id)
);
CREATE TABLE IF NOT EXISTS node_pool_system_anchor (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    group_id BIGINT NOT NULL UNIQUE REFERENCES device_groups(id) ON DELETE RESTRICT
);
