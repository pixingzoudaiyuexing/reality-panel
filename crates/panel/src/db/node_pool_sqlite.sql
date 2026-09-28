CREATE TABLE IF NOT EXISTS node_pool_nodes (
    identity_group_id INTEGER NOT NULL REFERENCES device_groups(id) ON DELETE CASCADE,
    node_id TEXT NOT NULL CHECK (length(node_id) BETWEEN 1 AND 128 AND node_id NOT GLOB '*[^A-Za-z0-9_-]*'),
    display_name TEXT NOT NULL DEFAULT '' CHECK (length(display_name) <= 128),
    retirement_state TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (retirement_state IN ('ACTIVE', 'RETIRED')),
    retired_at TEXT,
    retired_by INTEGER,
    retirement_reason TEXT,
    retirement_version INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (identity_group_id, node_id)
);
CREATE TABLE IF NOT EXISTS node_pool_system_anchor (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    group_id INTEGER NOT NULL UNIQUE REFERENCES device_groups(id) ON DELETE RESTRICT
);
