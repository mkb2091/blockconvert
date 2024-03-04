-- Add migration script here
CREATE TABLE IF NOT EXISTS Rules (
    id SERIAL PRIMARY KEY,
    rule TEXT NOT NULL UNIQUE
);