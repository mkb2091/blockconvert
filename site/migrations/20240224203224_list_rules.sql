-- Add migration script here
CREATE table list_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    list_id INTEGER NOT NULL,
    rule_id INTEGER NOT NULL,
    FOREIGN KEY (list_id) REFERENCES filterLists(id),
    FOREIGN KEY (rule_id) REFERENCES rules(id)
);