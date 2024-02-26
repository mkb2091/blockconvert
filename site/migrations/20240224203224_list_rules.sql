-- Add migration script here
CREATE table list_rules (
    id SERIAL PRIMARY KEY,
    list_id INTEGER NOT NULL,
    rule_id INTEGER NOT NULL,
    FOREIGN KEY (list_id) REFERENCES filterLists(id),
    FOREIGN KEY (rule_id) REFERENCES rules(id)
);