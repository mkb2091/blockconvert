-- Add migration script here

ALTER TABLE filterLists RENAME TO OldFilterListContents;

CREATE TABLE IF NOT EXISTS filterLists (
    id SERIAL PRIMARY KEY,
    url TEXT NOT NULL UNIQUE,
    format TEXT NOT NULL,
    contents TEXT NOT NULL,
    lastUpdated INTEGER NOT NULL,
    etag TEXT
);

INSERT INTO filterLists (url, format, contents, lastUpdated, etag) SELECT url, '', contents, lastUpdated, etag FROM filterLists;

DROP TABLE OldFilterListContents;