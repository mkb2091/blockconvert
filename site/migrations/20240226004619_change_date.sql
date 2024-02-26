-- Add migration script here
alter table filterLists alter column lastUpdated type timestamp with time zone using to_timestamp(lastUpdated);