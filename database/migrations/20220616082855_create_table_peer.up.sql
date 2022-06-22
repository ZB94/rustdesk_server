-- Add up migration script here
create table peer
(
    guid               uuid primary key not null,
    uuid               uuid             not null,
    id                 varchar(100)     not null,
    pk                 bytea            not null,
    status             smallint         not null,
    created_at         timestamptz      not null default (current_timestamp),
    socket_addr        varchar(29)      not null,
    last_register_time timestamptz      not null,
    note               varchar(300)     null
);
create unique index index_peer_id on peer (id);
create index index_peer_created_at on peer (created_at);
create index index_peer_status on peer (status);
