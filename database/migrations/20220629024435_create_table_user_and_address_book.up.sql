-- Add up migration script here
create table "user"
(
    username text     not null,
    password text     not null,
    perm     smallint not null,
    disabled boolean  not null default false,
    primary key (username, perm)
);
insert into "user" values ('admin', 'admin', 0, false);
insert into "user" values ('admin', 'admin', 1, false);

create table address_book
(
    username   text        not null,
    updated_at timestamptz not null default current_timestamp,
    tags       jsonb       not null default jsonb_build_array(),
    peers      jsonb       not null default jsonb_build_array()
);
insert into address_book(username) values ('admin');
