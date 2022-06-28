create table users (
    user_id varchar(255) primary key,
    username varchar(255) unique not null,
    email_address varchar(255) unique not null,
    first_name varchar(255) not null,
    last_name varchar(255),
    country varchar(255) not null,
    user_password varchar(255) not null);

create table educator(
    educator_id varchar(255) primary key,
    educator_email varchar(255) unique not null,
    first_name varchar(255) not null,
    last_name varchar(255) not null,
    country varchar(255) not null,
    password varchar(255) not null);