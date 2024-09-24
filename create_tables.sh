#!/bin/bash

PASSWD_CREATE="CREATE TABLE IF NOT EXISTS passwd ( \
    login               TEXT NOT NULL UNIQUE, \
	password			TEXT DEFAULT 'x', \
	uid					INTEGER	NOT NULL PRIMARY KEY AUTOINCREMENT, \
	gid					INTEGER NOT NULL, \
	gecos				TEXT DEFAULT '', \
	home				TEXT DEFAULT '', \
	shell				TEXT DEFAULT '/bin/bash', \
	last_online_auth 	INTEGER); \
    INSERT INTO passwd (login, uid, gid) VALUES ('TEST', 49999, 49999); \
    DELETE FROM passwd WHERE login='TEST';"

SHADOW_CREATE="CREATE TABLE IF NOT EXISTS shadow ( \
	login           TEXT NOT NULL UNIQUE PRIMARY KEY, \
	password        TEXT    NOT NULL, \
	last_pwd_change	INTEGER NOT NULL DEFAULT -1, \
	min_pwd_age     INTEGER NOT NULL DEFAULT 0, \
	max_pwd_age     INTEGER NOT NULL DEFAULT 99999, \
	pwd_warn_period	INTEGER NOT NULL DEFAULT 7, \
	pwd_inactivity	INTEGER NOT NULL DEFAULT 7, \
	expiration_date	INTEGER NOT NULL DEFAULT -1);"

GROUPS_CREATE="CREATE TABLE IF NOT EXISTS groups ( \
	name		TEXT NOT NULL UNIQUE, \
	password	TEXT DEFAULT 'x', \
	gid			INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT); \
    INSERT INTO groups (name, gid) VALUES ('TEST', 49999); \
    DELETE FROM groups WHERE name='TEST';"

GROUP_MEMBERS="CREATE TABLE IF NOT EXISTS members ( \
	gid		INTEGER NOT NULL, \
	uid     INTEGER NOT NULL);"

PASSWD_DB_FILE="passwd.db"
GROUPS_DB_FILE="groups.db"
SHADOW_DB_FILE="shadow.db"

mkdir -p db

[ -f "db/${GROUPS_DB_FILE}" ] || echo $GROUP_MEMBERS | sqlite3 db/${GROUPS_DB_FILE}
[ -f "db/${GROUPS_DB_FILE}" ] || echo $GROUPS_CREATE | sqlite3 db/${GROUPS_DB_FILE}
[ -f "db/${SHADOW_DB_FILE}" ] || echo $SHADOW_CREATE | sqlite3 db/${SHADOW_DB_FILE}
[ -f "db/${PASSWD_DB_FILE}" ] || echo $PASSWD_CREATE | sqlite3 db/${PASSWD_DB_FILE}