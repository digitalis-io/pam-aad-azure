#include <sqlite3.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <security/pam_appl.h>
#include <security/pam_ext.h>
#include <security/pam_modules.h>
#include <sys/syslog.h>

#define DB_FILE_NAME "azure.db"
#define PASSWD_CREATE "CREATE TABLE IF NOT EXISTS passwd ( \
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

#define SHADOW_CREATE "CREATE TABLE IF NOT EXISTS shadow ( \
	uid             INTEGER NOT NULL UNIQUE, \
	password        TEXT    NOT NULL, \
	last_pwd_change	INTEGER NOT NULL DEFAULT -1, \
	min_pwd_age     INTEGER NOT NULL DEFAULT -1, \
	max_pwd_age     INTEGER NOT NULL DEFAULT -1, \
	pwd_warn_period	INTEGER NOT NULL DEFAULT -1, \
	pwd_inactivity	INTEGER NOT NULL DEFAULT -1, \
	expiration_date	INTEGER NOT NULL DEFAULT -1, \
	PRIMARY KEY('uid'));"

#define GROUPS_CREATE "CREATE TABLE IF NOT EXISTS groups ( \
	name		TEXT NOT NULL UNIQUE, \
	password	TEXT DEFAULT 'x', \
	gid			INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT); \
    INSERT INTO groups (name,gid) VALUES ('TEST', 49999); \
    DELETE FROM groups WHERE name='TEST';"

#define GROUP_MEMBERS "CREATE TABLE IF NOT EXISTS members ( \
	gid		INTEGER NOT NULL, \
	uid     INTEGER NOT NULL \
	PRIMARY KEY('uid'));"

extern char *cache_directory, *cache_owner, *cache_group;


/*
Returns:
0 - cache initialised or existing
1 - error
*/
int init_cache(void) { 
    sqlite3 *db;
    sqlite3_stmt *res;
    char db_path[strlen(cache_directory)+strlen(DB_FILE_NAME)];
    char *err_msg = 0;

    sprintf(db_path, "%s/%s", cache_directory, DB_FILE_NAME);
    if (access(db_path, F_OK) == 0) {
        return 0;
    }
    
    int rc = sqlite3_open(db_path, &db);
    
    if (rc != SQLITE_OK) {
        
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        
        return 1;
    }
    
    rc = sqlite3_exec(db, PASSWD_CREATE, 0, 0, &err_msg);
    if (rc != SQLITE_OK ) {
        
        fprintf(stderr, "SQL error: %s\n", err_msg);
        
        sqlite3_free(err_msg);        
        sqlite3_close(db);
        
        return 1;
    }
    rc = sqlite3_exec(db, SHADOW_CREATE, 0, 0, &err_msg);
    if (rc != SQLITE_OK ) {
        
        fprintf(stderr, "SQL error: %s\n", err_msg);
        
        sqlite3_free(err_msg);        
        sqlite3_close(db);
        
        return 1;
    }
    rc = sqlite3_exec(db, GROUPS_CREATE, 0, 0, &err_msg);
    if (rc != SQLITE_OK ) {
        
        fprintf(stderr, "SQL error: %s\n", err_msg);
        
        sqlite3_free(err_msg);        
        sqlite3_close(db);
        
        return 1;
    }
    rc = sqlite3_exec(db, GROUP_MEMBERS, 0, 0, &err_msg);
    if (rc != SQLITE_OK ) {
        
        fprintf(stderr, "SQL error: %s\n", err_msg);
        
        sqlite3_free(err_msg);        
        sqlite3_close(db);
        
        return 1;
    }
    sqlite3_close(db);
    
    return 0;
}

int cache_user(pam_handle_t *pamh, char *user, char *user_addr) {
    sqlite3 *db;
    sqlite3_stmt *res;
    char db_path[strlen(cache_directory)+strlen(DB_FILE_NAME)];
    char *err_msg = 0;

    sprintf(db_path, "%s/%s", cache_directory, DB_FILE_NAME);
    if (access(db_path, F_OK) != 0) {
        init_cache();
    }
    
    int rc = sqlite3_open(db_path, &db);
    
    if (rc != SQLITE_OK) {
        
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        
        return 1;
    }
    char group_insert[255];
    int gid;
    sprintf(group_insert, "INSERT OR IGNORE INTO groups (name) VALUES('%s')", user_addr);
    rc = sqlite3_exec(db, group_insert, 0, 0, &err_msg);
    if (rc != SQLITE_OK ) {
        
        fprintf(stderr, "SQL error: %s\n", err_msg);
        pam_syslog(pamh, LOG_ERR, "group insert %s\n", err_msg);
        
        sqlite3_free(err_msg);        
        sqlite3_close(db);
        
        return 1;
    }

    sprintf(group_insert, "SELECT gid FROM groups WHERE name = '%s'", user_addr);
    rc = sqlite3_prepare_v2(db, group_insert, -1, &res, 0);    
    
    if (rc != SQLITE_OK) {
        
        fprintf(stderr, "Failed to fetch data: %s\n", sqlite3_errmsg(db));
        pam_syslog(pamh, LOG_ERR, "select gid from groups: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        
        return 1;
    }
    pam_syslog(pamh, LOG_ERR, "END OF prepare");
    rc = sqlite3_step(res);
    gid = sqlite3_column_int(res, 0);

    char passwd_insert[255];
    sprintf(passwd_insert, "INSERT OR IGNORE INTO passwd (login, gid, homedir) VALUES('%s', '/home/%s')", user_addr, gid, user);

    rc = sqlite3_exec(db, passwd_insert, 0, 0, &err_msg);
    if (rc != SQLITE_OK ) {
        
        fprintf(stderr, "SQL error: %s\n", err_msg);
        
        sqlite3_free(err_msg);        
        sqlite3_close(db);
        
        return 1;
    }
    return 0;
}