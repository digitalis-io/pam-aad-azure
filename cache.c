#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <security/pam_appl.h>
#include <security/pam_ext.h>
#include <security/pam_modules.h>
#include <sys/syslog.h>
#include <jansson.h>
#include <crypt.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <openssl/sha.h>
#define _POSIX_SOURCE
#include <pwd.h>
#include <grp.h>
#include <ctype.h>

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
	login           TEXT NOT NULL UNIQUE PRIMARY KEY, \
	password        TEXT    NOT NULL, \
	last_pwd_change	INTEGER NOT NULL DEFAULT -1, \
	min_pwd_age     INTEGER NOT NULL DEFAULT -1, \
	max_pwd_age     INTEGER NOT NULL DEFAULT -1, \
	pwd_warn_period	INTEGER NOT NULL DEFAULT -1, \
	pwd_inactivity	INTEGER NOT NULL DEFAULT -1, \
	expiration_date	INTEGER NOT NULL DEFAULT -1);"

#define GROUPS_CREATE "CREATE TABLE IF NOT EXISTS groups ( \
	name		TEXT NOT NULL UNIQUE, \
	password	TEXT DEFAULT 'x', \
	gid			INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT); \
    INSERT INTO groups (name, gid) VALUES ('TEST', 49999); \
    DELETE FROM groups WHERE name='TEST';"

#define GROUP_MEMBERS "CREATE TABLE IF NOT EXISTS members ( \
	gid		INTEGER NOT NULL, \
	uid     INTEGER NOT NULL);"

extern char *cache_directory, *cache_owner, *cache_group, *cache_mode;

int create_cache_directory(pam_handle_t *pamh) {
    // Check if the directory already exists
    struct stat st;
    if (stat(cache_directory, &st) == 0) {
        if (S_ISDIR(st.st_mode)) {
            fprintf(stderr, "Cache directory %s already exists. Skipping creation.\n", cache_directory);
            return 0;
        }
    }

    int mode = strtol(cache_mode, 0, 8);
    pam_syslog(pamh, LOG_DEBUG, "Creating %s with mode %d\n", cache_directory, mode);
    // Create the directory
    if (mkdir(cache_directory, mode) == -1) {
        fprintf(stderr, "Cache directory %s could not be created.\n", cache_directory);
        return 1;
    }

    struct passwd *p;
    struct group *grp;
    int uid = 0;
    int gid = 0;

    /* It will default to root if something goes wrong */
    if ((p = getpwnam(cache_owner)) != NULL)
        uid = p->pw_uid;
    if ((grp = getgrnam(cache_owner)) != NULL)
        gid = grp->gr_gid;

    if (chown(cache_directory, uid, gid) == -1) {
        fprintf(stderr, "Could not chown %s to %s.\n", cache_directory, cache_mode);
        return 1;
    }
    return 0;
}

char * user_without_at(char *user_str) {
    char *user = strdup(user_str);
    char *token = strtok(user, "@");
    if (token == NULL)
        return user_str;
    return strdup(user);
}

void hashPasswordSHA512(const char* password, char* hashedPassword) {
    unsigned char hash[SHA512_DIGEST_LENGTH];
    SHA512_CTX sha512;

    SHA512_Init(&sha512);
    SHA512_Update(&sha512, password, strlen(password));
    SHA512_Final(hash, &sha512);

    for (int i = 0; i < SHA512_DIGEST_LENGTH; i++) {
        sprintf(hashedPassword + (i * 2), "%02x", hash[i]);
    }

    hashedPassword[128] = '\0';  // Null-terminate the string
}

sqlite3 *db_connect(pam_handle_t *pamh) {
    sqlite3 *db;
    sqlite3_stmt *res;
    char db_path[strlen(cache_directory)+strlen(DB_FILE_NAME)];
    char *err_msg = 0;

    sprintf(db_path, "%s/%s", cache_directory, DB_FILE_NAME);
    if (access(db_path, F_OK) != 0) {
        pam_syslog(pamh, LOG_ERR,  "Cannot connect to the database because it has not been initialised");
        return NULL;
    }

    int rc = sqlite3_open(db_path, &db);
    
    if (rc != SQLITE_OK) {
        
        pam_syslog(pamh, LOG_ERR,  "Cannot open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        
        return NULL;
    } 
    return db;
}

/*
0 error or user not found
*/
int get_user_uid(pam_handle_t *pamh, char *user_addr) {
    sqlite3 *db;
    sqlite3_stmt *res;
    int rc;
    char *err_msg = 0;

    db = db_connect(pamh);
    if (db == NULL)
        return 0;

    char query[255];
    sprintf(query, "SELECT uid FROM passwd WHERE login = '%s'", user_addr);
    rc = sqlite3_prepare_v2(db, query, -1, &res, 0);    
    
    if (rc != SQLITE_OK) {
        pam_syslog(pamh, LOG_ERR, "select uid from passwd: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        
        return 1;
    }

    int uid = 0;
    rc = sqlite3_step(res);
    if (rc == SQLITE_ROW) {
        uid = sqlite3_column_int(res, 0);
    }

    sqlite3_finalize(res);
    sqlite3_close(db);
    return uid;
}

/*
0 error or user not found
*/
int get_group_gid(pam_handle_t *pamh, char *group_name) {
    sqlite3 *db;
    sqlite3_stmt *res;
    int rc;
    char *err_msg = 0;

    db = db_connect(pamh);
    if (db == NULL)
        return 0;

    char query[255];
    sprintf(query, "SELECT gid FROM groups WHERE name = '%s'", group_name);
    rc = sqlite3_prepare_v2(db, query, -1, &res, 0);    
    
    if (rc != SQLITE_OK) {
        pam_syslog(pamh, LOG_ERR, "select gid from groups: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        
        return 1;
    }

    int gid = 0;
    rc = sqlite3_step(res);
    if (rc == SQLITE_ROW) {
        gid = sqlite3_column_int(res, 0);
    }
    sqlite3_finalize(res);
    sqlite3_close(db);
    return gid;
}

/*
Returns:
0 - cache initialised or existing
1 - error
*/
int init_cache(pam_handle_t *pamh) { 
    sqlite3 *db;
    sqlite3_stmt *res;
    char *err_msg = 0;
    char db_path[strlen(cache_directory)+strlen(DB_FILE_NAME)];

    sprintf(db_path, "%s/%s", cache_directory, DB_FILE_NAME);
    if (access(db_path, F_OK) == 0) {
        return 0;
    }

    pam_syslog(pamh, LOG_DEBUG,  "Creating sqlite3 DB in %s", db_path);
    int rc = sqlite3_open(db_path, &db);
    
    if (rc != SQLITE_OK) {
        
        pam_syslog(pamh, LOG_ERR,  "Cannot open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        
        return NULL;
    }
    if (db == NULL) {
        pam_syslog(pamh, LOG_ERR,  "SQL init: could not connect to the DB");
        return 1;
    }

    rc = sqlite3_exec(db, PASSWD_CREATE, 0, 0, &err_msg);
    if (rc != SQLITE_OK ) {
        
        pam_syslog(pamh, LOG_ERR,  "SQL error passwd create: %s\n", err_msg);
        
        sqlite3_free(err_msg);        
        sqlite3_close(db);
        
        return 1;
    }
    rc = sqlite3_exec(db, SHADOW_CREATE, 0, 0, &err_msg);
    if (rc != SQLITE_OK ) {
        
        pam_syslog(pamh, LOG_ERR,  "SQL error shadow create: %s\n", err_msg);
        
        sqlite3_free(err_msg);        
        sqlite3_close(db);
        
        return 1;
    }
    rc = sqlite3_exec(db, GROUPS_CREATE, 0, 0, &err_msg);
    if (rc != SQLITE_OK ) {
        
        pam_syslog(pamh, LOG_ERR,  "SQL error groups create: %s\n", err_msg);
        
        sqlite3_free(err_msg);        
        sqlite3_close(db);
        
        return 1;
    }
    rc = sqlite3_exec(db, GROUP_MEMBERS, 0, 0, &err_msg);
    if (rc != SQLITE_OK ) {
        
        pam_syslog(pamh, LOG_ERR,  "SQL error group members: %s\n", err_msg);
        
        sqlite3_free(err_msg);        
        sqlite3_close(db);
        
        return 1;
    }
    rc = sqlite3_exec(db, SHADOW_CREATE, 0, 0, &err_msg);
    if (rc != SQLITE_OK ) {
        
        pam_syslog(pamh, LOG_ERR,  "SQL error shadow create: %s\n", err_msg);
        
        sqlite3_free(err_msg);
        sqlite3_close(db);
        
        return 1;
    }
    sqlite3_finalize(res);
    sqlite3_close(db);
    
    return 0;
}

int cache_user(pam_handle_t *pamh, char *user_addr, char *password) {
    sqlite3 *db;
    sqlite3_stmt *res;
    char db_path[strlen(cache_directory)+strlen(DB_FILE_NAME)];
    char *err_msg = 0;
    int rc;

    db = db_connect(pamh);
    if (db == NULL)
        return 1;

    char group_insert[255];
    int gid;
    sprintf(group_insert, "INSERT OR IGNORE INTO groups (name) VALUES('%s')", user_addr);

    rc = sqlite3_exec(db, group_insert, 0, 0, &err_msg);
    if (rc != SQLITE_OK ) {
        
        pam_syslog(pamh, LOG_ERR,  "SQL error: %s\n", err_msg);
        pam_syslog(pamh, LOG_DEBUG, "%s\n", group_insert);
        
        sqlite3_free(err_msg);        
        sqlite3_close(db);
        
        return 1;
    }

    sprintf(group_insert, "SELECT gid FROM groups WHERE name = '%s'", user_addr);
    rc = sqlite3_prepare_v2(db, group_insert, -1, &res, 0);    
    
    if (rc != SQLITE_OK) {
        
        pam_syslog(pamh, LOG_ERR,  "Failed to fetch data: %s\n", sqlite3_errmsg(db));
        pam_syslog(pamh, LOG_ERR, "select gid from groups: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        
        return 1;
    }

    rc = sqlite3_step(res);
    if (rc == SQLITE_ROW) {
        gid = sqlite3_column_int(res, 0);
    }

    char passwd_insert[255];
    sprintf(passwd_insert, "INSERT OR IGNORE INTO passwd (login, gid, home) VALUES('%s', %d, '/home/%s')", user_addr, gid, user_without_at(user_addr));

    rc = sqlite3_exec(db, passwd_insert, 0, 0, &err_msg);
    if (rc != SQLITE_OK ) {
        
        pam_syslog(pamh, LOG_ERR,  "SQL error: %s\n", err_msg);
        
        sqlite3_free(err_msg);        
        sqlite3_close(db);
        
        return 1;
    }

    /* Shadow */
    char shadow_insert[255];
    //char hashedPassword[129];
    //hashPasswordSHA512(password, hashedPassword);
    //sprintf(shadow_insert, "INSERT OR IGNORE INTO shadow (login, password) VALUES('%s', '%s')", user_addr, hashedPassword);
    sprintf(shadow_insert, "INSERT OR IGNORE INTO shadow (login, password) VALUES('%s', 'x')", user_addr);
    pam_syslog(pamh, LOG_DEBUG, "%s\n", shadow_insert);

    rc = sqlite3_exec(db, shadow_insert, 0, 0, &err_msg);
    if (rc != SQLITE_OK ) {
        
        pam_syslog(pamh, LOG_ERR,  "SQL error shadow: %s\n", err_msg);
        
        sqlite3_free(err_msg);        
        sqlite3_close(db);
        
        return 1;
    }
    sqlite3_finalize(res);
    sqlite3_close(db);

    return 0;
}

int cache_insert_group(pam_handle_t *pamh, char *group) {
    sqlite3 *db;
    sqlite3_stmt *res;
    char *err_msg = 0;
    int rc = 0;

    db = db_connect(pamh);
    if (db == NULL)
        return 1;

    char group_insert[255];    
    sprintf(group_insert, "INSERT OR IGNORE INTO groups (name) VALUES('%s')", group);
    rc = sqlite3_exec(db, group_insert, 0, 0, &err_msg);
    if (rc != SQLITE_OK ) {
        
        pam_syslog(pamh, LOG_ERR,  "SQL error: %s\n", err_msg);
        pam_syslog(pamh, LOG_DEBUG, "%s\n", group_insert);
        
        sqlite3_free(err_msg);
        sqlite3_close(db);
        
        return 1;
    }
    int gid = get_group_gid(pamh, group);
    sqlite3_finalize(res);
    sqlite3_close(db);

    return gid;
}

int cache_user_group(pam_handle_t *pamh, char *user_addr, char *group) {
    sqlite3 *db;
    sqlite3_stmt *res;
    char *err_msg = 0;

    db = db_connect(pamh);
    if (db == NULL)
        return 1;

    int uid = get_user_uid(pamh, user_addr);
    int gid = get_group_gid(pamh, group);
    if (gid == 0)
        gid = cache_insert_group(pamh, group);
    if (gid < 100) {
        pam_syslog(pamh, LOG_ERR,  "Cannot add %s to group %s due to SQL error", user_addr, group);
        return 1;
    }

    int rc;
    char group_insert[255];

    sprintf(group_insert, "INSERT OR IGNORE INTO members VALUES(%d, %d)", gid, uid);
    rc = sqlite3_exec(db, group_insert, 0, 0, &err_msg);
    if (rc != SQLITE_OK ) {
        
        pam_syslog(pamh, LOG_ERR,  "SQL error: %s\n", err_msg);
        pam_syslog(pamh, LOG_DEBUG, "%s\n", group_insert);
        
        sqlite3_free(err_msg);        
        sqlite3_close(db);
        
        return 1;
    }
    sqlite3_finalize(res);
    sqlite3_close(db);
    return 0;
}

int cache_user_groups(pam_handle_t *pamh, char *user_addr, json_t *groups) {
    size_t index;
    json_t *value;

    json_array_foreach(groups, index, value) {
        const char *group = json_string_value(json_object_get(value, "displayName"));
        if ((group == NULL) || (strlen(group)) < 2) continue;
        pam_syslog(pamh, LOG_DEBUG, "Caching group member %s of group %s\n", user_addr, group);

        int ret = cache_user_group(pamh, user_addr, group);
        if (ret != 0) {
            pam_syslog(pamh, LOG_ERR, "Error caching group member %s of group %s\n", user_addr, group);
        }
    }

    return 0;
}