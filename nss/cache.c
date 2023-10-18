#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <security/pam_appl.h>
#include <security/pam_ext.h>
#include <security/pam_modules.h>
#include <sys/syslog.h>
#include <crypt.h>
#include <sys/stat.h>
#include <sys/types.h>
#define _POSIX_SOURCE
#include <pwd.h>
#include <grp.h>
#include <ctype.h>
#include <time.h>
#include <jansson.h>
#include "types.h"

#define PASSWD_DB_FILE "passwd.db"
#define GROUPS_DB_FILE "groups.db"
#define SHADOW_DB_FILE "shadow.db"
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
	min_pwd_age     INTEGER NOT NULL DEFAULT 0, \
	max_pwd_age     INTEGER NOT NULL DEFAULT 99999, \
	pwd_warn_period	INTEGER NOT NULL DEFAULT 7, \
	pwd_inactivity	INTEGER NOT NULL DEFAULT 7, \
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

#define HOME_ROOT "/azure"

long days_since_epoch() {
    time_t now;
    time(&now); // Get the current time in seconds since epoch

    // The number of seconds in a day is 24 * 60 * 60
    long days = now / (24 * 60 * 60);
    return days;
}

int create_cache_directory() {
    if (json_config.tenant == NULL)
        load_config(&json_config);

    // Check if the directory already exists
    struct stat st;
    if (stat(json_config.cache_directory, &st) == 0) {
        if (S_ISDIR(st.st_mode)) {
            fprintf(stderr, "Cache directory %s already exists. Skipping creation.\n", json_config.cache_directory);
            return 0;
        }
    }

    int mode = strtol(json_config.cache_mode, 0, 8);
    fprintf(stderr, "Creating %s with mode %d\n", json_config.cache_directory, mode);
    // Create the directory
    if (mkdir(json_config.cache_directory, mode) == -1) {
        fprintf(stderr, "Cache directory %s could not be created.\n", json_config.cache_directory);
        return 1;
    }

    struct passwd *p;
    struct group *grp;
    int uid = 0;
    int gid = 0;

    /* It will default to root if something goes wrong */
    if ((p = getpwnam(json_config.cache_owner)) != NULL)
        uid = p->pw_uid;
    if ((grp = getgrnam(json_config.cache_owner)) != NULL)
        gid = grp->gr_gid;

    if (chown(json_config.cache_directory, uid, gid) == -1) {
        fprintf(stderr, "Could not chown %s to %s.\n", json_config.cache_directory, json_config.cache_mode);
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

/*
Returns:
0 - cache initialised or existing
1 - error
*/
int init_cache(const char *db_file) { 
    sqlite3 *db;
    sqlite3_stmt *res;
    char *err_msg = 0;

    if (json_config.tenant == NULL)
        load_config(&json_config);

    char db_path[255];
    sprintf(db_path, "%s/%s", json_config.cache_directory, db_file);

    int rc = sqlite3_open(db_path, &db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        
        return NULL;
    }
        
    if (db == NULL) {
        fprintf(stderr,  "Cannot open database: %s\n", sqlite3_errmsg(db));
        
        return NULL;
    }

    if (strcmp(db_file, PASSWD_DB_FILE) == 0) {
        rc = sqlite3_exec(db, PASSWD_CREATE, 0, 0, &err_msg);
        if (rc != SQLITE_OK ) {
            
            fprintf(stderr, "SQL error passwd create: %s\n", err_msg);
            
            sqlite3_free(err_msg);        
            sqlite3_close(db);
            
            return 1;
        }
    } else if (strcmp(db_file, SHADOW_DB_FILE) == 0) {
        rc = sqlite3_exec(db, SHADOW_CREATE, 0, 0, &err_msg);
        if (rc != SQLITE_OK ) {
            
            fprintf(stderr,  "SQL error shadow create: %s\n", err_msg);
            
            sqlite3_free(err_msg);        
            sqlite3_close(db);
            
            return 1;
        }
    } else if (strcmp(db_file, GROUPS_DB_FILE) == 0) {
        rc = sqlite3_exec(db, GROUPS_CREATE, 0, 0, &err_msg);
        if (rc != SQLITE_OK ) {
            
            fprintf(stderr,  "SQL error groups create: %s\n", err_msg);
            
            sqlite3_free(err_msg);        
            sqlite3_close(db);
            
            return 1;
        }

        rc = sqlite3_exec(db, GROUP_MEMBERS, 0, 0, &err_msg);
        if (rc != SQLITE_OK ) {
            
            fprintf(stderr,  "SQL error group members: %s\n", err_msg);
            
            sqlite3_free(err_msg);
            sqlite3_close(db);
            
            return 1;
        
        }
    }

    sqlite3_finalize(res);
    sqlite3_close(db);
    
    return 0;
}

int cache_user_shadow(char *user_addr) {
    sqlite3 *db;
    char *err_msg = 0;
    int rc;

    if (json_config.tenant == NULL)
        load_config(&json_config);

    db = db_connect(SHADOW_DB_FILE);
    if (db == NULL)
        return 1;

    /* Shadow */
    char shadow_insert[255];
    sprintf(shadow_insert, "INSERT OR IGNORE INTO shadow (login, password, last_pwd_change, expiration_date) VALUES('%s', 'x', %ld, %ld)", user_addr, days_since_epoch(), days_since_epoch()+90);
    fprintf(stderr, "NSS DEBUG: %s\n", shadow_insert);

    rc = sqlite3_exec(db, shadow_insert, 0, 0, &err_msg);
    if (rc != SQLITE_OK ) {
        
        fprintf(stderr,  "SQL error shadow: %s\n", err_msg);
        
        sqlite3_free(err_msg);        
        sqlite3_close(db);
        
        return 1;
    }

    sqlite3_close(db);

    return 0;
}

int cache_user(char *user_addr) {
    sqlite3 *db;
    char *err_msg = 0;
    int rc;

    if (json_config.tenant == NULL)
        load_config(&json_config);

    db = db_connect(GROUPS_DB_FILE);
    if (db == NULL)
        return 1;

    int gid = cache_insert_group(user_addr);

    char passwd_insert[255];
    db = db_connect(PASSWD_DB_FILE);
    if (db == NULL)
        return 1;

    sprintf(passwd_insert, "INSERT OR IGNORE INTO passwd (login, gid, home) VALUES('%s', %d, '%s/%s')", user_addr, gid, HOME_ROOT, user_without_at(user_addr));

    rc = sqlite3_exec(db, passwd_insert, 0, 0, &err_msg);
    if (rc != SQLITE_OK ) {
        
        fprintf(stderr,  "SQL error: %s\n", err_msg);
        
        sqlite3_free(err_msg);        
        sqlite3_close(db);
        
        return 1;
    }

    sqlite3_close(db);

    fprintf(stderr, "%s():%d - Caching shadow credentials for user [%s]\n", __FUNCTION__, __LINE__, user_addr);
    rc = cache_user_shadow(user_addr);
    if (rc != 0) {
        fprintf(stderr, "user cached but not the shadow entries");
    }

    return rc;
}

int get_group_gid(char *group_name) {
    sqlite3 *db;
    sqlite3_stmt *res;
    int rc;
    char *err_msg = 0;

    if (json_config.tenant == NULL)
        load_config(&json_config);

    db = db_connect(GROUPS_DB_FILE);
    if (db == NULL)
        return 0;

    char query[255];
    sprintf(query, "SELECT gid FROM groups WHERE name = '%s'", group_name);
    rc = sqlite3_prepare_v2(db, query, -1, &res, 0);    
    
    if (rc != SQLITE_OK) {
        fprintf(stderr, "select gid from groups: %s\n", sqlite3_errmsg(db));
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

int cache_insert_group(char *group) {
    sqlite3 *db;
    sqlite3_stmt *res;
    char *err_msg = 0;
    int rc = 0;
    const char *group_insert_template = "INSERT OR IGNORE INTO groups (name) VALUES('%s')";

    if (json_config.tenant == NULL)
        load_config(&json_config);

    db = db_connect(GROUPS_DB_FILE);
    if (db == NULL)
        return 1;

    char group_insert[strlen(group) + strlen(group_insert_template)];
    sprintf(group_insert, group_insert_template, group);

    fprintf(stderr, "%s():%d - %s\n", __FUNCTION__, __LINE__, group_insert);
    rc = sqlite3_exec(db, group_insert, 0, 0, &err_msg);
    if (rc != SQLITE_OK ) {
        
        fprintf(stderr,  "SQL error: %s\n", err_msg);
        fprintf(stderr, "%s\n", group_insert);
        
        sqlite3_free(err_msg);
        sqlite3_close(db);
        
        return 1;
    }
    fprintf(stderr, "%s():%d - %s\n", __FUNCTION__, __LINE__, group_insert);

    int gid = get_group_gid(group);
    sqlite3_finalize(res);
    sqlite3_close(db);

    return gid;
}

int cache_user_group(char *user_addr, char *group) {
    sqlite3 *db;
    sqlite3_stmt *res;
    char *err_msg = 0;

    if (json_config.tenant == NULL)
        load_config(&json_config);

    /* Ensure db is created */
    if (init_cache(GROUPS_DB_FILE) != 0) {
        fprintf(stderr, "%s():%d failed to init cache\n", __FUNCTION__, __LINE__);
        return 0;
    }
    if (init_cache(PASSWD_DB_FILE) != 0) {
        fprintf(stderr, "%s():%d failed to init cache\n", __FUNCTION__, __LINE__);
        return 0;
    }

    db = db_connect(GROUPS_DB_FILE);
    if (db == NULL)
        return 1;

    int uid = get_user_uid(user_addr);
    int gid = get_group_gid(group);
    if (gid == 0)
        gid = cache_insert_group(group);
    if (gid < 100) {
        fprintf(stderr,  "Cannot add %s to group %s due to SQL error", user_addr, group);
        return 1;
    }

    int rc;
    char group_insert[255];

    sprintf(group_insert, "INSERT OR IGNORE INTO members VALUES(%d, %d)", gid, uid);
    rc = sqlite3_exec(db, group_insert, 0, 0, &err_msg);
    if (rc != SQLITE_OK ) {
        
        fprintf(stderr,  "SQL error: %s\n", err_msg);
        fprintf(stderr, "%s\n", group_insert);
        
        sqlite3_free(err_msg);        
        sqlite3_close(db);
        
        return 1;
    }
    sqlite3_finalize(res);
    sqlite3_close(db);
    return 0;
}

int cache_user_groups(char *user_addr, json_t *groups) {
    size_t index;
    json_t *value;

    /* Ensure db is created */
    if (init_cache(GROUPS_DB_FILE) != 0) {
        fprintf(stderr, "%s():%d failed to init cache\n", __FUNCTION__, __LINE__);
        return 0;
    }
    if (init_cache(PASSWD_DB_FILE) != 0) {
        fprintf(stderr, "%s():%d failed to init cache\n", __FUNCTION__, __LINE__);
        return 0;
    }

    json_array_foreach(groups, index, value) {
        const char *group = json_string_value(json_object_get(value, "displayName"));
        if ((group == NULL) || (strlen(group)) < 2) continue;
        fprintf(stderr, "Caching group member %s of group %s\n", user_addr, group);

        int ret = cache_user_group(user_addr, group);
        if (ret != 0) {
            fprintf(stderr, "Error caching group member %s of group %s\n", user_addr, group);
        }
    }

    return 0;
}
