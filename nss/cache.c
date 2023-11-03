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

long days_since_epoch() {
    time_t now;
    time(&now); // Get the current time in seconds since epoch

    // The number of seconds in a day is 24 * 60 * 60
    long days = now / (24 * 60 * 60);
    return days;
}

int file_permissions_correct(char *filename, char *mode) {
    struct stat fs;
    
    int r = stat(filename, &fs);
    if (r < 0) return r; // ERROR

    char target_mode_str[7];
    if (strlen(mode) == 4) {
        sprintf(target_mode_str, "10%s", mode);
    }
    int mode_target = strtol(target_mode_str, 0, 8);
    
    return fs.st_mode == mode_target;
}

int set_file_permissions(char *filename, char *mode) {
    struct stat fs;

    int r = stat(filename, &fs);
    if (r < 0) return r; // ERROR

    char target_mode_str[7];
    if (strlen(mode) == 4) {
        sprintf(target_mode_str, "10%s", mode);
    }
    int mode_target = strtol(target_mode_str, 0, 8);
    return chmod(filename, mode_target);
}

int create_cache_directory() {
    if (json_config.tenant == NULL)
        load_config(&json_config);

    if ((access(json_config.cache_directory, W_OK) != 0) && (getuid() != 0)) {
        if (DEBUG) fprintf(stderr, "%s(): The current user cannot create %s\n", __FUNCTION__, json_config.cache_directory);
        return 1;
    }

    // Check if the directory already exists
    struct stat st;
    if (stat(json_config.cache_directory, &st) == 0) {
        if (S_ISDIR(st.st_mode)) {
            if (DEBUG) fprintf(stderr, "Cache directory %s already exists. Skipping creation.\n", json_config.cache_directory);
            return 0;
        }
    }

    int mode = strtol("0755", 0, 8);
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
    
    if ((access(json_config.cache_directory, W_OK) != 0) && (geteuid() != 0)) {
        if (DEBUG) fprintf(stderr, "The current user cannot write to %s\n", json_config.cache_directory);
        return 0;
    }

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
    
    set_file_permissions(db_file, json_config.cache_mode);
    return 0;
}

int cache_user_shadow(char *user_addr) {
    sqlite3 *db;
    sqlite3_stmt *res;
    int rc;

    if (json_config.tenant == NULL)
        load_config(&json_config);

    char db_path[strlen(json_config.cache_directory)+strlen(SHADOW_DB_FILE)+2];
    sprintf(db_path, "%s/%s", json_config.cache_directory, SHADOW_DB_FILE);
    if ((access(db_path, W_OK) != 0) && (getuid() != 0)) {
        if (DEBUG) fprintf(stderr, "The current user cannot write to %s\n", db_path);
        return 1;
    }
    db = db_connect(SHADOW_DB_FILE);
    if (db == NULL)
        return 1;

    /* Shadow */
    if (sqlite3_prepare_v2(db, "INSERT OR IGNORE INTO shadow (login, password, last_pwd_change, expiration_date) VALUES(?, 'x', ?, ?)", -1, &res, NULL)) {
       fprintf(stderr, "%s(): Error executing sql statement\n", __FUNCTION__);
       sqlite3_close(db);
       return 1;
    }
    sqlite3_bind_text(res, 1, user_addr, -1, NULL);
    sqlite3_bind_int (res, 2, days_since_epoch());
    sqlite3_bind_int (res, 3, days_since_epoch() + 90);

    rc = sqlite3_step(res);
    if (rc != SQLITE_DONE) {
        fprintf(stderr, "%s(): Failed to cache user: %s\n",  __FUNCTION__, sqlite3_errmsg(db));
        sqlite3_finalize(res);
        sqlite3_close(db);
        return rc;
    }

    sqlite3_finalize(res);
    sqlite3_close(db);

    return 0;
}

int cache_user(char *user_addr) {
    sqlite3 *db;
    sqlite3_stmt *res;
    int rc;

    if (json_config.tenant == NULL)
        load_config(&json_config);

    char db_path[strlen(json_config.cache_directory)+strlen(PASSWD_DB_FILE)+5];
    sprintf(db_path, "%s/%s", json_config.cache_directory, PASSWD_DB_FILE);
    if ((access(db_path, W_OK) != 0) && (geteuid() != 0)) {
        if (DEBUG) fprintf(stderr, "%s(): The current user cannot write to %s\n", __FUNCTION__, db_path);
        return 1;
    }

    sprintf(db_path, "%s/%s", json_config.cache_directory, GROUPS_DB_FILE);
    if ((access(db_path, W_OK) != 0) && (geteuid() != 0)) {
        if (DEBUG) fprintf(stderr, "The current user cannot write to %s\n", db_path);
        return 1;
    }

    if (init_cache_all() > 0) {
        return 1;
    }

    db = db_connect(GROUPS_DB_FILE);
    if (db == NULL)
        return 1;

    fprintf(stderr, "Calling cache_insert_group");
    int gid = cache_insert_group(user_addr);
    if (gid < 100) {
        if (DEBUG) fprintf(stderr, "Could not cache user/group for %s\n", user_addr);
        return 0;
    }

    char passwd_insert[255];
    db = db_connect(PASSWD_DB_FILE);
    if (db == NULL)
        return 1;

    if (sqlite3_prepare_v2(db, "INSERT OR IGNORE INTO passwd (login, gid, home) VALUES(?, ?, ?)", -1, &res, NULL)) {
       fprintf(stderr, "%s(): Error executing sql statement\n", __FUNCTION__);
       sqlite3_close(db);
       return 1;
    }
    char home[255];
    sprintf(home, "%s/%s", json_config.home_directory, user_without_at(user_addr));
    sqlite3_bind_text(res, 1, user_addr, -1, NULL);
    sqlite3_bind_int (res, 2, gid);
    sqlite3_bind_text(res, 3, home, -1, NULL);

    rc = sqlite3_step(res);
    if (rc != SQLITE_DONE) {
        fprintf(stderr, "%s(): Failed to cache user: %s\n",  __FUNCTION__, sqlite3_errmsg(db));
        sqlite3_finalize(res);
        sqlite3_close(db);
        return rc;
    }

    if (DEBUG) fprintf(stderr, "%s():%d - Caching shadow credentials for user [%s]\n", __FUNCTION__, __LINE__, user_addr);
    rc = cache_user_shadow(user_addr);
    if (rc != 0) {
        fprintf(stderr, "user cached but not the shadow entries");
    }
    sqlite3_finalize(res);
    sqlite3_close(db);

    return rc;
}

int get_group_gid(char *group_name) {
    sqlite3 *db;
    sqlite3_stmt *res;
    int rc;

    db = db_connect(GROUPS_DB_FILE);
    if (db == NULL)
        return 0;

    char db_path[strlen(json_config.cache_directory)+strlen(GROUPS_DB_FILE)+5];
    sprintf(db_path, "%s/%s", json_config.cache_directory, GROUPS_DB_FILE);
    if (access(db_path, R_OK) != 0) {
        if (DEBUG) fprintf(stderr, "The current user cannot read from %s\n", db_path);
        return 1;
    }

    if (sqlite3_prepare_v2(db,"SELECT gid FROM groups WHERE name = ?", -1, &res, NULL)) {
       fprintf(stderr, "%s(): Error executing sql statement\n", __FUNCTION__);
       sqlite3_close(db);
       return 1;
    }
    sqlite3_bind_text(res, 1, group_name, -1, NULL);

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

    char db_path[strlen(json_config.cache_directory)+strlen(GROUPS_DB_FILE)+5];
    sprintf(db_path, "%s/%s", json_config.cache_directory, GROUPS_DB_FILE);
    if ((access(db_path, W_OK) != 0) && (geteuid() !=0)) {
        if (DEBUG) fprintf(stderr, "%s(): The current user cannot write to %s\n", __FUNCTION__, db_path);
        return 1;
    }

    db = db_connect(GROUPS_DB_FILE);
    if (db == NULL)
        return 1;

    char group_insert[strlen(group) + strlen(group_insert_template)];
    sprintf(group_insert, group_insert_template, group);

    rc = sqlite3_exec(db, group_insert, 0, 0, &err_msg);
    if (rc != SQLITE_OK ) {
        
        fprintf(stderr,  "SQL error: %s\n", err_msg);
        
        sqlite3_free(err_msg);
        sqlite3_close(db);
        
        return 1;
    }

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

int init_cache_all() {
    int rc = 0;
    rc = create_cache_directory();
    if (rc != 0) {
        return 10;
    }

    rc += init_cache(PASSWD_DB_FILE);
    rc += init_cache(SHADOW_DB_FILE);
    rc += init_cache(GROUPS_DB_FILE);

    return rc;
}
