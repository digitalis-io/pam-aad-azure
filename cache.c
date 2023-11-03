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
#include <sys/stat.h>
#include <sys/types.h>
#define _POSIX_SOURCE
#include <pwd.h>
#include <grp.h>
#include <ctype.h>
#include <time.h>
#include <errno.h>
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

extern struct nss_config json_config;

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

int create_cache_directory(pam_handle_t *pamh) {
    // Check if the directory already exists
    struct stat st;
    if (stat(json_config.cache_directory, &st) == 0) {
        if (S_ISDIR(st.st_mode)) {
            pam_syslog(pamh, LOG_ERR,  "Cache directory %s already exists. Skipping creation.\n", json_config.cache_directory);
            return 0;
        }
    }
    if (geteuid() != 0) {
        if (access(json_config.cache_directory, W_OK) != 0) {
            pam_syslog(pamh, LOG_ERR, "The current user cannot write to %s\n", json_config.cache_directory);
            return 0;
        }
    }
    int mode = strtol(json_config.cache_mode, 0, 8);
    pam_syslog(pamh, LOG_DEBUG, "Creating %s with mode %d\n", json_config.cache_directory, mode);
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

sqlite3 *db_connect(pam_handle_t *pamh, const char *db_file) {
    sqlite3 *db;
    sqlite3_stmt *res;
    char db_path[strlen(json_config.cache_directory)+strlen(db_file)];
    char *err_msg = 0;

    sprintf(db_path, "%s/%s", json_config.cache_directory, db_file);
    if (access(db_path, F_OK) != 0) {
        pam_syslog(pamh, LOG_DEBUG,  "Cannot connect to the database because it has not been initialised");

        if (init_cache(pamh, db_file) != 0) {
            pam_syslog(pamh, LOG_ERR,  "Cannot connect to the database because it has not been initialised");
            return NULL;
        }
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
    sqlite3_stmt *stmt;
    int rc;
    char *err_msg = 0;

    db = db_connect(pamh, PASSWD_DB_FILE);
    if (db == NULL)
        return 0;

    if (sqlite3_prepare_v2(db,"SELECT uid FROM passwd WHERE login = ?", -1, &stmt, NULL)) {
       pam_syslog(pamh, LOG_ERR, "%s(): Error executing sql statement\n", __FUNCTION__);
       sqlite3_close(db);
       return 1;
    }
    sqlite3_bind_text(stmt, 1, user_addr, -1, NULL);

    int uid = 0;
    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        uid = sqlite3_column_int(stmt, 0);
    }

    sqlite3_finalize(stmt);
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

    db = db_connect(pamh, GROUPS_DB_FILE);
    if (db == NULL)
        return 0;

    if (sqlite3_prepare_v2(db,"SELECT gid FROM groups WHERE name = ?", -1, &res, NULL)) {
       pam_syslog(pamh, LOG_ERR, "%s(): Error executing sql statement\n", __FUNCTION__);
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

/*
Returns:
0 - cache initialised or existing
1 - error
*/
int init_cache(pam_handle_t *pamh, const char *db_file) { 
    sqlite3 *db;
    sqlite3_stmt *res;
    char *err_msg = 0;
    char db_path[strlen(json_config.cache_directory)+strlen(db_file)];
    sprintf(db_path, "%s/%s", json_config.cache_directory, db_file);
    if (geteuid() != 0) {
        if (access(db_path, W_OK) != 0) {
            pam_syslog(pamh, LOG_DEBUG,  "The current user %d cannot write to %s\n", geteuid(), db_path);
            return 1;
        }
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

    if (db_file == PASSWD_DB_FILE) {
        rc = sqlite3_exec(db, PASSWD_CREATE, 0, 0, &err_msg);
        if (rc != SQLITE_OK ) {
            
            pam_syslog(pamh, LOG_ERR,  "SQL error passwd create: %s\n", err_msg);
            
            sqlite3_free(err_msg);        
            sqlite3_close(db);
            
            return 1;
        }
    } else if (db_file == SHADOW_DB_FILE) {
        rc = sqlite3_exec(db, SHADOW_CREATE, 0, 0, &err_msg);
        if (rc != SQLITE_OK ) {
            
            pam_syslog(pamh, LOG_ERR,  "SQL error shadow create: %s\n", err_msg);
            
            sqlite3_free(err_msg);        
            sqlite3_close(db);
            
            return 1;
        }
    } else if (db_file == GROUPS_DB_FILE) {
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
    }

    sqlite3_finalize(res);
    sqlite3_close(db);
    char full_path[strlen(db_file)+strlen(json_config.cache_directory)+1];
    sprintf(full_path, "%s/%s", json_config.cache_directory, db_file);
    if (geteuid() == 0) {
        if (set_file_permissions(full_path, json_config.cache_mode) == -1) {
            pam_syslog(pamh, LOG_ERR, "Cannot set permissions for %s: %s\n", db_file, strerror(errno));
        }
    }
  
    return 0;
}

int cache_user(pam_handle_t *pamh, char *user_addr) {
    sqlite3 *db;
    sqlite3_stmt *res;
    int rc;

    db = db_connect(pamh, GROUPS_DB_FILE);
    if (db == NULL)
        return 1;

    char db_path[255];
    sprintf(db_path, "%s/%s", json_config.cache_directory, GROUPS_DB_FILE);
    if (geteuid() != 0) {
        if (access(db_path, W_OK) != 0) {
            pam_syslog(pamh, LOG_DEBUG,  "The current user cannot write to %s\n", db_path);
            return 1;
        }
    }

    if (sqlite3_prepare_v2(db,"INSERT OR IGNORE INTO groups (name) VALUES (?)", -1, &res, NULL)) {
       pam_syslog(pamh, LOG_ERR, "%s(): Error preparing sql statement: %s\n", __FUNCTION__, sqlite3_errmsg(db));
       sqlite3_close(db);
       return 1;
    }
    sqlite3_bind_text(res, 1, user_addr, -1, NULL);
    rc = sqlite3_step(res);
    if ((rc != SQLITE_OK ) && (rc != SQLITE_DONE)) {        
        pam_syslog(pamh, LOG_ERR, "%s(): Failed to cache groups: %s - %d\n",  __FUNCTION__, sqlite3_errmsg(db), rc);
        sqlite3_finalize(res);
        sqlite3_close(db);
        return rc;
    }
    sqlite3_reset(res);

    int gid;
    gid = get_group_gid(pamh, user_addr);

    sprintf(db_path, "%s/%s", json_config.cache_directory, PASSWD_DB_FILE);
    if (geteuid() != 0) {
        if (access(db_path, W_OK) != 0) {
            pam_syslog(pamh, LOG_DEBUG,  "The current user %d cannot write to %s\n", geteuid(), db_path);
            return 1;
        }
    }
    db = db_connect(pamh, PASSWD_DB_FILE);
    if (db == NULL)
        return 1;

    if (sqlite3_prepare_v2(db, "INSERT OR IGNORE INTO passwd (login, gid, home) VALUES(?, ?, ?)", -1, &res, NULL)) {
       pam_syslog(pamh, LOG_ERR, "%s(): Error preparing sql statement: %s\n", __FUNCTION__, sqlite3_errmsg(db));
       sqlite3_close(db);
       return 1;
    }
    char home[255];
    sprintf(home, "%s/%s", HOME_ROOT, user_without_at(user_addr));
    sqlite3_bind_text(res, 1, user_addr, -1, NULL);
    sqlite3_bind_int (res, 2, gid);
    sqlite3_bind_text(res, 3, home, -1, NULL);

    pam_syslog(pamh, LOG_DEBUG,  "INSERT OR IGNORE INTO passwd (login, gid, home) VALUES('%s', %d, '%s')", user_addr, gid, home);

    rc = sqlite3_step(res);
    if (rc != SQLITE_DONE) {
        pam_syslog(pamh, LOG_ERR, "%s(): Failed to cache groups: %s\n",  __FUNCTION__, sqlite3_errmsg(db));
        sqlite3_finalize(res);
        sqlite3_close(db);
        return rc;
    }

    sqlite3_finalize(res);
    sqlite3_close(db);

    pam_syslog(pamh, LOG_DEBUG, "Caching shadow credentials for user [%s]", user_addr);
    rc = cache_user_shadow(pamh, user_addr);
    if (rc != 0) {
        pam_syslog(pamh, LOG_ERR,  "user cached but not the shadow entries");
    }
    
    return rc;
}

int cache_user_shadow(pam_handle_t *pamh, char *user_addr) {
    sqlite3 *db;
    sqlite3_stmt *res;
    char db_path[strlen(json_config.cache_directory)+strlen(SHADOW_DB_FILE) + 10];
    char *err_msg = 0;
    int rc;

    db = db_connect(pamh, SHADOW_DB_FILE);
    if (db == NULL)
        return 1;

    pam_syslog(pamh, LOG_DEBUG, "%s: Caching shadow credentials for user [%s]", __FUNCTION__, user_addr);
    sprintf(db_path, "%s/%s", json_config.cache_directory, SHADOW_DB_FILE);
    if (geteuid() != 0) {
        if (access(db_path, W_OK) != 0) {
            pam_syslog(pamh, LOG_DEBUG,  "The current user cannot write to %s\n", db_path);
            return 1;
        }
    }

    /* Shadow */
    if (sqlite3_prepare_v2(db, "INSERT OR IGNORE INTO shadow (login, password, last_pwd_change, expiration_date) VALUES(?, 'x', ?, ?)", -1, &res, NULL)) {
       pam_syslog(pamh, LOG_ERR, "%s(): Error executing sql statement\n", __FUNCTION__);
       sqlite3_close(db);
       return 1;
    }
    sqlite3_bind_text(res, 1, user_addr, -1, NULL);
    sqlite3_bind_int (res, 2, days_since_epoch());
    sqlite3_bind_int (res, 3, days_since_epoch() + 90);

    rc = sqlite3_step(res);
    if (rc != SQLITE_DONE) {
        pam_syslog(pamh, LOG_ERR, "%s(): Failed to cache user: %s\n",  __FUNCTION__, sqlite3_errmsg(db));
        sqlite3_finalize(res);
        sqlite3_close(db);
        return rc;
    }

    sqlite3_finalize(res);
    sqlite3_close(db);

    return 0;
}

int cache_insert_group(pam_handle_t *pamh, char *group) {
    sqlite3 *db;
    sqlite3_stmt *stmt;
    int rc = 0;

    db = db_connect(pamh, GROUPS_DB_FILE);
    if (db == NULL)
        return 1;

    char db_path[255];
    sprintf(db_path, "%s/%s", json_config.cache_directory, GROUPS_DB_FILE);
    if (geteuid() != 0) {
        if (access(db_path, W_OK) != 0) {
            pam_syslog(pamh, LOG_DEBUG,  "The current user %d cannot write to %s\n", geteuid(), db_path);
            return 1;
        }
    }

    if (rc = sqlite3_prepare_v2(db, "INSERT OR IGNORE INTO groups (name) VALUES(?)", -1, &stmt, NULL)) {
       fprintf(stderr, "%s(): Error executing sql statement\n", __FUNCTION__);
       sqlite3_finalize(stmt);
       sqlite3_close(db);
       return 1;
    }
    sqlite3_bind_text(stmt, 1, group, -1, NULL);

    rc = sqlite3_step(stmt);
    if ((rc != SQLITE_OK ) && (rc != SQLITE_DONE)) {        
        pam_syslog(pamh, LOG_ERR,  "SQL error: %s\n", sqlite3_errmsg(db));
        
        sqlite3_close(db);
        
        return 1;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);

    int gid = get_group_gid(pamh, group);

    return gid;
}

int cache_user_group(pam_handle_t *pamh, char *user_addr, char *group) {
    sqlite3 *db;
    sqlite3_stmt *stmt;
    char *err_msg = 0;

    if (json_config.tenant == NULL)
        load_config(&json_config);

    db = db_connect(pamh, GROUPS_DB_FILE);
    if (db == NULL)
        return 1;

    char db_path[255];
    if (geteuid() != 0) {
        sprintf(db_path, "%s/%s", json_config.cache_directory, GROUPS_DB_FILE);
        if (access(db_path, W_OK) != 0) {
            pam_syslog(pamh, LOG_DEBUG,  "The current user cannot write to %s\n", db_path);
            return 1;
        }
    }

    int uid = get_user_uid(pamh, user_addr);
    if (uid < 100) {
        pam_syslog(pamh, LOG_ERR, "Cannot find user %s in the cache\n", user_addr);
        return 1;
    }
    int gid = get_group_gid(pamh, group);
    if (gid == 0)
        gid = cache_insert_group(pamh, group);
    if (gid < 100) {
        pam_syslog(pamh, LOG_ERR,  "Cannot add %s to group %s due to SQL error", user_addr, group);
        return 1;
    }

    int rc;
    if (rc = sqlite3_prepare_v2(db, "INSERT OR IGNORE INTO members VALUES(?, ?)", -1, &stmt, NULL)) {
       fprintf(stderr, "%s(): Error executing sql statement: %s\n", __FUNCTION__, sqlite3_errstr(db));
       sqlite3_close(db);
       return 1;
    }

    sqlite3_bind_int (stmt, 1, gid);
    sqlite3_bind_int (stmt, 2, uid);
    pam_syslog(pamh, LOG_DEBUG, "==>> INSERT OR IGNORE INTO members VALUES(%d, %d)\n", uid, gid);

    if (sqlite3_step(stmt) == SQLITE_ERROR)
        rc = 1;
    else
        rc = 0;

    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return rc;
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

/* FIXME: add error checking */
int init_cache_all(pam_handle_t *pamh) {
    int rc = 0;
    rc += init_cache(pamh, PASSWD_DB_FILE);
    rc += init_cache(pamh, SHADOW_DB_FILE);
    rc += init_cache(pamh, GROUPS_DB_FILE);
    return rc;
}
