#include <nss.h>
#include <pwd.h>
#include <grp.h>
#include <nss.h>
#include <shadow.h>
#include <stdio.h>
#include <sqlite3.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <stdlib.h>

#define PASSWD_DB_FILE "passwd.db"
#define GROUPS_DB_FILE "groups.db"
#define SHADOW_DB_FILE "shadow.db"
#define DEBUG 1

pthread_mutex_t pwent_mutex;
const char *cache_directory = "/opt/aad";
const char *cache_owner = "root"; 
const char *cache_group = "postgres";
const char *cache_mode = "0440";

sqlite3 *db_connect(const char *db_file) {
    sqlite3 *db;
    char db_path[strlen(cache_directory)+strlen(db_file)];

    //pthread_mutex_lock(&pwent_mutex);
    sprintf(db_path, "%s/%s", cache_directory, db_file);
    if (access(db_path, F_OK) != 0) {
        fprintf(stderr, "Cannot connect to the database because it has not been initialised\n");
        return NULL;
    }

    int rc = sqlite3_open(db_path, &db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        
        return NULL;
    } 
    //pthread_mutex_unlock(&pwent_mutex);

    return db;
}

/*
-1 error or not found
*/
int get_user_uid(char *user_addr) {
    sqlite3 *db;
    sqlite3_stmt *res;
    int rc;

    db = db_connect(PASSWD_DB_FILE);
    if (db == NULL)
        return -1;

    char query[255];
    sprintf(query, "SELECT uid FROM passwd WHERE login = '%s'", user_addr);
    printf("QUERY = %s\n", query);
    rc = sqlite3_prepare_v2(db, query, -1, &res, 0);    
    
    if (rc != SQLITE_OK) {
        fprintf(stderr, "select uid from passwd: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        
        return -1;
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

enum nss_status get_user_groups(const char *user_addr, gid_t **groups) {
    sqlite3 *db;
    sqlite3_stmt *stmt;
    int rc = NSS_STATUS_SUCCESS;
    const char *query = "SELECT distinct(gid) FROM members WHERE uid=%d";

    int uid = get_user_uid(user_addr);
    if (uid < 0) {
        fprintf("Could not find the UID for the user %s\n", user_addr);
        return NSS_STATUS_NOTFOUND;
    }
    db = db_connect(GROUPS_DB_FILE);

    if (db == NULL)
        return NSS_STATUS_NOTFOUND;

    char groups_query[strlen(query)+10];

    sprintf(groups_query, query, uid);
    if (DEBUG)
        fprintf(stderr, "==>> %s\n", groups_query);

    rc = sqlite3_prepare_v2(db, groups_query, -1, &stmt, 0);    
    
    if (rc != SQLITE_OK) {
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        
        return NSS_STATUS_NOTFOUND;
    }

    int i = 0;
    while (rc = sqlite3_step(stmt) != SQLITE_DONE) {
        if (rc == 1) {
            groups[i] = malloc(sizeof(gid_t *));
            groups[i] = (gid_t *)sqlite3_column_int(stmt, 0);
            i++;
        }
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);

    return rc;
}

enum nss_status get_group_by_query(const char *query, struct group *result) {
    sqlite3 *db;
    sqlite3_stmt *res;
    int rc;

    db = db_connect(GROUPS_DB_FILE);
    if (db == NULL)
        return NSS_STATUS_NOTFOUND;

    if (DEBUG)
        fprintf(stderr, "==>> %s\n", query);

    rc = sqlite3_prepare_v2(db, query, -1, &res, 0);    
    
    if (rc != SQLITE_OK) {
        sqlite3_finalize(res);
        sqlite3_close(db);
        
        return NSS_STATUS_NOTFOUND;
    }

    /* init struct with random default */
    *result = (struct group) {
        .gr_passwd = "x"
    };
    // Execute the SQL statement and fetch the results
    while ((rc = sqlite3_step(res)) == SQLITE_ROW) {
        // Access column values using sqlite3_column_* functions
        result->gr_name = strdup(sqlite3_column_text(res, 0));
        result->gr_gid = sqlite3_column_int(res, 1);
    }
    
    if (!result->gr_gid)
        rc = NSS_STATUS_NOTFOUND;
    else
        rc = NSS_STATUS_SUCCESS;

    sqlite3_finalize(res);
    sqlite3_close(db);

    if (result->gr_name == NULL)
        rc = NSS_STATUS_NOTFOUND;
    else
        rc = NSS_STATUS_SUCCESS;
    return rc;
}

enum nss_status get_user_by_query(const char *query, struct passwd *result) {
    sqlite3 *db;
    sqlite3_stmt *res;
    int rc;

    db = db_connect(PASSWD_DB_FILE);
    if (db == NULL) {
        return NSS_STATUS_NOTFOUND;
    }

    if (DEBUG)
        fprintf(stderr, "==>> %s\n", query);

    rc = sqlite3_prepare_v2(db, query, -1, &res, 0);    
    
    if (rc != SQLITE_OK) {
        sqlite3_finalize(res);
        sqlite3_close(db);
        
        return NSS_STATUS_NOTFOUND;
    }

    /* init struct with random default */
    *result = (struct passwd) {
        .pw_shell = "/bin/bash",
        .pw_passwd = "x"
    };
    // Execute the SQL statement and fetch the results
    while ((rc = sqlite3_step(res)) == SQLITE_ROW) {
        // Access column values using sqlite3_column_* functions
        result->pw_name = strdup(sqlite3_column_text(res, 0));
        result->pw_uid = sqlite3_column_int(res, 1);
        result->pw_gid = sqlite3_column_int(res, 2);
        result->pw_gecos = strdup(sqlite3_column_text(res, 3));
        result->pw_dir = strdup(sqlite3_column_text(res, 4));
        result->pw_shell = strdup(sqlite3_column_text(res, 5));
    }
    
    if (!result->pw_uid)
        rc = NSS_STATUS_NOTFOUND;
    else
        rc = NSS_STATUS_SUCCESS;

    sqlite3_finalize(res);
    sqlite3_close(db);
    return rc;
}

enum nss_status get_shadow_by_query(const char *query, struct spwd *result) {
    sqlite3 *db;
    sqlite3_stmt *res;
    int rc;

    db = db_connect(SHADOW_DB_FILE);
    if (db == NULL)
        return NSS_STATUS_NOTFOUND;

    if (DEBUG)
        fprintf(stderr, "==>> %s\n", query);

    rc = sqlite3_prepare_v2(db, query, -1, &res, 0);    
    
    if (rc != SQLITE_OK) {
        sqlite3_finalize(res);
        sqlite3_close(db);
        
        return NSS_STATUS_NOTFOUND;
    }

    /* init struct with random default */
    *result = (struct spwd) {
        .sp_pwdp = "x"
    };
    // SELECT login, password, last_pwd_change, min_pwd_age, max_pwd_age, pwd_warn_period, pwd_inactivity, expiration_date FROM shadow WHERE login = 'brian.stark@digitalis.io'
    // Execute the SQL statement and fetch the results
    while ((rc = sqlite3_step(res)) == SQLITE_ROW) {
        // Access column values using sqlite3_column_* functions
        result->sp_namp = strdup(sqlite3_column_text(res, 0));
        result->sp_pwdp = strdup(sqlite3_column_text(res, 1));
        result->sp_lstchg = sqlite3_column_int(res, 2);
        result->sp_min = sqlite3_column_int(res, 3);
        result->sp_max = sqlite3_column_int(res, 4);
        result->sp_warn = sqlite3_column_int(res, 5);
        result->sp_inact = sqlite3_column_int(res, 6);
        result->sp_expire = sqlite3_column_int(res, 7);
    }
    
    if (!result->sp_namp)
        rc = NSS_STATUS_NOTFOUND;
    else
        rc = NSS_STATUS_SUCCESS;

    sqlite3_finalize(res);
    sqlite3_close(db);
    return rc;
}
/**********************************************************/

enum nss_status _nss_aad_setpwent (void) {
    if (DEBUG) fprintf(stderr, "NSS DEBUG: Called %s\n", __FUNCTION__);
    return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_aad_endpwent (void) {
    if (DEBUG) fprintf(stderr, "NSS DEBUG: Called %s\n", __FUNCTION__);
    return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_aad_getpwnam_r (const char *name, struct passwd *result, char *buffer, size_t buflen, int *errnop) {
    if (DEBUG) fprintf(stderr, "NSS DEBUG: Called %s with arguments name = %s\n", __FUNCTION__, name);

    char query[255];
    sprintf(query, "SELECT login, uid, gid, gecos, home, shell FROM passwd WHERE login = '%s'", name);

    cache_user(name);

    int rc = get_user_by_query((char *)query, result);
    if (rc == NSS_STATUS_NOTFOUND) {
        fprintf(stderr, "NSS DEBUG: %s user %s not found on first look\n", __FUNCTION__, name);
        cache_user(name);
        rc = get_user_by_query((char *)query, result);
    }

    return rc;
}

enum nss_status _nss_aad_getpwbyuid_r (uid_t uid, struct passwd *result, char *buffer, size_t buflen, int *errnop) {
    if (DEBUG) fprintf(stderr, "NSS DEBUG: Called %s\n", __FUNCTION__);
    char query[255];
    sprintf(query, "SELECT login, uid, gid, gecos, home, shell FROM passwd WHERE uid = %d", uid);

    int rc = get_user_by_query((char *)query, result);

    return rc;
}

enum nss_status _nss_aad_getpwbynam_r (const char *name, struct passwd *result, char *buffer, size_t buflen, int *errnop) {
    if (DEBUG) fprintf(stderr, "NSS DEBUG: Called %s\n", __FUNCTION__);
    return NSS_STATUS_NOTFOUND;
}

enum nss_status _nss_aad_getpwuid_r (uid_t uid, struct passwd *result, char *buffer, size_t buflen, int *errnop)
{
    char query[255];
    sprintf(query, "SELECT login, uid, gid, gecos, home, shell FROM passwd WHERE uid = %d", uid);

    int rc = get_user_by_query((char *)query, result);
    return rc;
}

/* Groups */

enum nss_status _nss_aad_getgrnam_r(const char *name, struct group *gr, char *buffer, size_t buflen, int *errnop) {
    if (DEBUG) fprintf(stderr, "NSS DEBUG: Called %s\n", __FUNCTION__);

    char query[255];
    sprintf(query, "SELECT name, gid FROM groups WHERE name = '%s'", name);

    int rc = get_group_by_query((char *)query, gr);

    return rc;
}

enum nss_status _nss_aad_getgrent_r(struct group *gr, char *buffer, size_t buflen, int *errnop) {
    if (DEBUG) fprintf(stderr, "NSS DEBUG: Called %s\n", __FUNCTION__);
    gid_t gid = getgid ();
    char query[255];
    sprintf(query, "SELECT name, gid FROM groups WHERE gid = '%d'", gid);
    if (DEBUG) fprintf(stderr, "NSS DEBUG: %s\n", query);

    int rc = get_group_by_query((char *)query, gr);

    return rc;
}

enum nss_status _nss_aad_getgrgid_r (uid_t gid, struct group *gr, char *buffer, size_t buflen, int *errnop) {
    if (DEBUG) fprintf(stderr, "NSS DEBUG: Called %s\n", __FUNCTION__);
    char query[255];
    sprintf(query, "SELECT name, gid FROM groups WHERE gid = %d", gid);

    int rc = get_group_by_query((char *)query, gr);

    return rc;
}

/* return all the user groups except its primary */
enum nss_status _nss_aad_initgroups_dyn(const char *user, gid_t gid, long int *start, 
        long int *size, gid_t **groupsp, long int limit,
        int *errnop) {

    if (DEBUG) fprintf(stderr, "NSS DEBUG: Called %s for user %s\n", __FUNCTION__, user);

    groupsp = malloc(sizeof(gid_t *) * *size+1);
    return get_user_groups(user, groupsp);
}

/*
Shadow
*/

enum nss_status
_nss_aad_getspent_r(struct spwd *spbuf, char *buf,
                      size_t buflen, int *errnop) {

    if (DEBUG) fprintf(stderr, "NSS DEBUG: Called %s\n", __FUNCTION__);
    return NSS_STATUS_NOTFOUND;
}

/*
 * Get shadow information using username.
 */

enum nss_status _nss_aad_getspnam_r(const char* name, struct spwd *result,
               char *buf, size_t buflen, int *errnop) {

    if (DEBUG) fprintf(stderr, "NSS DEBUG: Called %s with arguments name = %s\n", __FUNCTION__, name);
    char query[255];
    sprintf(query, "SELECT login, password, last_pwd_change, min_pwd_age, max_pwd_age, pwd_warn_period, pwd_inactivity, expiration_date FROM shadow WHERE login = '%s'", name);

    int rc = get_shadow_by_query((char *)query, result);


    return rc;
}
