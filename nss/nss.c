#include <nss.h>
#include <pwd.h>
#include <grp.h>
#include <nss.h>
#include <pwd.h>
#include <shadow.h>
#include <stdio.h>
#include <sqlite3.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>

#define PASSWD_DB_FILE "passwd.db"
#define GROUPS_DB_FILE "groups.db"
#define SHADOW_DB_FILE "shadow.db"
#define DEBUG 1

pthread_mutex_t pwent_mutex;
const char *cache_directory = "/opt/aad";

sqlite3 *db_connect(const char *db_file) {
    sqlite3 *db;
    char db_path[strlen(cache_directory)+strlen(db_file)];

    pthread_mutex_lock(&pwent_mutex);
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
    pthread_mutex_unlock(&pwent_mutex);
    return db;
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
    // Execute the SQL statement and fetch the results
    while ((rc = sqlite3_step(res)) == SQLITE_ROW) {
        // Access column values using sqlite3_column_* functions
        result->sp_namp = strdup(sqlite3_column_text(res, 0));
        result->sp_pwdp = strdup(sqlite3_column_text(res, 1));
        result->sp_lstchg = sqlite3_column_int(res, 3);
        result->sp_min = sqlite3_column_int(res, 4);
        result->sp_max = sqlite3_column_int(res, 5);
        result->sp_warn = sqlite3_column_int(res, 6);
        result->sp_inact = sqlite3_column_int(res, 7);
        result->sp_expire = sqlite3_column_int(res, 8);
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
    if (DEBUG) fprintf(stderr, "NSS DEBUG: Called %s with arguments name = %s buffer = %s\n", __FUNCTION__, name, buffer);

    char query[255];
    sprintf(query, "SELECT login, uid, gid, gecos, home, shell FROM passwd WHERE login = '%s'", name);

    int rc = get_user_by_query((char *)query, result);

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

/*
 * getgrnam
 */

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
    if (DEBUG) fprintf(stderr, "NSS DEBUG: Called %s\n", __FUNCTION__);
    return NSS_STATUS_NOTFOUND;
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
