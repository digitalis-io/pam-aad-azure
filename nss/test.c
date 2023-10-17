#include <nss.h>
#include <pwd.h>
#include <grp.h>
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

const char *cache_directory = "/opt/aad";
sqlite3 *db_connect(const char *db_file) {
    sqlite3 *db;
    char db_path[strlen(cache_directory)+strlen(db_file)];

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
    return db;
}

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

int main() {
    gid_t **groups = malloc(sizeof(gid_t *) * 10);

    get_user_groups("sergio.rua@digitalis.io", groups);
    printf("Group ID: %d\n", groups[0]);
    printf("Group ID: %d\n", groups[1]);

    // for (int i=0;i<=1;i++) {
    //     printf("Hello: %s\n", groups[i]->gr_name);
    // }
    free(groups);
}