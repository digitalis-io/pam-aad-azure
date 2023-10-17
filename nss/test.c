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
const char *cache_owner = "root"; 
const char *cache_group = "postgres";
const char *cache_mode = "0440";

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

int cache_user(char *user_addr) {
    sqlite3 *db;
    sqlite3_stmt *res;
    char *err_msg = NULL;
    int rc;
    const char *group_insert_template = "INSERT OR IGNORE INTO groups (name) VALUES('%s')";

    db = db_connect(GROUPS_DB_FILE);
    if (db == NULL)
        return 1;

    char group_insert[strlen(group_insert_template) + strlen(user_addr) + 2];
    sprintf(group_insert, group_insert_template, user_addr);
    fprintf(stderr, "NSS DEBUG: %s\n", group_insert);

    rc = sqlite3_exec(db, group_insert, 0, 0, &err_msg);
    fprintf(stderr, "RC = %d\n", rc);
    if (rc != SQLITE_OK ) {
        fprintf(stderr, "SQL error: %s\n", err_msg);
        fprintf(stderr, "%s\n", group_insert);
        
        sqlite3_free(err_msg);        
        sqlite3_close(db);
        
        return 1;
    }
}

int main() {
    cache_user("john@digitalis.io");
}