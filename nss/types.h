#include <stdbool.h>
#include <jansson.h>
#include <curl/curl.h>
#include <jwt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <uuid/uuid.h>
#include <sqlite3.h>

#define CONFIG_FILE "/etc/pam_aad.conf"
#ifndef DEBUG
#define DEBUG 0
#endif

#define DEBUG_MSG(fmt, ...) fprintf(stderr, "%s():%d - " fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__)

#define PASSWD_DB_FILE "passwd.db"
#define GROUPS_DB_FILE "groups.db"
#define SHADOW_DB_FILE "shadow.db"
#define HOME_ROOT "/home"

struct azure_user {
    char *mail;
    char *display_name;
};

struct nss_config {
    char *cache_directory;
    char *cache_owner; 
    char *cache_group;
    char *cache_mode;
    char *client_id;
    char *group_id;
    char *group_name;
    char *tenant;
    char *client_secret;
    char *domain;
    char *ab_token;
    char *home_directory;
    char *proxy_address;
    bool debug;
    int user_expires_after;
};

extern struct nss_config json_config;

int load_config(struct nss_config *json_config);
char *get_client_token();
json_t *curl(const char *endpoint, const char *post_body,
                    struct curl_slist *headers);
const char * get_user_from_azure(const char *user_addr);

extern int init_cache(const char *db_file);
extern int init_cache_all();
//extern int cache_insert_group(char *group);
extern sqlite3 *db_connect(const char *db_file);
bool is_valid_email(const char *user);
