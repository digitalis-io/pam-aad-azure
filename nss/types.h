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
    char *group_id, *group_name, *tenant, *client_secret,
        *domain, *ab_token;
    bool debug;
};

extern struct nss_config json_config;

int load_config(struct nss_config *json_config);
char *get_client_token();
json_t *curl(const char *endpoint, const char *post_body,
                    struct curl_slist *headers);
const char * get_user_from_azure(const char *user_addr);

extern int init_cache(const char *db_file);
extern void init_cache_all();
extern int cache_insert_group(char *group);
extern sqlite3 *db_connect(const char *db_file);