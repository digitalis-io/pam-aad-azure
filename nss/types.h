#include <stdbool.h>
#include <jansson.h>

#define CONFIG_FILE "/etc/pam_aad.conf"

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

int load_config();
char *get_client_token();
json_t *curl(const char *endpoint, const char *post_body,
                    struct curl_slist *headers);