#include <jansson.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <security/pam_appl.h>
#include <security/pam_ext.h>
#include <security/pam_misc.h>
#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_SESSION
#include <security/pam_modules.h>
#include <sys/syslog.h>

#ifndef DEBUG
#define DEBUG 0
#endif
#define HOME_ROOT "/home"
#define CONFIG_FILE "/etc/pam_aad.conf"
#define AUTH_ERROR "authorization_pending"
#define HOST "https://login.microsoftonline.com/"
#define SCOPE "https%3A%2F%2Fgraph.microsoft.com%2F.default+openid+profile+email"
#define GRAPH "https://graph.microsoft.com/v1.0"
#define TTW 5                   /* time to wait in seconds */
#define USER_AGENT "azure_authenticator_pam/1.0"

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
    int user_expires_after;
    char *proxy_address;
    bool debug;
};

int load_config(struct nss_config *json_config);
int create_cache_directory(pam_handle_t *pamh);
