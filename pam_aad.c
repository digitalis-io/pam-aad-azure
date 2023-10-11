#include <curl/curl.h>
#include <jansson.h>
#include <jwt.h>
#include <security/pam_appl.h>
#include <security/pam_ext.h>
#include <security/pam_modules.h>
#include <sys/syslog.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <uuid/uuid.h>

#define AUTH_ERROR "authorization_pending"
#define CONFIG_FILE "/etc/pam_aad.conf"
#define DEBUG true
#define HOST "https://login.microsoftonline.com/"
#define SCOPE "https%3A%2F%2Fgraph.microsoft.com%2F.default+openid+profile+email"
#define GRAPH "https://graph.microsoft.com/v1.0"
#define TTW 5                   /* time to wait in seconds */
#define USER_AGENT "azure_authenticator_pam/1.0"

#define PASSWD_FILE "/etc/passwd"
#define RESOURCE_ID "00000002-0000-0000-c000-000000000000"
#define SHADOW_FILE "/etc/shadow"

#ifndef _AAD_EXPORT
#define STATIC static
#else
#define STATIC
#endif

struct message {
    size_t lines_read;
    char *data[];
};

struct response {
    char *data;
    size_t size;
};

char *cache_directory, *cache_owner, *cache_group;

STATIC size_t read_callback(void *ptr, size_t size, size_t nmemb,
                            void *userp)
{
    struct message *msg = (struct message *) userp;
    char *data;

    if ((size == 0) || (nmemb == 0) || ((size * nmemb) < 1)) {
        return 0;
    }
    data = msg->data[msg->lines_read];

    if (data) {
        size_t len = strlen(data);
        memcpy(ptr, data, len);
        msg->lines_read++;
        return len;
    }

    return 0;
}

STATIC size_t response_callback(void *contents, size_t size, size_t nmemb,
                                void *userp)
{
    size_t realsize = size * nmemb;
    struct response *resp = (struct response *) userp;
    char *ptr = realloc(resp->data, resp->size + realsize + 1);
    if (ptr == NULL) {
        // Out of memory
        printf("Not enough memory (realloc returned NULL)\n");
        return 0;
    }

    resp->data = ptr;
    memcpy(&(resp->data[resp->size]), contents, realsize);
    resp->size += realsize;
    resp->data[resp->size] = 0;

    return realsize;
}

STATIC json_t *curl(pam_handle_t * pamh, const char *endpoint, const char *post_body,
                    struct curl_slist *headers, bool debug)
{
    CURL *curl;
    CURLcode res;
    json_t *data = NULL;
    json_error_t error;

    struct response resp;

    resp.data = malloc(1);
    resp.size = 0;

    curl = curl_easy_init();
    curl_easy_setopt(curl, CURLOPT_URL, endpoint);
    if (post_body != NULL)
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_body);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, response_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *) &resp);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, USER_AGENT);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 1L);
    if (headers)
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    if (debug)
        curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

    res = curl_easy_perform(curl);

    if (res != CURLE_OK) {
        pam_syslog(pamh, LOG_DEBUG, "curl_easy_perform() failed: %s\n", endpoint);
        pam_syslog(pamh, LOG_ERR, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
    } else {
        data = json_loads(resp.data, 0, &error);

        if (!data) {
            pam_syslog(pamh, LOG_ERR, "json_loads() failed: %s\n", error.text);

            return NULL;
        }
    }

    curl_easy_cleanup(curl);
    free(resp.data);

    return data;
}

STATIC char * oauth_request(pam_handle_t * pamh, const char *client_id,
                          const char *client_secret,
                          const char *tenant,
                          const char *username, const char *password,
                          bool debug)
{
    char endpoint[255];
    char post_body[255];
    json_t * json_data;

    sprintf(endpoint, "%s%s/oauth2/v2.0/token", HOST, tenant);
    sprintf(post_body, "scope=%s&client_id=%s&client_secret=%s&grant_type=password&username=%s&password=%s",
        "openid", client_id, client_secret, username, password);

    json_data = curl(pamh, endpoint, post_body, NULL, debug);

    char *err_str;
    if (json_object_get(json_data, "error_description")) {
        err_str =
            json_string_value(json_object_get(json_data, "error_description"));
        if (strstr(err_str, "AADSTS50076") == NULL) {
            return NULL; // Access denied
        }
    }
    printf("%s", json_dumps(json_data, JSON_INDENT(4)));
    pam_syslog(pamh, LOG_DEBUG,"%s", err_str);

    char *jwt_str;
    sprintf(endpoint, "%s%s/oauth2/v2.0/token", HOST, tenant);
    sprintf(post_body, "scope=%s&client_id=%s&client_secret=%s&grant_type=client_credentials",
        SCOPE, client_id, client_secret);

    json_data = curl(pamh, endpoint, post_body, NULL, debug);
    printf("%s", json_dumps(json_data, JSON_INDENT(4)));

    if (json_object_get(json_data, "access_token")) {
        jwt_str =
            json_string_value(json_object_get(json_data, "access_token"));
    } else {
        pam_syslog(pamh, LOG_ERR,
                "json_object_get() failed: access_token not found\n");
        pam_syslog(pamh, LOG_ERR,
                "%s\n", jwt_str);
        exit(1);
    }
    // Access granted
    return jwt_str;
}

// STATIC int verify_user(jwt_t * jwt, const char *username)
// {
//     const char *email = jwt_get_grant(jwt, "email");
//     return (strcmp(email, username) == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
// }

STATIC int verify_jwt_tenant(jwt_t * jwt, const char *tenant)
{
    char iss[strlen("https://sts.windows.net/")+strlen(tenant)+1];
    sprintf(iss, "https://sts.windows.net/%s/", tenant);
    const char *ret_iss = jwt_get_grant(jwt, "iss");
    return (strcmp(iss, ret_iss) == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

char *get_user_id(pam_handle_t * pamh, const char *user_addr, const char *auth_token, bool debug) {
    json_t *resp, *json_data;
    struct curl_slist *headers = NULL;
    int ret = EXIT_FAILURE;
    char auth_header[strlen(auth_token)+255];
    char endpoint[255];

    sprintf(auth_header, "Authorization: Bearer %s", auth_token);

    headers = curl_slist_append(headers, auth_header);
    headers = curl_slist_append(headers, "Content-Type: application/json");

    sprintf(endpoint, "%s/users/?$filter=startsWith(mail,%%20%%27%s%%27%%20)", GRAPH, user_addr);
    resp = curl(pamh, endpoint, NULL, headers, debug);
    json_data = json_object_get(resp, "value");
    printf("%s", json_dumps(json_data, JSON_INDENT(4)));

    if (json_data) {
        json_t *element;
        element = json_array_get(json_data, 0);
        if (element != NULL) {
            return json_string_value(json_object_get(element, "id"));
        }
    } else {
        pam_syslog(pamh, LOG_ERR, "get_user_id - json_object_get() failed: value NULL\n");
    }

    curl_slist_free_all(headers);
    json_decref(resp);

    return NULL;
}

// curl -sH "Authorization: Bearer $jwt" "https://graph.microsoft.com/v1.0/users/f92cf108-b23e-4927-8a30-259b04bcdd8d/memberOf" | jq .
// curl -sH "Authorization: Bearer $jwt" 'https://graph.microsoft.com/v1.0/users/ruthdegroot@tokenise.onmicrosoft.com' | jq .
// curl -sH "Authorization: Bearer $jwt" 'https://graph.microsoft.com/v1.0/users/hayato_digitalis.io%23EXT%23@tokenise.onmicrosoft.com' | jq .
// curl --location --request GET 'https://graph.microsoft.com/v1.0/users?$filter=startsWith(mail,%20%27brian.stark@digitalis.io%27%20)'
STATIC int verify_group(pam_handle_t * pamh, const char *user_addr, const char *auth_token, const char *group_id,
                        bool debug)
{
    char *user_id;
    user_id = get_user_id(pamh, user_addr, auth_token, debug);
    if (user_id == NULL) {
        pam_syslog(pamh, LOG_ERR, "get_user_id - is NULL\n");
        return EXIT_FAILURE;
    }

    json_t *resp;
    struct curl_slist *headers = NULL;
    int ret = EXIT_FAILURE;
    char auth_header[strlen(auth_token)+255];
    char endpoint[255];

    sprintf(auth_header, "Authorization: Bearer %s", auth_token);

    headers = curl_slist_append(headers, auth_header);
    headers = curl_slist_append(headers, "Content-Type: application/json");

    sprintf(endpoint, "%s/users/%s/memberOf?$select=id,displayName", GRAPH, user_id);

    resp = curl(pamh, endpoint, NULL, headers, debug);
    resp = json_object_get(resp, "value");
    printf("%s", json_dumps(resp, JSON_INDENT(4)));

    if (resp) {
        size_t index;
        json_t *value;

        json_array_foreach(resp, index, value) {
            // TODO: add caching for groups here
            if (strcmp(json_string_value(json_object_get(value, "id")), group_id) == 0)
                ret = EXIT_SUCCESS;
        }
    } else {
        pam_syslog(pamh, LOG_ERR, "json_object_get() failed: value NULL\n");
    }

    curl_slist_free_all(headers);
    json_decref(resp);

    return ret;
}

STATIC int azure_authenticator(pam_handle_t * pamh, const char *user)
{
    jwt_t *jwt;
    bool debug = DEBUG;
    const char *client_id, *group_id, *group_name, *tenant, *client_secret,
        *domain, *ab_token, *tenant_addr, *smtp_server;

    json_t *json_data = NULL, *config = NULL;
    json_error_t error;
    int ret = EXIT_FAILURE;

    config = json_load_file(CONFIG_FILE, 0, &error);
    if (!config) {
        pam_syslog(pamh, LOG_ERR, "error in config on line %d: %s\n", error.line,
                error.text);
        return ret;
    }

    if (json_object_get(config, "debug"))
        if (strcmp
            (json_string_value(json_object_get(config, "debug")),
             "true") == 0)
            debug = true;

    if (json_object_get(json_object_get(config, "client"), "id")) {
        client_id =
            json_string_value(json_object_get
                              (json_object_get(config, "client"), "id"));
    } else {
        pam_syslog(pamh, LOG_ERR, "error with Client ID in JSON\n");
        return ret;
    }

    if (json_object_get(json_object_get(config, "client"), "secret")) {
        client_secret =
            json_string_value(json_object_get
                              (json_object_get(config, "client"), "secret"));
    } else {
        pam_syslog(pamh, LOG_ERR, "error with Client Secret in JSON\n");
        return ret;
    }

    if (json_object_get(config, "domain")) {
        domain = json_string_value(json_object_get(config, "domain"));
    } else {
        pam_syslog(pamh, LOG_ERR, "error with Domain in JSON\n");
        return ret;
    }

    if (json_object_get(json_object_get(config, "group"), "id")) {
        group_id =
            json_string_value(json_object_get
                              (json_object_get(config, "group"), "id"));
        group_name =
            json_string_value(json_object_get
                              (json_object_get(config, "group"), "name"));
    } else {
        pam_syslog(pamh, LOG_ERR, "error with Group ID in JSON\n");
        return ret;
    }

    if (json_object_get(config, "tenant")) {
        tenant =
            json_string_value(json_object_get
                              (json_object_get(config, "tenant"), "name"));
        if (json_object_get(json_object_get(config, "tenant"), "address")) {
            tenant_addr =
                json_string_value(json_object_get
                                  (json_object_get(config, "tenant"),
                                   "address"));
        } else {
            pam_syslog(pamh, LOG_ERR, "error with tenant address in JSON\n");
            return ret;
        }
    } else {
        pam_syslog(pamh, LOG_ERR, "error with tenant in JSON\n");
        return ret;
    }

    /* Caching details */
    cache_directory =
        json_string_value(json_object_get
                            (json_object_get(config, "cache"), "directory"));
    cache_owner =
        json_string_value(json_object_get
                            (json_object_get(config, "cache"), "owner"));
    cache_group =
        json_string_value(json_object_get
                            (json_object_get(config, "cache"), "group"));

    if (cache_owner == NULL) cache_owner = "root";
    if (cache_group == NULL) cache_group = "root";
    //if (cache_directory == NULL) cache_directory = "/var/lib/cache/pam-aad-azure";
    if (cache_directory == NULL) cache_directory = "/tmp";

    init_cache();


    char user_addr[strlen(user)+strlen(domain)+5];
    if (strstr(user, "@") == NULL) {
        sprintf(user_addr, "%s@%s", user, domain);
    } else {
        sprintf(user_addr, "%s", user);
    }

    curl_global_init(CURL_GLOBAL_ALL);

    char *user_pass;
    if (pam_get_item(pamh, PAM_AUTHTOK, (const void **)&user_pass) != PAM_SUCCESS) {
        pam_syslog(pamh, LOG_DEBUG, "Failed to get password for user %s", user_pass);
        return EXIT_FAILURE;
    }

    char *jwt_str;
    jwt_str = oauth_request(pamh, client_id, client_secret, tenant, user_addr, user_pass, debug);
    printf("JWT: %s\n", jwt_str);
    pam_syslog(pamh, LOG_DEBUG, "jwt: %s\n", jwt_str);
    if (jwt_str == NULL) {
        pam_syslog(pamh, LOG_ERR, "Access denied");
        return EXIT_FAILURE;
    }

    if (jwt_decode(&jwt, jwt_str, NULL, 0) != 0) {
        pam_syslog(pamh, LOG_ERR, "Error decoding JWT token");
        return EXIT_FAILURE;
    }
    // if (verify_user(pamh, jwt, user_addr) == 0) {
    //     ret = EXIT_SUCCESS;
    // }
    if (verify_jwt_tenant(jwt, tenant) == 0) {
        ret = EXIT_SUCCESS;
    } else {
        pam_syslog(pamh, LOG_ERR, "Tenant %s does not match\n", tenant);
    }

    if (verify_group(pamh, user_addr, jwt_str, group_id, debug) == 0) {
        ret = EXIT_SUCCESS;
    } else {
        ret = EXIT_FAILURE;
        pam_syslog(pamh, LOG_ERR, "%s does not belong to group %s", user_addr, group_id);
    }

    /* Cache user */
    pam_syslog(pamh, LOG_DEBUG, "Calling cache_user function");
    cache_user(pamh, user, user_addr);

    // if (verify_user(jwt, user_addr) == 0
    //     && verify_group(pamh, ab_token, group_id, debug) == 0) {
    //     ret = EXIT_SUCCESS;
    // }
    curl_global_cleanup();
    jwt_free(jwt);
    json_decref(config);

    return ret;
}


PAM_EXTERN int pam_sm_authenticate(pam_handle_t *
                                   pamh, int flags, int argc, const char
                                   **argv)
{
    const char *user;
    int ret = PAM_AUTH_ERR;
    if (pam_get_user(pamh, &user, NULL) != PAM_SUCCESS) {
        pam_syslog(pamh, LOG_ERR, "pam_get_user(): failed to get a username\n");
        return ret;
    }
    pam_syslog(pamh, LOG_INFO, "AAD authentication for %s", user);

    if (azure_authenticator(pamh, user) == EXIT_SUCCESS) {
        pam_syslog(pamh, LOG_INFO, "AAD authentication for %s was SUCCESSFUL", user);
        return PAM_SUCCESS;
    }

    pam_syslog(pamh, LOG_INFO, "AAD authentication for %s was denied", user);
    return ret;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t * pamh,
                              int flags, int argc, const char **argv)
{
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *
                                pamh, int flags,
                                int argc, const char **argv)
{
    return PAM_SUCCESS;
}
