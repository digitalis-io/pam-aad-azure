#include <curl/curl.h>
#include <jansson.h>
#include <jwt.h>
#include <security/pam_appl.h>
#include <security/pam_ext.h>
#include <security/pam_misc.h>
#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_SESSION
#include <security/pam_modules.h>
#include <sys/syslog.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <uuid/uuid.h>
#include <regex.h>
#include "types.h"

#define PAM_AAD_VERSION "0.2.0"

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

struct nss_config json_config;

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
    if (strlen(json_config.proxy_address) > 5) {
        curl_easy_setopt(curl, CURLOPT_PROXY, json_config.proxy_address);
    }

    if (headers)
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    if (debug) {
        curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
    }

    res = curl_easy_perform(curl);

    if (res != CURLE_OK) {
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
    char endpoint[512];
    char post_body[2048];
    json_t * json_data;
    char *jwt_str = NULL;
    CURL *curl_handle;
    char *encoded_secret, *encoded_password;

    /* URL-encode credentials (may contain special chars) */
    curl_handle = curl_easy_init();
    encoded_secret = curl_easy_escape(curl_handle, client_secret, 0);
    encoded_password = curl_easy_escape(curl_handle, password, 0);

    /* Resource Owner Password Credentials flow */
    snprintf(endpoint, sizeof(endpoint), "%s%s/oauth2/v2.0/token", HOST, tenant);
    snprintf(post_body, sizeof(post_body),
             "scope=%s&client_id=%s&client_secret=%s&grant_type=password&username=%s&password=%s",
             "openid", client_id, encoded_secret, username, encoded_password);

    curl_free(encoded_secret);
    curl_free(encoded_password);
    curl_easy_cleanup(curl_handle);

    json_data = curl(pamh, endpoint, post_body, NULL, debug);

    if (json_data == NULL) {
        pam_syslog(pamh, LOG_ERR, "oauth_request: failed to get response from Azure AD");
        return NULL;
    }

    /* Check for successful authentication */
    if (json_object_get(json_data, "access_token")) {
        const char *token = json_string_value(json_object_get(json_data, "access_token"));
        if (token) {
            jwt_str = strdup(token);
            pam_syslog(pamh, LOG_INFO, "Password authentication successful for %s", username);
        }
        json_decref(json_data);
        return jwt_str;
    }

    /* Check for errors */
    if (json_object_get(json_data, "error_description")) {
        const char *err_str = json_string_value(json_object_get(json_data, "error_description"));

        /* AADSTS50076: MFA required - user needs Conditional Access exemption */
        if (err_str && strstr(err_str, "AADSTS50076") != NULL) {
            pam_syslog(pamh, LOG_ERR, "MFA required for %s - configure Conditional Access to exempt this app", username);
            json_decref(json_data);
            return NULL;
        }

        /* AADSTS50079: MFA registration required */
        if (err_str && strstr(err_str, "AADSTS50079") != NULL) {
            pam_syslog(pamh, LOG_ERR, "MFA setup required for %s - configure Conditional Access to exempt this app", username);
            json_decref(json_data);
            return NULL;
        }

        /* AADSTS50126: Invalid username or password */
        if (err_str && strstr(err_str, "AADSTS50126") != NULL) {
            pam_syslog(pamh, LOG_ERR, "Invalid username or password for %s", username);
            json_decref(json_data);
            return NULL;
        }

        /* Other errors */
        pam_syslog(pamh, LOG_ERR, "Azure AD authentication error: %s", err_str ? err_str : "unknown");
        json_decref(json_data);
        return NULL;
    }

    json_decref(json_data);
    pam_syslog(pamh, LOG_ERR, "oauth_request: unexpected response from Azure AD");
    return NULL;
}

STATIC int verify_jwt_tenant(jwt_t * jwt, const char *tenant)
{
    char iss[strlen("https://sts.windows.net/")+strlen(tenant)+2];  // +2 for '/' and '\0'
    sprintf(iss, "https://sts.windows.net/%s/", tenant);
    const char *ret_iss = jwt_get_grant(jwt, "iss");
    return (strcmp(iss, ret_iss) == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

const char *get_user_id(pam_handle_t * pamh, const char *user_addr, const char *auth_token, bool debug) {
    json_t *resp, *json_data;
    struct curl_slist *headers = NULL;
    int ret = EXIT_FAILURE;
    char auth_header[strlen(auth_token)+255];
    char endpoint[255];

    sprintf(auth_header, "Authorization: Bearer %s", auth_token);

    headers = curl_slist_append(headers, auth_header);
    headers = curl_slist_append(headers, "Content-Type: application/json");

    sprintf(endpoint, "%s/users/?$filter=startsWith(mail,%%20%%27%s%%27%%20)", GRAPH, user_addr);
    resp = curl(pamh, endpoint, NULL, headers, DEBUG);
    json_data = json_object_get(resp, "value");
    if (DEBUG) printf("%s", json_dumps(json_data, JSON_INDENT(4)));

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

STATIC int verify_group(pam_handle_t * pamh, const char *user_addr, const char *auth_token,
                        bool debug)
{
    const char *user_id;
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

    sprintf(endpoint, "%s/users/%s/transitiveMemberOf/microsoft.graph.group?$count=true&$select=id,displayName", GRAPH, user_id);

    resp = curl(pamh, endpoint, NULL, headers, DEBUG);
    resp = json_object_get(resp, "value");
    if (DEBUG) printf("%s", json_dumps(resp, JSON_INDENT(4)));

    if (resp) {
        size_t index;
        json_t *value;

        if (cache_user_groups(pamh, user_addr, resp) != 0)
            pam_syslog(pamh, LOG_ERR, "cache_user_groups() returned an error");

        json_array_foreach(resp, index, value) {
            if ((strcmp(json_string_value(json_object_get(value, "id")), json_config.group_id) == 0) ||
                (strcmp(json_string_value(json_object_get(value, "displayName")), json_config.group_name) == 0))
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
    bool debug = DEBUG;

    json_t *json_data = NULL, *config = NULL;
    json_error_t error;
    int ret = EXIT_FAILURE;

    if (json_config.tenant == NULL)
        load_config(&json_config);


    if (init_cache_all(pamh) > 0) {
        pam_syslog(pamh, LOG_ERR, "The user %s has not been cached", user);
        return PAM_AUTH_ERR;
    }

    char user_addr[strlen(user)+strlen(json_config.domain)+5];
    if (strstr(user, "@") == NULL) {
        sprintf(user_addr, "%s@%s", user, json_config.domain);
    } else {
        sprintf(user_addr, "%s", user);
    }

    curl_global_init(CURL_GLOBAL_ALL);

    /* Cache user */
    if (cache_user(pamh, user_addr) != 0) {
        pam_syslog(pamh, LOG_WARNING, "The user %s has not been cached", user_addr);
    }

    const char *user_pass;
    if (pam_get_item(pamh, PAM_AUTHTOK, (const void **)&user_pass) != PAM_SUCCESS) {
        pam_syslog(pamh, LOG_DEBUG, "pam_get_item(): Failed to get cached password for user [%s]", user_addr);
    }
    if (user_pass == NULL) {
        pam_syslog(pamh, LOG_DEBUG, "pam_get_authtok(): getting password prompt for user [%s]", user_addr);
        ret = pam_get_authtok(pamh, PAM_AUTHTOK, &user_pass, NULL);
        if (ret != PAM_SUCCESS) {
            pam_syslog(pamh, LOG_ERR, "pam_get_authtok(): auth could not get the password for the user [%s]", user_addr);
            return PAM_AUTH_ERR;
        }
    }

    char *jwt_str;
    jwt_str = oauth_request(pamh, json_config.client_id, json_config.client_secret, json_config.tenant, user_addr, user_pass, debug);

    if (jwt_str == NULL) {
        pam_syslog(pamh, LOG_ERR, "Access denied");
        return EXIT_FAILURE;
    }

    if ((json_config.group_id != NULL) && (strcmp(json_config.group_id, ""))) {
        if (verify_group(pamh, user_addr, jwt_str, debug) == 0) {
            ret = EXIT_SUCCESS;
        } else {
            ret = EXIT_FAILURE;
            pam_syslog(pamh, LOG_ERR, "%s does not belong to group %s", user_addr, json_config.group_name);
        }
    } else if (strlen(jwt_str) > 100) // FIXME: add proper validation
        ret = EXIT_SUCCESS;

    curl_global_cleanup();
    json_decref(config);

    return ret;
}

bool is_valid_email(pam_handle_t *pamh, const char *user) {
    regex_t regex;
    int ret;
    char msgbuf[100];
    bool isValid = false;

    // Regular expression for basic email validation
    const char *pattern = "^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$";

    // Compile regular expression
    ret = regcomp(&regex, pattern, REG_EXTENDED);
    if (ret) {
        fprintf(stderr, "Could not compile regex\n");
        return false;
    }

    // Execute regular expression
    ret = regexec(&regex, user, 0, NULL, 0);
    if (!ret) {
        isValid = true;
    } else if (ret == REG_NOMATCH) {
        isValid = false;
    } else {
        regerror(ret, &regex, msgbuf, sizeof(msgbuf));
        pam_syslog(pamh, LOG_ERR, "is_valid_email(): Regex match failed: %s\n", msgbuf);
        isValid = false;
    }

    // Free memory allocated to the pattern buffer by regcomp()
    regfree(&regex);

    return isValid;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *
                                   pamh, int flags, int argc, const char
                                   **argv)
{
    const char *user;

    pam_syslog(pamh, LOG_INFO, "Azure AD authentication version %s", PAM_AAD_VERSION);
    if (json_config.tenant == NULL)
        load_config(&json_config);

    if (pam_get_user(pamh, &user, NULL) != PAM_SUCCESS) {
        pam_syslog(pamh, LOG_ERR, "pam_get_user(): failed to get a username\n");
        return PAM_AUTH_ERR;
    }
    pam_syslog(pamh, LOG_INFO, "AAD authentication for %s", user);

    if (is_valid_email(pamh, user) == false) {
        pam_syslog(pamh, LOG_ERR, "The user is not a valid email address: [%s]", user);
        return PAM_AUTH_ERR;
    }

    if (azure_authenticator(pamh, user) == EXIT_SUCCESS) {
        pam_syslog(pamh, LOG_INFO, "AAD authentication for %s was SUCCESSFUL", user);
        pam_end(pamh, PAM_SUCCESS);
        return PAM_SUCCESS;
    }

    pam_syslog(pamh, LOG_INFO, "pam_sm_authenticate(): AAD authentication for %s was denied", user);

    return PAM_AUTH_ERR;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t * pamh,
                              int flags, int argc, const char **argv) {
    return PAM_IGNORE;
}

int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc,
    const char **argv) {

    (void) flags;

    return PAM_SUCCESS;
}

int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc,
    const char **argv) {

    (void) flags;

    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc,
        const char **argv) {
    return PAM_SUCCESS;
}
