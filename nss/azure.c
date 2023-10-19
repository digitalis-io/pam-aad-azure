#include <jansson.h>
#include <jwt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <uuid/uuid.h>
#include <curl/curl.h>
#include "types.h"

#define AUTH_ERROR "authorization_pending"
#define CONFIG_FILE "/etc/pam_aad.conf"
#define HOST "https://login.microsoftonline.com/"
#define SCOPE "https%3A%2F%2Fgraph.microsoft.com%2F.default+openid+profile+email"
#define GRAPH "https://graph.microsoft.com/v1.0"
#define TTW 5                   /* time to wait in seconds */
#define USER_AGENT "azure_authenticator_pam/1.0"

struct message {
    size_t lines_read;
    char *data[];
};

struct response {
    char *data;
    size_t size;
};

size_t read_callback(void *ptr, size_t size, size_t nmemb,
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

size_t response_callback(void *contents, size_t size, size_t nmemb,
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

json_t *curl(const char *endpoint, const char *post_body,
                    struct curl_slist *headers)
{
    CURL *curl;
    CURLcode res;
    json_t *data = NULL;
    json_error_t error;
    bool debug = DEBUG;

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

    if (debug) {
        if (DEBUG) fprintf(stderr, "Query: %s\n", endpoint);
        curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
    }

    res = curl_easy_perform(curl);

    if (res != CURLE_OK) {
        fprintf(stderr, "curl_easy_perform() failed: %s\n", endpoint);
        fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
    } else {
        data = json_loads(resp.data, 0, &error);

        if (!data) {
            fprintf(stderr, "json_loads() failed: %s\n", error.text);

            return NULL;
        }
    }

    curl_easy_cleanup(curl);
    free(resp.data);

    return data;
}

const char * get_user_from_azure(const char *user_addr) {
    json_t *resp, *json_data;
    struct curl_slist *headers = NULL;
    int ret = EXIT_FAILURE;
    char endpoint[255];
    char post_body[255];

    if (json_config.tenant == NULL) {
        if (load_config(&json_config) != 0) {
            fprintf(stderr, "%s: load_config() failed\n", __FUNCTION__);
            return NULL;
        }
    }

    sprintf(endpoint, "%s%s/oauth2/v2.0/token", HOST, json_config.tenant);
    sprintf(post_body, "scope=%s&client_id=%s&client_secret=%s&grant_type=client_credentials",
        SCOPE, json_config.client_id, json_config.client_secret);

    json_data = curl(endpoint, post_body, NULL);

    char *jwt_str;
    
    if (json_object_get(json_data, "access_token")) {
        jwt_str =
            json_string_value(json_object_get(json_data, "access_token"));
    } else {
        fprintf(stderr,
                "json_object_get() failed: access_token not found\n");
        fprintf(stderr,
                "%s\n", jwt_str);
        return 1;
    }

    char *auth_header = malloc(strlen(jwt_str) + 23);
    strcpy(auth_header, "Authorization: Bearer ");
    strcat(auth_header, jwt_str);
    
    headers = curl_slist_append(headers, auth_header);

    sprintf(endpoint, "%s/users/?$filter=startsWith(mail,%%20%%27%s%%27%%20)", GRAPH, user_addr);
    resp = curl(endpoint, NULL, headers);
    json_data = json_object_get(resp, "value");
    if (DEBUG) printf("%s", json_dumps(json_data, JSON_INDENT(4)));

    if (json_data) {
        json_t *element;
        element = json_array_get(json_data, 0);
        if (element != NULL) {
            const char *user_id = json_string_value(json_object_get(element, "id"));
            return user_id;
        }
    } else {
        fprintf(stderr, "%s() - json_object_get() failed: value NULL\n", __FUNCTION__);
    }

    curl_slist_free_all(headers);
    json_decref(resp);

    return NULL;
}
