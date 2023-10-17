#include <curl/curl.h>
#include <jansson.h>
#include <jwt.h>
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

    if (debug) {
        fprintf(stderr, "Query: %s\n", endpoint);
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

// char *get_user_id(const char *user_addr, bool debug) {
//     json_t *resp, *json_data;
//     struct curl_slist *headers = NULL;
//     int ret = EXIT_FAILURE;
//     char auth_header[strlen(auth_token)+255];
//     char endpoint[255];

//     sprintf(auth_header, "Authorization: Bearer %s", auth_token);

//     headers = curl_slist_append(headers, auth_header);
//     headers = curl_slist_append(headers, "Content-Type: application/json");

//     sprintf(endpoint, "%s/users/?$filter=startsWith(mail,%%20%%27%s%%27%%20)", GRAPH, user_addr);
//     resp = curl(pamh, endpoint, NULL, headers, debug);
//     json_data = json_object_get(resp, "value");
//     printf("%s", json_dumps(json_data, JSON_INDENT(4)));

//     if (json_data) {
//         json_t *element;
//         element = json_array_get(json_data, 0);
//         if (element != NULL) {
//             return json_string_value(json_object_get(element, "id"));
//         }
//     } else {
//         pam_syslog(pamh, LOG_ERR, "get_user_id - json_object_get() failed: value NULL\n");
//     }

//     curl_slist_free_all(headers);
//     json_decref(resp);

//     return NULL;
// }