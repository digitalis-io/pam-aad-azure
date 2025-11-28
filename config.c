#include <jansson.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "types.h"


int load_config(struct nss_config *json_config) {
    json_t *json_data = NULL, *config = NULL;
    json_error_t error;
    int ret = EXIT_FAILURE;

    // json_config = malloc(sizeof(struct nss_config *));

    config = json_load_file(CONFIG_FILE, 0, &error);
    if (!config) {
        fprintf(stderr, "error in config on line %d: %s\n", error.line,
                error.text);
        return ret;
    }

    json_config->debug = false;
    if (json_object_get(config, "debug"))
        if (strcmp
            (json_string_value(json_object_get(config, "debug")),
             "true") == 0)
            json_config->debug = true;

    if (json_object_get(json_object_get(config, "client"), "id")) {
        json_config->client_id =
            json_string_value(json_object_get
                              (json_object_get(config, "client"), "id"));
    } else {
        fprintf(stderr, "error with Client ID in JSON\n");
        return ret;
    }

    if (json_object_get(json_object_get(config, "client"), "secret")) {
        json_config->client_secret =
            json_string_value(json_object_get
                              (json_object_get(config, "client"), "secret"));
    } else {
        fprintf(stderr, "error with Client Secret in JSON\n");
        return ret;
    }

    if (json_object_get(config, "domain")) {
        json_config->domain = json_string_value(json_object_get(config, "domain"));
    } else {
        fprintf(stderr, "error with Domain in JSON\n");
        return ret;
    }

    /* Optional: proxy_address (default empty) */
    if (json_object_get(config, "proxy_address")) {
        json_config->proxy_address = (char *)json_string_value(json_object_get(config, "proxy_address"));
    } else {
        json_config->proxy_address = "";
    }

    if (json_object_get(config, "user_expires_after")) {
        json_config->user_expires_after = json_number_value(json_object_get(config, "user_expires_after"));
    } else {
        json_config->user_expires_after = -1;
    }

    if (json_object_get(json_object_get(config, "group"), "id")) {
        json_config->group_id =
            json_string_value(json_object_get
                              (json_object_get(config, "group"), "id"));
        json_config->group_name =
            json_string_value(json_object_get
                              (json_object_get(config, "group"), "name"));
    } else {
        fprintf(stderr, "error with Group ID in JSON\n");
        return ret;
    }

    if (json_object_get(config, "tenant")) {
        json_config->tenant =
            json_string_value(json_object_get
                              (json_object_get(config, "tenant"), "name"));
    } else {
        fprintf(stderr, "error with tenant in JSON\n");
        return ret;
    }

    /* Caching details */
    json_config->cache_directory =
        json_string_value(json_object_get
                            (json_object_get(config, "cache"), "root_directory"));
    json_config->cache_owner =
        json_string_value(json_object_get
                            (json_object_get(config, "cache"), "owner"));
    json_config->cache_group =
        json_string_value(json_object_get
                            (json_object_get(config, "cache"), "group"));
    json_config->cache_mode =
        json_string_value(json_object_get
                            (json_object_get(config, "cache"), "mode"));

    if (json_object_get(config, "home")) {
        json_config->home_directory =
            json_string_value(json_object_get
                                (json_object_get(config, "home"), "directory"));
    } else {
        if (DEBUG) fprintf(stderr, "error with tenant in JSON: no home directory\n");
        json_config->home_directory = HOME_ROOT;
    }

    return 0;
}
