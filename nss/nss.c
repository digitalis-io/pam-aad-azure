#include <nss.h>
#include <pwd.h>
#include <grp.h>
#include <nss.h>
#include <pwd.h>
#include <stdio.h>

enum nss_status _nss_aad_setpwent (void) {
    fprintf(stderr, "NSS DEBUG: Called %s\n", __FUNCTION__);
    return NSS_STATUS_SUCCESS;
}
enum nss_status _nss_aad_endpwent (void) {
    fprintf(stderr, "NSS DEBUG: Called %s\n", __FUNCTION__);
    return NSS_STATUS_SUCCESS;
}
enum nss_status _nss_aad_getpwnam_r (struct passwd *result, char *buffer, size_t buflen, int *errnop) {
    fprintf(stderr, "NSS DEBUG: Called %s\n", __FUNCTION__);
    result->pw_name = "sergio";
    result->pw_gecos = "Serg";
    result->pw_gid = 900000;
    result->pw_uid = 999999;
    result->pw_shell = "/bin/bash";
    return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_aad_getpwbyuid_r (uid_t uid, struct passwd *result, char *buffer, size_t buflen, int *errnop) {
    fprintf(stderr, "NSS DEBUG: Called %s\n", __FUNCTION__);
    return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_aad_getpwbynam_r (const char *name, struct passwd *result, char *buffer, size_t buflen, int *errnop) {
    fprintf(stderr, "NSS DEBUG: Called %s\n", __FUNCTION__);
    return NSS_STATUS_SUCCESS;
}