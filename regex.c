#include <regex.h>                                                              
#include <locale.h>                                                             
#include <stdio.h>                                                              
#include <stdlib.h> 

int is_valid_email(const char *user) {
    regex_t regex;
    const char *reg_exp2 = "\\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,4}\\b";

    int reti = regcomp(&regex, reg_exp2, REG_EXTENDED);
    if( reti ){
        fprintf(stderr, "Could not compile regex\n"); 
        return 1;
    }

    fprintf(stderr, "%s(): checking the user [%s] is a valid email", __FUNCTION__, user);
    /* Execute regular expression */
    reti = regexec(&regex, user, 0, NULL, 0);
    if( !reti ){
        return 0;
    }
    return 1;
}

int main() {
    is_valid_email("sergio.rua@digitalis.io");
}