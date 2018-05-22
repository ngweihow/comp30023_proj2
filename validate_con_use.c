/*   Validation of Basic Key Constraints and Enhanced Key Usage body
     +------------------------------------------------------------------+
     | Project Code for Computer Systems COMP30023 2018 S1              |
     | A simple program to validate TLS certificate files               |
     | To compile: Run the Makefile with "make"                         |
     | Written by: Wei How Ng (828472) wein4                            |
     +------------------------------------------------------------------+

 */

// ----------------------------------------------------------------------
// Library and header includes
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>

// Importation of header files
#include "validate_con_use.h"

// ----------------------------------------------------------------------

/* Validation of Key Usage and constraints
 * ---------------------------------------
 * cert: The certificate to validate the key usage/constraints of 
 *
 * return: Value of 1 if check was successful or 0 if not 
 */
int
validate_key_usage_cons(X509* cert) {


    // Constraints and Usage checks
    const char* basic_con = "CA:FALSE";
    const char* enhanced_use = "TLS Web Server Authentication";

    int constraint_ok, usage_ok;

    // Check for Basic Contraints -----------------------------------
    X509_EXTENSION *ex_bc = X509_get_ext(cert, 
        X509_get_ext_by_NID(cert, NID_basic_constraints, -1));

    if(!ex_bc) {
        // Handle errors
        fprintf(stderr, "Error in getting key constraints");
        exit(EXIT_FAILURE);
    }

    constraint_ok = checking_ext(ex_bc, basic_con);


    // Check for Enhanced Key Usage ---------------------------------
     X509_EXTENSION *ex_eu = X509_get_ext(cert, 
        X509_get_ext_by_NID(cert, NID_ext_key_usage, -1));
    
    if(!ex_eu) {
        // Handle errors
        fprintf(stderr, "Error in getting key constraints");
        exit(EXIT_FAILURE);
    }

    usage_ok = checking_ext(ex_eu, enhanced_use);


    // Contraint not found
    return (constraint_ok && usage_ok);
}

/* Validation of Enhanced Key Usage or Basic Constraints
 * -----------------------------------------------------
 * ex: The extension as a x509_EXTENSION file
 * match_type: The type of extension to be matched as a string
 *
 * return: Value of 1 if check was successful or 0 if not 
 */
int
checking_ext(X509_EXTENSION *ex, const char* match_type) {

    // Buffer Memory
    BUF_MEM *bptr = NULL;
    char *buf = NULL;

    // Initialise the a new BIO
    BIO *bio = BIO_new(BIO_s_mem());
    if (!X509V3_EXT_print(bio, ex, 0, 0)) {
        fprintf(stderr, "Error in reading extensions");
    }
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bptr);
    BIO_set_close(bio, BIO_NOCLOSE);

    //bptr->data is not NULL terminated - add null character
    buf = malloc((bptr->length + 1) * sizeof(char));
    memcpy(buf, bptr->data, bptr->length);
    buf[bptr->length] = '\0';
    
    // Check if string is present in the 
    char* ret  = strstr(buf, match_type);

    // Free BIO and buf
    BUF_MEM_free(bptr);
    BIO_free_all(bio);
    free(buf);

    // Return true if check passed
    if(ret != NULL) {
        // Basic constraint found!
        return 1;
    }
    

    // Checked string not found
    return 0;
}
