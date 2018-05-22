/*   Certificate Common Name and Subject Alternative Name Checker body
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
#include <fnmatch.h>

// Importation of header files
#include "validate_names.h"

// ----------------------------------------------------------------------
/* Name Validations
 *
 */

/* Validate the All Names with the given URL 
 * -----------------------------------------
 * cert: The certificate to validate the domain of 
 * url: The url described for this certificate in the CSV
 *
 * return: Value of 1 if check was successful or 0 if not 
 */
int
validate_names (X509* cert, const char* url) {
    
    // Check if Common Name is valid
    if(validate_ca(cert, url)) {
        return 1;
    }

    // Else check for any valid Subject Alternative Names
    else if(validate_san(cert, url)){
        return 1;
    }

    // Return 0 if no names are found
    else {
        return 0;
    }

}


/* Validate the Domain Name in Common Name
 * ---------------------------------------
 * cert: The certificate to validate the domain of 
 * url: The url described for this certificate in the CSV
 *
 * return: Value of 1 if check was successful or 0 if not 
 */
int 
validate_ca(X509* cert, const char* url) {

    // Common Names     
    X509_NAME_ENTRY* cn_entry = NULL;
    ASN1_STRING* cn_asn1 = NULL;
    char* common_name = NULL;
    X509_NAME* name = X509_get_subject_name(cert);
    int common_name_loc = -1;

    // Initialising Certificate Subject Name
    if(!name) {
        // Handle errors
        fprintf(stderr, "Error in reading certificate subject name");
        exit(EXIT_FAILURE);
    }


    // Find position of the CN in the Subject Name of the certificate
    common_name_loc = X509_NAME_get_index_by_NID(name, NID_commonName, -1);
    if(common_name_loc < 0) {
        // Handle errors
        fprintf(stderr, "Error in finding position of common name");
        exit(EXIT_FAILURE);
    }

    // Extract the CN field
    cn_entry = X509_NAME_get_entry(name, common_name_loc);
    if(!cn_entry) {
        // Handle errors
        fprintf(stderr, "Error in extracting common name");
        exit(EXIT_FAILURE);
    }

    // Convert the common name to a C string
    cn_asn1 = X509_NAME_ENTRY_get_data(cn_entry);
    if(!cn_asn1) {
        // Handle errors
        fprintf(stderr, "Error in extracting common name");
        exit(EXIT_FAILURE);
    }           

    // Convert the Common Name from asn1 string to C string
    common_name = (char *) ASN1_STRING_data(cn_asn1);

    
    // strcmp to compare exact match
    // fnmatch to compare wildcard matches
    if(!(strcmp(common_name, url)) ||
        !(fnmatch(common_name, url, 0))) {
        return 1;
    }
    
    return 0;
}


/* Validate the Subject Alternative Name extension
 * -----------------------------------------------
 * cert: The certificate to validate the domain of 
 * url: The url described for this certificate in the CSV
 *
 * return: Value of 1 if check was successful or 0 if not 
 */
int
validate_san(X509* cert, const char* url) {
    
    // Setting variables to help iterate through list of SAN
    int i;
    int san_n = -1;

    // Return value defaulted to false
    int ret = 0;

    // Get list of all Subject Alternative Names
    STACK_OF(GENERAL_NAME)* san_list = NULL;
    san_list = X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
    san_n = sk_GENERAL_NAME_num(san_list);

    // Validating that the san_list is not empty
    if(!san_list) {
        // Does not have SAN 
        return 0;
    }

    // Loop through each SAN to compare
    for(i=0;i<san_n;i++) {

        // Match the SAN against the url
        const GENERAL_NAME* san_name = sk_GENERAL_NAME_value(san_list, i);
        if(!san_name) {
            // Invalid SAN            
            break;
        }

        // Check if it is a DNS name
        if(san_name->type == GEN_DNS) {
            // Once valid, convert to C string
            char* san_string = (char* ) ASN1_STRING_data(san_name->d.dNSName);

            // Break if nullbyte found in DNS
            if((strlen(san_string)) !=
                (unsigned int) ASN1_STRING_length(san_name->d.dNSName)) {

                break;
            }

            // Check if it matches url and wildcard matching
            if(!(strcmp(san_string, url)) ||
                !(fnmatch(san_string, url, 0))) {

                // Return 1 if matched
                ret = 1;
            }
        }
    }

    // Free all variables used
    sk_GENERAL_NAME_pop_free(san_list, GENERAL_NAME_free);

    return ret;
}