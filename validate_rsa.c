/*   Validation of RSA Key Length in bits body
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
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/rsa.h>

// Importation of header files
#include "validate_rsa.h"

// Definitions
#define MIN_RSA_LEN 2048

// ----------------------------------------------------------------------
/* Key Validations
 *
 */

/* RSA Key Length Validation
 * -------------------------
 * cert: The certificate to validate the key's length of  
 * data: The data struct for storing the contents of the csv
 *
 * return: Value of 1 if check was successful or 0 if not 
 */
int
validate_rsa_length(X509* cert) {

    // Return value defaulted to false
    int ret = 0;

    // Getting the public key from the certificate
    EVP_PKEY* pkey = X509_get_pubkey(cert);
    if(!pkey && (EVP_PKEY_RSA == pkey->type)) {
        // Handle errors
        fprintf(stderr, "Error in reading public key from cert");
        exit(EXIT_FAILURE);
    }

    // Getting the RSA key and its length in bytes
    RSA *rsa_key = EVP_PKEY_get1_RSA(pkey);
    int pkey_length = RSA_size(rsa_key);

    // Convert bytes to bits and check
    if((pkey_length * 8) >= MIN_RSA_LEN) {
        ret = 1;
    }

    // Free the keys
    RSA_free(rsa_key);
    EVP_PKEY_free(pkey);

    return ret;
}