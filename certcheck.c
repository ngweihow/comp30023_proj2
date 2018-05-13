/*   Main CertCheck File
     +------------------------------------------------------------------+
     | Project Code for Computer Systems COMP30023 2018 S1              |
     | A simple program to validate TLS certificate files               |
     | To compile: Run the Makefile with "make"                         |
     | Written by: Wei How Ng (828472) wein4                            |
     +------------------------------------------------------------------+

 */


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





// ----------------------------------------------------------------------
/* Main Function
 *
 */

int 
main(int argc, char *argv[])
{   

    // Initialisation of the certificates 
    BIO *certificate_bio = NULL;
    X509 *cert = NULL;
    X509_NAME *cert_issuer = NULL;
    X509_CINF *cert_inf = NULL;
    STACK_OF(X509_EXTENSION) * ext_list;

    // Initialise openSSL
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();

    // Create BIO object to read certificate
    certificate_bio = BIO_new(BIO_s_file());


     // Read certificate into BIO
    if (!(BIO_read_filename(certificate_bio, test_cert_example))) {
        fprintf(stderr, "Error in reading cert BIO filename");
        exit(EXIT_FAILURE);
    }

    // Reading the PEM file
    if (!(cert = PEM_read_bio_X509(certificate_bio, NULL, 0, NULL))){
        fprintf(stderr, "Error in loading certificate");
        exit(EXIT_FAILURE);
    }


    // Reading the CSV File



    return 0;
}

// ----------------------------------------------------------------------
