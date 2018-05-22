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
#include "file_io.h"
#include "validate_names.h"
#include "validate_times.h"
#include "validate_rsa.h"
#include "validate_con_use.h"

// Definitions
#define MIN_SIZE 10
#define VALID 1

// ---------------------------------------------------------------------- 
// Function Declarations
void validate_cert(cert_t* data, int i);
void debug(cert_t* data, int n);
// ----------------------------------------------------------------------
/* Main Function
 *
 */

int 
main(int argc, char *argv[])
{   
    int i;

    // ------------------------------------------------------------------
    // Initialising data struct and info struct for it
    cert_t *data = malloc(MIN_SIZE * sizeof(cert_t));
    data_info_t data_info;
    data_info.current_size = 0;
    data_info.max_size = MIN_SIZE;

    // Parsing the CSV File
    data = read_file(argv[1], data, &data_info);
    // ------------------------------------------------------------------
    // Validating each certificate

    // Loop through struct
    for(i=0;i<(data_info.current_size);i++) {
        // Validate each certificate        
        validate_cert(data, i);
    }
    //debug(data, data_info.current_size);

    // ------------------------------------------------------------------
    // Exporting it to the outputc CSV file
    export_csv(data, data_info.current_size);


    // Freeing the data after 
    for(i=0;i<(data_info.current_size);i++) {
        // Free each individual certificate struct      
        free(data[i].file_path);
        free(data[i].url);
    }
    free(data);

    return 0;
}

// ----------------------------------------------------------------------
/* Helper Functions
 *
 */

/* Validating each cert inside of the input CSV
 * --------------------------------------------
 * data: The data struct for storing the contents of the csv
 * i: The current index of the array of certs
 */
void
validate_cert(cert_t* data, int i) {

    char* path = data[i].file_path;
    char* url = data[i].url;

    // Initialisation of the certificates 
    BIO *certificate_bio = NULL;
    X509 *cert = NULL;

    // Initialise openSSL
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();

    // Create BIO object to read certificate
    certificate_bio = BIO_new(BIO_s_file());


     // Read certificate into BIO
    if (!(BIO_read_filename(certificate_bio, path))) {
        // Handle errors
        fprintf(stderr, "Error in reading cert BIO filename");
        exit(EXIT_FAILURE);
    }

    // Reading the PEM file
    if (!(cert = PEM_read_bio_X509(certificate_bio, NULL, 0, NULL))){
        // Handle errors
        fprintf(stderr, "Error in loading certificate");
        exit(EXIT_FAILURE);
    }

    // Validity Variables
    int period, names, rsa, key_con_usage;

    // Validations
    period = validate_period(cert);
    rsa = validate_rsa_length(cert);
    names = validate_names(cert, url);
    key_con_usage = validate_key_usage_cons(cert);


    // If all validates to true, mark the cert as valid
    if(period && names && rsa && key_con_usage) {
        data[i].validate = VALID;
    }

    // Free BIO and cert
    BIO_free_all(certificate_bio);
    X509_free(cert);
}



/* Debug function to print out the struct array
 * --------------------------------------------
 * data: The data struct for storing the contents of the csv.
 * n: The length of the array structure. 
 */
void
debug(cert_t* data, int n) {
    int i;

    // Loop through everything and print it out to the csv
    for(i=0;i<n;i++) {
        // Printing each value into a row in the csv
        printf("%d\npath: %s\nurl: %s\nvalid: %d\n\n", 
            (i+1), data[i].file_path, data[i].url, data[i].validate);
    }
}