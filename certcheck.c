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
#include <openssl/rsa.h>
#include <time.h>
#include <fnmatch.h>

// Importation of header files 


// Definitions
#define _GNU_SOURCE
#define MAX_LINE_LENGTH 128
#define MIN_SIZE 10
#define INVALID 0
#define VALID 1
#define MIN_RSA_LEN 2048

// ----------------------------------------------------------------------
// Definition of Structs

// Struct for the main data structure array
typedef struct{
    char* file_path;
    char* url;
    int validate;
} cert_t;

// Struct to hold the information regarding the array
typedef struct {
    int current_size;
    int max_size;
} data_info_t;

// ---------------------------------------------------------------------- 
// Function Declarations
cert_t* read_file(char* path, cert_t* data, data_info_t* data_info);
void expand_array(data_info_t* info, cert_t** data);
void validate_cert(cert_t* data, int i);
int validate_period(X509 *cert);
int validate_ca(X509* cert, cert_t *data, int i);
int validate_san(X509* cert,cert_t *data, int i);
int validate_rsa_length(X509* cert,cert_t *data);
int validate_key_usage(X509* cert,cert_t *data);
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
    debug(data, data_info.current_size);

    // ------------------------------------------------------------------
    // Exporting it to the outputc CSV file



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


/* File Reading Function to parse the CSV Files into a struct
 * ----------------------------------------------------------
 * path: The path string containing the path to the file
 * data: The data struct for storing the contents of the csv
 * data_len: The current length of the data struct array
 */
cert_t*
read_file(char* path, cert_t* data, data_info_t* data_info) {

    // Predefining variables used
    const char comma[2] = ",";
    const char newline[2] = "\n";

    // Opening the file
    FILE *fp = fopen(path, "r");

    // Loop through the file 
    if(fp) {

        char line[MAX_LINE_LENGTH];

        // Reading each line of the CSV File
        while(fgets(line, sizeof(line), fp) != NULL) {

            // Check if the array has enough memory allocated to it
            expand_array(data_info, &data);

            // Copy the string into each cert_t in the struct
            data[(data_info->current_size)].file_path = strdup(strtok(line, comma));
            data[(data_info->current_size)].url = strdup(strtok(NULL, newline));
            data[(data_info->current_size)].validate = INVALID;

            //printf("%s\n", data[(data_info->current_size)].file_path);
            //printf("%s\n", data[(data_info->current_size)].url);

            // Update the details of the struct 
            data_info->current_size++;
        } 
    }
    // Handle Errors
    else {
        perror("ERROR reading from file");
        exit(1);
    } 

    return data;

}

/* Helper function to realloc space for the struct array
 * -----------------------------------------------------
 * info: The information struct containing info on array
 * data: The actual data struct array to realloc
 */
void
expand_array(data_info_t* info, cert_t** data) {

    // Perform size checking
    if((info->current_size) == (info->max_size)) {
        // Expand the size by two
        info->max_size = info->max_size * 2;
        
        // Reallocate size of array in accordance to length
        *data = realloc(*data, info->max_size * sizeof(cert_t));

        // Error Handling
        if(!(*data)) {
            perror("ERROR reallocation of memory to data array");
            exit(1);
        } 
    }
}


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
    int period, ca, san, rsa, key_con;

    // Validations
    period = validate_period(cert);
    ca = validate_ca(cert, data, i);
    rsa = validate_rsa_length(cert, data);

    // If all validates to true, mark the cert as valid
    if(period * ca * rsa) {
        data[i].validate = VALID;
    }

    // Printing certificate information for debugging
    //print_bio = BIO_new_fp(stdout, BIO_NOCLOSE);
    //x509_print_ex(, cert, XN_FLAG_COMPAT, X509_FLAG_COMPAT);


}

// ----------------------------------------------------------------------
/* Time Validations
 *
 */

/* Validate Period of Certificate 
 * ------------------------------
 * cert: The certificate to validate the time period of 
 *
 * return: Value of 1 if check was successful or 0 if not
 */
int
validate_period(X509 *cert) {

    // Getting the not before and after times 
    ASN1_TIME *not_before = X509_get_notBefore(cert);
    ASN1_TIME *not_after = X509_get_notAfter(cert);

    int day, sec;

    // Checking the time difference between the two times

    int after_val = 0, before_val = 0;

    // Check if the certificate time is not after
    if(ASN1_TIME_diff(&day, &sec, NULL, not_after)) {
        // Valid if difference in time are the same or negative
        if (day >= 0 && sec >= 0)
            after_val = 1;
    }

    // Check if the certificate time is not before
    if(ASN1_TIME_diff(&day, &sec, NULL, not_before)) {
        // Valid if difference in time are the same or positive
        if(day <= 0 && sec <= 0)
            before_val = 1;
    }
   
    // Return validity of before and after
    return (after_val && before_val);
}

// ----------------------------------------------------------------------
/* Name Validations
 *
 */


/* Validate the Domain Name in Common Name
 * ---------------------------------------
 * cert: The certificate to validate the domain of 
 * data: The data struct for storing the contents of the csv
 * i: The index of the current cert that is being validated
 *
 * return: Value of 1 if check was successful or 0 if not 
 */
int 
validate_ca(X509* cert,cert_t *data, int i) {

    // Matching the Domain Names
    const char* url = data[i].url;

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
    if(!(strcmp(common_name, url)) && !(fnmatch(common_name, url, FNM_PERIOD))) {
        return 1;
    }
    
    return 0;
}


/* Validate the Subject Alternative Name extension
 * -----------------------------------------------
 * cert: The certificate to validate the domain of 
 * data: The data struct for storing the contents of the csv
 * i: The index of the current cert that is being validated
 *
 * return: Value of 1 if check was successful or 0 if not 
 */
int
validate_san(X509* cert,cert_t *data, int i) {
    
    
    int san_loc = -1; 

    // Matching the Domain Names
    const char* url = data[i].url;

    // Get list of all SAN extensions
    STACK_OF(X509_EXTENSION)* ext_list = NULL;
    ext_list = X509_get_ext(cert, san_loc);

    // Validating that the ext_list is not empty
    if(!ext_list) {
        // Handle errors
        fprintf(stderr, "Error in reading certificate san extensions");
        exit(EXIT_FAILURE);
    }

    /*
    // Finding NID extension
    san_loc = X509_get_index_by_NID(name, NID_commonName, -1);
    if(san_loc < 0) {
        return 0;
    }
    */







    return 0;
}

// ----------------------------------------------------------------------
/* Key Validations
 *
 */

/* RSA Key Length Validation
 * -------------------------
 * cert: The certificate to validate the domain of 
 * data: The data struct for storing the contents of the csv
 *
 * return: Value of 1 if check was successful or 0 if not 
 */
int
validate_rsa_length(X509* cert,cert_t *data) {

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
        return 1;
    }

    RSA_free(rsa_key);

    return 0;
}

/* Validation of Key Usage and constraints
 * ---------------------------------------
 * cert: The certificate to validate the domain of 
 * data: The data struct for storing the contents of the csv
 *
 * return: Value of 1 if check was successful or 0 if not 
 */
int
validate_key_usage(X509* cert,cert_t *data) {

    // Constraints and Usage checks
    const char* basic_con = "CA:FALSE";
    const char* enhanced_use = "TLS Web Server Authentication";

    // Check each key and their match their usage



    return 0;
}




/* Export to the export CSV File
 * -----------------------------
 * data: The data struct for storing the contents of the csv.
 * n: The length of the array structure. 
 */
void
export_csv(cert_t* data, int n) {

    // Handling the file operations
    int i;
    const char* filename = "sample_output.csv"; 
    FILE *fp = fopen(filename, "w+");


    // Loop through everything and print it out to the csv
    for(i=0;i<n;i++) {
        // Printing each value into a row in the csv
        fprintf(fp, "%s,%s,%d\n", 
            data[i].file_path, data[i].url, data[i].validate);
    }

    // Close the CSV File
    fclose(fp); 
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
        printf("path: %s\nurl: %s\nvalid: %d\n\n", 
            data[i].file_path, data[i].url, data[i].validate);
    }
}