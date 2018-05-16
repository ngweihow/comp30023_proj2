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
#include <time.h>
#include <fnmatch.h>

// Importation of header files 


// Definitions
#define MAX_LINE_LENGTH 128
#define MIN_SIZE 2

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
void read_file(char* path, cert_t* data, data_info_t* data_info);
void expand_array(data_info_t* info, cert_t* data);
void validate_cert(cert_t* data, int i);
int validate_ca(X509_NAME name, cert_t *data, int i);

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
    read_file(argv[1], data, &data_info);


    // ------------------------------------------------------------------
    // Validating each certificate

    // Loop through struct
    for(i=0;i<(data_info.current_size);i++) {
        // Validate each certificate
        validate_cert(data, i);
    }

    // ------------------------------------------------------------------
    // Exporting it to the outputc CSV file

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
void 
read_file(char* path, cert_t* data, data_info_t* data_info) {

    // Predefining variables used
    const char comma[2] = ",";
    char* cell;

    // Opening the file
    FILE *fp = fopen(path, "r");

    // Loop through the file 
    if(fp) {

        char line[MAX_LINE_LENGTH];

        // Reading each line of the CSV File
        while(fgets(line, sizeof(line), fp) != NULL) {
            
            // Check if the array has enough memory allocated to it
            expand_array(data_info, data);

            // Get content of cells and parse them into the struct
            (data[(data_info->current_size)]).file_path = strtok(line, comma);
            (data[(data_info->current_size)]).url = strtok(NULL, comma);

            // Update the details of the struct 
            data_info->current_size++;
        } 
    }
    
    // Handle Errors
    else {
        perror("ERROR reading from file");
        exit(1);
    } 

}

/* Helper function to realloc space for the struct array
 * -----------------------------------------------------
 * info: The information struct containing info on array
 * data: The actual data struct array to realloc
 */
void
expand_array(data_info_t* info, cert_t* data) {

    // Perform size checking
    if((info->current_size) >= (info->max_size)) {
        // Expand the size by two
        info->max_size = info->max_size * 2;
        printf("%d\n", (info->max_size));
        // Reallocate size of array in accordance to length
        data = realloc(data, ((info->max_size) * sizeof(cert_t)));
        
        // Error Handling
        if(!data) {
            perror("ERROR reallocation of memory to data array");
            exit(1);
        } 
    }
}

/* Concatenate function to appending one string to another 
 * -------------------------------------------------------
 * s1: First String to be at the front.
 * s2: Second String to be at the back.
 *
 * return: Pointer to the concatenated string.
 */
/*
char*
concat(char* s1, char* s2) {   
    // Determine the length of the output and allocating memory for it.
    int output_len = strlen(s1) + strlen(s2) + 1;
    char* concat_str = malloc(output_len * sizeof(char));

    // Copy the first string into the allocated return string.
    strcpy(concat_str, s1);
    // Concat the second on onto the allocated return string afterwards.
    strcat(concat_str, s2);

    return concat_str;
}
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

    // Initialising Certificate Subject Name
    if (!(X509_get_subject_name(cert))) {
        // Handle errors
        fprintf(stderr, "Error in reading certificate subject name");
        exit(EXIT_FAILURE);
    }



    // Printing certificate information for debugging
    //print_bio = BIO_new_fp(stdout, BIO_NOCLOSE);
    //x509_print_ex(, cert, XN_FLAG_COMPAT, X509_FLAG_COMPAT);


}


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

    // Getting the current time
    time_t time_now = time(NULL);

    // Check if current time is in range
    //return ((time_now > not_before) && (time_now < not_after));
    return 0;
}


/* Validate the Domain Name in Common Name
 * ---------------------------------------
 * cert: The certificate to validate the domain of 
 * name: The name of the certificate 
 * url: The string type of
 * i: The index of the current cert that is being validated
 *
 * return: Value of 1 if check was successful or 0 if not 
 */
int 
validate_ca(X509_NAME name,cert_t *data, int i) {

    /* Wild Card Handling */ 


    /*
    // Matching the Domain Names
    const char* url = data[i].url;

    // strcmp to compare exact match
    // fnmatch to compare wildcard matches
    if(!(strcmp(name, url)) && !(fnmatch(url, name, 0))) {
        return 1;
    }

    return 0;
    */
}



int
validate_san(){

}