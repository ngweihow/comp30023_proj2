/*   File input and output handler file header
     +------------------------------------------------------------------+
     | Project Code for Computer Systems COMP30023 2018 S1              |
     | A simple program to validate TLS certificate files               |
     | To compile: Run the Makefile with "make"                         |
     | Written by: Wei How Ng (828472) wein4                            |
     +------------------------------------------------------------------+

 */

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
void export_csv(cert_t* data, int n);
