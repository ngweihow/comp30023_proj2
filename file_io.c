/*   File input and output handler file body
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

// Importation of header files
#include "file_io.h"

// Definitions
#define MAX_LINE_LENGTH 128
#define INVALID 0

// ----------------------------------------------------------------------

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
