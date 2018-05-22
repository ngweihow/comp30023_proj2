/*   Certificate Common Name and Subject Alternative Name Checker header
     +------------------------------------------------------------------+
     | Project Code for Computer Systems COMP30023 2018 S1              |
     | A simple program to validate TLS certificate files               |
     | To compile: Run the Makefile with "make"                         |
     | Written by: Wei How Ng (828472) wein4                            |
     +------------------------------------------------------------------+

 */


// ---------------------------------------------------------------------- 
// Function Declarations
int validate_names (X509* cert, const char* url);
int validate_ca(X509* cert, const char* url);
int validate_san(X509* cert, const char* url);