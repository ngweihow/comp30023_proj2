/*   Validation of Basic Key Constraints and Enhanced Key Usage header
     +------------------------------------------------------------------+
     | Project Code for Computer Systems COMP30023 2018 S1              |
     | A simple program to validate TLS certificate files               |
     | To compile: Run the Makefile with "make"                         |
     | Written by: Wei How Ng (828472) wein4                            |
     +------------------------------------------------------------------+

 */

// ---------------------------------------------------------------------- 
// Function Declarations
int validate_key_usage_cons(X509* cert);
int checking_ext(X509_EXTENSION *ex, const char* match_type);