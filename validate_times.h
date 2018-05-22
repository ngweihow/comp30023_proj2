/*   Validation of Not Before and Not After Times header
     +------------------------------------------------------------------+
     | Project Code for Computer Systems COMP30023 2018 S1              |
     | A simple program to validate TLS certificate files               |
     | To compile: Run the Makefile with "make"                         |
     | Written by: Wei How Ng (828472) wein4                            |
     +------------------------------------------------------------------+

 */

// ---------------------------------------------------------------------- 
// Function Declarations
int validate_period(X509 *cert);
