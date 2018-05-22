/*   Validation of Not Before and Not After Times body
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
#include <time.h>

// Importation of header files
#include "validate_times.h"

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
