#     Standard Make File
#     +------------------------------------------------------------------+
#     | Project Code for Computer Systems COMP30023 2018 S1              |
#     | A simple program to validate TLS Certificate Files               |
#     | To compile: Run the Makefile with "make"                         |
#     | Written by: Wei How Ng (828472) wein4                            |
#     +------------------------------------------------------------------+
#

CC = gcc
CFLAGS = -Wall -lssl -lcrypto
EXE = certcheck
OBJ = certcheck.o file_io.o validate_names.o validate_times.o validate_rsa.o validate_con_use.o

$(EXE): $(OBJ)
	$(CC) -o $(EXE) $(OBJ) $(CFLAGS) 

clean: 
	rm $(OBJ) $(EXE)


scp:
	scp *.c *.h Makefile ubuntu@115.146.85.92:./comp30023_all/comp30023_p2/

