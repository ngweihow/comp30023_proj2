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
OBJ = certcheck.o

$(EXE): $(OBJ)
	$(CC) -o $(EXE) $(OBJ) $(CFLAGS) 

clean: 
	rm $(OBJ) $(EXE)


scp:
	scp *.c Makefile ubuntu@115.146.85.92:./comp30023_all/comp30023_p2/

