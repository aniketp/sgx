#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "sgx_trts.h"
#include "../Enclave.h"
#include "Enclave_t.h"

#define MAXLEN 1024

/*
 * [in]: Ecall: Copy password inside
 */
void authenticate(char *password)
{
	FILE *file;
	char buff[MAXLEN];
	bzero(buff, MAXLEN);
	int i = 0;
	int c;

	file = fopen("enclavepass.txt", "r");
	if (file == NULL)
		exit(EXIT_FAILURE);

	while ((c = (char)fgetc(file)) != ',') {
		buff[i++] = c;
	}
	
	/* If the first word was not password, then the file has been tampered with */	
	if (!strncmp(buff, "password", i-1)) {
		i = 0;
		bzero(buff, MAXLEN);
		while ((c = (char)fgetc(file)) != '\n') {
			buff[i++] = c;
		}
		assert(!strncmp(buff, password, sizeof(password)));
	}

	fclose(file);
	return;
}

/*
 * [in-out] Ecall: Copy input buffer and export the relevant password
 */
void viewpassword(char *choice, char *input)
{
	FILE *file;
	char buff[BUFFLEN];
	bzero(buff, MAXLEN);

	file = fopen("enclavepass.txt", "r");
	if (file == NULL)
		exit(EXIT_FAILURE);

	while(true) {
		int i = 0;
		int c;

		bzero(buff, MAXLEN);
		while ((c = (char)fgetc(file)) != ',') {
			buff[i++] = c;
		}

		/* If the first word was not the account, then we skip to the next line */
		if (strncmp(buff, choice, sizeof(choice))) {
			while ((c = (char)fgetc(file)) != '\n') {
				/* Check if we've reached the end of file */
				if (fgetc(file) == EOF)
					break;
			}
		}
		else {
			i = 0;
			bzero(buff, MAXLEN);
			while ((c = (char)fgetc(file)) != '\n') {
				buff[i++] = c;	
			}
			strncpy(input, buff, sizeof(buff));
			break;
		}
	}
	return;
}


