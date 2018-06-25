/*
 * Copyright (C) 2011-2018 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

/* Test Array Attributes */

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
			while ((c = (char)fgetc(file)) != '\n');
		}
		else {
			i = 0;
			bzero(buff, MAXLEN);
			while ((c = (char)fgetc(file)) != '\n') {
				buff[i++] = c;	
			}
			strncpy(input, buff, sizeof(buff));
		}
	}
	return;
}


