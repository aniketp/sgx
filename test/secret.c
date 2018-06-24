#include <string.h>
#include "secret.h"

void secret_function(char *buf, size_t len) {
	const char *secret = "Secret Key";
	if (len > sizeof(secret))
		memcpy(buf, secret, strlen(secret) + 1);
}
