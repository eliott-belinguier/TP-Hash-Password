#ifndef _EXO3_HASH_H_
#define _EXO3_HASH_H_

#include <stddef.h>

int salt_hash(const void *data, size_t len, unsigned char *hash_buff);

#endif
