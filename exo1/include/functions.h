#ifndef _EXO1_FUNCTIONS_H_
#define _EXO1_FUNCTIONS_H_

#include <stddef.h>
#include <stdint.h>

size_t func_sha1(const void *data, size_t len, char **hash_buffer);
size_t func_sha224(const void *data, size_t len, char **hash_buffer);
size_t func_sha256(const void *data, size_t len, char **hash_buffer);
size_t func_sha512(const void *data, size_t len, char **hash_buffer);

#endif
