#include <alloca.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>

#define HEXA "0123456789ABCDEF"

static void to_printable(char *hash_buffer, size_t len)
{
    size_t data_len = len / 2;
    unsigned char *buffer = alloca(data_len * sizeof(char));

    memcpy(buffer, hash_buffer, data_len);
    for (size_t i = 0; i < data_len; i++) {
        hash_buffer[i * 2] = HEXA[(buffer[i] / sizeof(HEXA)) % sizeof(HEXA)];
        hash_buffer[i * 2 + 1] = HEXA[buffer[i] % sizeof(HEXA)];
    }
}

size_t func_sha1(const void *data, size_t len, char **hash_buffer)
{
    size_t hash_len = SHA_DIGEST_LENGTH * 2;
    char *result = malloc(hash_len);

    if (!result)
        return 0;
    SHA1(data, len, (unsigned char *) result);
    to_printable(result, hash_len);
    *hash_buffer = result;
    return hash_len;
}

size_t func_sha224(const void *data, size_t len, char **hash_buffer)
{
    size_t hash_len = SHA_DIGEST_LENGTH * 2;
    char *result = malloc(hash_len);

    if (!result)
        return 0;
    SHA224(data, len, (unsigned char *) result);
    to_printable(result, hash_len);
    *hash_buffer = result;
    return hash_len;
}

size_t func_sha256(const void *data, size_t len, char **hash_buffer)
{
    size_t hash_len = SHA_DIGEST_LENGTH * 2;
    char *result = malloc(hash_len);

    if (!result)
        return 0;
    SHA256(data, len, (unsigned char *) result);
    to_printable(result, hash_len);
    *hash_buffer = result;
    return hash_len;
}

size_t func_sha512(const void *data, size_t len, char **hash_buffer)
{
    size_t hash_len = SHA_DIGEST_LENGTH * 2;
    char *result = malloc(hash_len);

    if (!result)
        return 0;
    SHA512(data, len, (unsigned char *) result);
    to_printable(result, hash_len);
    *hash_buffer = result;
    return hash_len;
}
