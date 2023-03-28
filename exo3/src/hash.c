#include <openssl/sha.h>
#include <stdint.h>
#include <stdlib.h>

static uint32_t data_hash_code(const void *data, size_t len)
{
    uint32_t hash = 0;
    const char *data_ptr = (const char *) data;

    if (!data || !len)
        return hash;
    for (size_t i = 0; i < len; i++)
        hash = hash * 31 + data_ptr[i];
    return hash;
}

static void salt_fill(void *buff, size_t len)
{
    uint8_t *buff_ptr = buff;
    
    for (size_t i = 0; i < len; i++)
        buff_ptr[i] = rand() % 255;
}

int salt_hash(const void *data, size_t len, unsigned char *hash_buff)
{
    uint32_t hash_code = data_hash_code(data, len);
    char salt[1024];
    size_t salt_i;
    SHA_CTX context;
    int success = 1;

    srand(hash_code);
    salt_i = rand() % len;
    salt_fill(salt, 1024);
    success = SHA1_Init(&context)
        && SHA1_Update(&context, data, salt_i)
        && SHA1_Update(&context, salt, 1024)
        && SHA1_Update(&context, data + salt_i, len - salt_i);
    success = SHA1_Final(hash_buff, &context) & success;
    return success;
}
