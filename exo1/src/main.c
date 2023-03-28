#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "functions.h"

struct function {
    uint64_t hash;
    size_t (*function)(void const *data, size_t len, char **hash_buffer);
};

struct function functions[] = {
    {3528965, func_sha1}, // sha1
    {3391337928, func_sha224}, // sha224
    {3391338023, func_sha256}, // sha256
    {3391340778, func_sha512}, // sha512
    {0, 0}
};

static uint64_t str_hash_code(char const *str)
{
    uint64_t hash = 0;

    if (!str)
        return hash;
    for (; *str; str++)
        hash = hash * 31 + *str;
    return hash;
}

int main(int argc, char **argv)
{
    uint64_t inst_hash;
    size_t (*function)(void const *data, size_t len, char **hash_buffer) = 0;
    char *hash;
    size_t hash_len;

    if (argc != 3)
        return EINVAL;
    inst_hash = str_hash_code(argv[1]);
    for (size_t i = 0; functions[i].hash; i++) {
        if (functions[i].hash == inst_hash) {
            function = functions[i].function;
            break;
        }
    }
    if (!function)
        return EINVAL;
    hash_len = function(argv[2], strlen(argv[2]), &hash);
    if (!hash_len)
        return errno;
    write(1, hash, hash_len);
    write(1, "\n", 1);
    free(hash);
    return 0;
}
