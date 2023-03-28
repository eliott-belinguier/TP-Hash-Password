#include <errno.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <string.h>

static void close_db(FILE **file)
{
    fclose(*file);
}

int main(int argc, char **argv)
{
    unsigned char password_hash[SHA_DIGEST_LENGTH];
    unsigned char current_db_hash[SHA_DIGEST_LENGTH];
    FILE *password_db __attribute__ ((cleanup (close_db)));
    size_t n = 0;
    char *line;
    ssize_t line_size;
    size_t line_count;
    
    if (argc != 3)
        return EINVAL;
    password_db = fopen(argv[1], "r");
    if (!password_db)
        return errno;
    line_count = 1;
    SHA1((unsigned char *) argv[2], strlen(argv[2]), password_hash);
    while ((line_size = getline(&line, &n, password_db)) != -1) {
        SHA1((unsigned char *) line, line_size - 1, current_db_hash);
        if (!memcmp(password_hash, current_db_hash, SHA_DIGEST_LENGTH)) {
            printf("line: %lu password: %s", line_count, line);
            break;
        }
        ++line_count;
    }
    return 0;
}
