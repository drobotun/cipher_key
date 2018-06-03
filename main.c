#include <time.h>

#include "cipher_key.h"
#include "cipher_key_test.h"

static void
print_key(uint8_t *key, size_t key_length)
{
    printf("Key = ");
    for(unsigned int i = 0; i < key_length; i++)
        printf("%02x", key[i]);
    printf("\n");
}

void get_time_start(){
    time_t time_start = time(NULL);
    printf("Start hashing: %s", ctime(&time_start));
}

void get_time_end(){
    time_t time_end = time(NULL);
    printf("End hashing: %s", ctime(&time_end));
}

int main()
{
    printf("Test password: %s\n", test_password);
    printf("Test salt: %s\n", test_salt);
    printf("Key length = %d\n", test_key_length);
    printf("Number of iterations = %d\n", test_num_iter);
    uint8_t *key;
    key = malloc(test_key_length);
    get_time_start();
    PBKDF_2(test_password, test_pass_length, test_salt, test_salt_length,
            test_num_iter, test_key_length, key);
    print_key(key, test_key_length);
    get_time_end();
}
