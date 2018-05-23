#ifndef CIPHER_KEY_TEST_H
#define CIPHER_KEY_TEST_H

unsigned char test_password[25] = {'p', 'a', 's', 's', 'w', 'o', 'r', 'd',
                                   'P', 'A', 'S', 'S', 'W', 'O', 'R', 'D',
                                   'p', 'a', 's', 's', 'w', 'o', 'r', 'd', 0x00};
unsigned char test_salt[37] = {'s', 'a', 'l', 't',
                               'S', 'A', 'L', 'T',
                               's', 'a', 'l', 't',
                               'S', 'A', 'L', 'T',
                               's', 'a', 'l', 't',
                               'S', 'A', 'L', 'T',
                               's', 'a', 'l', 't',
                               'S', 'A', 'L', 'T',
                               's', 'a', 'l', 't', 0x00};

unsigned int test_pass_length = 24;
unsigned int test_salt_length = 36;
unsigned int test_key_length = 100;

unsigned int test_num_iter = 4096;

#endif // CIPHER_KEY_TEST_H
