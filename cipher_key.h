#ifndef CIPHER_KEY_H
#define CIPHER_KEY_H

#include <stdfix.h>
#include <stdint.h>
#include <string.h>
#include <malloc.h>
#include <stdio.h>

#include "gost_3411_2012_calc.h"

void
PBKDF_2(const uint8_t *password, size_t size_pass, const uint8_t *salt, size_t size_salt,
        uint64_t num_iter, uint64_t key_length, uint8_t *key);

#endif // CIPHER_KEY_H
