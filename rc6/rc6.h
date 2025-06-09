#ifndef RC6_H
#define RC6_H

#include <stdint.h>

void rc6_encrypt_block(uint8_t *key, uint8_t *plaintext, uint8_t *ciphertext);
void rc6_decrypt_block(uint8_t *key, uint8_t *ciphertext, uint8_t *plaintext);



#endif // RC6_H

