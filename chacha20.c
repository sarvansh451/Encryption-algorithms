#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define HEX_STRING_SIZE 64

void hex_to_bytes(const char* hex_string, unsigned char* bytes, size_t* length) {
    size_t hex_len = strlen(hex_string);
    *length = hex_len / 2;
    for (size_t i = 0; i < *length; i++) {
        sscanf(hex_string + 2 * i, "%2hhx", &bytes[i]);
    }
}

int main(void)
{
    /* Test Vector 1 Inputs in Hex Form */
    const char* key_hex = "0000000000000000000000000000000000000000000000000000000000000000";
    const char* iv_hex = "01000000000000000000000000000000";
    const char* plaintext_hex = "12345678"; 

    unsigned char key[32];
    unsigned char iv[16];
    unsigned char plaintext[64];

    size_t key_len, iv_len, plaintext_len;

    /* Convert hex strings to byte arrays */
    hex_to_bytes(key_hex, key, &key_len);
    hex_to_bytes(iv_hex, iv, &iv_len);
    hex_to_bytes(plaintext_hex, plaintext, &plaintext_len);

    unsigned char ciphertext[64];
    unsigned char decryptedtext[64];
    int ciphertext_len, decryptedtext_len;

    /* Initialize the library */
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    /* Create and initialize the context */
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Error creating context\n");
        return 1;
    }

    /* Initialize encryption operation */
    if (1 != EVP_EncryptInit_ex(ctx, EVP_chacha20(), NULL, key, iv)) {
        fprintf(stderr, "Error initializing encryption\n");
        return 1;
    }

    /* Provide the message to be encrypted, and obtain the encrypted output */
    int len;
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
        fprintf(stderr, "Error during encryption\n");
        return 1;
    }
    ciphertext_len = len;

    /* Finalize encryption */
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        fprintf(stderr, "Error finalizing encryption\n");
        return 1;
    }
    ciphertext_len += len;

    /* Show the encrypted text */
    printf("Ciphertext is:\n");
    for (int i = 0; i < ciphertext_len; i++) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");

    /* Initialize decryption operation */
    if (1 != EVP_DecryptInit_ex(ctx, EVP_chacha20(), NULL, key, iv)) {
        fprintf(stderr, "Error initializing decryption\n");
        return 1;
    }

    /* Provide the message to be decrypted, and obtain the plaintext output */
    if (1 != EVP_DecryptUpdate(ctx, decryptedtext, &len, ciphertext, ciphertext_len)) {
        fprintf(stderr, "Error during decryption\n");
        return 1;
    }
    decryptedtext_len = len;

    /* Finalize decryption */
    if (1 != EVP_DecryptFinal_ex(ctx, decryptedtext + len, &len)) {
        fprintf(stderr, "Error finalizing decryption\n");
        return 1;
    }
    decryptedtext_len += len;

    /* Show the decrypted text */
    printf("Decrypted text is:\n");
    for (int i = 0; i < decryptedtext_len; i++) {
        printf("%02x", decryptedtext[i]);
    }
    printf("\n");

    /* Verify the decrypted text matches the original plaintext */
    if (memcmp(decryptedtext, plaintext, plaintext_len) == 0) {
        printf("Decryption successful, plaintext matches original value.\n");
    }
    else {
        printf("Decryption failed, plaintext does not match original value.\n");
    }

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    EVP_cleanup();
    ERR_free_strings();

    return 0;
}

