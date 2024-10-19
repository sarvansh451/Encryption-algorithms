#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>

static int cipher_enc(const char* alg,
    const unsigned char* pt, size_t pt_len,
    const unsigned char* key, size_t key_len,
    const unsigned char* iv, size_t iv_len,
    unsigned char* ct, size_t ct_len,
    int enc) {
    int ret = 0, out_len = 0, len = 0;
    EVP_CIPHER_CTX* ctx = NULL;
    EVP_CIPHER* cipher = NULL;

    printf("%s : %s\n", alg, enc ? "encrypt" : "decrypt");

    if (!pt || !pt_len || !key || !key_len || !iv || !iv_len || !ct || !ct_len) {
        printf("Invalid input parameters.\n");
        return 0;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        printf("Failed to create cipher context.\n");
        return 0;
    }

    cipher = EVP_get_cipherbyname(alg);
    if (!cipher) {
        printf("Unsupported cipher algorithm.\n");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    if (!EVP_CipherInit_ex(ctx, cipher, NULL, key, iv, enc)) {
        printf("Failed to initialize cipher.\n");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    if (!EVP_CipherUpdate(ctx, ct, &len, pt, pt_len)) {
        printf("Failed to perform cipher update.\n");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    out_len += len;

    if (!EVP_CipherFinal_ex(ctx, ct + len, &len)) {
        printf("Failed to perform cipher finalization.\n");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    out_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return out_len;
}

int main() {
    const char* algorithm = "AES-256-CBC";
    const unsigned char plaintext[] = "sarvansh mehta";
    const size_t plaintext_len = strlen((char*)plaintext);
    const unsigned char key[] = "01234567890123456789012345678901"; // 256-bit key
    const size_t key_len = strlen((char*)key);
    const unsigned char iv[] = "0123456789012345"; // 128-bit IV
    const size_t iv_len = strlen((char*)iv);
    unsigned char ciphertext[256] = { 0 }; // Make sure it's large enough

    int ciphertext_len = cipher_enc(algorithm,
        plaintext, plaintext_len,
        key, key_len,
        iv, iv_len,
        ciphertext, sizeof(ciphertext),
        1); // 1 for encryption, 0 for decryption

    if (ciphertext_len > 0) {
        printf("Ciphertext: ");
        for (int i = 0; i < ciphertext_len; ++i)
            printf("%02x", ciphertext[i]);
        printf("\n");
    }
    else {
        printf("Encryption failed.\n");
    }

    return 0;
}
