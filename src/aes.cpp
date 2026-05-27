#include "aes.h"
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <cstring>
#include <vector>
#include <string>

// to lowercase hex string
static std::string to_hex(const unsigned char* data, size_t len) {
    static const char kHex[] = "0123456789abcdef";
    std::string out;
    out.resize(len * 2);
    for (size_t i = 0; i < len; i++) {
        unsigned char b = data[i];
        out[i * 2] = kHex[b >> 4];
        out[i * 2 + 1] = kHex[b & 0x0F];
    }
    return out;
}

// derive a subkey from master_key using HKDF-SHA256
// 'info' distinguishes the purpose ("enc" vs "mac")
static bool derive_subkey(unsigned char out[32],
                           const unsigned char* master_key,
                           const char* info) {
    EVP_KDF* kdf = EVP_KDF_fetch(nullptr, "HKDF", nullptr);
    if (!kdf) return false;

    EVP_KDF_CTX* kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (!kctx) return false;

    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string("digest", (char*)"SHA256", 0),
        OSSL_PARAM_construct_octet_string("key", (void*)master_key, 32),
        OSSL_PARAM_construct_octet_string("info", (void*)info, strlen(info)),
        OSSL_PARAM_construct_end()
    };

    int ok = EVP_KDF_derive(kctx, out, 32, params);
    EVP_KDF_CTX_free(kctx);
    return ok == 1;
}

std::string compute_aes(const std::string& plaintext,
                        const unsigned char* master_key) {
    // Derive separate subkeys for encryption and authentication
    unsigned char enc_key[32];
    unsigned char mac_key[32];
    if (!derive_subkey(enc_key, master_key, "aes-enc") ||
        !derive_subkey(mac_key, master_key, "hmac-mac")) {
        return "ERROR_HKDF";
    }

    // Fixed IV derived from master_key so all TMR nodes produce identical output
    // TMR voting requires deterministic encryption across all nodes
    unsigned char iv[16];
    unsigned char iv_key[32];
    if (!derive_subkey(iv_key, master_key, "aes-iv")) {
        return "ERROR_IV_DERIVE";
    }
    memcpy(iv, iv_key, 16);

    // Dynamic buffer size
    size_t max_cipher_len = plaintext.size() + EVP_MAX_BLOCK_LENGTH;
    std::vector<unsigned char> ciphertext(max_cipher_len);

    int len = 0;
    int ciphertext_len = 0;

    // Step 1: Create EVP context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return "ERROR_CTX";

    // Step 2: Init with enc_key
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, enc_key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return "ERROR_INIT";
    }

    // Step 3: Encrypt
    if (EVP_EncryptUpdate(ctx,
                          ciphertext.data(), &len,
                          reinterpret_cast<const unsigned char*>(plaintext.data()),
                          static_cast<int>(plaintext.size())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return "ERROR_UPDATE";
    }
    ciphertext_len = len;

    // Step 4: Flush padding
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + ciphertext_len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return "ERROR_FINAL";
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    // Step 5: HMAC-SHA256 over ciphertext using mac_key
    unsigned char hmac_buf[EVP_MAX_MD_SIZE];
    unsigned int hmac_len = 0;
    unsigned char* hmac_ret = HMAC(EVP_sha256(),
         mac_key, 32,
         ciphertext.data(), static_cast<int>(ciphertext_len),
         hmac_buf, &hmac_len);

    if (!hmac_ret || hmac_len == 0) return "ERROR_HMAC";

    // format: ciphertext_hex:hmac_hex
    return to_hex(ciphertext.data(), ciphertext_len) + ":" +
           to_hex(hmac_buf, hmac_len);
}