#include "crypto.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <zlib.h>
#include <stdexcept>
#include <cstring>
#include <iostream>

namespace msg {

// ── AES-256-GCM ────────────────────────────────────────────

static constexpr int AES_KEY_SIZE = 32;  // 256 bit
static constexpr int GCM_IV_SIZE  = 12;  // 96 bit (recommended for GCM)
static constexpr int GCM_TAG_SIZE = 16;  // 128 bit

Bytes Crypto::generateSessionKey() {
    Bytes key(AES_KEY_SIZE);
    if (RAND_bytes(key.data(), AES_KEY_SIZE) != 1) {
        throw std::runtime_error("RAND_bytes failed for session key");
    }
    return key;
}

Bytes Crypto::generateIV() {
    Bytes iv(GCM_IV_SIZE);
    if (RAND_bytes(iv.data(), GCM_IV_SIZE) != 1) {
        throw std::runtime_error("RAND_bytes failed for IV");
    }
    return iv;
}

Bytes Crypto::encrypt(const Bytes& plaintext, const Bytes& key) {
    if (key.size() != AES_KEY_SIZE) {
        std::cerr << "[Crypto] Invalid key size: " << key.size() << std::endl;
        return {};
    }

    Bytes iv = generateIV();

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return {};

    Bytes result;
    result.reserve(GCM_IV_SIZE + plaintext.size() + 16 + GCM_TAG_SIZE);

    // Prepend IV
    result.insert(result.end(), iv.begin(), iv.end());

    int len = 0, ciphertext_len = 0;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) goto fail;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_SIZE, nullptr) != 1) goto fail;
    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) != 1) goto fail;

    {
        Bytes ciphertext(plaintext.size() + 16);
        if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), (int)plaintext.size()) != 1) goto fail;
        ciphertext_len = len;

        if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) goto fail;
        ciphertext_len += len;

        result.insert(result.end(), ciphertext.begin(), ciphertext.begin() + ciphertext_len);
    }

    {
        // Append TAG
        Bytes tag(GCM_TAG_SIZE);
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_SIZE, tag.data()) != 1) goto fail;
        result.insert(result.end(), tag.begin(), tag.end());
    }

    EVP_CIPHER_CTX_free(ctx);
    return result;

fail:
    EVP_CIPHER_CTX_free(ctx);
    std::cerr << "[Crypto] AES-GCM encrypt failed" << std::endl;
    return {};
}

Bytes Crypto::decrypt(const Bytes& ciphertext, const Bytes& key) {
    if (key.size() != AES_KEY_SIZE) {
        std::cerr << "[Crypto] Invalid key size: " << key.size() << std::endl;
        return {};
    }
    if (ciphertext.size() < GCM_IV_SIZE + GCM_TAG_SIZE) {
        std::cerr << "[Crypto] Ciphertext too short" << std::endl;
        return {};
    }

    // Extract IV, encrypted data, TAG
    const uint8_t* iv = ciphertext.data();
    size_t enc_len = ciphertext.size() - GCM_IV_SIZE - GCM_TAG_SIZE;
    const uint8_t* enc_data = ciphertext.data() + GCM_IV_SIZE;
    const uint8_t* tag = ciphertext.data() + GCM_IV_SIZE + enc_len;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return {};

    Bytes plaintext(enc_len + 16);
    int len = 0, plaintext_len = 0;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) goto fail;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_SIZE, nullptr) != 1) goto fail;
    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv) != 1) goto fail;

    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, enc_data, (int)enc_len) != 1) goto fail;
    plaintext_len = len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_SIZE, (void*)tag) != 1) goto fail;

    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) {
        std::cerr << "[Crypto] AES-GCM tag verification failed (data tampered)" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    plaintext.resize(plaintext_len);
    return plaintext;

fail:
    EVP_CIPHER_CTX_free(ctx);
    std::cerr << "[Crypto] AES-GCM decrypt failed" << std::endl;
    return {};
}

Bytes Crypto::encryptStr(const std::string& plaintext, const Bytes& key) {
    Bytes data(plaintext.begin(), plaintext.end());
    return encrypt(data, key);
}

std::string Crypto::decryptStr(const Bytes& ciphertext, const Bytes& key) {
    auto plain = decrypt(ciphertext, key);
    return {plain.begin(), plain.end()};
}

// ── Zlib compression ───────────────────────────────────────

Bytes Compression::compress(const Bytes& data) {
    if (data.empty()) return {};

    uLongf bound = compressBound(data.size());
    Bytes result(bound + 4); // 4 bytes for original size prefix

    // Store original size (big-endian) for decompression
    uint32_t orig_size = (uint32_t)data.size();
    result[0] = (orig_size >> 24) & 0xFF;
    result[1] = (orig_size >> 16) & 0xFF;
    result[2] = (orig_size >> 8) & 0xFF;
    result[3] = orig_size & 0xFF;

    uLongf compressed_size = bound;
    int rc = ::compress2(result.data() + 4, &compressed_size, data.data(), data.size(), Z_DEFAULT_COMPRESSION);
    if (rc != Z_OK) {
        std::cerr << "[Compression] compress failed: " << rc << std::endl;
        return {};
    }

    result.resize(4 + compressed_size);
    return result;
}

Bytes Compression::decompress(const Bytes& data) {
    if (data.size() < 4) return {};

    // Read original size
    uint32_t orig_size = ((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16) |
                         ((uint32_t)data[2] << 8) | data[3];

    if (orig_size > 10 * 1024 * 1024) { // max 10 MB
        std::cerr << "[Compression] decompressed size too large: " << orig_size << std::endl;
        return {};
    }

    Bytes result(orig_size);
    uLongf dest_len = orig_size;
    int rc = ::uncompress(result.data(), &dest_len, data.data() + 4, data.size() - 4);
    if (rc != Z_OK) {
        std::cerr << "[Compression] decompress failed: " << rc << std::endl;
        return {};
    }

    result.resize(dest_len);
    return result;
}

Bytes Compression::compressStr(const std::string& data) {
    Bytes bytes(data.begin(), data.end());
    return compress(bytes);
}

std::string Compression::decompressStr(const Bytes& data) {
    auto result = decompress(data);
    return {result.begin(), result.end()};
}

} // namespace msg
