#pragma once

#include "types.h"
#include <string>

namespace msg {

// ── AES-256-GCM payload encryption ─────────────────────────
// Используется симметричный сессионный ключ, согласованный при аутентификации.
// Формат зашифрованных данных: [IV 12 bytes][ciphertext][TAG 16 bytes]

class Crypto {
public:
    // Генерация случайного 256-битного ключа
    static Bytes generateSessionKey();

    // Генерация случайного IV (12 байт для GCM)
    static Bytes generateIV();

    // Шифрование AES-256-GCM
    // Вход: plaintext, key (32 bytes)
    // Выход: [IV(12)][ciphertext][TAG(16)]
    static Bytes encrypt(const Bytes& plaintext, const Bytes& key);

    // Дешифрование AES-256-GCM
    // Вход: [IV(12)][ciphertext][TAG(16)], key (32 bytes)
    // Выход: plaintext или пустой вектор при ошибке
    static Bytes decrypt(const Bytes& ciphertext, const Bytes& key);

    // Шифрование строки (удобная обёртка)
    static Bytes encryptStr(const std::string& plaintext, const Bytes& key);
    static std::string decryptStr(const Bytes& ciphertext, const Bytes& key);
};

// ── Zlib compression ───────────────────────────────────────
class Compression {
public:
    static Bytes compress(const Bytes& data);
    static Bytes decompress(const Bytes& data);

    static Bytes compressStr(const std::string& data);
    static std::string decompressStr(const Bytes& data);
};

} // namespace msg
