#pragma once

#include <string>
#include <vector>
#include <filesystem>
#include <fstream>
#include <sodium.h>

namespace minidrive {

inline bool crypto_init() {
    return sodium_init() >= 0;
}

inline std::string hash_password(const std::string& password) {
    char hash[crypto_pwhash_STRBYTES];
    if (crypto_pwhash_str(hash, password.c_str(), password.size(),
                          crypto_pwhash_OPSLIMIT_INTERACTIVE,
                          crypto_pwhash_MEMLIMIT_INTERACTIVE) != 0) {
        return "";
    }
    return std::string(hash);
}

inline bool verify_password(const std::string& hash, const std::string& password) {
    return crypto_pwhash_str_verify(hash.c_str(), password.c_str(), password.size()) == 0;
}

inline std::string hash_data(const uint8_t* data, size_t len) {
    unsigned char hash[crypto_generichash_BYTES];
    crypto_generichash(hash, sizeof(hash), data, len, nullptr, 0);
    char hex[crypto_generichash_BYTES * 2 + 1];
    sodium_bin2hex(hex, sizeof(hex), hash, sizeof(hash));
    return std::string(hex);
}

inline std::string hash_data(const std::vector<uint8_t>& data) {
    return hash_data(data.data(), data.size());
}

inline std::string hash_data(const std::string& data) {
    return hash_data(reinterpret_cast<const uint8_t*>(data.data()), data.size());
}

inline std::string hash_file(const std::filesystem::path& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) return "";
    
    crypto_generichash_state state;
    crypto_generichash_init(&state, nullptr, 0, crypto_generichash_BYTES);
    
    char buffer[65536];
    while (file.read(buffer, sizeof(buffer)) || file.gcount() > 0) {
        crypto_generichash_update(&state, reinterpret_cast<unsigned char*>(buffer),
                                  static_cast<size_t>(file.gcount()));
    }
    
    unsigned char hash[crypto_generichash_BYTES];
    crypto_generichash_final(&state, hash, sizeof(hash));
    
    char hex[crypto_generichash_BYTES * 2 + 1];
    sodium_bin2hex(hex, sizeof(hex), hash, sizeof(hash));
    return std::string(hex);
}

}
