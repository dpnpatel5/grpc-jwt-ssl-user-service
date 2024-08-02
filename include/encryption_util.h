#ifndef ENCRYPTION_UTIL_H
#define ENCRYPTION_UTIL_H

#include <vector>
#include <string>

class EncryptionUtil {
public:
    static std::vector<unsigned char> GenerateKey();
    static std::vector<unsigned char> Encrypt(const std::string& plaintext, const std::vector<unsigned char>& key);
    static std::string Decrypt(const std::vector<unsigned char>& ciphertext, const std::vector<unsigned char>& key);
};

#endif // ENCRYPTION_UTIL_H

