#include "db.h"
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <iostream>
#include <sstream>
#include <iomanip>

std::string DB::jwt_secret = std::getenv("JWT_SECRET") ? std::getenv("JWT_SECRET") : "default_secret_key";

const std::string& DB::GetJwtSecret() {
    return jwt_secret;
}

DB& DB::Instance() {
    static DB instance;
    return instance;
}

bool DB::RegisterUser(const std::string& username, const std::string& password, const std::string& email) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (users_.count(username)) {
        return false; // User already exists
    }

    std::string salt, password_hash;
    salt = GenerateSalt();
    password_hash = HashPassword(password, salt);
    users_[username] = {username, password_hash, salt, email};
    std::cout << "User registered successfully\n" << std::endl;
    std::cout << "Username: " << username << std::endl;
    std::cout << "Email: " << email << std::endl;
    return true;
}

std::string DB::LoginUser(const std::string& username, const std::string& password) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = users_.find(username);
    if (it != users_.end()) {
        std::string salt = it->second.salt;
        std::string hashed_password = HashPassword(password, salt);
        if (hashed_password == it->second.password_hash) {
            return CreateToken(username); // Generate a JWT token
        } else {
            std::cout << "Password does not match\n" << std::endl;
        }
    } else {
        std::cout << "User not found\n" << std::endl;
    }
    return "";
}

User DB::GetUserProfile(const std::string& token) {
    std::lock_guard<std::mutex> lock(mutex_);
    // Verify and decode the token
    try {
        auto decoded_token = jwt::decode(token);
        auto verifier = jwt::verify()
            .allow_algorithm(jwt::algorithm::hs256{jwt_secret})
            .with_issuer("auth0");
        verifier.verify(decoded_token);

        auto username = decoded_token.get_payload_claim("username").as_string();
        if (users_.count(username)) {
            return users_[username];
        }
    } catch (const std::exception& e) {
        std::cerr << "Invalid token: " << e.what() << std::endl;
    }

    return User{};
}

std::string DB::GenerateSalt() {
    const int salt_length = 16;
    unsigned char salt_bytes[salt_length];
    RAND_bytes(salt_bytes, salt_length);

    std::ostringstream salt_stream;
    for (int i = 0; i < salt_length; ++i) {
        salt_stream << std::setw(2) << std::setfill('0') << std::hex << (int)salt_bytes[i];
    }

    return salt_stream.str();
}

std::string DB::HashPassword(const std::string& password, const std::string& salt) {
    std::string salted_password = salt + password;

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;

    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(mdctx, salted_password.c_str(), salted_password.size());
    EVP_DigestFinal_ex(mdctx, hash, &hash_len);
    EVP_MD_CTX_free(mdctx);

    std::ostringstream hash_stream;
    for (unsigned int i = 0; i < hash_len; ++i) {
        hash_stream << std::setw(2) << std::setfill('0') << std::hex << (int)hash[i];
    }

    return hash_stream.str();
}

std::string DB::CreateToken(const std::string& username) {
    auto token = jwt::create()
        .set_issuer("auth0")
        .set_type("JWT")
        .set_payload_claim("username", jwt::claim(username))
        .set_payload_claim("timestamp", jwt::claim(std::to_string(std::chrono::system_clock::now().time_since_epoch().count())))
        .sign(jwt::algorithm::hs256{GetJwtSecret()});
    return token;
}

