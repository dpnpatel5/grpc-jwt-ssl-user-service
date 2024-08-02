#ifndef DB_H
#define DB_H

#include <string>
#include <unordered_map>
#include <mutex>
#include <jwt-cpp/jwt.h>

struct User {
    std::string username;
    std::string password_hash;
    std::string salt;
    std::string email;
};

class DB {
public:
    static DB& Instance();
    bool RegisterUser(const std::string& username, const std::string& password, const std::string& email);
    std::string LoginUser(const std::string& username, const std::string& password);
    User GetUserProfile(const std::string& token);
    static const std::string& GetJwtSecret();

private:
    DB() = default;
    ~DB() = default;
    DB(const DB&) = delete;
    DB& operator=(const DB&) = delete;

    std::unordered_map<std::string, User> users_;
    std::mutex mutex_;

    std::string GenerateSalt();
    std::string HashPassword(const std::string& password, const std::string& salt);
    std::string CreateToken(const std::string& username);
    static std::string jwt_secret;
};

#endif // DB_H

