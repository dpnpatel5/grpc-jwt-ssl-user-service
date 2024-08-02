#include "user_management.grpc.pb.h"
#include <grpcpp/grpcpp.h>
#include <iostream>

using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;
using user_management::UserService;
using user_management::RegisterUserRequest;
using user_management::RegisterUserResponse;
using user_management::LoginUserRequest;
using user_management::LoginUserResponse;
using user_management::GetUserProfileRequest;
using user_management::GetUserProfileResponse;

class UserManagementClient {
public:
    UserManagementClient(std::shared_ptr<Channel> channel)
        : stub_(UserService::NewStub(channel)) {}

    bool RegisterUser(const std::string& username, const std::string& password, const std::string& email) {
        RegisterUserRequest request;
        request.set_username(username);
        request.set_password(password);
        request.set_email(email);

        RegisterUserResponse response;
        ClientContext context;

        Status status = stub_->RegisterUser(&context, request, &response);

        if (status.ok()) {
            std::cout << "RegisterUser response: " << response.message() << std::endl;
            return response.success();
        } else {
            std::cerr << "RegisterUser failed: " << status.error_message() << std::endl;
            return false;
        }
    }

    std::string LoginUser(const std::string& username, const std::string& password) {
        LoginUserRequest request;
        request.set_username(username);
        request.set_password(password);

        LoginUserResponse response;
        ClientContext context;

        Status status = stub_->LoginUser(&context, request, &response);

        if (status.ok() && response.success()) {
            return response.token();
        } else {
            std::cerr << "LoginUser failed: " << status.error_message() << std::endl;
            return "";
        }
    }

    void GetUserProfile(const std::string& token) {
        GetUserProfileRequest request;
        request.set_token(token);

        GetUserProfileResponse response;
        ClientContext context;

        Status status = stub_->GetUserProfile(&context, request, &response);

        if (status.ok()) {
            std::cout << "GetUserProfile success: username=" << response.username()
                      << ", email=" << response.email() << std::endl;
        } else {
            std::cerr << "GetUserProfile failed: " << status.error_message() << std::endl;
        }
    }

private:
    std::unique_ptr<UserService::Stub> stub_;
};

int main(int argc, char** argv) {
    UserManagementClient client(grpc::CreateChannel("localhost:50051", grpc::InsecureChannelCredentials()));

    std::string action;
    std::cout << "Enter action (register/login): ";
    std::cin >> action;

    if (action == "register") {
        std::string username;
        std::string password;
        std::string email;

        std::cout << "Enter username: ";
        std::cin >> username;
        std::cout << "Enter password: ";
        std::cin >> password;
        std::cout << "Enter email: ";
        std::cin >> email;

        // Register a user
        bool registered = client.RegisterUser(username, password, email);

        if (registered) {
            std::cout << "User registered successfully.\n";
        } else {
            std::cout << "Registration failed.\n";
        }
    } else if (action == "login") {
        std::string username;
        std::string password;

        std::cout << "Enter username: ";
        std::cin >> username;
        std::cout << "Enter password: ";
        std::cin >> password;

        // Log in the user
        std::string token = client.LoginUser(username, password);

        if (!token.empty()) {
            std::cout << "User logged in successfully.\n";

            // Get the user's profile
            client.GetUserProfile(token);
        } else {
            std::cout << "Login failed.\n";
        }
    } else {
        std::cout << "Invalid action.\n";
    }

    return 0;
}

