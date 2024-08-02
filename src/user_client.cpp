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

    bool RegisterUser(const std::string& username, const std::string& password, const std::string& email,const std::string& ccnumber,const std::string& cvv) {
        RegisterUserRequest request;
        request.set_username(username);
        request.set_password(password);
        request.set_email(email);
        request.set_ccnumber(ccnumber);
        request.set_cvv(cvv);

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
            std::cout << "GetUserProfile success:"<<std::endl; 
            std::cout << "Username=" << response.username()<< std::endl;
            std::cout << "Email=" << response.email() << std::endl;
            std::cout << "Credit Card Number=" << response.ccnumber()<< std::endl;
            std::cout << "CVV=" << response.cvv()<< std::endl;
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
        std::string ccnumber;
        std::string cvv;

        std::cout << "Enter username: ";
        std::cin >> username;
        std::cout << "Enter password: ";
        std::cin >> password;
        std::cout << "Enter email: ";
        std::cin >> email;
        std::cout << "Enter Credit Card Nu,ber: ";
        std::cin >> ccnumber;
        std::cout << "Enter cvv: ";
        std::cin >> cvv;

        // Register a user
        bool registered = client.RegisterUser(username, password, email,ccnumber,cvv);

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

