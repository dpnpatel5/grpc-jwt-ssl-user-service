#include "user_service.h"
#include "db.h"

/*using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::Status;
*/
namespace user_management {

Status UserServiceImpl::RegisterUser(ServerContext* context, const RegisterUserRequest* request, RegisterUserResponse* response) {
    // Implement registration logic here
    bool success = DB::Instance().RegisterUser(request->username(), request->password(), request->email());
    response->set_success(success);
    response->set_message(success ? "User registered successfully" : "Registration failed");
    return Status::OK;
}

Status UserServiceImpl::LoginUser(ServerContext* context, const LoginUserRequest* request, LoginUserResponse* response) {
    // Implement login logic here
    std::string token = DB::Instance().LoginUser(request->username(), request->password());
    response->set_success(!token.empty());
    response->set_token(token);
    return Status::OK;
}

Status UserServiceImpl::GetUserProfile(ServerContext* context, const GetUserProfileRequest* request, GetUserProfileResponse* response) {
    // Implement profile retrieval logic here
    auto user = DB::Instance().GetUserProfile(request->token());
    response->set_username(user.username);
    response->set_email(user.email);
    return Status::OK;
}

} // namespace user_management

