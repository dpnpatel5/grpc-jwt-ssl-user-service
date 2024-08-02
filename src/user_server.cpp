#include "user_service.h"
#include <grpcpp/grpcpp.h>
#include <iostream>

using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::Status;

void RunServer() {
    std::string server_address("0.0.0.0:50051");
    user_management::UserServiceImpl service;

 //   grpc::SslServerCredentialsOptions ssl_opts;
   // ssl_opts.pem_root_certs = /* Load root certificates */;
   // ssl_opts.pem_key_cert_pairs.push_back({/* Load private key */, /* Load server certificate */});

    ServerBuilder builder;
    builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
//    builder.AddListeningPort(server_address, grpc::SslServerCredentials(ssl_opts));
    builder.RegisterService(&service);
    std::unique_ptr<Server> server(builder.BuildAndStart());
    std::cout << "Server listening on " << server_address << std::endl;

    server->Wait();
}

int main(int argc, char** argv) {
    RunServer();
    return 0;
}

