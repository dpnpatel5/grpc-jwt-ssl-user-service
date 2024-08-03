#include "user_service.h"
#include <grpcpp/grpcpp.h>
#include <iostream>
#include <fstream>
#include <memory>
#include <sstream>

using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::Status;

void read ( const std::string& filename, std::string& data )
{
    std::ifstream file ( filename.c_str (), std::ios::in );

    if ( file.is_open () )
    {
        std::stringstream ss;
        ss << file.rdbuf ();

        file.close ();

        data = ss.str ();
    }

    return;
}

void RunServer() {

    std::string server_address ( "localhost:50051" );
    std::string servercert;
    std::string serverkey;
    read("../cert/sslcred.crt", servercert);
    read("../cert/sslcred.key", serverkey);


    grpc::SslServerCredentialsOptions::PemKeyCertPair pkcp;
    pkcp.private_key = serverkey;
    pkcp.cert_chain = servercert;

    grpc::SslServerCredentialsOptions ssl_opts;
    ssl_opts.pem_root_certs="";
    ssl_opts.pem_key_cert_pairs.push_back(pkcp);

    std::shared_ptr<grpc::ServerCredentials> creds;
    creds = grpc::SslServerCredentials(ssl_opts);



    ServerBuilder builder;
    builder.AddListeningPort(server_address, grpc::SslServerCredentials( ssl_opts ));
    
    user_management::UserServiceImpl service;
    builder.RegisterService(&service);
    std::unique_ptr<Server> server(builder.BuildAndStart());
    std::cout << "Server listening on " << server_address << std::endl;

    server->Wait();
}

int main(int argc, char** argv) {
    RunServer();
    return 0;
}

