# grpc-jwt-ssl-user-service

A gRPC-based user management service that supports secure user registration, login, and profile retrieval.

- Implements password hashing and JWT authentication, with Protobuf for data serialization.
- Implements gRPC SSL (Secure Sockets Layer) to provide encrypted communication between a gRPC client and server.

## Features

- **User Registration**: Securely register new users.
- **User Login**: Authenticate users using JWT.
- **Profile Retrieval**: Retrieve user profiles securely.
- **Password Hashing**: Securely store passwords using hashing.
- **JWT Authentication**: Use JSON Web Tokens for user authentication.
- **gRPC SSL/TLS**: Encrypt communication between client and server.

## Prerequisites

- C++ Compiler
- gRPC
- Protobuf
- OpenSSL
- CMake
- Make

## Setup

1. **Clone the Repository**
    ```sh
    git clone https://github.com/dpnpatel5/grpc-jwt-ssl-user-service.git
    cd grpc-jwt-ssl-user-service
    ```

2. **Generate SSL Certificates and Keys**
    ```sh
    ./cert/generate_cert.sh
    ```

3. **Build the Project**
    ```sh
    mkdir build
    cd build
    cmake ..
    make
    ```

## Usage

1. **Run the Server**
    ```sh
    ./build/user_server
    ```

2. **Run the Client**
    ```sh
    ./bin/user_client
    ```

## File Structure

- `src/`: Source code for server and client.
- `proto/`: Protobuf definitions.
- `cert/`: SSL certificates and keys.
- `build/`: Build directory.

