cmake_minimum_required(VERSION 3.10)
project(UserManagementService)

# Add jwt-cpp
include(FetchContent)
FetchContent_Declare(
  jwt-cpp
  GIT_REPOSITORY https://github.com/Thalhammer/jwt-cpp.git
  GIT_TAG v0.5.0
)
FetchContent_MakeAvailable(jwt-cpp)

# Find packages
find_package(Protobuf REQUIRED)
find_package(gRPC REQUIRED)
find_program(_PROTOBUF_PROTOC protoc)
find_program(_GRPC_CPP_PLUGIN_EXECUTABLE grpc_cpp_plugin)


# Add proto files
set(PROTO_FILES ${CMAKE_SOURCE_DIR}/proto/user_management.proto)

# Generated sources
set(PROTO_SRCS ${CMAKE_CURRENT_BINARY_DIR}/user_management.pb.cc)
set(PROTO_HDRS ${CMAKE_CURRENT_BINARY_DIR}/user_management.pb.h)
set(GRPC_SRCS ${CMAKE_CURRENT_BINARY_DIR}/user_management.grpc.pb.cc)
set(GRPC_HDRS ${CMAKE_CURRENT_BINARY_DIR}/user_management.grpc.pb.h)

add_custom_command(
  OUTPUT ${PROTO_SRCS} ${PROTO_HDRS} ${GRPC_SRCS} ${GRPC_HDRS}
  COMMAND ${_PROTOBUF_PROTOC}
  ARGS --grpc_out=${CMAKE_CURRENT_BINARY_DIR}
       --cpp_out=${CMAKE_CURRENT_BINARY_DIR}
       -I${CMAKE_CURRENT_BINARY_DIR}/../proto
       --plugin=protoc-gen-grpc=${_GRPC_CPP_PLUGIN_EXECUTABLE}
       user_management.proto
  DEPENDS ${PROTO_FILES}
  COMMENT "Generating protobuf and grpc files"
)

add_custom_target(proto_gen ALL
  DEPENDS ${PROTO_SRCS} ${PROTO_HDRS} ${GRPC_SRCS} ${GRPC_HDRS}
)
# Include directories
include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_CURRENT_BINARY_DIR})
# Add source files
set(SOURCE_FILES
    src/encryption_util.cpp
    src/user_db_api.cpp
    src/user_server.cpp
    src/user_db.cpp
    ${PROTO_SRCS}
    ${GRPC_SRCS}
)

# Add executable
add_executable(user_server ${SOURCE_FILES})

# Link libraries
target_link_libraries(user_server
    gRPC::grpc++_reflection
    protobuf::libprotobuf
    jwt-cpp::jwt-cpp
    pthread
)

# Client
# Add source files
set(CLIENT_SOURCE_FILES
    src/user_client.cpp
    ${PROTO_SRCS}
    ${GRPC_SRCS}
)

# Add executable
add_executable(user_client ${CLIENT_SOURCE_FILES})

# Link libraries
target_link_libraries(user_client
    gRPC::grpc++_reflection
    protobuf::libprotobuf
    jwt-cpp::jwt-cpp
    pthread
)

# Include generated files
include_directories(${CMAKE_BINARY_DIR})


