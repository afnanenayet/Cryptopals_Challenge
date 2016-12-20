cmake_minimum_required(VERSION 3.7)

# Project variables
set(PROJECT_NAME Cryptopals_Challenge)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY bin)

project(${PROJECT_NAME} C CXX)

set(CMAKE_CXX_STANDARD 14)

include_directories(include)

# Adding all .cpp files in folder /src
file(GLOB SOURCE_FILES
    src/*.cpp)

# Lets us use custom Find{Library} CMake files in our own project hierarchy
# (rather than whatever the system prefix is - keeps it more portable)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/contrib/cmake")

find_package(CryptoPP REQUIRED)
add_executable(Cryptopals_Challenge ${SOURCE_FILES})
target_link_libraries(${PROJECT_NAME} cryptopp)
