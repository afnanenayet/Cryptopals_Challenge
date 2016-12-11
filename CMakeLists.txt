cmake_minimum_required(VERSION 3.7)
project(Cryptopals_Challenge C CXX)

set(CMAKE_CXX_STANDARD 14)

include_directories(b64)
include_directories(include)

# Adding all .cpp files in folder /src
file(GLOB SOURCE_FILES
    src/*.cpp)

add_executable(Cryptopals_Challenge ${SOURCE_FILES})
