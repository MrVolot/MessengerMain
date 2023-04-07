cmake_minimum_required(VERSION 3.8)
project(certificateUtils)

set(CMAKE_CXX_STANDARD 17)

find_package(OpenSSL REQUIRED)

add_library(certificateUtils STATIC certificateUtils.cpp)
target_include_directories(certificateUtils PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(certificateUtils OpenSSL::SSL OpenSSL::Crypto)
