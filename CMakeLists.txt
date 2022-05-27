cmake_minimum_required(VERSION 3.4)
project(COTP LANGUAGES C CXX)

option(COTP_BUILD_TESTS "Enable the tests for this project" OFF)
option(COTP_INSTALL "Install targets of this project" OFF)
option(COTP_COVERAGE "Enable coverage generation" OFF)

set(CMAKE_C_STANDARD 99)

if(COTP_COVERAGE)
    if(CMAKE_COMPILER_IS_GNUCXX)
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} --coverage -fprofile-arcs -ftest-coverage")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} --coverage -fprofile-arcs -ftest-coverage")
    endif()
endif()

# C API
add_library(cotp cotp.c cotp.h otpuri.c otpuri.h)
target_link_libraries(cotp PUBLIC m)
set_target_properties(cotp PROPERTIES PUBLIC_HEADER "cotp.h;otpuri.h")

# CXX API
add_library(cotp_cxx INTERFACE cotp.hpp otpuri.hpp)
target_link_libraries(cotp_cxx INTERFACE cotp)
set_target_properties(cotp_cxx PROPERTIES PUBLIC_HEADER "cotp.hpp;otpuri.hpp")

if(COTP_INSTALL)
    install(TARGETS cotp cotp_cxx)
endif()

if(COTP_BUILD_TESTS)
    enable_testing()

    find_package(OpenSSL REQUIRED)

    # C API
    add_executable(cotp_c_test test/main.c)
    target_link_libraries(cotp_c_test PRIVATE cotp OpenSSL::SSL)
    add_test(NAME cotp_test_c_api COMMAND cotp_c_test)

    # CXX API
    add_executable(cotp_cxx_test test/main.cpp)
    target_link_libraries(cotp_cxx_test PRIVATE cotp_cxx OpenSSL::SSL)
    add_test(NAME cotp_test_cxx_api COMMAND cotp_cxx_test)
endif()