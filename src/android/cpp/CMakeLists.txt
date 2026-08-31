cmake_minimum_required(VERSION 3.18.1)

project(irootsecurity)

add_library(
        irootsecurity
        SHARED
        native_security.cpp
        runtime_checks.cpp
)

find_library(
        log-lib
        log
)

target_link_libraries(
        irootsecurity
        ${log-lib}
)

target_compile_options(
        irootsecurity
        PRIVATE
        -fvisibility=hidden
)