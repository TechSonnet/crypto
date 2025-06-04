cmake_minimum_required(VERSION 3.31)
project(crypto_algorithm C)

set(CMAKE_C_STANDARD 99)


# 定义 TRIVIUM 相关的源文件列表
set(TRIVIUM_SOURCES
        trivium/trivium.c
        trivium/trivium_test.c
)

add_executable(crypto_algorithm
        ${TRIVIUM_SOURCES}
        main.c)
