cmake_minimum_required(VERSION 3.31)
project(crypto_algorithm C)

set(CMAKE_C_STANDARD 99)


# 定义 SHA3_512 相关的源文件列表
set(SHA3_512_SOURCES
        sha3_512/sha3_512.c
        sha3_512/sha3_512_test.c
)

# 定义 RC4 相关的源文件列表
set(RC4_SOURCES
        rc4/rc4.c
        rc4/rc4_test.c
)

# 定义 TRIVIUM 相关的源文件列表
set(TRIVIUM_SOURCES
        trivium/trivium.c
        trivium/trivium_test.c
)

add_executable(crypto_algorithm
        ${SHA3_512_SOURCES}
        ${RC4_SOURCES}
        ${TRIVIUM_SOURCES}
        main.c)
