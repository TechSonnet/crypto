cmake_minimum_required(VERSION 3.31)
project(crypto_algorithm C)

set(CMAKE_C_STANDARD 99)


# 定义 ZUC_256 相关的源文件列表
set(UTILS_SOURCES
        utils/test_utils.h
        utils/test_utils.c
)

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

# 定义 ZUC_256 相关的源文件列表
set(ZUC_256_SOURCES
        zuc_256/zuc_256.c
        zuc_256/zuc_test.c
)


# 定义 ZUC_256 相关的源文件列表
set(rc6_SOURCES
        rc6/rc6.c
        rc6/test_rc6.c
)

add_executable(crypto_algorithm
        ${UTILS_SOURCES}
        ${SHA3_512_SOURCES}
        ${RC4_SOURCES}
        ${ZUC_256_SOURCES}
        ${TRIVIUM_SOURCES}
        ${rc6_SOURCES}
        main.c)
