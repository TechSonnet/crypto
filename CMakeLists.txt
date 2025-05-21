cmake_minimum_required(VERSION 3.31)
project(crypto C)

set(CMAKE_C_STANDARD 99)


# 定义源文件列表
# 定义 SHA3 相关的源文件列表
set(SHA3_SOURCES
        sha3_512/sha3_512.c
        test/test_sha3_512.c
)

# 定义 SHA3 相关的源文件列表
set(MD5_SOURCES
        md5/MD5.c
        test/test_md5.c
)

# 定义 SHA_256 相关的源文件列表
set(SHA_256_SOURCES
        sha_256/sha_256.c
        test/test_sha_256.c
)

# 定义 RC4 相关的源文件列表
set(RC4_SOURCES
        rc4/rc4.c
        test/test_rc4.c
)


# 创建一个包含所有加密技术的可执行文件
add_executable(crypto
        ${SHA3_SOURCES}
        ${MD5_SOURCES}
        ${SHA_256_SOURCES}
        ${RC4_SOURCES}
        test/main.c
)



