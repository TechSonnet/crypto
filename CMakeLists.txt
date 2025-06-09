cmake_minimum_required(VERSION 3.31)
project(crypto_algorithm C)

set(CMAKE_C_STANDARD 99)


# ���� ZUC_256 ��ص�Դ�ļ��б�
set(UTILS_SOURCES
        utils/test_utils.h
        utils/test_utils.c
)

# ���� SHA3_512 ��ص�Դ�ļ��б�
set(SHA3_512_SOURCES
        sha3_512/sha3_512.c
        sha3_512/sha3_512_test.c
)

# ���� RC4 ��ص�Դ�ļ��б�
set(RC4_SOURCES
        rc4/rc4.c
        rc4/rc4_test.c
)

# ���� TRIVIUM ��ص�Դ�ļ��б�
set(TRIVIUM_SOURCES
        trivium/trivium.c
        trivium/trivium_test.c
)

# ���� ZUC_256 ��ص�Դ�ļ��б�
set(ZUC_256_SOURCES
        zuc_256/zuc_256.c
        zuc_256/zuc_test.c
)


# ���� ZUC_256 ��ص�Դ�ļ��б�
set(rc6_SOURCES
        rc6/rc6.c
        rc6/rc6_test.c
)


add_executable(crypto_algorithm
        ${UTILS_SOURCES}
        ${SHA3_512_SOURCES}
        ${RC4_SOURCES}
        ${ZUC_256_SOURCES}
        ${TRIVIUM_SOURCES}
        ${rc6_SOURCES}
        main.c)
