
/* trivium.h */
/*
    This file is part of the AVR-Crypto-Lib.
    Copyright (C) 2008  Daniel Otte (daniel.otte@rub.de)

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
#ifndef TRIVIUM_H_
#define TRIVIUM_H_
#include <stdint.h>


/**
 * @brief Trivium流加密接口
 * @param plaintext     明文数据
 * @param plaintext_len 明文长度（字节）
 * @param key           输入密钥（10字节固定长度）
 * @param key_len       密钥长度（必须为10）
 * @param iv            输入初始向量（10字节固定长度）
 * @param iv_len        初始向量长度（必须为10）
 * @param ciphertext    密文输出缓冲区
 * @param ciphertext_len 输出缓冲区长度（必须 >= plaintext_len）
 */
void trivium_encrypt(
    const uint8_t *plaintext,
    size_t plaintext_len,
    const uint8_t key[10],
    size_t key_len,
    const uint8_t iv[10],
    size_t iv_len,
    uint8_t *ciphertext,
    size_t ciphertext_len);

/**
 * @brief Trivium流解密接口
 * @param ciphertext    密文数据
 * @param ciphertext_len 密文长度（字节）
 * @param key           输入密钥（10字节固定长度）
 * @param key_len       密钥长度（必须为10）
 * @param iv            输入初始向量（10字节固定长度）
 * @param iv_len        初始向量长度（必须为10）
 * @param plaintext     明文输出缓冲区
 * @param plaintext_len 输出缓冲区长度（必须 >= ciphertext_len）
 */
void trivium_decrypt(
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    const uint8_t key[10],
    size_t key_len,
    const uint8_t iv[10],
    size_t iv_len,
    uint8_t *plaintext,
    size_t plaintext_len);

#endif /*TRIVIUM_H_*/
