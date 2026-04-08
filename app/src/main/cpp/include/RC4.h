

#pragma once  // ：同一个 .c 文件内的重复包含

// 👇 加上这一段关键代码
#ifdef __cplusplus
extern "C" {
#endif

// RC4 加密函数（原封不动）
void rc4_encrypt(char *data, unsigned int data_length, const char *key, unsigned key_length);

// 👇 结束标记
#ifdef __cplusplus
}
#endif