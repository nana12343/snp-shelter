#ifndef VSOCK_SERVER_H
#define VSOCK_SERVER_H

#define VSOCK_PORT 1234
#define BUFFER_SIZE 4096
#define END_SIGNAL "exit_lx_yxk"
#define MAX_CONNECTIONS 3

// AEAD加密参数
#define ENCRYPTION_KEY "0123456789abcdef0123456789abcdef"
#define ENCRYPTION_NONCE "1234567890ab"
#define ENCRYPTION_TAG_LEN 16
#define ENCRYPTION_MARKER "[ENCRYPTED]:"
#define ENCRYPTION_MARKER_LEN 12

// 日志宏
#define LOG_INFO(fmt, ...) printf("INFO: " fmt "\n", ##__VA_ARGS__)

// 导出函数声明
int vsock_server(const char *command);
void process_encrypted_data(const char *buffer, int length);
int aead_decrypt(const unsigned char *ciphertext, int ciphertext_len,unsigned char *plaintext, int *plaintext_len);

#endif // VSOCK_SERVER_H
