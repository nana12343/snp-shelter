#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/vm_sockets.h>
#include <sys/select.h>
#include <errno.h>
#include <sys/wait.h>
#include <openssl/evp.h>

#define VSOCK_PORT 1234
#define BUFFER_SIZE 4096
#define END_SIGNAL "exit_lx_yxk"

// AEAD加密参数
#define ENCRYPTION_KEY "0123456789abcdef0123456789abcdef"  // 32字节密钥(AES-256)
#define ENCRYPTION_NONCE "1234567890ab"  // 12字节Nonce(GCM模式)
#define ENCRYPTION_TAG_LEN 16  // GCM标签长度
#define ENCRYPTION_MARKER "[ENCRYPTED]:"
#define ENCRYPTION_MARKER_LEN 12  

// 日志宏
#define LOG_ERROR(fmt, ...) fprintf(stderr, "ERROR: " fmt "\n", ##__VA_ARGS__)
#define LOG_INFO(fmt, ...) printf("INFO: " fmt "\n", ##__VA_ARGS__)
#define LOG_DEBUG(fmt, ...) printf("DEBUG: " fmt "\n", ##__VA_ARGS__)

/*
 * 函数 get_argv() 用于解析命令行参数并分割成单独的参数
 * 参数:
 *   - char *u_argv: 原始命令行字符串
 *   - char *user_argv[]: 存储分割后的参数数组
 *   - char *filename: 存储第一个参数(文件名)
 *   - int* len: 返回参数个数
 * 返回值:
 *   - int: 成功返回0
 */
int get_argv(char *u_argv, char *user_argv[], char *filename, int* len) {
    char *tokens[20];
    int token_count = 0;

    char *token = strtok(u_argv, " ");
    while (token != NULL && token_count < 20) {
        tokens[token_count] = token;
        token_count++;
        token = strtok(NULL, " ");
    }

    if (token_count > 0) {
        strcpy(filename, tokens[0]);
    }

    for (int i = 0; i < token_count; i++) {
        user_argv[i] = tokens[i];
    }

    if (token_count > 1) {
        user_argv[token_count] = NULL;
    }
    *len = token_count;
    return 0;
}

/*
 * 函数 aead_encrypt() 用于使用AEAD模式加密数据
 * 参数:
 *   - const unsigned char *plaintext: 明文数据
 *   - int plaintext_len: 明文长度
 *   - unsigned char *ciphertext: 加密后的输出缓冲区
 *   - int *ciphertext_len: 返回加密后的数据长度
 * 返回值:
 *   - int: 成功返回0，失败返回-1
 */
int aead_encrypt(const unsigned char *plaintext, int plaintext_len,unsigned char *ciphertext, int *ciphertext_len) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int cipher_len;
    
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        return -1;
    }

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, (const unsigned char *)ENCRYPTION_KEY,(const unsigned char *)ENCRYPTION_NONCE)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    cipher_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    cipher_len += len;

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, ENCRYPTION_TAG_LEN, ciphertext + cipher_len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    cipher_len += ENCRYPTION_TAG_LEN;

    *ciphertext_len = cipher_len;
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

/*
 * 函数 connect_to_host() 用于连接到VSOCK主机
 * 参数:
 *   - int *vsock_fd: 返回创建的VSOCK套接字描述符
 * 返回值:
 *   - int: 成功返回0，失败返回-1
 */
int connect_to_host(int *vsock_fd) {
    struct sockaddr_vm vsock_addr;
    
    if ((*vsock_fd = socket(AF_VSOCK, SOCK_STREAM, 0)) < 0) {
        perror("VSOCK socket creation failed");
        LOG_ERROR("VSOCK socket creation failed");
        return -1;
    }

    memset(&vsock_addr, 0, sizeof(vsock_addr));
    vsock_addr.svm_family = AF_VSOCK;
    vsock_addr.svm_cid = 2;
    vsock_addr.svm_port = VSOCK_PORT;

    LOG_INFO("Connecting to host (CID: 2, Port: %d)...", VSOCK_PORT);
    
    if (connect(*vsock_fd, (struct sockaddr *)&vsock_addr, sizeof(vsock_addr)) < 0) {
        perror("VSOCK connect failed");
        LOG_ERROR("VSOCK connect failed");
        close(*vsock_fd);
        return -1;
    }

    return 0;
}

/*
 * 函数 is_prompt_message() 用于判断输出内容是否为提示信息
 * 参数:
 *   - const char *output: 待检测的输出字符串
 * 返回值:
 *   - int: 是提示信息返回1，否则返回0
 */
int is_prompt_message(const char *output) {
    // 检测常见的提示模式
    if (strstr(output, "请输入") || strstr(output, "输入")) {
        return 1;
    }
    return 0;
}

/*
 * 函数 main() 是程序主入口，负责建立VSOCK连接、解析命令行参数，创建管道与子进程通信，并通过select函数实现非阻塞的I/O操作
 * 参数:
 *   - 无
 * 返回值:
 *   - int: 程序退出状态(0表示成功)
 */
int main() {
    int vsock_fd, pipe_fd1[2], pipe_fd2[2];
    char buffer[BUFFER_SIZE];
    char filename[BUFFER_SIZE];
    char u_argv[BUFFER_SIZE];
    char *user_argv[20];
    ssize_t read_size;
    int collecting_result = 0;
    char result_buffer[BUFFER_SIZE] = {0};
    size_t result_len = 0;

    if (connect_to_host(&vsock_fd) < 0) {
        exit(EXIT_FAILURE);
    }

    LOG_INFO("Connected to host, waiting for command...");

    read_size = read(vsock_fd, u_argv, sizeof(u_argv));
    if (read_size <= 0) {
        perror("VSOCK read error");
        LOG_ERROR("VSOCK read error");
        close(vsock_fd);
        exit(EXIT_FAILURE);
    }
    u_argv[read_size] = '\0';

    LOG_INFO("Executing program: %s", u_argv);

    int len = 0;
    get_argv(u_argv, user_argv, filename, &len);

    if (pipe(pipe_fd1) == -1 || pipe(pipe_fd2) == -1) {
        perror("Pipe creation failed");
        close(vsock_fd);
        exit(EXIT_FAILURE);
    }

    pid_t pid = fork();
    if (pid == -1) {
        perror("Fork failed");
        close(vsock_fd);
        close(pipe_fd1[0]);
        close(pipe_fd1[1]);
        close(pipe_fd2[0]);
        close(pipe_fd2[1]);
        exit(EXIT_FAILURE);
    }

    if (pid == 0) { // 子进程
        close(pipe_fd1[1]);
        close(pipe_fd2[0]);

        dup2(pipe_fd1[0], STDIN_FILENO);
        close(pipe_fd1[0]);
  
        dup2(pipe_fd2[1], STDOUT_FILENO);
        close(pipe_fd2[1]);

        execv(filename, user_argv);
        perror("execv failed");
        exit(EXIT_FAILURE);
    } else { // 父进程
        close(pipe_fd1[0]);
        close(pipe_fd2[1]);

        fd_set readfds;
        int max_fd = vsock_fd > pipe_fd2[0] ? vsock_fd : pipe_fd2[0];
        char result_buffer[BUFFER_SIZE] = {0};
        size_t result_len = 0;

        while (1) {
            FD_ZERO(&readfds);
            FD_SET(vsock_fd, &readfds);
            FD_SET(pipe_fd2[0], &readfds);

            int activity = select(max_fd + 1, &readfds, NULL, NULL, NULL);
            if (activity < 0 && errno != EINTR) {
                perror("select error");
                break;
            }

            if (FD_ISSET(pipe_fd2[0], &readfds)) {
                read_size = read(pipe_fd2[0], buffer, sizeof(buffer));
                if (read_size <= 0) {
                    if (read_size < 0) perror("pipe read error");
                    
                    // 程序结束时处理加密结果
                    if (result_len > 0) {
                        unsigned char ciphertext[BUFFER_SIZE];
                        int ciphertext_len;
                        
                        if (aead_encrypt((unsigned char *)result_buffer, result_len,ciphertext, &ciphertext_len) == 0) {
                            // 发送完整的加密标记头和数据
                            write(vsock_fd, ENCRYPTION_MARKER, ENCRYPTION_MARKER_LEN);
                            write(vsock_fd, ciphertext, ciphertext_len);
                            LOG_INFO("Sent encrypted result (%d bytes)", ciphertext_len);
                        } else {
                            perror("Encryption failed");
                        }
                    }
                    break;
                }
                
                buffer[read_size] = '\0';
                
                if (is_prompt_message(buffer)) {
                    // 提示信息直接发送
                    write(vsock_fd, buffer, read_size);
                    LOG_DEBUG("Sent prompt: %.*s", (int)read_size, buffer);
                } else {
                    // 收集计算结果
                    if (result_len + read_size < sizeof(result_buffer)) {
                        memcpy(result_buffer + result_len, buffer, read_size);
                        result_len += read_size;
                        LOG_DEBUG("Collected result (%zu bytes)", result_len);
                    }
                }
            }

            if (FD_ISSET(vsock_fd, &readfds)) {
                read_size = read(vsock_fd, buffer, sizeof(buffer));
                if (read_size <= 0) {
                    if (read_size < 0) perror("VSOCK read error");
                    break;
                }
                buffer[read_size] = '\0';
                write(pipe_fd1[1], buffer, read_size);
            }
        }
        
        close(vsock_fd);
        close(pipe_fd1[1]);
        close(pipe_fd2[0]);

        wait(NULL);
    }

    return 0;
}
