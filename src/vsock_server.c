#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <linux/vm_sockets.h>
#include <sys/socket.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <vsock_server.h>
#include <log.h>

typedef struct {
    int socket;
    int running;
} ThreadArgs;

/*
 * 函数 aead_decrypt() 用于使用AEAD模式解密数据
 * 参数:
 *   - const unsigned char *ciphertext: 密文数据
 *   - int ciphertext_len: 密文长度
 *   - unsigned char *plaintext: 解密后的明文输出缓冲区
 *   - int *plaintext_len: 返回解密后的明文长度
 * 返回值:
 *   - int: 成功返回0，失败返回-1
 */
int aead_decrypt(const unsigned char *ciphertext, int ciphertext_len,unsigned char *plaintext, int *plaintext_len) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plain_len;
    
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL)) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (1 != EVP_DecryptInit_ex(ctx, NULL, NULL, (const unsigned char *)ENCRYPTION_KEY,(const unsigned char *)ENCRYPTION_NONCE)) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    int data_len = ciphertext_len - ENCRYPTION_TAG_LEN;
    if (data_len <= 0) {
        fprintf(stderr, "Invalid ciphertext length\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, data_len)) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plain_len = len;

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, ENCRYPTION_TAG_LEN, (void *)(ciphertext + data_len))) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plain_len += len;

    *plaintext_len = plain_len;
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

/*
 * 函数 process_encrypted_data() 用于处理接收到的加密数据
 * 参数:
 *   - const char *buffer: 接收到的数据缓冲区
 *   - int length: 数据长度
 * 返回值:
 *   - void
 */
void process_encrypted_data(const char *buffer, int length) {
    if (strncmp(buffer, ENCRYPTION_MARKER, ENCRYPTION_MARKER_LEN) == 0) {
        // 计算密文长度并准备输出
        int cipher_len = length - ENCRYPTION_MARKER_LEN;
        const char *cipher_start = buffer + ENCRYPTION_MARKER_LEN;
        
        // 输出密文(十六进制格式)
        printf("Received encrypted data:\n");
        for (int i = 0; i < cipher_len; i++) {
            printf("%02x", (unsigned char)cipher_start[i]);
        }
        
        // 解密数据
        unsigned char plaintext[BUFFER_SIZE];
        int plaintext_len;
        
        if (aead_decrypt((const unsigned char *)cipher_start,cipher_len,plaintext, &plaintext_len) == 0) {
            plaintext[plaintext_len] = '\0';
            printf("\nDecrypted result:\n%s", plaintext);
        } else {
            printf("Decryption failed!\n");
        }
    } else {
        // 明文数据直接显示
        printf("%.*s", length, buffer);
    }
    fflush(stdout);
}

/*
 * 函数 receive_messages() 用于接收来自VSOCK客户端的消息
 * 参数:
 *   - void *args: 线程参数(ThreadArgs结构体指针)
 * 返回值:
 *   - void *: 总是返回NULL
 */
void *receive_messages(void *args) {
    ThreadArgs *targs = (ThreadArgs *)args;
    char buffer[BUFFER_SIZE];
    
    while (targs->running) {
        int valread = read(targs->socket, buffer, BUFFER_SIZE - 1);
        if (valread <= 0) {
            targs->running = 0;
            break;
        }

        buffer[valread] = '\0';
        if (strcmp(buffer, END_SIGNAL) == 0) {
            targs->running = 0;
            break;
        }

        process_encrypted_data(buffer, valread);
    }
    return NULL;
}

/*
 * 函数 send_messages() 用于向VSOCK客户端发送消息
 * 参数:
 *   - void *args: 线程参数(ThreadArgs结构体指针)
 * 返回值:
 *   - void *: 总是返回NULL
 */
void *send_messages(void *args) {
    ThreadArgs *targs = (ThreadArgs *)args;
    char message[BUFFER_SIZE];
    
    while (targs->running && fgets(message, sizeof(message), stdin)) {
        if (send(targs->socket, message, strlen(message), 0) < 0) {
            targs->running = 0;
            break;
        }
    }
    return NULL;
}

/*
 * 函数 init_vsock_server() 用于初始化VSOCK服务器
 * 参数:
 *   - int *server_fd: 返回创建的服务器套接字描述符
 * 返回值:
 *   - int: 成功返回0，失败返回-1
 */
int init_vsock_server(int *server_fd) {
    struct sockaddr_vm server_addr;
    
    if ((*server_fd = socket(AF_VSOCK, SOCK_STREAM, 0)) < 0) {
        perror("VSOCK socket creation failed");
        LOG_ERROR("VSOCK socket creation failed");
        return -1;
    }

    int opt = 1;
    if (setsockopt(*server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("Setsockopt failed");
        LOG_ERROR("Setsockopt failed");
        close(*server_fd);
        return -1;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.svm_family = AF_VSOCK;
    server_addr.svm_cid = VMADDR_CID_ANY;
    server_addr.svm_port = VSOCK_PORT;

    if (bind(*server_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("VSOCK bind failed");
        LOG_ERROR("VSOCK bind failed");
        close(*server_fd);
        return -1;
    }

    if (listen(*server_fd, MAX_CONNECTIONS) < 0) {
        perror("VSOCK listen failed");
        LOG_ERROR("VSOCK listen failed");
        close(*server_fd);
        return -1;
    }
    return 0;
}

/*
 * 函数 vsock_server() 是VSOCK服务器主函数
 * 参数:
 *   - const char *command: 要发送给客户端的初始命令
 * 返回值:
 *   - int: 成功返回0，失败返回-1
 */
int vsock_server(const char *command) {
    int server_fd, client_fd;
    struct sockaddr_vm client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    pthread_t receive_thread, send_thread;
    ThreadArgs args;

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    if (init_vsock_server(&server_fd) < 0) {
        EVP_cleanup();
        ERR_free_strings();
        return -1;
    }
    printf("Waiting for client to connect on VSOCK...\n");
    
    if ((client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_addr_len)) < 0) {
        perror("VSOCK accept failed");
        close(server_fd);
        EVP_cleanup();
        ERR_free_strings();
        return -1;
    }
    printf("Sending command: %s\n", command);

    if (send(client_fd, command, strlen(command), 0) < 0) {
        perror("Command send failed");
        close(client_fd);
        close(server_fd);
        EVP_cleanup();
        ERR_free_strings();
        return -1;
    }

    args.socket = client_fd;
    args.running = 1;

    pthread_create(&receive_thread, NULL, receive_messages, &args);
    pthread_create(&send_thread, NULL, send_messages, &args);

    pthread_join(receive_thread, NULL);
    pthread_join(send_thread, NULL);

    printf("Connection closed\n");
    close(client_fd);
    close(server_fd);
    
    EVP_cleanup();
    ERR_free_strings();

    return 0;
}
