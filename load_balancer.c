#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <errno.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <microhttpd.h>

#define MAX_EVENTS 1024
#define BUFFER_SIZE 4096

struct backend_server {
    char ip[16];
    int port;
    int weight;
};

struct config {
    int listen_port;
    int max_connections;
    int web_port;
    char web_username[256];
    char web_password[256];
    struct backend_server backend_servers[10];
    int backend_server_num;
    char cert_file[256];
    char key_file[256];
};

struct config config;

int read_config(const char *filename) {
    FILE *fp = fopen(filename, "r");
    if (fp == NULL) {
        perror("fopen");
        return -1;
    }

    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "listen_port")) {
            sscanf(line, "listen_port = %d", &config.listen_port);
        } else if (strstr(line, "max_connections")) {
            sscanf(line, "max_connections = %d", &config.max_connections);
        } else if (strstr(line, "web_port")) {
            sscanf(line, "web_port = %d", &config.web_port);
        } else if (strstr(line, "web_username")) {
            sscanf(line, "web_username = %s", config.web_username);
        } else if (strstr(line, "web_password")) {
            sscanf(line, "web_password = %s", config.web_password);
        } else if (strstr(line, "server")) {
            char ip[16];
            int port, weight;
            sscanf(line, "server%*d = %15[^:]:%d:%d", ip, &port, &weight);
            strcpy(config.backend_servers[config.backend_server_num].ip, ip);
            config.backend_servers[config.backend_server_num].port = port;
            config.backend_servers[config.backend_server_num].weight = weight;
            config.backend_server_num++;
        } else if (strstr(line, "cert_file")) {
            sscanf(line, "cert_file = %s", config.cert_file);
        } else if (strstr(line, "key_file")) {
            sscanf(line, "key_file = %s", config.key_file);
        }
    }

    fclose(fp);
    return 0;
}

int backend_server_index = 0;

int create_socket(int port) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return -1;
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    if (bind(sockfd, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
        perror("bind");
        return -1;
    }

    if (listen(sockfd, 10) < 0) {
        perror("listen");
        return -1;
    }

    return sockfd;
}

int connect_backend_server() {
    struct backend_server *backend = &config.backend_servers[backend_server_index];
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return -1;
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(backend->ip);
    server_addr.sin_port = htons(backend->port);

    if (connect(sockfd, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
        perror("connect");
        return -1;
    }

    backend_server_index = (backend_server_index + 1) % config.backend_server_num;

    return sockfd;
}

SSL_CTX *init_openssl_context() {
    SSL_library_init();
    SSL_load_error_strings();
    SSL_CTX *ctx = SSL_CTX_new(SSLv23_server_method());
    if (ctx == NULL) {
        perror("SSL_CTX_new");
        return NULL;
    }

    if (SSL_CTX_use_certificate_file(ctx, config.cert_file, SSL_FILETYPE_PEM) <= 0) {
        perror("SSL_CTX_use_certificate_file");
        SSL_CTX_free(ctx);
        return NULL;
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, config.key_file, SSL_FILETYPE_PEM) <= 0) {
        perror("SSL_CTX_use_PrivateKey_file");
        SSL_CTX_free(ctx);
        return NULL;
    }

    return ctx;
}

int send_response(struct MHD_Connection *connection, int status_code, const char *response_body) {
    struct MHD_Response *response = MHD_create_response_from_buffer(strlen(response_body), (void *) response_body, MHD_RESPMEM_PERSISTENT);
    MHD_queue_response(connection, status_code, response);
    MHD_destroy_response(response);
    return MHD_YES;
}

int check_authentication(struct MHD_Connection *connection) {
    // 这里需要实现基本的 HTTP Basic Authentication
    // 为了简单起见，这里只检查用户名和密码是否匹配
    const char *username = MHD_get_connection_values(connection, MHD_GET_USERNAME, NULL);
    const char *password = MHD_get_connection_values(connection, MHD_GET_PASSWORD, NULL);

    if (username != NULL && password != NULL && strcmp(username, config.web_username) == 0 && strcmp(password, config.web_password) == 0) {
        return 1; // 认证成功
    } else {
        return 0; // 认证失败
    }
}

int handle_config_request(struct MHD_Connection *connection, const char *url, const char *method, const char *upload_data, size_t *upload_data_size) {
    if (!check_authentication(connection)) {
        // 返回 401 Unauthorized
        return MHD_queue_response(connection, MHD_HTTP_UNAUTHORIZED, MHD_create_response_from_buffer(0, NULL, MHD_RESPMEM_PERSISTENT));
    }

    if (strcmp(method, "GET") == 0) {
        // 返回配置信息
        char response_body[4096];
        snprintf(response_body, sizeof(response_body), "{\"listen_port\": %d
          , \"max_connections\": %d, \"web_port\": %d}", config.listen_port, config.max_connections, config.web_port);
        return send_response(connection, MHD_HTTP_OK, response_body);
    } else if (strcmp(method, "POST") == 0) {
        // 更新配置信息
        // 这里需要解析 upload_data，并更新 config 变量
        // 为了简单起见，这里只更新 listen_port
        int new_listen_port;
        sscanf(upload_data, "listen_port=%d", &new_listen_port);
        config.listen_port = new_listen_port;
        // 重新加载配置
        // ...
        return send_response(connection, MHD_HTTP_OK, "Config updated");
    }
    return send_response(connection, MHD_HTTP_NOT_FOUND, "Not found");
}

int answer_to_connection(void *cls, struct MHD_Connection *connection, const char *url, const char *method, const char *version, const char *upload_data, size_t *upload_data_size, void **con_cls) {
    if (strcmp(url, "/config") == 0) {
        return handle_config_request(connection, url, method, upload_data, upload_data_size);
    }
    return send_response(connection, MHD_HTTP_NOT_FOUND, "Not found");
}

int main() {
    if (read_config("load_balancer.conf") < 0) {
        return 1;
    }

    SSL_CTX *ssl_ctx = init_openssl_context();
    if (ssl_ctx == NULL) {
        return 1;
    }

    int server_sockfd = create_socket(config.listen_port);
    if (server_sockfd < 0) {
        return 1;
    }

    int epoll_fd = epoll_create1(0);
    if (epoll_fd < 0) {
        perror("epoll_create1");
        return 1;
    }

    struct epoll_event event;
    event.events = EPOLLIN;
    event.data.fd = server_sockfd;

    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server_sockfd, &event) < 0) {
        perror("epoll_ctl");
        return 1;
    }

    struct epoll_event events[MAX_EVENTS];
    char buffer[BUFFER_SIZE];
    int client_count = 0;

    // 创建 Web 服务器
    struct MHD_Daemon *web_daemon = MHD_start_daemon(MHD_USE_SELECT_INTERNALLY, config.web_port, NULL, NULL, &answer_to_connection, NULL, MHD_OPTION_END);
    if (web_daemon == NULL) {
        fprintf(stderr, "Failed to start web server\n");
        return 1;
    }

    while (1) {
        int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
        if (nfds < 0) {
            perror("epoll_wait");
            break;
        }

        for (int i = 0; i < nfds; i++) {
            if (events[i].data.fd == server_sockfd) {
                if (client_count >= config.max_connections) {
                    continue;
                }
                int client_sockfd = accept(server_sockfd, NULL, NULL);
                if (client_sockfd < 0) {
                    perror("accept");
                    continue;
                }
                SSL *ssl = SSL_new(ssl_ctx);
                SSL_set_fd(ssl, client_sockfd);
                if (SSL_accept(ssl) <= 0) {
                    ERR_print_errors_fp(stderr);
                    close(client_sockfd);
                    SSL_free(ssl);
                    continue;
                }
                int backend_sockfd = connect_backend_server();
                if (backend_sockfd < 0) {
                    close(client_sockfd);
                    SSL_free(ssl);
                    continue;
                }

                event.events = EPOLLIN | EPOLLOUT;
                event.data.ptr = ssl;
                if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_sockfd, &event) < 0) {
                    perror("epoll_ctl");
                    close(client_sockfd);
                    close(backend_sockfd);
                    SSL_free(ssl);
                    continue;
                }

                event.data.fd = backend_sockfd;
                if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, backend_sockfd, &event) < 0) {
                    perror("epoll_ctl");
                    close(client_sockfd);
                    close(backend_sockfd);
                    SSL_free(ssl);
                    continue;
                }

                client_count++;
            } else if (events[i].events & EPOLLIN) {
                SSL *ssl = (SSL *) events[i].data.ptr;
                int client_sockfd = SSL_get_fd(ssl);
                int other_sockfd = -1;

                for (int j = 0; j < nfds; j++) {
                    if (events[j].data.fd != server_sockfd && events[j].data.fd != client_sockfd) {
                        other_sockfd = events[j].data.fd;
                        break;
                    }
                }

                if (other_sockfd < 0) {
                    continue;
                }

                int len = SSL_read(ssl, buffer, BUFFER_SIZE);
                if (len > 0) {
                    send(other_sockfd, buffer, len, 0);
                } else {
                    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, client_sockfd, NULL);
                    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, other_sockfd, NULL);
                    close(client_sockfd);
                    close(other_sockfd);
                    SSL_free(ssl);
                    client_count--;
                }
            } else if (events[i].events & EPOLLOUT) {
                // 处理后端服务器的响应
                // 这里需要根据实际情况实现
            }
        }
    }

    close(server_sockfd);
    close(epoll_fd);
    SSL_CTX_free(ssl_ctx);
    MHD_stop_daemon(web_daemon);

    return 0;
}
