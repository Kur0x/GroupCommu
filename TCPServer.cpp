#include "TCPServer.h"


TCPServer::TCPServer(u_int32_t ip, uint16_t port) : ip(ip), portno(port) {
    auto Log = get("console");
    Log->info("Initializing TCP server");
    for (int i = 0; i < CLIENT_MAX; i++) {
        client_fds[i].stat = ClientData::TO_RECV;
        client_fds[i].send_len = 0;
        client_fds[i].recv_len = 0;
        client_fds[i].recv_playload = new char[ClientData::BUFFER_LEN];
        client_fds[i].send_playload = new char[ClientData::BUFFER_LEN];
    }

    onRecvCallBack = nullptr;
}


TCPServer::~TCPServer() {
}

void TCPServer::StartServer() {
    auto Log = get("console");
    Log->info("Starting server");
    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = ip;
    serv_addr.sin_port = htons(portno);


    //定义sockfd
    server_sockfd = socket(AF_INET, SOCK_STREAM, 0);

    int flags1;
    flags1 = fcntl(server_sockfd, F_GETFL);
    flags1 |= O_NONBLOCK;
    if (fcntl(server_sockfd, F_SETFL, flags1) == -1) {
        perror("fcntl");
        exit(1);
    }

    int nRecvBuf = 100 * 1024;         //设置为100K
    if (setsockopt(server_sockfd, SOL_SOCKET, SO_RCVBUF, (const char *) &nRecvBuf, sizeof(int)) < 0) {
        perror("call to setsockopt");
        close(server_sockfd);
        exit(1);
    }


    //设置地址可重用
    int reuse = 1;
    setsockopt(server_sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));


    //bind，成功返回0，出错返回-1
    if (bind(server_sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) == -1) {
        perror("bind");
        exit(1);
    }

    printf("监听%d端口\n", portno);
    //listen，成功返回0，出错返回-1
    if (listen(server_sockfd, QUEUE) == -1) {
        perror("listen");
        exit(1);
    }

    //printf("等待客户端连接\n");

    int now_fd = server_sockfd;
    struct sockaddr_in client_addr;
    socklen_t length = sizeof(client_addr);

    while (1) {
        int i;
        fd_set rfds;
        int retval1;
        //int conn;

        FD_ZERO(&rfds);
        FD_SET(server_sockfd, &rfds);

        for (i = 0; i < CLIENT_MAX; i++)
            if (client_fds[i].clientfd) {
                FD_SET(client_fds[i].clientfd, &rfds);
                if (now_fd < client_fds[i].clientfd)
                    now_fd = client_fds[i].clientfd;
            }
        retval1 = select(now_fd + 1, &rfds, NULL, NULL, NULL);

        if (retval1 > 0) {
            if (FD_ISSET(server_sockfd, &rfds)) {
                int conn = accept(server_sockfd, (struct sockaddr *) &client_addr, &length);
                if (conn < 0) {
                    perror("connect");
                    exit(1);
                } else {
                    for (i = 0; i < CLIENT_MAX; i++)
                        if (!client_fds[i].clientfd) {
                            client_fds[i].clientfd = conn;
                            printf("客户端%d连接成功\n", i + 1);
                            break;
                        }
                }
                int flags;
                flags = fcntl(conn, F_GETFL);
                flags |= O_NONBLOCK;
                if (fcntl(conn, F_SETFL, flags) == -1) {
                    perror("fcntl");
                    exit(1);
                }

            }
        }


        for (i = 0; i < CLIENT_MAX; i++)
            if (client_fds[i].clientfd > 0) {
                if (FD_ISSET(client_fds[i].clientfd, &rfds)) {
                    //TODO
                    if (client_fds[i].stat == ClientData::TO_RECV)//recv
                    {
                        if (tcp_recv_server(client_fds[i].clientfd, client_fds[i].recv_playload,
                                            ClientData::BUFFER_LEN) <= 0) {
                            perror("recv");
                            exit(1);
                        }
                        onRecvCallBack(&client_fds[i]);
                    }
                    if (client_fds[i].stat == ClientData::TO_SEND)//send
                    {
                        if (tcp_send_server(client_fds[i].clientfd, client_fds[i].send_playload,
                                            client_fds[i].send_len) <= 0) {
                            perror("send");
                            exit(1);
                        }

                    }

                }

            }
    }


}

int TCPServer::tcp_send_server(int clientfd, const char *data, size_t len) {
    int ret;
    if (len <= 0) {
        //log->debug("invalid send recv_len");
        return -1;
    }

    do {
        auto Log = get("console");
        Log->info("Server sending to client");
        ret = send(clientfd, data, len, 0);
    } while (ret < 0 && errno == EINTR);
    //log->debug("send return:{}", ret);
    auto Log = get("console");
    Log->info("Sending done");

    int i;
    for (i = 0; i < CLIENT_MAX; i++) {
        if (client_fds[i].clientfd == clientfd)
            break;
    }
    client_fds[i].stat = ClientData::TO_RECV;
    return ret;
}


//TODO 广播


int TCPServer::tcp_recv_server(int clifd, char *data, size_t len) {
    if (!data) {
        //log->debug("recv_playload is null");
        auto Log = get("console");
        Log->error("Null payload recved from client");
        return -1;
    }
    auto Log = get("console");
    Log->info("Received msg from client");
    int ret = recv(clifd, data, len, 0);
    //log->debug("read return:{}", ret);
    return ret;
}

void TCPServer::SendPacket(string id, char *playload, size_t len) {
    int i;
    for (i = 0; i < CLIENT_MAX; i++) {
        if (client_fds[i].id == id)
            break;
    }

    if (client_fds[i].send_len + len > ClientData::BUFFER_LEN) {
        //log->critical("send buffer will overflow!");
        return;
    }
    memcpy(client_fds[i].send_playload + client_fds[i].send_len, playload, len);
    client_fds[i].send_len += len;
    client_fds[i].stat = ClientData::TO_SEND;
}

void TCPServer::setOnRecvCallBack(void(*callBack)(ClientData *)) {
    onRecvCallBack = callBack;
}

