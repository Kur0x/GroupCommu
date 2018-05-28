#include "TCPServer.h"


TCPServer::TCPServer(u_int32_t ip, uint16_t port) : ip(ip), portno(port) {
    Log = get("console");
    Log->info("Initializing TCP server");
    bzero(client_fds, CLIENT_MAX * sizeof(ClientData));
    onRecvCallBack = nullptr;
    onAcceptCallBack = nullptr;
}


TCPServer::~TCPServer() {
}

void TCPServer::StartServer() {
    auto Log = get("console");
    Log->info("Starting server {}", portno);
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
    if (::bind(server_sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) == -1) {
        perror("bind");
        exit(1);
    }

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
        fd_set rfds, wfds;
        int retval1;
        struct timeval timeout = {0, 30};

        FD_ZERO(&rfds);
        FD_ZERO(&wfds);
        FD_SET(server_sockfd, &rfds);

        for (i = 0; i < CLIENT_MAX; i++)
            if (client_fds[i].clientfd) {
                FD_SET(client_fds[i].clientfd, &rfds);
                FD_SET(client_fds[i].clientfd, &wfds);
                if (now_fd < client_fds[i].clientfd)
                    now_fd = client_fds[i].clientfd;
            }
        retval1 = select(now_fd + 1, &rfds, &wfds, NULL, &timeout);
        if (retval1 < 0)
            continue;
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
                            client_fds[i].recv_playload = new char[ClientData::BUFFER_LEN];
                            client_fds[i].send_playload = new char[ClientData::BUFFER_LEN];
                            client_fds[i].stat = ClientData::TO_RECV;
                            Log->info("client connected: {}", i);
                            if (onAcceptCallBack != nullptr)
                                onAcceptCallBack(&client_fds[i]);
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
                if (FD_ISSET(client_fds[i].clientfd, &rfds))
                    if (client_fds[i].stat == ClientData::TO_RECV)//recv
                    {
                        if (!client_fds[i].half)
                            client_fds[i].recv_len = 0;
                        int ret = tcp_recv_server(client_fds[i].clientfd,
                                                  client_fds[i].recv_playload + client_fds[i].recv_len,
                                                  ClientData::BUFFER_LEN - client_fds[i].recv_len);
                        if (ret == 0) {
                            Log->info("A client disconnected!");
                            delete client_fds[i].send_playload;
                            delete client_fds[i].recv_playload;
                            bzero(&client_fds[i], sizeof(client_fds[i]));
                            continue;
                        } else if (ret < 0) {
                            perror("recv");
                            exit(1);
                        }
                        client_fds[i].recv_len += ret;
                        onRecvCallBack(&client_fds[i]);
                    }


                if (FD_ISSET(client_fds[i].clientfd, &wfds))
                    if (client_fds[i].stat == ClientData::TO_SEND)//send
                    {
                        int ret = tcp_send_server(client_fds[i].clientfd, client_fds[i].send_playload,
                                                  client_fds[i].send_len);
                        client_fds[i].send_len = 0;
                        if (ret < 0) {
                            perror("send");
                            exit(1);
                        } else if (ret == 0) {
                            Log->info("A client disconnected!");
                            bzero(&client_fds[i], sizeof(client_fds[i]));
                        }

                    }
            }
    }


}

int TCPServer::tcp_send_server(int clientfd, const char *data, size_t len) {
    int ret;
    if (len <= 0) {
        Log->debug("invalid send recv_len");
        return -1;
    }

    do {
        ret = send(clientfd, data, len, 0);
    } while (ret < 0 && errno == EINTR);
    Log->debug("send return:{}", ret);

    int i;
    for (i = 0; i < CLIENT_MAX; i++) {
        if (client_fds[i].clientfd == clientfd)
            break;
    }
    client_fds[i].stat = ClientData::TO_RECV;
    return ret;
}

void TCPServer::Broadcast(const char *playload, size_t len) {
    Log->info("Broadcast");

    for (int i = 0; i < CLIENT_MAX; i++) {
        if (client_fds[i].clientfd <= 0)
            continue;
        SendPacket(client_fds[i].id, playload, len);
    }
}


int TCPServer::tcp_recv_server(int clifd, char *data, size_t len) {
    if (!data) {
        Log->error("Null payload recved from client");
        return -1;
    }
    int ret = recv(clifd, data, len, 0);
    Log->debug("read return:{}", ret);
    return ret;
}

void TCPServer::SendPacket(string id, const char *playload, size_t len) {
    int i;
    for (i = 0; i < CLIENT_MAX; i++) {
        if (client_fds[i].id == id)
            break;
    }
    Log->debug("send packet to {}", id);
    if (client_fds[i].send_len + len > ClientData::BUFFER_LEN) {
        Log->critical("send buffer will overflow!");
        return;
    }
    memcpy(client_fds[i].send_playload + client_fds[i].send_len, playload, len);
    client_fds[i].send_len += len;
    client_fds[i].stat = ClientData::TO_SEND;

}

void TCPServer::setOnRecvCallBack(void(*callBack)(ClientData *)) {
    onRecvCallBack = callBack;
}

void TCPServer::setOnAcceptCallBack(void (*callBack)(ClientData *)) {
    onAcceptCallBack = callBack;

}

