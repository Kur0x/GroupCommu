#pragma once

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <fcntl.h>
#include <sys/time.h>
#include <cerrno>
#include <ctime>
#include <getopt.h>
#include <arpa/inet.h>
#include "common.h"

using std::string;

class TCPServer {
public:
    static constexpr int QUEUE = 20;
    static constexpr int CLIENT_MAX = 1000;
    static constexpr int BCAST_PORT = 9999;
    const char *BCAST_IP = "255.255.255.255";

    TCPServer(u_int32_t ip, uint16_t port);

    ~TCPServer();

    void StartServer();

    void SendPacket(string id, const char *playload, size_t len);

    void setOnRecvCallBack(void(*callBack)(ClientData *));

    void setOnAcceptCallBack(void(*callBack)(ClientData *));

    void Broadcast(const char *playload, size_t len);

private:
    u_int32_t ip;
    uint16_t portno;
    struct sockaddr_in serv_addr;
    int server_sockfd;
    ClientData client_fds[CLIENT_MAX];

    //ClientData* cli_data;

    //回调函数
    void (*onRecvCallBack)(ClientData *data);

    void (*onAcceptCallBack)(ClientData *data);


    int tcp_recv_server(int clifd, char *data, size_t len);

    int tcp_send_server(int serverfd, const char *data, size_t len);

};
