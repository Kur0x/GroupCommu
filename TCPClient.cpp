//
// Created by kurox on 18-4-10.
//

#include "TCPClient.h"


TCPClient::TCPClient(u_int32_t ip, uint16_t port) : portno(port), ip(ip) {
    auto Log = get("console");
    Log->info("starting TCP client");
    cli_data = new ClientData;
    cli_data->send_len = 0;
    cli_data->recv_len = 0;
    cli_data->recv_playload = new char[ClientData::BUFFER_LEN];
    cli_data->send_playload = new char[ClientData::BUFFER_LEN];
    onRecvCallBack = nullptr;
    onFinCallBack = nullptr;
    onConnectedCallBack = nullptr;
}


void TCPClient::ConnectServer() {
    auto Log = get("console");
    Log->info("Client connecting server...");
    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = ip;
//    if (inet_pton(AF_INET, ip, &serv_addr.sin_addr) <= 0)
//        error("ERROR inet_pton");
    serv_addr.sin_port = htons(portno);

    cli_data->serverfd = socket(AF_INET, SOCK_STREAM, 0);
    cli_data->start_time = time(NULL);
    if (cli_data->serverfd < 0) {
//        log->critical("ERROR opening socket");
        exit(-1);
    }
//    log->debug("start connection");
    connect(cli_data->serverfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr));
//    log->info("tcp block connected");
    if (onConnectedCallBack != nullptr) {
        onConnectedCallBack(cli_data);
        Log->info("Connected to Server");
    }
    tcp_block();
//    }
}

void TCPClient::tcp_block() {
    int n;
    while (true) {
        n = tcp_recv_server(cli_data->serverfd, cli_data->recv_playload, ClientData::BUFFER_LEN);
        cli_data->recv_len = n;
        if (n == 0) {
            if (onFinCallBack != nullptr)
                onFinCallBack(cli_data);
        }
        if (n < 0) {
//            log->critical("ERROR recv");
            auto Log = get("console");
            Log->error("Receiving msg from server error");
            exit(0);
        }
        auto Log = get("console");
        Log->info("Received msg from server");
        if (onRecvCallBack != nullptr) {
            onRecvCallBack(cli_data);
        }
        if (cli_data->stat == ClientData::TO_SEND) {
            Log->info("sending msg to server");
            n = tcp_send_server(cli_data->serverfd, cli_data->send_playload, cli_data->send_len);
            if (n < 0) {
//                log->critical("ERROR send");
                exit(0);
            }
            cli_data->send_len = 0;
        }
    }
}

int TCPClient::tcp_send_server(int serverfd, const char *data, size_t len) {
    int ret;
    if (len <= 0) {
//        log->debug("invalid send recv_len");
        return -1;
    }

    do {
        ret = send(serverfd, data, len, 0);
    } while (ret < 0 && errno == EINTR);
//    log->debug("send return:{}", ret);
    auto Log = get("console");
    Log->info("Client sending done");
    cli_data->stat = ClientData::TO_RECV;
    return ret;
}

int TCPClient::tcp_recv_server(int clifd, char *data, size_t len) {
    if (!data) {
//        log->debug("recv_playload is null");
        auto Log = get("console");
        Log->error("Null payload from server");
        return -1;
    }

    int ret = recv(clifd, data, len, 0);
//    log->debug("read return:{}", ret);
    return ret;
}

void TCPClient::setOnRecvCallBack(void(*callBack)(ClientData *)) {
    onRecvCallBack = callBack;
}

void TCPClient::setOnConnectedCallBack(void(*callBack)(ClientData *)) {
    onConnectedCallBack = callBack;
}

void TCPClient::setOnFinCallBack(void(*callBack)(ClientData *)) {
    onFinCallBack = callBack;
}

void TCPClient::SendPacket(char *playload, size_t len) {
    if (cli_data->send_len + len > ClientData::BUFFER_LEN) {
//        log->critical("send buffer will overflow!");
        return;
    }
    memcpy(cli_data->send_playload + cli_data->send_len, playload, len);
    cli_data->send_len += len;
    cli_data->stat = ClientData::TO_SEND;
}

TCPClient::~TCPClient() {
    delete cli_data->recv_playload;
    delete cli_data->send_playload;
    delete cli_data;
}

