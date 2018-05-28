//
// Created by kurox on 18-4-10.
//

#include "TCPClient.h"


TCPClient::TCPClient(u_int32_t ip, uint16_t port) : portno(port), ip(ip) {

    auto Log = get("console");
    Log->info("starting TCP client");
    cli_data = new ClientData;
    cli_data->stat = ClientData::TO_SEND;
    cli_data->send_len = 0;
    cli_data->recv_len = 0;
    cli_data->recv_playload = new char[ClientData::BUFFER_LEN];
    cli_data->send_playload = new char[ClientData::BUFFER_LEN];
    cli_data->fin = false;
    onRecvCallBack = nullptr;
    onFinCallBack = nullptr;
    onConnectedCallBack = nullptr;

}


void TCPClient::ConnectServer() {
    auto Log = get("console");
    Log->info("Client start connecting server...");
    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = ip;

    serv_addr.sin_port = htons(portno);

    cli_data->serverfd = socket(AF_INET, SOCK_STREAM, 0);
    cli_data->start_time = time(NULL);
    if (cli_data->serverfd < 0) {
        Log->critical("ERROR opening socket");
        exit(-1);
    }
    int n = connect(cli_data->serverfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr));
    if (n < 0) {
        Log->critical("Connect error!");
        exit(-1);
    }
    Log->info("Connected to Server");

    if (onConnectedCallBack != nullptr) {
        onConnectedCallBack(cli_data);
    } else cli_data->stat = ClientData::TO_RECV;
    tcp_block();
    //    }
}

void TCPClient::tcp_block() {
    auto Log = get("console");
    int n;
    while (true) {
        if (cli_data->stat == ClientData::TO_SEND) {
//            Log->info("sending msg to server");
            n = tcp_send_server(cli_data->serverfd, cli_data->send_playload, cli_data->send_len);
            if (n < 0) {
                get("console")->critical("ERROR send");
                exit(0);
            }
            cli_data->send_len = 0;
        }
        if (cli_data->fin)
            return;
        n = tcp_recv_server(cli_data->serverfd, cli_data->recv_playload + cli_data->recv_len,
                            ClientData::BUFFER_LEN - cli_data->recv_len);
        cli_data->recv_len += n;
        if (n == 0) {
            if (onFinCallBack != nullptr)
                onFinCallBack(cli_data);
        }
        if (n < 0) {
            Log->critical("Receiving msg from server error");
            exit(0);
        }

//        Log->info("Received msg from server");
        if (onRecvCallBack != nullptr) {
            onRecvCallBack(cli_data);
        }
        if (cli_data->fin)
            return;
    }
}

int TCPClient::tcp_send_server(int serverfd, const char *data, size_t len) {
    int ret;
    if (len <= 0) {
        get("console")->debug("invalid send recv_len");
        return -1;
    }

    do {
        ret = send(serverfd, data, len, 0);
    } while (ret < 0 && errno == EINTR);
    get("console")->debug("send return:{}", ret);
    get("console")->info("Client sending done");
    cli_data->stat = ClientData::TO_RECV;
    return ret;
}

int TCPClient::tcp_recv_server(int clifd, char *data, size_t len) {
    if (!data) {
        get("console")->debug("recv_playload is null");
        return -1;
    }

    int ret = recv(clifd, data, len, 0);
    get("console")->debug("read return:{}", ret);
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

