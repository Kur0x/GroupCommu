//
// Created by kurox on 18-4-10.
//

#ifndef CLION_TCPSOCKET_H
#define CLION_TCPSOCKET_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <fcntl.h>
#include <sys/time.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <getopt.h>
#include <arpa/inet.h>
#include "common.h"

class TCPClient {
public:
	TCPClient(u_int32_t ip, uint16_t port);

	~TCPClient();

	void setOnRecvCallBack(void(*callBack)(ClientData *));

	void setOnConnectedCallBack(void(*callBack)(ClientData *));

	void setOnFinCallBack(void(*callBack)(ClientData *));

	void ConnectServer();

	void SendPacket(char *playload, size_t len);

private:
	u_int32_t ip;
	uint16_t portno;
	struct sockaddr_in serv_addr;

    //回调函数
	void(*onRecvCallBack)(ClientData *data);

	void(*onConnectedCallBack)(ClientData *data);

	void(*onFinCallBack)(ClientData *data);

	ClientData *cli_data = nullptr;

	int tcp_recv_server(int clifd, char *data, size_t len);

	int tcp_send_server(int serverfd, const char *data, size_t len);

	void tcp_block();


};


#endif //CLION_TCPSOCKET_H
