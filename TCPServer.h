#pragma once
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


using namespace std;

class ClientData
{
	// TODO recv_playload struct
public:
	int serverfd;
	static constexpr int BUFFER_LEN = 65536;
	static constexpr int TO_SEND = 0;
	static constexpr int TO_RECV = 1;
	time_t start_time;
	int clientfd;
	string id;//上层标识
	int stat;
	size_t recv_len;
	size_t send_len;
	char * recv_playload;
	char * send_playload;
};



class TCPServer
{
public:
	static constexpr int QUEUE = 20;
	static constexpr int CLIENT_MAX = 1000;
	TCPServer(u_int32_t ip, uint16_t port);
	~TCPServer();
	void StartServer();
	void SendPacket(string id,char *playload, size_t len);
	void setOnRecvCallBack(void(*callBack)(ClientData *));

private:
	u_int32_t ip;
	uint16_t portno;
	struct sockaddr_in serv_addr;
	int server_sockfd;
	ClientData client_fds[CLIENT_MAX];

	//ClientData* cli_data;

	//回调函数
	void(*onRecvCallBack)(ClientData* data);


	int tcp_recv_server(int clifd, char *data, size_t len);
	int tcp_send_server(int serverfd, const char *data, size_t len);

};


