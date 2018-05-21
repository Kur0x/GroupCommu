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
	bzero((char *)&serv_addr, sizeof(serv_addr));
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
		return -1;
	}

	int ret = recv(clifd, data, len, 0);
	//    log->debug("read return:{}", ret);
	return ret;
}

void TCPClient::RecvBroadcast(char *playload, size_t len)
{
	int ret = -1;
	int sock;
	struct sockaddr_in server_addr; //服务器端地址
	struct sockaddr_in from_addr; //客户端地址
	int from_len = sizeof(struct sockaddr_in);
	int count = -1;
	fd_set readfd; //读文件描述符集合
	struct timeval timeout;
	timeout.tv_sec = 2;
	timeout.tv_usec = 0;

	sock = socket(AF_INET, SOCK_DGRAM, 0); //建立数据报套接字
	if (sock < 0)
	{
		perror("sock error");
		exit(0);
	}

	memset((void*)&server_addr, 0, sizeof(struct sockaddr_in));
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = htons(INADDR_ANY);
	server_addr.sin_port = htons(BCAST_PORT);

	//将地址结构绑定到套接字上
	ret = bind(sock, (struct sockaddr*) &server_addr, sizeof(server_addr));
	if (ret < 0)
	{
		perror("bind error");
		exit(0);
	}

	while (1)
	{
		timeout.tv_sec = 100;
		timeout.tv_usec = 0;

		//文件描述符集合清0
		FD_ZERO(&readfd);
		//将套接字描述符加入到文件描述符集合
		FD_SET(sock, &readfd);

		//select侦听是否有数据到来
		ret = select(sock + 1, &readfd, NULL, NULL, &timeout); //侦听是否可读
		switch (ret)
		{
		case -1: //发生错误
			perror("select error:");
			break;
		case 0: //超时
			printf("select timeout\n");
			break;
		default:
			if (FD_ISSET(sock, &readfd))
			{
				count = recvfrom(sock, playload, len, 0,(struct sockaddr*)&from_addr, &from_len); //接收客户端发送的数据
				if(count>0)
					printf("Client Recv Broadcast\n\tPort: %d\n",ntohs(from_addr.sin_port));
			}
			break;
		}
		break;
	}
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

