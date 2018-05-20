////1552212 端启航
//#include <iostream>
//#include "MMX/RsaSignature.h"
//#include "MMX/ElGamalSignature.h"
//#include "MMX/Cryptography.h"
//#include "MMX/CA.h"
//#include <fstream>
//#include "MMX/Base64.h"
//#include <sstream>
//#include "TCPClient.h"
//#include "Member.h"
//#include <string>
//u_int32_t ip;
//u_int16_t port;
//using namespace std;
//
////PROTOCOL
//#define PROTO_C2S 0x00
//#define PROTO_S2C 0x01
//#define PROTO_PUB_PARA 0x01
//#define PROTO_JOIN_GROUP 0x02
//#define PROTO_KEY_EX 0x03
//#define PROTO_KEY_BROADCAST 0x04
//#define HEADLEN 4
//TCPClient* server;
//group_sig::member* m;
//struct header_t
//{
//	uint8_t proto_ori;
//	uint8_t proto_type;
//	uint16_t len;
//};
//
//string id;//id，由命令行输入
//ZZ psk;
//void send_req(u_int8_t type,string msg="")
//{
//	header_t head;
//	head.proto_ori = PROTO_C2S;
//	head.proto_type = type;
//	if (msg == "")
//	{
//		head.len = 0;
//		server->SendPacket((char*)&head, HEADLEN);
//	}
//	else {
//		head.len = msg.size();
//		char *buffer = new char[HEADLEN + msg.size()];
//		memcpy(buffer, &head, HEADLEN);
//		memcpy(buffer + HEADLEN, msg.c_str(), msg.size());
//		server->SendPacket(buffer, HEADLEN + msg.size());
//	}
//}
//string get_str(char* src)
//{
//	return string(src + HEADLEN);
//}
//void onRecv(ClientData *data)
//{
//	header_t* header;
//	header = (header_t*)(data->recv_playload);
//
//	string msg;
//	switch (header->proto_type) {
//	case PROTO_PUB_PARA:{
//		group_sig::public_para* p=new group_sig::public_para;
//		memcpy(p, data->recv_playload + HEADLEN, header->len);
//		m = new group_sig::member(id, *p);
//
//		//send PROTO_JOIN_GROUP
//		send_req(PROTO_JOIN_GROUP,m->JoinGroupMsg(psk));
//		break;}
//	case PROTO_JOIN_GROUP:{
//		msg=get_str(data->recv_playload);
//		m->onRecvV(msg);
//		break;}
//	case PROTO_KEY_EX:{
//		msg = get_str(data->recv_playload);
//		m->onKeyExchangeRequestRecv(msg);
//		break;}
//	case PROTO_KEY_BROADCAST:{
//		msg = get_str(data->recv_playload);
//		m->onGroupKeyBoardcastRecv(msg);
//		break;}
//	default:
//		break;
//	}
//}
//
//void onConnected(ClientData */*data*/)
//{
//	send_req(PROTO_PUB_PARA, id);
//}
//
//int main()
//{
//    ip=inet_addr("192.168.1.2");
//    port=9999;
//	server=new TCPClient(ip,port);
//	server->setOnConnectedCallBack(onConnected);
//	server->setOnRecvCallBack(onRecv);
//	server->ConnectServer();
//	return 0;
//}
