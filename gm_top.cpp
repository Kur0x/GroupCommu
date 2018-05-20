//1552212 端启航
#include <iostream>
#include "MMX/RsaSignature.h"
#include "MMX/ElGamalSignature.h"
#include "MMX/Cryptography.h"
#include "MMX/CA.h"
#include <fstream>
#include "MMX/Base64.h"
#include <sstream>
#include "TCPServer.h"
#include "Member.h"
#include <string>
#include "TCPClient.h"
#include "GM.h"

u_int32_t ip;
u_int16_t port;
using namespace std;

//PROTOCOL
#define PROTO_C2S 0x00
#define PROTO_S2C 0x01
#define PROTO_PUB_PARA 0x01
#define PROTO_JOIN_GROUP 0x02
#define PROTO_KEY_EX 0x03
#define PROTO_KEY_BROADCAST 0x04
#define HEADLEN 4
TCPServer *server;
group_sig::GM *gm;
struct header_t {
    uint8_t proto_ori;
    uint8_t proto_type;
    uint16_t len;
};

string hardware_id;//id，由命令行输入

void send_r(string id, u_int8_t type, string msg = "") {
    header_t head;
    head.proto_ori = PROTO_S2C;
    head.proto_type = type;
    if (msg == "") {
        head.len = 0;
        server->SendPacket(id, (char *) &head, HEADLEN);
    } else {
        head.len = msg.size();
        char *buffer = new char[HEADLEN + msg.size()];
        memcpy(buffer, &head, HEADLEN);
        memcpy(buffer + HEADLEN, msg.c_str(), msg.size());
        server->SendPacket(id, buffer, HEADLEN + msg.size());
    }
}

string get_str(char *src) {
    return string(src + HEADLEN);
}

void onRecv(ClientData *data) {
    header_t *header;
    header = (header_t *) (data->recv_playload);

    string msg, y, z, m, sig, vv;
    ZZ v;
    switch (header->proto_type) {
        case PROTO_PUB_PARA: {
            string id = get_str(data->recv_playload);
            data->id = id;
            group_sig::public_para p = gm->getPublicPara();
            header_t head;
            head.proto_ori = PROTO_S2C;
            head.proto_type = PROTO_PUB_PARA;
            head.len = sizeof(group_sig::public_para);
            char *buffer = new char[HEADLEN + head.len];
            memcpy(buffer, &head, HEADLEN);
            memcpy(buffer + HEADLEN, &p, head.len);
            server->SendPacket(data->id, buffer, HEADLEN + head.len);
            break;
        }
        case PROTO_JOIN_GROUP: {
            msg = get_str(data->recv_playload);
            v = gm->verify(data->id, msg);
            vv = Cryptography::numberToString(v, false);
            send_r(data->id, PROTO_JOIN_GROUP, vv);
            gm->keyExchangeRequest(data->id);
            break;
        }
        case PROTO_KEY_EX: {
            msg = get_str(data->recv_playload);
            gm->onKeyExchangeResponseRecv(msg);
            msg = gm->getBroadcastMsg();
            // TODO
//            server->broadcast(msg, msg.size());
            break;
        }
        default:
            break;
    }
}

int main() {
    ip=inet_addr("192.168.1.2");
    port=9999;
    gm = new group_sig::GM(1234);
    server = new TCPServer(ip, port);
    server->setOnRecvCallBack(onRecv);
    server->StartServer();
    return 0;
}
