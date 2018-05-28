//1552212 端启航
#include <iostream>
#include <NetworkUtility.h>
#include "MMX/RsaSignature.h"
#include "TCPServer.h"
#include "Member.h"
#include "GM.h"

using namespace std;


TCPServer *server;
group_sig::GM *gm;

string hardware_id;//id，由命令行输入

void send_r(const string &id, u_int8_t type, string msg = "") {
    auto Log = get("console");
    Log->info("GM sending type {0:x} to {1}", type, id);
    header_t head{};
    head.proto_ori = PROTO_S2C;
    head.proto_type = type;
    if (msg == "") {
        head.len = 0;
        server->SendPacket(id, (char *) &head, HEADLEN);
    } else {
        head.len = msg.size() + 1;
        char *buffer = new char[HEADLEN + msg.size() + 1];
        memcpy(buffer, &head, HEADLEN);
        memcpy(buffer + HEADLEN, msg.c_str(), msg.size() + 1);
        server->SendPacket(id, buffer, HEADLEN + msg.size() + 1);
    }
}


void handle_commu(const string &buf) {
    auto Log = get("console");
    string from;
    string to;
    string msg;
    stringstream ss(buf);
    ss >> from >> to >> msg;
    Log->info("message from {} to {}", from, to);
    send_r(to, PROTO_COMMU, buf);
}

void onRecv_gm(ClientData *data) {
    auto Log = get("console");
    header_t *header;
    header = (header_t *) (data->recv_playload);
    stringstream ss;
    NetworkUtility::print_payload(ss, (const u_char *) data->recv_playload, data->recv_len);
    Log->debug("recv raw packet:\n{}", ss.str());

    if (header->len + HEADLEN > data->recv_len) {
        Log->debug("half packet detected!");
        data->half = true;
        return;
    } else data->half = false;

    string msg, y, z, m, sig, vv;
    ZZ v;
    switch (header->proto_type) {
        case PROTO_PUB_PARA: {
            Log->info("GM recv public para request form {}", data->id);
            string id = get_str(data->recv_playload);
            data->id = id;
            group_sig::public_para p = gm->getPublicPara();
            header_t head;
            head.proto_ori = PROTO_S2C;
            head.proto_type = PROTO_PUB_PARA;
            string str;

            str += Cryptography::numberToString(p.a, false) + " ";
            str += Cryptography::numberToString(p.b, false) + " ";
            str += Cryptography::numberToString(p.epsilon, false) + " ";
            str += Cryptography::numberToString(p.G, false) + " ";
            str += Cryptography::numberToString(p.g, false) + " ";
            str += Cryptography::numberToString(p.n, false) + " ";
            str += to_string(p.lambda);
            head.len = str.size() + 1;

            char *buffer = new char[HEADLEN + head.len];
            memcpy(buffer, &head, HEADLEN);
            memcpy(buffer + HEADLEN, str.c_str(), head.len);
            server->SendPacket(data->id, buffer, HEADLEN + head.len);
            break;
        }
        case PROTO_JOIN_GROUP: {
            Log->info("GM recv join group request form {}", data->id);
            msg = get_str(data->recv_playload);
            v = gm->verify(data->id, msg);
            vv = Cryptography::numberToString(v, false);
            send_r(data->id, PROTO_JOIN_GROUP, vv);
            send_r(data->id, PROTO_KEY_EX, gm->getKeyChain());
            break;
        }
        case PROTO_KEY_EX: {
            Log->info("GM recv key exchg msg form {}", data->id);
            msg = get_str(data->recv_playload);
            gm->onKeyExchangeResponseRecv(msg);
            msg = gm->getBroadcastMsg();
            header_t head{};
            head.proto_ori = PROTO_S2C;
            head.proto_type = PROTO_KEY_BROADCAST;
            head.len = msg.size() + 1;
            int packet_len = HEADLEN + msg.size() + 1;
            char *buffer = new char[packet_len];
            memcpy(buffer, &head, HEADLEN);
            memcpy(buffer + HEADLEN, msg.c_str(), msg.size() + 1);
            server->Broadcast(buffer, packet_len);
            delete[] buffer;
            break;
        }
        case PROTO_COMMU: {
            msg = get_str(data->recv_playload);
            handle_commu(msg);
            break;
        }
        default:
            Log->critical("unknown type: {0:x}", header->proto_type);
            break;
    }
}

int main_gm(string ip, u_int16_t port, ZZ psk) {
    auto Log = get("console");
    Log->info("starting GM");
    gm = new group_sig::GM(128, psk);
    server = new TCPServer(inet_addr(ip.c_str()), port);
    server->setOnRecvCallBack(onRecv_gm);
    server->StartServer();
    return 0;
}
