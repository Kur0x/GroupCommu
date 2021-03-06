//1552212 端启航
#include <iostream>
#include <NetworkUtility.h>
#include <map>
#include "MMX/RsaSignature.h"
#include "TCPServer.h"
#include "Member.h"
#include "GM.h"

using namespace std;


TCPServer *server;
group_sig::GM *gm;

string hardware_id;//id，由命令行输入
//vector<pair<string,string>> client_list;

void send_r(const string &id, u_int8_t type, string msg = "") {
//    INFO("GM sending type {0:x} to {1}", type, id);
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
        delete[] buffer;
    }
}

void send_r(const string &id, u_int8_t type, const char *payload, u_int16_t len) {
//    INFO("GM sending type {0:x} to {1}", type, id);
    header_t head{};
    head.proto_ori = PROTO_S2C;
    head.proto_type = type;

    head.len = len;
    char *buffer = new char[HEADLEN + len];
    memcpy(buffer, &head, HEADLEN);
    memcpy(buffer + HEADLEN, payload, len);
    server->SendPacket(id, buffer, HEADLEN + len);
    delete[] buffer;

}


void handle_commu(const char *buf) {
    char from[ID_LEN];
    char to[ID_LEN];
    memcpy(from, buf + HEADLEN, ID_LEN);
    memcpy(to, buf + HEADLEN + ID_LEN, ID_LEN);
    INFO("relaying message from {} to {}", from, to);
    send_r(to, PROTO_COMMU, buf + HEADLEN, ((header_t *) buf)->len);
}

void onRecv_gm(ClientData *data) {
    header_t *header;
    header = (header_t *) (data->recv_playload);
    stringstream ss;
    NetworkUtility::print_payload(ss, (const u_char *) data->recv_playload, data->recv_len);
    DEBUG("recv raw packet:\n{}", ss.str());

    if (header->len + HEADLEN > data->recv_len) {
        DEBUG("half packet detected!");
        data->half = true;
        return;
    } else data->half = false;

    string msg, y, z, m, sig, vv;
    ZZ v;
    switch (header->proto_type) {
        case PROTO_PUB_PARA: {
            string id = get_str(data->recv_playload);
            data->id = id;
            INFO("GM recv public para request from {}", id);

            // update client map
            struct sockaddr_in sa;
            socklen_t len = sizeof(sa);
            if (!getpeername(data->clientfd, (struct sockaddr *) &sa, &len)) {
                gm->client_map[data->id] = inet_ntoa(sa.sin_addr);
                WARN("{} {}", data->id, inet_ntoa(sa.sin_addr));
            }
            //get para
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
            str += to_string(p.lambda) + " ";

            head.len = str.size() + 1;
            char *buffer = new char[HEADLEN + head.len];
            memcpy(buffer, &head, HEADLEN);
            memcpy(buffer + HEADLEN, str.c_str(), head.len);

            INFO("GM sending public para to {}", id);
            server->SendPacket(data->id, buffer, HEADLEN + head.len);
            break;
        }
        case PROTO_JOIN_GROUP: {
            INFO("GM recv join group request from {}", data->id);
            msg = get_str(data->recv_playload);
            v = gm->verify(data->id, msg);
            vv = Cryptography::numberToString(v, false);
            INFO("GM sending join group response to {}", data->id);
            send_r(data->id, PROTO_JOIN_GROUP, vv);
            INFO("GM sending key exchange request to {}", data->id);
            send_r(data->id, PROTO_KEY_EX, gm->getKeyChain());
            break;
        }
        case PROTO_KEY_EX: {
            INFO("GM recv key exchg msg from {}", data->id);
            msg = get_str(data->recv_playload);
            gm->onKeyExchangeResponseRecv(msg);

            msg = gm->getBroadcastMsg();

            // make packet
            header_t head{};
            head.proto_ori = PROTO_S2C;
            head.proto_type = PROTO_KEY_BROADCAST;
            head.len = msg.size() + 1;
            int packet_len = HEADLEN + msg.size() + 1;
            char *buffer = new char[packet_len];
            memcpy(buffer, &head, HEADLEN);
            memcpy(buffer + HEADLEN, msg.c_str(), msg.size() + 1);
            INFO("GM broadcasting group key message...", data->id);
            server->Broadcast(buffer, packet_len);
            delete[] buffer;
            break;
        }
        case PROTO_COMMU: {
            handle_commu(data->recv_playload);
            break;
        }
        default:
            CRITICAL("unknown type: {0:x}", header->proto_type);
            break;
    }
    if (!data->half)
        data->recv_len = 0;
}

void onAccept_gm(ClientData *data) {
//    struct sockaddr_in sa;
//    socklen_t len = sizeof(sa);
//    if (!getpeername(data->clientfd, (struct sockaddr *) &sa, &len)) {
//        gm->client_map[data->id] = inet_ntoa(sa.sin_addr);
//        WARN("{} {}",data->id,inet_ntoa(sa.sin_addr));
//        client_list.emplace_back(data->id,inet_ntoa(sa.sin_addr));
//        printf( "对方IP：%s ", inet_ntoa(sa.sin_addr));
//        printf( "对方PORT：%d ", ntohs(sa.sin_port));
//}

}

int main_gm(string ip, u_int16_t port, const ZZ &psk, int lambda = 64) {
    INFO("starting GM");
    gm = new group_sig::GM(lambda, psk);
    server = new TCPServer(inet_addr(ip.c_str()), port);
    server->setOnRecvCallBack(onRecv_gm);
    server->setOnAcceptCallBack(onAccept_gm);
    server->StartServer();
    return 0;
}
