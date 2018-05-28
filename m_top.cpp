//1552212 端启航
#include <iostream>
#include "MMX/RsaSignature.h"
#include <sstream>
#include "TCPClient.h"
#include "Member.h"
#include "NetworkUtility.h"
#include "TCPServer.h"
#include <csignal>

using namespace std;


TCPClient *client;
TCPServer *server_m;
group_sig::member *m;

string m_id;//id，由命令行输入
ZZ m_psk;//id，由命令行输入

char conf_type;

void send_req(u_int8_t type, const string &msg = "") {
    auto Log = get("console");
    Log->info("Client sending request of type {0:x}...", type);
    header_t head;
    head.proto_ori = PROTO_C2S;
    head.proto_type = type;
    if (msg == "") {
        head.len = 0;
        client->SendPacket((char *) &head, HEADLEN);
    } else {
        head.len = msg.size() + 1;
        char *buffer = new char[HEADLEN + msg.size() + 1];
        memcpy(buffer, &head, HEADLEN);
        memcpy(buffer + HEADLEN, msg.c_str(), msg.size() + 1);
        client->SendPacket(buffer, HEADLEN + msg.size() + 1);
    }
}

void send_m(string to, string msg) {
    auto Log = get("console");
    string from = m_id;
    Log->info("send message from {} to {}", from, to);
    string buffer;
    string encripted;
    encripted += msg;
    encripted += " ";
    encripted += m->sig(msg);
//    Log->debug("send_m/send buffer: {}", encripted);
    encrypt(encripted, m->groupKey);
    buffer += from + " ";
    buffer += to + " ";
    buffer += encripted + " ";
    send_req(PROTO_COMMU, buffer);
}

void handle_m(const string &buf) {
    auto Log = get("console");
    string from;
    string to;
    string msg;
    stringstream ss(buf);
    ss >> from >> to >> msg;
    Log->info("recv message from {} to {}", from, to);
    decrypt(msg, m->groupKey);
    Log->debug("onRecv_mm/msg(decrypted): {}", msg);
    stringstream sss(msg);
    string mmp, sig;
    sss >> mmp >> sig;
    if (!m->ver(mmp, sig)) {
        Log->error("msg verify error!");
    } else Log->info("msg verify passed!");
}


void onRecv_m(ClientData *data) {
    auto Log = get("console");
    header_t *header;
    stringstream ss;
    NetworkUtility::print_payload(ss, (const u_char *) data->recv_playload, data->recv_len);
    Log->debug("recv raw packet:\n{}", ss.str());



    NEXT:
    header = (header_t *) (data->recv_playload);
    if (header->len + HEADLEN > data->recv_len) {
        Log->debug("half packet deceted!");
        data->half = true;
        return;
    } else data->half = false;
    switch (header->proto_type) {
        case PROTO_PUB_PARA: {
            Log->info("Client recv public para msg");
//		group_sig::public_para* p=new group_sig::public_para;
            char *p = new char[header->len + 1];
            memcpy(p, data->recv_playload + HEADLEN, header->len);
            stringstream stream(p);
            group_sig::public_para *para = new group_sig::public_para;
            string temp;
            stream >> temp;
            para->a = Cryptography::stringToNumber(temp, false);
            stream >> temp;
            para->b = Cryptography::stringToNumber(temp, false);
            stream >> temp;
            para->epsilon = Cryptography::stringToNumber(temp, false);
            stream >> temp;
            para->G = Cryptography::stringToNumber(temp, false);
            stream >> temp;
            para->g = Cryptography::stringToNumber(temp, false);
            stream >> temp;
            para->n = Cryptography::stringToNumber(temp, false);
            long l;
            stream >> l;
            para->lambda = l;

            m = new group_sig::member(m_id, para, m_psk);

            //send PROTO_JOIN_GROUP
            send_req(PROTO_JOIN_GROUP, m->JoinGroupMsg(m_psk));
            break;
        }
        case PROTO_JOIN_GROUP: {
            Log->info("Client recv join group msg v");
            string msg = get_str((char *) header);
            m->onRecvV(msg);
            if (header->len + HEADLEN < data->recv_len) {
                Log->debug("dup packet detected");
                char *buffer = new char[8192];
                int packet1_len = header->len + HEADLEN;
                memcpy(buffer, (char *) header + packet1_len, data->recv_len - packet1_len);
                memcpy(data->recv_playload, buffer, data->recv_len - packet1_len);
                data->recv_len = data->recv_len - packet1_len;
                goto NEXT;
            }
            break;
        }
        case PROTO_KEY_EX: {
            Log->info("Client recv key exchg msg");
            string msg = get_str((char *) header);
            string ret = m->onKeyExchangeRequestRecv(msg);
            send_req(PROTO_KEY_EX, ret);
            if (header->len + HEADLEN < data->recv_len) {
                Log->debug("dup packet detected");
                char *buffer = new char[8192];
                int packet1_len = header->len + HEADLEN;
                memcpy(buffer, (char *) header + packet1_len, data->recv_len - packet1_len);
                memcpy(data->recv_playload, buffer, data->recv_len - packet1_len);
                data->recv_len = data->recv_len - packet1_len;
                goto NEXT;
            }
            break;
        }
        case PROTO_KEY_BROADCAST: {
            Log->info("Client recv broadcast msg");
            string msg = get_str((char *) header);
            m->onGroupKeyBoardcastRecv(msg);
            Log->info("initial state done!");
            break;
        }
        case PROTO_COMMU: {
            handle_m(get_str((char *) header));
            break;
        }
        default:
            Log->critical("unknown type: {0:x}", header->proto_type);
            break;
    }
    data->recv_len = 0;
}

void onConnected(ClientData */*data*/) {
    auto Log = get("console");
    Log->info("Client requesting public para msg...");
    send_req(PROTO_PUB_PARA, m_id);
}

void onFin(ClientData */*data*/) {
    auto Log = get("console");
    Log->info("Connection fin!");
    exit(0);
}

void sigroutine(int dunno) { /* 信号处理例程，其中dunno将会得到信号的值 */
    string to;
    string msg;
    cout << "\n请输入对方id：";
    cin >> to;
    cout << "请输入要发送的消息：";
    cin >> msg;
    send_m(to, msg);
}

int main_m(string ip, u_int16_t port, string id, const ZZ &psk) {
#ifndef __APPLE__
    struct sigaction act, oact;
    act.sa_handler = sigroutine;
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0 | SA_INTERRUPT;

    sigaction(SIGTSTP, &act, &oact);
#endif
    m_id = id;
    m_psk = psk;
    auto Log = get("console");
    Log->info("starting member connecting " + ip);
    client = new TCPClient(inet_addr(ip.c_str()), port);
    client->setOnConnectedCallBack(onConnected);
    client->setOnRecvCallBack(onRecv_m);
    client->setOnFinCallBack(onFin);
    client->ConnectServer();

    return 0;
}

