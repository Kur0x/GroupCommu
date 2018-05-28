//1552212 端启航
#include <iostream>
#include "MMX/RsaSignature.h"
#include <sstream>
#include "TCPClient.h"
#include "Member.h"
#include "NetworkUtility.h"
#include "TCPServer.h"

using namespace std;


TCPClient *client;
TCPServer *server_m;
group_sig::member *m;

string m_id;//id，由命令行输入
ZZ m_psk;//id，由命令行输入

char conf_type;

void send_req(u_int8_t type, string msg = "") {
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

void onRecv_m(ClientData *data) {
    auto Log = get("console");
    header_t *header;
    stringstream ss;
    NetworkUtility::print_payload(ss, (const u_char *) data->recv_playload, data->recv_len);
    Log->debug("recv raw packet:\n{}", ss.str());
    string msg;



    int off = 0;
    NEXT:
    header = (header_t *) (data->recv_playload + off);
    Log->debug("len+HEADLEN: {}", header->len+HEADLEN);
    if (header->len + HEADLEN > data->recv_len) {
        Log->debug("half packet deceted!");
        return;
    }
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
            msg = get_str((char*)header);
            m->onRecvV(msg);
            if (header->len + HEADLEN < data->recv_len) {
                Log->debug("dup packet detected");
                off += header->len + HEADLEN;
                goto NEXT;
            }
            break;
        }
        case PROTO_KEY_EX: {
            Log->info("Client recv key exchg msg");
            msg = get_str((char*)header);
            string ret = m->onKeyExchangeRequestRecv(msg);
            send_req(PROTO_KEY_EX, ret);
            if (header->len + HEADLEN < data->recv_len) {
                Log->debug("dup packet detected");
                off += header->len + HEADLEN;
                goto NEXT;
            }
            break;
        }
        case PROTO_KEY_BROADCAST: {
            Log->info("Client recv broadcast msg");
            msg = get_str((char*)header);
            m->onGroupKeyBoardcastRecv(msg);
            Log->info("initial state done!");
            data->fin = true;
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

void commu(string ip, u_int16_t port);

int main_m(string ip, u_int16_t port, string id, ZZ psk) {
    m_id = id;
    m_psk = psk;
    auto Log = get("console");
    Log->info("starting member at " + ip);
    client = new TCPClient(inet_addr(ip.c_str()), port);
    client->setOnConnectedCallBack(onConnected);
    client->setOnRecvCallBack(onRecv_m);
    client->setOnFinCallBack(onFin);
    client->ConnectServer();

    commu("192.2.2.2", 4434);
    return 0;
}

void onRecv_mm(ClientData *data);

void onAccept_mm(ClientData *data);

void commu(string ip, u_int16_t port) {
    cout << "请输入类型：";
    cin >> conf_type;

    if (conf_type == 's') {
        server_m = new TCPServer(inet_addr("0.0.0.0"), port);
        server_m->setOnRecvCallBack(onRecv_mm);
        server_m->setOnAcceptCallBack(onAccept_mm);
        server_m->StartServer();
    } else {
        cout << "请输入对方ip：";
        string commu_ip;
        cin >> commu_ip;
        delete client;
        client = new TCPClient(inet_addr(commu_ip.c_str()), port);
        client->setOnConnectedCallBack(nullptr);
        client->setOnRecvCallBack(onRecv_m);
        client->setOnFinCallBack(onFin);
        client->ConnectServer();
    }
}

void onAccept_mm(ClientData *data) {
    auto Log = get("console");
    Log->debug("onAccept_mm");
    string send_buffer;
    string msg;
    msg = "testsetesteaaesteataestesrfekelfjasefkeafjael;kfjealkfjaeslkfjaeslfhaejklfheasafklaes";
    send_buffer += msg;
    send_buffer += " ";
    send_buffer += m->sig(msg);
    Log->debug("onAccept_mm/send buffer: {}", send_buffer);
    encrypt(send_buffer, m->groupKey);
    server_m->SendPacket(data->id, send_buffer.c_str(), send_buffer.size() + 1);
}

void onRecv_mm(ClientData *data) {
    auto Log = get("console");

    stringstream ss;
    NetworkUtility::print_payload(ss, (const u_char *) data->recv_playload, data->recv_len);
    Log->debug("recv raw packet:\n{}", ss.str());
    string msg = data->recv_playload;
    Log->debug("onRecv_mm/msg: {}", msg);
    decrypt(msg, m->groupKey);
    Log->debug("onRecv_mm/msg(decrypted): {}", msg);
    stringstream sss(msg);
    string mmp, sig;
    sss >> mmp >> sig;
    if (!m->ver(mmp, sig)) {
        Log->error("msg verify error!");
    } else Log->info("msg verify passed!");
}
