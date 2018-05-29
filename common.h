#pragma once

#include <NTL/ZZ.h>
#include "spdlog/spdlog.h"
#include <functional>
#include "murmur3.h"

using namespace NTL;
using namespace spdlog;
//PROTOCOL
#define PROTO_C2S 0x00
#define PROTO_S2C 0x01
#define PROTO_PUB_PARA 0x01
#define PROTO_JOIN_GROUP 0x02
#define PROTO_KEY_EX 0x03
#define PROTO_KEY_BROADCAST 0x04
#define PROTO_COMMU 0x05
#define HEADLEN 4
#define ID_LEN 16
struct header_t {
    uint8_t proto_ori;
    uint8_t proto_type;
    uint16_t len;
};
struct commu_t {
    header_t header;
};


inline std::string get_str(char *src) {
    int size = ((header_t *) (src))->len;
    if (size == 0)
        return "";
    std::string str(src + HEADLEN);
    if (str.size() + 1 != size)
        get("console")->critical("\\0 error in get_str {}/{}", str.size(), size);
    return str;
}

struct cspair {
    ZZ c;
    std::vector<ZZ> s;
    int cnt;

    cspair() { cnt = 0; }

    cspair(const cspair &p) {
        c = p.c;
        for (auto i:p.s) {
            s.push_back(i);
        }
        cnt = s.size();
    }

    cspair &operator=(const cspair &p) {
        c = p.c;
        for (auto i:p.s) {
            s.push_back(i);
        }
        cnt = s.size();
        return *this;
    }
};

class ClientData {
public:
    int serverfd;
    static constexpr int BUFFER_LEN = 65536;
    static constexpr int TO_SEND = 0;
    static constexpr int TO_RECV = 1;
    time_t start_time;
    int clientfd;
    std::string id;//上层标识
    int stat;
    size_t recv_len;
    size_t send_len;
    char *recv_playload;
    char *send_playload;
    bool half;
    bool fin;
};


namespace group_sig {
    /**
     * \brief 公开参数 (n, b, G, g, a, λ, ε)
     */
    struct public_para {
        ZZ n;
        ZZ b;
        ZZ G;
        ZZ g;
        ZZ a; // 系统安全性参数a
        long lambda;
        ZZ epsilon;
    };
}

ZZ findRandomInZn(const ZZ &n);

void encrypt(std::string &in, ZZ key);

void decrypt(std::string &in, ZZ key);

void decrypt(char *in, ZZ key, int len);