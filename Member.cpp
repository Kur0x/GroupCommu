#include "Member.h"
#include <MMX/Cryptography.h>

using namespace group_sig;

void int2str(const int &i, string &str) {
    stringstream stream;
    stream << i;
    str = stream.str();
}

member::member(string id, public_para *para, ZZ psk)
        : id(id), psk(psk) {
    this->para = para;
    Log = get("console");
    RandomBits(x, para->lambda);
    y = PowerMod(para->a, x, para->n);
    z = PowerMod(para->g, y, para->n);
}


string member::JoinGroupMsg(ZZ psk) {
    //构造知识签名证明证明自己拥有私钥x
    const ZZ m(psk);//知识签名总得签点啥//PSK
    cspair p = SKLOG(m, y, para->a);
    string result =
            Cryptography::numberToString(y, false) + ' ' +
            Cryptography::numberToString(para->a, false) + ' ' +
            Cryptography::numberToString(p.c, false) + ' ' +
            Cryptography::numberToString(p.s[0], false);

    stringstream ss;
    ss << y << ' '
       << z << ' '
       << result;

    get("console")->info(ss.str());
    return ss.str();
}

bool member::onRecvV(string msg) {
    v = Cryptography::stringToNumber(msg, false);
    return true;
}

//x是待签名的消息
string member::sig(const ZZ &x) const {
    ZZ r = RandomBnd(para->n - 1) + 1; //[1,p-1]
    ZZ gg = PowerMod(para->g, r, para->n);
    ZZ zz = PowerMod(gg, y, para->n);
    cspair v1 = SKLOGLOG(x, zz, gg, para->a, this->x);
    cspair v2 = SKROOTLOG(x, MulMod(zz, gg, para->n), gg, para->b, v);
    Log->debug("SKROOTLOG done");
    string result = Cryptography::numberToString(gg, false) + ' ' +
                    Cryptography::numberToString(zz, false) + ' ' +
                    Cryptography::numberToString(v1.c, false);
    string cnt_str;
    int2str(v1.cnt, cnt_str);
    result += ' ';
    result += cnt_str;
    Log->debug("v1.cnt: {}", v1.cnt);
    for (int i = 0; i < v1.cnt; i++) {
        result += ' ';
        result += Cryptography::numberToString(v1.s[i], false);
    }

    result += ' ';
    result += Cryptography::numberToString(v2.c, false);
    int2str(v2.cnt, cnt_str);
    result += ' ';
    result += cnt_str;
    Log->debug("v2.cnt: {}", v2.cnt);
    for (int i = 0; i < v2.cnt; i++) {
        result += ' ';
        result += Cryptography::numberToString(v2.s[i], false);
    }

    Log->debug("msg after signing: {}", result);
    return result;
}

string member::sig(const string &x) const {
    return this->sig(Cryptography::stringToNumber(x));
}

bool member::ver(string msg, string sig) const
{
    ZZ m = Cryptography::stringToNumber(msg, false);
    stringstream stream(sig);
    string token;
    stream >> token;
    ZZ gg = Cryptography::stringToNumber(token, false);
    stream >> token;
    ZZ zz = Cryptography::stringToNumber(token, false);
    cspair v1, v2;
    stream >> token;
    v1.c = Cryptography::stringToNumber(token, false);
    stream >> v1.cnt;
    for (int i = 0; i < v1.cnt; i++) {
        stream >> token;
        v1.s.push_back(Cryptography::stringToNumber(token, false));
    }
    stream >> token;
    v2.c = Cryptography::stringToNumber(token, false);
    stream >> v2.cnt;
    for (int i = 0; i < v2.cnt; i++) {
        v2.s.push_back(Cryptography::stringToNumber(token, false));
    }
    if (SKLOGLOGver(m, zz, gg, para->a, v1) && SKROOTLOGver(m, zz, gg, para->b, v2)) {
        return true;
    }
    return false;
}

//传输的消息的格式是 gn gn gn...
string member::onKeyExchangeRequestRecv(string msg) const {
    stringstream stream(msg);
    vector<ZZ> gn_buffer;

    string gn_str;
    while (stream >> gn_str) {
        gn_buffer.push_back(Cryptography::stringToNumber(gn_str));
    }
    vector<ZZ> gn_output;
    if (gn_buffer.empty()) {
        gn_output.push_back(PowerMod(para->g, x, para->n));
    } else if (gn_buffer.size() == 1) {
        gn_output.push_back(*gn_buffer.begin());
        gn_output.push_back(PowerMod(para->g, x, para->n));
        gn_output.push_back(PowerMod(gn_output.at(0) % para->n , x, para->n));
    } else {
        gn_output.push_back(*gn_buffer.rbegin());
        for (auto it : gn_buffer) {
            gn_output.push_back(PowerMod(it % para->n, x, para->n));
        }
    }

    stringstream send_buf;
    for (auto i:gn_output) {
        send_buf << Cryptography::numberToString(i, false) << " ";
    }
    return send_buf.str();
}

void member::onGroupKeyBoardcastRecv(string msg) {
    stringstream stream(msg);
    Log->debug("onGroupKeyBoardcastRecv/msg: {}", msg);
    string id, gn;
    while (stream >> id >> gn) {
//        Log->debug("id: {}", id);
//        Log->debug("gn: {}", gn);
        if (id == this->id) {
            groupKey = PowerMod(Cryptography::stringToNumber(gn, false) % para->n, x, para->n);
            Log->debug("Group key update: {}", Cryptography::numberToString(groupKey, false));
            return;
        }
    }
    Log->error("No Group key!!!");
}


cspair member::SKLOG(const ZZ &m, const ZZ &y, const ZZ &g) const {
//	unsigned long r = RandomWord();
    ZZ r;
    cspair p;
    string concatStr;
    size_t n;


    fucked:
    r = findRandomInZn(para->n);
    Log->debug("r: {}", Cryptography::numberToString(r, false));
    concatStr = Cryptography::numberToString(m, false) + Cryptography::numberToString(y, false) +
                Cryptography::numberToString(g, false) +
                Cryptography::numberToString(PowerMod(g, r, para->n), false);
    Log->debug("g^r: {}", Cryptography::numberToString(PowerMod(g, r, para->n), false));
    Log->debug("SKLOG\nm: {}\ny: {}\ng: {}", Cryptography::numberToString(m, false),
               Cryptography::numberToString(y, false), Cryptography::numberToString(g, false));


    n = h(concatStr);

    p.c = conv<ZZ>(n);
    p.s.resize(1);
    p.s[0] = r - p.c * x;
    Log->debug("x: {}", Cryptography::numberToString(x, false));
    Log->debug("c: {}", Cryptography::numberToString(p.c, false));

    if (p.s[0] < 0) {
        Log->debug("fucked");
        goto fucked;
    }
//	p.s[0] = r - p.c * this->x;
    p.cnt = 1;
    Log->debug("c: {}\ns: {}", Cryptography::numberToString(p.c, false), Cryptography::numberToString(p.s[0], false));
    ZZ temp = MulMod(PowerMod(g, p.s[0], para->n), PowerMod(y, p.c, para->n), para->n);
    Log->debug("c*x: {}", Cryptography::numberToString(p.c * this->x, false));
    Log->debug("g^r 2: {}", Cryptography::numberToString(temp, false));

    return p;
}

ZZ findRandInlamda(const long &lambda, const ZZ &x, int type=1){
    ZZ result;
    RandomBits(result, lambda);
    if(type == 1) {
        while (result < x) {
            RandomBits(result, lambda);
        }
    }
    return result;
}

cspair member::SKLOGLOG(const ZZ &m, const ZZ &y, const ZZ &g, const ZZ &a, const ZZ &alpha) const {
    Log->debug("SKLOGLOG");
    cspair p;

    string concatStr = Cryptography::numberToString(m, false) + Cryptography::numberToString(y, false) +
                       Cryptography::numberToString(g, false) + Cryptography::numberToString(a, false);

    int k = 32;//由hash函数决定
    long l = RandomBnd(k - 1) + 1;
    ZZ *r = new ZZ[l], *t = new ZZ[l];
    for (int i = 0; i < l; i++) {
        r[i] = findRandInlamda(para->lambda, alpha);
        r[i] = PowerMod(a, r[i], para->n);
        t[i] = PowerMod(g, r[i], para->n);
        concatStr += Cryptography::numberToString(t[i], false);
    }


    size_t n = h(concatStr);

    p.c = conv<ZZ>(n);
    p.s.resize(l);
    p.cnt = l;
    for (int i = 0; i < l; i++) {
        if (IsZero((p.c >> i) & 0x1)) {
            p.s[i] = r[i];
        } else {
            p.s[i] = r[i] - alpha;
        }
    }

    return p;
}

cspair member::SKROOTLOG(const ZZ &m, const ZZ &y, const ZZ &g, const ZZ &e, const ZZ &beta) const {
    Log->debug("SKROOTLOG");
    cspair p;

    string concatStr = Cryptography::numberToString(m, false) + Cryptography::numberToString(y, false) +
                       Cryptography::numberToString(g, false) + Cryptography::numberToString(e, false);

    int k = 32;//由hash函数决定
    long l = RandomBnd(k - 1) + 1;
    Log->debug("l in SKROOTLOG: {}", l);
    ZZ *r = new ZZ[l], *t = new ZZ[l];
    for (int i = 0; i < l; i++) {
        r[i] = findRandInlamda(para->lambda, beta, 2);
        r[i] = PowerMod(r[i], e, para->n);
        t[i] = PowerMod(g, r[i], para->n);
        concatStr += Cryptography::numberToString(t[i], false);
    }

    size_t n = h(concatStr);

    p.c = conv<ZZ>(n);
    p.s.resize(l);
    p.cnt = l;
    for (int i = 0; i < l; i++) {
        if (IsZero((p.c >> i) & 0x1)) {
            p.s[i] = r[i];
        } else {
//            ZZ temp = PowerMod(this->x, -1, para->n);
//            p.s[i] = MulMod(r[i], temp, para->n);
            p.s[i] = r[i] / beta;
            p.s[i] = p.s[i] % para->n;
        }
    }

    return p;
}


bool member::SKLOGLOGver(const ZZ &m, const ZZ &y, const ZZ &g, const ZZ &a, const cspair &p) const {
    string concatStr = Cryptography::numberToString(m, false) + Cryptography::numberToString(y, false) +
                       Cryptography::numberToString(g, false) + Cryptography::numberToString(a, false);
    for (int i = 0; i < p.s.size(); i++) {
        ZZ as = PowerMod(a, p.s[i], para->n);
        ZZ t = IsZero((p.c >> i) & 0x1) ? PowerMod(g, as, para->n) : PowerMod(y, as, para->n);
        concatStr += Cryptography::numberToString(t, false);
    }


    size_t n = h(concatStr);

    ZZ cc = conv<ZZ>(n);
    if (cc == p.c) {
        return true;
    }
    return false;
}

bool member::SKROOTLOGver(const ZZ &m, const ZZ &y, const ZZ &g, const ZZ &e, const cspair &p) const {
    string concatStr = Cryptography::numberToString(m, false) + Cryptography::numberToString(y, false) +
                       Cryptography::numberToString(g, false) + Cryptography::numberToString(e, false);
    for (int i = 0; i < p.s.size(); i++) {
        ZZ se = PowerMod(p.s[i], e, para->n);
        ZZ t = IsZero((p.c >> i) & 0x1) ? PowerMod(g, se, para->n) : PowerMod(y, se, para->n);
        concatStr += Cryptography::numberToString(t, false);
    }


    size_t n = h(concatStr);

    ZZ cc = conv<ZZ>(n);
    if (cc == p.c) {
        return true;
    }
    return false;
}
