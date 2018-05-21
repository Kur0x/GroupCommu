#include "CA.h"
#include "Base64.h"
#include <fstream>

CA::CA() {
    cout << "正在初始化CA..." << endl;

    rsa.generateKeyPair();
    el_gamal.generateKeyPair();
}

// 证书格式为 id n b ca_sig_method s(数字都是数字字符串形式)
string CA::requare(const string &id, RSA::PublicKey *pk, int ca_sig_method) {
    string pk_string = numberToString(pk->n, false) + ' ' + numberToString(pk->b, false);
    string raw = id + ' ' + pk_string;//ID和公钥并起来
    ZZ s;// TA对alice 的身份标识和验证秘钥进行签名
    if (ca_sig_method == RSA_METHOD)
        s = rsa.sig(raw);
    else if (ca_sig_method == ELGAMAL_METHOD)
        s = el_gamal.sig(raw);
    // debug output
//	cout << "s:" << s << endl;
    // debug output
    string *cert = new string;
    Base64::Encode(raw + ' ' + numberToString(ZZ(ca_sig_method), false) + ' ' + numberToString(s, false), cert);
    return *cert;
}

// 证书格式为 id palpha beta ca_sig_method s(数字都是数字字符串形式)
string CA::requare(const string &id, ElGamal::PublicKey *pk, int ca_sig_method) {
    string pk_string = numberToString(pk->p, false) + ' ' +
                       numberToString(pk->alpha, false) + ' ' +
                       numberToString(pk->beta, false);
    string raw = id + ' ' + pk_string;//ID和公钥并起来
    ZZ s;// TA对alice 的身份标识和验证秘钥进行签名
    if (ca_sig_method == RSA_METHOD)
        s = rsa.sig(raw);
    else if (ca_sig_method == ELGAMAL_METHOD)
        s = el_gamal.sig(raw);

    string *cert = new string;
    Base64::Encode(raw + ' ' + numberToString(ZZ(ca_sig_method), false) + ' ' + numberToString(s, false), cert);
    return *cert;
}

string CA::requareMTI(const string &id, ZZ bt, int ca_sig_method) {
    string raw = id + ' ' + numberToString(bt);//ID和公钥并起来
    ZZ s;// TA对alice 的身份标识和验证秘钥进行签名
    if (ca_sig_method == RSA_METHOD)
        s = rsa.sig(raw);
    else if (ca_sig_method == ELGAMAL_METHOD)
        s = el_gamal.sig(raw);

    string *cert = new string;
    Base64::Encode(raw + ' ' + numberToString(ZZ(ca_sig_method)) + ' ' + numberToString(s), cert);
    return *cert;
}

bool CA::createCertFile(const string &id, const string &cert) {
    fstream out;
    out.open(id + ".txt", ios::out);
    if (!out.is_open())
        return false;
    out << "--BEGIN CERTIFICATE--\n";
    out << cert;
    out << "\n--END CERTIFICATE--\n";
    out.close();
    return true;
}

RSA::PublicKey *CA::getRSAPK() const {
    return rsa.getPK();
}

ElGamal::PublicKey *CA::getElGamalPK() const {
    return el_gamal.getPK();
}
