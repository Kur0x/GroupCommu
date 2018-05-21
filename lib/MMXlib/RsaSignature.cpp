#include "RsaSignature.h"
#include <ctime>
#include "Cryptography.h"

using namespace RSA;

PublicKey::PublicKey(const ZZ &n, const ZZ &b) : n(n), b(b) {
}

PrivateKey::PrivateKey(const ZZ &p, const ZZ &q, const ZZ &a) : p(p), q(q), a(a) {
    n = p * q;
}

RsaSignature::RsaSignature() : pk(nullptr), sk(nullptr) {
    SetSeed(conv<ZZ>(static_cast<long>(time(nullptr))));
}

void RsaSignature::generateKeyPair(int len) {
    ZZ p = GenPrime_ZZ(512);
    ZZ q = GenPrime_ZZ(512);// pq��ͬ�����Լ���Ϊ0�������ж�
    ZZ n = p * q;
    ZZ phiN = (p - 1) * (q - 1);
    ZZ b;
    while (true) {
        b = RandomBits_ZZ(NumBits(phiN));
        if (b > 1 && b < phiN && GCD(b, phiN) == 1)
            break;
    }
    ZZ a = InvMod(b, phiN);
    pk = new PublicKey(n, b);
    sk = new PrivateKey(p, q, a);
}


ZZ RsaSignature::sig(const ZZ &x) const {
    if (!sk)
        throw "SK not initialize!!!!!";
    return PowerMod(x % sk->n, sk->a, sk->n);
}

ZZ RsaSignature::sig(const string &x) const {
    if (!sk)
        throw "SK not initialize!!!!!";
    return PowerMod(stringToNumber(x) % sk->n, sk->a, sk->n);
}

ZZ RsaSignature::sig(const ZZ &x, PrivateKey *sk) {
    return PowerMod(x % sk->n, sk->a, sk->n);
}

bool RsaSignature::ver(const ZZ &x, const ZZ &y, PublicKey *pk) {
    return x % pk->n == PowerMod(y % pk->n, pk->b, pk->n);
}

bool RsaSignature::ver(const ZZ &x, const ZZ &y) const {
    if (!pk)
        throw "PK not initialize!!!!!";
    return x % pk->n == PowerMod(y % pk->n, pk->b, pk->n);
}

RsaSignature::~RsaSignature() {
    delete pk;
    delete sk;
}

PublicKey *RsaSignature::getPK() const {
    return pk;
}

PrivateKey *RsaSignature::getSK() const {
    return sk;
}
