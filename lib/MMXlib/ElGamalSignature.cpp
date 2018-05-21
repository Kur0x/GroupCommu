#include "ElGamalSignature.h"
#include <ctime>
#include <NTL/BasicThreadPool.h>

using namespace ElGamal;

PublicKey::PublicKey(const ZZ &p, const ZZ &alpha, const ZZ &beta)
        : p(p), alpha(alpha), beta(beta) {}

PrivateKey::PrivateKey(const ZZ &a) : a(a) {
}

ElGamalSignature::ElGamalSignature() : pk(nullptr), sk(nullptr) {
    SetSeed(conv<ZZ>(static_cast<long>(time(nullptr))));
}

void ElGamalSignature::generateKeyPair(int len) {
    ZZ p = findPrime(len);
    ZZ alpha = findPrimitiveRoot(p);
    ZZ a = RandomBnd(p - 2) + 1;//[1,p-1]
    ZZ beta = PowerMod(alpha, a, p);
    pk = new PublicKey(p, alpha, beta);
    sk = new PrivateKey(a);
}

ZZ ElGamalSignature::sig(const ZZ &x, PublicKey *pk, PrivateKey *sk) {
    ZZ k = RandomBnd(pk->p - 3) + 1;//[1,p-2]
    while (GCD(k, pk->p - 1) != 1) {
        k = RandomBnd(pk->p - 3) + 1;
    }
    ZZ gamma = PowerMod(pk->alpha, k, pk->p);
    //delta = (x-a*gamma)*k^(-1) mod (p-1)
    ZZ delta = MulMod(x - sk->a * gamma, InvMod(k, pk->p - 1), pk->p - 1);
    return gamma * pk->p + delta;
}

ZZ ElGamalSignature::sig(const ZZ &x) const {
    return this->sig(x, pk, sk);
}

ZZ ElGamalSignature::sig(const string &x) const {
    return this->sig(stringToNumber(x), pk, sk);
}

bool ElGamalSignature::ver(const ZZ &x, const ZZ &y, PublicKey *pk) {
    ZZ gamma = y / pk->p;
    ZZ delta = y % pk->p;
    //beta^(gamma)*gamma^delta==alpha^x (mod p)
    return (PowerMod(pk->beta, gamma, pk->p) * PowerMod(gamma, delta, pk->p)) % pk->p == PowerMod(pk->alpha, x, pk->p);
}

ElGamalSignature::~ElGamalSignature() {
    delete pk;
    delete sk;
}

PublicKey *ElGamalSignature::getPK() const {
    return pk;
}

PrivateKey *ElGamalSignature::getSK() const {
    return sk;
}
