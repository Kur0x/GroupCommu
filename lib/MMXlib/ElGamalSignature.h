#ifndef ELGAMAL_SIGNATURE_H
#define ELGAMAL_SIGNATURE_H

#include "NTL/ZZ.h"
#include "Cryptography.h"

using namespace NTL;

namespace ElGamal {
    struct PublicKey {
        ZZ p, alpha, beta;

        PublicKey(const ZZ &p, const ZZ &alpha, const ZZ &beta);
    };

    struct PrivateKey {
        ZZ a;

        PrivateKey(const ZZ &a);
    };

    class ElGamalSignature : public Cryptography {
    public:
        ElGamalSignature();

        void generateKeyPair(int len = ELGAMAL_KEYLEN);

        static ZZ sig(const ZZ &x, PublicKey *pk, PrivateKey *sk);

        ZZ sig(const ZZ &x) const;

        ZZ sig(const string &x) const;

        static bool ver(const ZZ &x, const ZZ &y, PublicKey *pk);

        ~ElGamalSignature();

        PublicKey *getPK() const;

        PrivateKey *getSK() const;

    private:
        PublicKey *pk;
        PrivateKey *sk;
    };
}
#endif
