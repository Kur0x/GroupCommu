#ifndef RSA_SIGNATURE_H
#define RSA_SIGNATURE_H

#include "Cryptography.h"

namespace RSA {
    struct PublicKey {
        ZZ n, b;

        PublicKey(const ZZ &n, const ZZ &b);
    };

    struct PrivateKey {
        ZZ p, q, a, n;

        PrivateKey(const ZZ &p, const ZZ &q, const ZZ &a);
    };

    class RsaSignature : public Cryptography {
    public:
        RsaSignature();

        void generateKeyPair(int len = RSA_KEYLEN);

        ZZ sig(const ZZ &x) const;

        ZZ sig(const string &x) const;

        static ZZ sig(const ZZ &x, PrivateKey *sk);

        static bool ver(const ZZ &x, const ZZ &y, PublicKey *pk);

        bool ver(const ZZ &x, const ZZ &y) const;

        ~RsaSignature();

        PublicKey *getPK() const;

        PrivateKey *getSK() const;

    private:
        PublicKey *pk;
        PrivateKey *sk;
    };
}
#endif
