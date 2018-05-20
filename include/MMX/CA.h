#ifndef CRYPTOGRAPH_H
#define CRYPTOGRAPH_H
#include "RsaSignature.h"
#include "ElGamalSignature.h"
#include "Cryptography.h"

class CA : public Cryptography
{
public:
	CA();
	string requare(const string& id, RSA::PublicKey* pk, int ca_sig_method);
	string requare(const string& id, ElGamal::PublicKey* pk, int ca_sig_method);
	string requareMTI(const string& id, ZZ bt, int ca_sig_method);
	bool createCertFile(const string& id, const string& cert);
	RSA::PublicKey* getRSAPK() const;
	ElGamal::PublicKey* getElGamalPK() const;
private:
	RSA::RsaSignature rsa;
	ElGamal::ElGamalSignature el_gamal;
};
#endif
