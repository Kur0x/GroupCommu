//
// Created by KuroX on 2018/5/27.
//
#include "common.h"
#include "MMX/Cryptography.h"

using namespace std;
ZZ findRandomInZn(const ZZ &n) {

    ZZ result;
    while (true) {
        result = RandomBits_ZZ(NumBits(n));
        if (result > 1 && result < n && GCD(result, n) == 1)
            break;
    }
    return result;
}

void encrypt(std::string &in, ZZ key) {
    string _key = Cryptography::numberToString(key);
    for (int i = 0; i < in.size(); ++i) {
        in[i] ^= _key[i % _key.size()];
    }
}

void decrypt(std::string &in, ZZ key) {
    return encrypt(in, key);
}

void decrypt(char *in, ZZ key, int len) {
    string _key = Cryptography::numberToString(key);
    for (int i = 0; i < len - 1; ++i) {
        in[i] ^= _key[i % _key.size()];
    }
}
