//
// Created by KuroX on 2018/5/27.
//
#include "common.h"
#include "MMX/Cryptography.h"
#include "aes256.hpp"
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


ByteArray encrypt(const unsigned char *in, size_t len, ZZ key) {
    string temp = Cryptography::numberToString(key, false);
    ByteArray _key;
    _key.resize(temp.size());
    std::copy(temp.begin(), temp.end(), _key.begin());
    ByteArray enc;
    ByteArray::size_type enc_len = Aes256::encrypt(_key, in, len, enc);
//    char *buffer = new char[enc.size()];
//    std::copy(enc.begin(), enc.end(), buffer);
    return enc;
}

ByteArray encrypt(const ByteArray &in, ZZ key) {
    string temp = Cryptography::numberToString(key, false);
    ByteArray _key;
    _key.resize(temp.size());
    std::copy(temp.begin(), temp.end(), _key.begin());
    ByteArray enc;
    ByteArray::size_type enc_len = Aes256::encrypt(_key, in, enc);
//    char *buffer = new char[enc.size()];
//    std::copy(enc.begin(), enc.end(), buffer);
    return enc;
}


ByteArray decrypt(const unsigned char *in, size_t len, ZZ key) {
    string temp = Cryptography::numberToString(key, false);
    ByteArray _key;
    _key.resize(temp.size());
    std::copy(temp.begin(), temp.end(), _key.begin());
    ByteArray enc;
    ByteArray::size_type enc_len = Aes256::decrypt(_key, in, len, enc);
//    char *buffer = new char[enc.size()];
//    std::copy(enc.begin(), enc.end(), buffer);
    return enc;
}

ByteArray decrypt(const ByteArray &in, ZZ key) {
    string temp = Cryptography::numberToString(key, false);
    ByteArray _key;
    _key.resize(temp.size());
    std::copy(temp.begin(), temp.end(), _key.begin());
    ByteArray enc;
    ByteArray::size_type enc_len = Aes256::decrypt(_key, in, enc);
//    char *buffer = new char[enc.size()];
//    std::copy(enc.begin(), enc.end(), buffer);
    return enc;
}