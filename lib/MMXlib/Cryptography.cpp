#include "Cryptography.h"
//#include <sstream>

ZZ Cryptography::stringToNumber(string str, bool bin) {
    // 二进制模式。可以把字母转换成数字
    if (bin) {
        ZZ number = conv<ZZ>((unsigned char)str[0]);
        long len = str.length();
        for (long i = 1; i < len; i++) {
            number *= 128;
            number += conv<ZZ>((unsigned char)str[i]);
        }
        return number;
    }
    // 数字模式。字符串中就是数字才能用这个！仅当字符串为”123”这样的数字串时才可以使用
    return conv<ZZ>(str.c_str());
}

string Cryptography::numberToString(ZZ num, bool bin) {
    if (bin) {
        long len = ceil(log(num) / log(128));
        string str;
        str.resize(len);
        for (long i = len - 1; i >= 0; i--) {
            str[i] = conv<int>(num % 128);
            num /= 128;
        }
        return str;
    }
    string s = "";
//	stringstream ss;
//	ss << num;
//	ss >> s;
    while (num != 0) {
        s.insert(s.begin(), char(num % 10 + '0'));
        num /= 10;
    }

    return s;

}

ZZ Cryptography::findPrime(int len) {
    ZZ q0 = GenGermainPrime_ZZ(len - 1);
    // A (Sophie) Germain prime is a prime p such that p' = 2*p+1 is also a prime.
    // Such primes are useful for cryptographic applications...cryptographers
    // sometimes call p' a "strong" or "safe" prime.
    // GenGermainPrime generates a random Germain prime n of length l
    // so that the probability that either n or 2*n+1 is not a prime
    // is bounded by 2^(-err).
    ZZ p = 2 * q0 + 1;
    return p;
    //	while (true)
    //	{
    //		ZZ r = conv<ZZ>("2");
    //		std::cout << NumBits(r)<< std::endl;
    //		ZZ q0 = GenPrime_ZZ(len-1);
    //		ZZ p = r * q0 + 1;
    //		std::cout << NumBits(p) << std::endl;
    //		if (ProbPrime(p) == 1)
    //			return p;
    //	}
}

ZZ Cryptography::findPrimitiveRoot(const ZZ &p) {
    //p-1的两个因子p1,p2
    ZZ p1 = conv<ZZ>("2");
    ZZ p2 = (p - 1) / p1;
    while (true) {
        ZZ g = RandomBnd(p - 3) + 2;
        //g是p的本原元当且仅当g对p-1的所有因子都有g^((p-1)/p[i]) (mod p) 不等于 1
        if (PowerMod(g, (p - 1) / p1, p) != 1)
            if (PowerMod(g, (p - 1) / p2, p) != 1)
                return g;
    }
}
