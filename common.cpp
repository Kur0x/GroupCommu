//
// Created by KuroX on 2018/5/27.
//
#include "common.h"

ZZ findRandomInZn(const ZZ &n) {

    ZZ result;
    while (true) {
        result = RandomBits_ZZ(NumBits(n));
        if (result > 1 && result < n && GCD(result, n) == 1)
            break;
    }
    return result;
}