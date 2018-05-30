#include <iostream>
#include "common.h"

using namespace std;

extern int main_gm(string ip, u_int16_t port, ZZ psk);

int main_m(string ip, u_int16_t port, string id, const ZZ &psk);

int main(int argc, char *argv[]) {
//    ZZ c = conv<ZZ>(12);
//
//    cout << IsZero((c >> 0) & 0x1) <<endl;
//    cout << IsZero((c >> 1) & 0x1) <<endl;
//    cout << IsZero((c >> 2) & 0x1) <<endl;
//    return 0;


//    ZZ aa,bb,nn;
//
//    RandomBits(nn, 65537);
//    RandomBits(aa, 511);
//    RandomBits(bb, 512);
//    ZZ gg = PowerMod(aa,bb, (nn));
//    return 0;
    // Console logger with color
    // usage https://github.com/gabime/spdlog
    auto Log = stdout_color_mt("console");
    set_level(level::debug);
    Log->info("Program started");
    if (argc < 2) {
        main_gm("0.0.0.0", 9999, conv<ZZ>(233333));
    } else {
        if (argc != 3) {
            Log->critical("Wrong usage!");
            return -1;
        }
        main_m(argv[1], 9999, argv[2], conv<ZZ>(233333));

    }
    return 0;
}
