#include <iostream>
#include "common.h"

using namespace std;

extern int main_gm(string ip, u_int16_t port, ZZ psk);

int main_m(string ip, u_int16_t port, string id, ZZ psk);

int main() {
    // Console logger with color
    // usage https://github.com/gabime/spdlog
    auto Log = stdout_color_mt("console");
    Log->info("Program started");

    main_gm("192.168.1.2", 9999, conv<ZZ>(233333));
    main_m("192.168.1.2", 9999, "Alice", conv<ZZ>(233333));
    return 0;
}
