#include <iostream>
#include "common.h"

using namespace std;

extern int main_gm(string ip, u_int16_t port);

extern int main_m(string ip, u_int16_t port);

int main() {
    // Console logger with color
    // usage https://github.com/gabime/spdlog
    auto Log = stdout_color_mt("console");
    Log->info("Program started");

    main_gm("192.168.1.2", 9999);
    return 0;
}