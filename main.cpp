#include <iostream>
#include "common.h"

using namespace std;

extern int main_gm(string ip, u_int16_t port, const ZZ &psk, int lambda);

int main_m(string ip, u_int16_t port, string id, const ZZ &psk);

int main(int argc, char *argv[]) {
    // Console logger with color
    // usage https://github.com/gabime/spdlog
    auto Log = stdout_color_mt("console");
    set_level(level::debug);
    Log->info("Program started");

    int oc;                     /*选项字符 */
    char *ip = nullptr;
    char *name = nullptr;
    char *t = nullptr;
    bool type = false;
    while ((oc = getopt(argc, argv, "gmint:")) != -1) {
        switch (oc) {
            case 'g':
                type = true;
                break;
            case 'm':
                type = false;
                break;
            case 'i':
                ip = optarg;
                break;
            case 'n':
                name = optarg;
                break;
            case 't':
                t = optarg;
                break;
            default:
                break;
        }
    }
    if (type) {//GM
        main_gm("0.0.0.0", 9999, conv<ZZ>(233333), 64);
    } else {
        main_m(ip, 9999, name, conv<ZZ>(233333));
    }
    return 0;
}
