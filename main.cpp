#include <iostream>
#include "common.h"

using namespace std;

extern int main_gm(string ip, u_int16_t port, const ZZ &psk, int lambda);

int main_m(string ip, u_int16_t port, string id, const ZZ &psk);

int main(int argc, char *argv[]) {
    // Console logger with color
    // usage https://github.com/gabime/spdlog
    auto Log = stdout_color_mt("console");
    Log->info("Program started");

    int oc;                     /*选项字符 */
    char *ip = nullptr;
    char *name = nullptr;
    char *p = nullptr;
    string log_level;
    bool type = false;
    while ((oc = getopt(argc, argv, "gminpl:")) != -1) {
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
            case 'p':
                p = optarg;
                break;
            case 'l':
                log_level = optarg;
                break;
            default:
                break;
        }
    }
    set_level(level::debug);
    if (log_level == "debug")
        set_level(level::debug);
    if (log_level == "info")
        set_level(level::info);
    if (log_level == "warn")
        set_level(level::warn);
    if (log_level == "err")
        set_level(level::err);
    if (log_level == "critical")
        set_level(level::critical);

    if (type) {//GM
        main_gm("0.0.0.0", 9999, conv<ZZ>(p), 64);
    } else {
        main_m(ip, 9999, name, conv<ZZ>(p));
    }
    return 0;
}
