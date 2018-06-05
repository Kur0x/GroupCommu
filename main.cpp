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
    string psk = "";
    string log_level;
    bool type = false;
    while ((oc = getopt(argc, argv, "gmhi:n:p:l:")) != -1) {
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
                psk = optarg;
                break;
            case 'l':
                log_level = optarg;
                break;
            case 'h':
                cout << "usage: {-h|-m} [-i <ip>] [-n <id>] -p <PSK> [-l <log_level>]" << endl;
                return 0;
            default:
                cout << "usage: {-h|-m} [-i <ip>] [-n <id>] -p <PSK> [-l <log_level>]" << endl;
                break;
        }
    }
    if (psk == "") {
        Log->critical("Wrong usage: no psk");
        return -1;
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

    ZZ _psk = conv<ZZ>(atoi(psk.c_str()));
    if (type) {//GM
        main_gm("0.0.0.0", 9999, _psk, 64);
    } else {
        if (!ip) {
            Log->critical("Wrong usage: no ip");
            return -1;
        }
        if (!name) {
            Log->critical("Wrong usage: no id");
            return -1;
        }
        main_m(ip, 9999, name, _psk);
    }
    return 0;
}
