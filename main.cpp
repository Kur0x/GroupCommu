#include <iostream>
#include "common.h"

#ifdef __linux__
#include <sys/prctl.h>
#endif

#include <signal.h>

using namespace std;

std::string LOGNAME = "test";

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
    string psk;
    string log_level;
    bool type = false;
    bool separate_gm = false;
    while ((oc = getopt(argc, argv, "sgmhi:n:p:l:")) != -1) {
        switch (oc) {
            case 's':
                separate_gm = true;
                break;
            case 'g': // GM
                type = true;
                break;
            case 'm': // Member
                type = false;
                break;
            case 'i': //IP
                ip = optarg;
                break;
            case 'n': //name
                name = optarg;
                break;
            case 'p': //psk
                psk = optarg;
                break;
            case 'l': //log_level
                log_level = optarg;
                break;
            case 'h':
                cout << "usage: {-g|-m} [-i <ip>] [-n <id>] -p <PSK> [-l <log_level>]" << endl;
                return 0;
            default:
                cout << "usage: {-g|-m} [-i <ip>] [-n <id>] -p <PSK> [-l <log_level>]" << endl;
                break;
        }
    }
    if (psk == "") {
        Log->critical("Wrong usage: no psk");
        return -1;
    }
    ZZ _psk = conv<ZZ>(atoi(psk.c_str()));
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


    if (separate_gm) {
        LOGNAME = "GM";
        auto Log = stdout_color_mt(LOGNAME);
        main_gm("0.0.0.0", 9999, _psk, 64);
        return 0;
    }
    if (!name) {
        Log->critical("Wrong usage: no id");
        return -1;
    }
    LOGNAME = name;
    Log = stdout_color_mt(LOGNAME);

    pid_t pid;
    if (type) {//GM
        pid = fork();
        if (pid == 0) {
#ifdef __linux__
            prctl(PR_SET_PDEATHSIG, SIGHUP);
#endif
            LOGNAME = "GM";
            auto Log = stdout_color_mt(LOGNAME);
            main_gm("0.0.0.0", 9999, _psk, 64);
            return 0;
        }
        sleep(1);
        main_m("192.168.1.2", 9999, name, _psk);
    } else {
        if (!ip) {
            Log->critical("Wrong usage: no ip");
            return -1;
        }
        main_m(ip, 9999, name, _psk);
    }
    return 0;
}
