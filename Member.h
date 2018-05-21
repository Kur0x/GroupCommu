#pragma once

#include "common.h"
#include <vector>
#include <sstream>
#include "SHA512.h"


namespace group_sig {
    typedef struct {
        ZZ c;
        std::vector<ZZ> s;
        int cnt;
    } cspair;

    class member {
    public:
        member(std::string id, public_para *para);

        std::string JoinGroupMsg(ZZ psk);

        //		static public_para get_para();
        bool onRecvV(std::string msg);

        std::string sig(const ZZ &x) const;

        std::string sig(const std::string &x) const;

        bool ver(const ZZ &x, const ZZ &y) const;

        cspair SKLOG(const ZZ &m, const ZZ &y, const ZZ &g) const;

        cspair SKLOGLOG(const ZZ &m, const ZZ &y, const ZZ &g, const ZZ &a) const;

        cspair SKROOTLOG(const ZZ &m, const ZZ &y, const ZZ &g, const ZZ &e) const;

        bool SKLOGver(const ZZ &m, const ZZ &y, const ZZ &g, const cspair &p) const;

        bool SKLOGLOGver(const ZZ &m, const ZZ &y, const ZZ &g, const ZZ &a, const cspair &p) const;

        bool SKROOTLOGver(const ZZ &m, const ZZ &y, const ZZ &g, const ZZ &e, const cspair &p) const;

        void onKeyExchangeRequestRecv(std::string msg) const;

        void onGroupKeyBoardcastRecv(std::string msg);

    private:
        const std::string id;
        ZZ x;
        ZZ y;
        ZZ z;
        ZZ v;
        public_para *para;

        ZZ groupKey;


    };

}
