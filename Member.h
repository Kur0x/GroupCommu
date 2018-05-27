#pragma once

#include "common.h"
#include <vector>
#include <sstream>
#include "SHA512.h"


namespace group_sig {


    class member {
    public:
        member(std::string id, public_para *para, ZZ psk);

        std::string JoinGroupMsg(ZZ psk);

        //		static public_para get_para();
        bool onRecvV(std::string msg);

        std::string sig(const ZZ &x) const;

        std::string sig(const std::string &x) const;

        bool ver(std::string msg, std::string sig) const;

        cspair SKLOG(const ZZ &m, const ZZ &y, const ZZ &g) const;

        cspair SKLOGLOG(const ZZ &m, const ZZ &y, const ZZ &g, const ZZ &a, const ZZ &alpha) const;

        cspair SKROOTLOG(const ZZ &m, const ZZ &y, const ZZ &g, const ZZ &e, const ZZ &beta) const;


        bool SKLOGLOGver(const ZZ &m, const ZZ &y, const ZZ &g, const ZZ &a, const cspair &p) const;

        bool SKROOTLOGver(const ZZ &m, const ZZ &y, const ZZ &g, const ZZ &e, const cspair &p) const;

        std::string onKeyExchangeRequestRecv(std::string msg) const;

        void onGroupKeyBoardcastRecv(std::string msg);

        ZZ groupKey;

    private:
        std::shared_ptr<logger> Log;
        const std::string id;
        ZZ x;
        ZZ y;
        ZZ z;
        ZZ v;
        public_para *para;

        ZZ psk;

    };

}
