#pragma once
#include "common.h"
#include <MMX/RsaSignature.h>
#include <vector>
#include "SHA512.h"
namespace group_sig
{
	struct member_info
	{
		string id;
		ZZ y;
		ZZ z;
	};

	class GM
	{
	public:
		explicit GM(long lambda, ZZ psk)
				: lambda(lambda), psk(psk)
		{
//			rsa_.generateKeyPair();
			init();
		}

		void init();
		public_para getPublicPara() const;
		ZZ verify(string id, string msg);
		string open(ZZ gg, ZZ zz);
		bool SKLOGver(const ZZ &m, const ZZ &y, const ZZ &g, const cspair &p) const;
		void keyExchangeRequest(string id);
		void onKeyExchangeResponseRecv(string msg);
		string getBroadcastMsg();
	private:
        shared_ptr<logger> Log;
//		RSA::RsaSignature rsa_; // (n rsa_b)
		ZZ G;
        ZZ g; // 循环群G，g为生成元，G的阶是G-1
		ZZ a;
        ZZ n;
        ZZ rsa_n;
        ZZ rsa_b;
        ZZ rsa_a;
		long lambda; //群成员私钥长度
		ZZ epsilon;
		vector<member_info> info;

		vector<ZZ> keyChain;
		ZZ groupKey;
		ZZ psk;

	};
}
