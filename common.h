#pragma once
#include <NTL/ZZ.h>
using namespace NTL;
using namespace std;

namespace group_sig
{
	/**
	 * \brief 公开参数 (n, b, G, g, a, λ, ε)
	 */
	struct public_para
	{
		ZZ n;
		ZZ b;
		ZZ G;
		ZZ g;
		ZZ a; // 系统安全性参数a
		long lambda;
		ZZ epsilon;
	};
}
