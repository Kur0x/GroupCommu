#include <memory.h>
#include <stdio.h>
#include "SHA512.h"



// 循环右移(64位)
#define ROR64( value, bits ) (((value) >> (bits)) | ((value) << (64 - (bits))))

//////////////////////////////////////////////////////
//                                                    //
// Ch,:Maj操作                                        //
// S:循环右移    R:同2**128除余右移                    //
// Sigma0:Sigma0函数                                //
// Sigma1:Sigma2函数                                //
// Gamma0:Gamma0函数                                //
// Gamma1:Gamma1函数                                //
//////////////////////////////////////////////////////

#define Ch( x, y, z )     (z ^ (x & (y ^ z)))
#define Maj(x, y, z )     (((x | y) & z) | (x & y))
#define S( x, n )         ROR64( x, n )
#define R( x, n )         (((x)&0xFFFFFFFFFFFFFFFFULL)>>((unsigned long long)n))
#define Sigma0( x )       (S(x, 28) ^ S(x, 34) ^ S(x, 39))
#define Sigma1( x )       (S(x, 14) ^ S(x, 18) ^ S(x, 41))
#define Gamma0( x )       (S(x, 1) ^ S(x, 8) ^ R(x, 7))
#define Gamma1( x )       (S(x, 19) ^ S(x, 61) ^ R(x, 6))

#define Sha512Round( a, b, c, d, e, f, g, h, i )       \
     t0 = h + Sigma1(e) + Ch(e, f, g) + K[i] + W[i];   \
     t1 = Sigma0(a) + Maj(a, b, c);                    \
     d += t0;                                          \
     h  = t0 + t1;

void SHA512Init(SHA512_CB *context) {
	context->count[0] = 0;
	context->count[1] = 0;
	context->state[0] = 0x6a09e667f3bcc908ULL;
	context->state[1] = 0xbb67ae8584caa73bULL;
	context->state[2] = 0x3c6ef372fe94f82bULL;
	context->state[3] = 0xa54ff53a5f1d36f1ULL;
	context->state[4] = 0x510e527fade682d1ULL;
	context->state[5] = 0x9b05688c2b3e6c1fULL;
	context->state[6] = 0x1f83d9abfb41bd6bULL;
	context->state[7] = 0x5be0cd19137e2179ULL;
}

void SHA512Update(SHA512_CB *context, unsigned char *input, unsigned long long inputlen) {
	unsigned long long index = 0, partlen = 0, i = 0; // i记录input的当前位置（初始为0）
	index = (context->count[1] >> 3) & 0x7F;  //index:总字长除127(11111111)取余后的余数
	partlen = 128 - index;  //partlen:同128相差的长度
	context->count[1] += inputlen << 3;  //更新count

										 // 统计字符的bit长度，如果小于说明类型溢出了(64bit)无法装下了
										 // 由于最后留下128bit填充字符长度，因而必须引入count[1]保存
										 // 64bit+64bit=128bit
	if (context->count[1] < (inputlen << 3))
		context->count[0]++;
	//右移动61位后就是count[0]应该记录的值。（左移3位，溢出的就是右移动61位的）
	context->count[0] += inputlen >> 61;

	//////////////////////////////////////////////////////////
	//                                                        //
	//     如果此次更新的长度，大于原长度同128做差的值，    //
	//     .ie. 加上刚更新的长度满足了128Bytes(1024位)      //
	//     因而可以进行一次加密循环                            //
	//                                                        //
	//////////////////////////////////////////////////////////

	if (inputlen >= partlen)
	{
		//将缺的partlen个字节数据加入缓冲区
		memcpy(&context->buffer[index], input, partlen);
		SHA512Transform(context->state, context->buffer);

		// 如果输入的字，还可以进行（还有整128字的）就继续进行一次加密循环

		for (i = partlen; i + 128 <= inputlen; i += 128)
			SHA512Transform(context->state, &input[i]);
		// 将当前位置设为0
		index = 0;
	}
	else
	{
		i = 0;
	}
	// 重新设置buffer区（处理过的字被覆盖成新字）
	memcpy(&context->buffer[index], &input[i], inputlen - i);
}

void SHA512Final(SHA512_CB *context, unsigned char digest[64]) {

// 用于补齐的数,最多补128字节也就是1024bit
	unsigned char PADDINGg[] = {
			0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	};

	unsigned int index = 0, padlen = 0;
	unsigned char bits[16]; // 记录字长信息
	index = (context->count[1] >> 3) & 0x7F; // 字长除127(11111111)取余长度
	padlen = (index < 112) ? (112 - index) : (240 - index); // 补齐的字长
	SHA512Encode(bits, context->count, 16);
	SHA512Update(context, PADDINGg, padlen);
	SHA512Update(context, bits, 16);
	SHA512Encode(digest, context->state, 64);
}

void SHA512Encode(unsigned char *output, unsigned long long *input, unsigned long long len) {
	unsigned long long i = 0, j = 0;
	while (j < len)
	{
		output[j + 7] = input[i] & 0xFF;
		output[j + 6] = (input[i] >> 8) & 0xFF; //0xFF:11111111
		output[j + 5] = (input[i] >> 16) & 0xFF;
		output[j + 4] = (input[i] >> 24) & 0xFF;
		output[j + 3] = (input[i] >> 32) & 0xFF;
		output[j + 2] = (input[i] >> 40) & 0xFF;
		output[j + 1] = (input[i] >> 48) & 0xFF;
		output[j] = (input[i] >> 56) & 0xFF;
		i++;
		j += 8;
	}
}


void SHA512Decode(unsigned long long *output, unsigned char *input, unsigned long long len) {
	unsigned long long i = 0, j = 0;
	while (j < len)
	{
		output[i] = ((unsigned long long)input[j + 7]) |
			((unsigned long long)input[j + 6] << 8) |
			((unsigned long long)input[j + 5] << 16) |
			((unsigned long long)input[j + 4] << 24) |
			((unsigned long long)input[j + 3] << 32) |
			((unsigned long long)input[j + 2] << 40) |
			((unsigned long long)input[j + 1] << 48) |
			((unsigned long long)input[j] << 56);
		i++;
		j += 8;
	}
}

void SHA512Transform(unsigned long long state[8], unsigned char block[128]) {
	unsigned long long S[8];
	unsigned long long W[80];
	unsigned long long t0;
	unsigned long long t1;
	int i = 0;
	printf("\n填充后(1024bits):\n0x");
	for (int index = 0; index<128; index++) {
		printf("%02x", block[index]);
	}
	printf("\n");
	// 把state的值复制给S
	for (i = 0; i < 8; i++)
	{
		S[i] = state[i];
	}

	// 将字符数组保存的编码转为unsigned long long
	SHA512Decode(W, block, 128);

	for (i = 16; i < 80; i++)
	{
		W[i] = Gamma1(W[i - 2]) + W[i - 7] + Gamma0(W[i - 15]) + W[i - 16];
	}

	for (i = 0; i < 80; i += 8)
	{
		Sha512Round(S[0], S[1], S[2], S[3], S[4], S[5], S[6], S[7], i + 0);
		Sha512Round(S[7], S[0], S[1], S[2], S[3], S[4], S[5], S[6], i + 1);
		Sha512Round(S[6], S[7], S[0], S[1], S[2], S[3], S[4], S[5], i + 2);
		Sha512Round(S[5], S[6], S[7], S[0], S[1], S[2], S[3], S[4], i + 3);
		Sha512Round(S[4], S[5], S[6], S[7], S[0], S[1], S[2], S[3], i + 4);
		Sha512Round(S[3], S[4], S[5], S[6], S[7], S[0], S[1], S[2], i + 5);
		Sha512Round(S[2], S[3], S[4], S[5], S[6], S[7], S[0], S[1], i + 6);
		Sha512Round(S[1], S[2], S[3], S[4], S[5], S[6], S[7], S[0], i + 7);
	}
//	printf("\n");
//	printf("A:%I64u\n", S[0]);
//	printf("B:%I64u\n", S[1]);
//	printf("C:%I64u\n", S[2]);
//	printf("D:%I64u\n", S[3]);
//	printf("E:%I64u\n", S[4]);
//	printf("F:%I64u\n", S[5]);
//	printf("G:%I64u\n", S[6]);
//	printf("H:%I64u\n", S[7]);
//	printf("\n");
	// Feedback
	for (i = 0; i < 8; i++)
	{
		state[i] = state[i] + S[i];
	}
}

//int main(int argc, char* argv[])
//{
//
//	int i;
//	unsigned char input[] = "jack";
//	printf("输入字符串的十六进制: 0x");
//	for (unsigned int i = 0; i<strlen((char*)input); i++) {
//		printf("%02x", input[i]);
//	}
//	printf("\n");
//
//	unsigned char sha512Code[64];
//
//	SHA512_CB sha512;
//
//	SHA512Init(&sha512);
//	SHA512Update(&sha512, input, strlen((char *)input));
//	SHA512Final(&sha512, sha512Code);
//
//	//Md5加密后的32位结果
//	printf("\n加密前:%s\n加密后128位:", input);
//	for (i = 0; i < 64; i++)
//	{
//		printf("%02x", sha512Code[i]);
//	}
//
//	getchar();
//
//	return 0;
//}