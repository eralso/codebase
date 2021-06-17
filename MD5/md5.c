/**
 * 1. 比特填充
 * 2. 附加消息长度 以2的64次方为模数
 * 
 * 分组 Y0, Y1, ..., Y(L-1) (每组512比特)
 * 每一组 Y(i), i = 0, 1, 2, ..., L-1 又可表示成16个32比特长的字，总字数 N=L*16
 * 因此消息又可按字表示成为 M[0, 1, ..., N-1] (M[i] 32比特) (1字=4字节)
 * 
 * MD5算法使用128比特长的缓冲区以存储中间结果和最终杂凑值，缓冲区可表示为4个32比特长的寄存器(A,B,C,D)
 * 
 * 以分组为单位：
 * 1. 每一组 Yq，q=0,1,2,...,L-1 (每组512比特) 都经过压缩函数处理，4轮的处理过程结构一样，但逻辑函数不同，分别是 F,G,H,I  每轮16步
 * 2. 每轮输入为当前处理的消息分组Yq和缓冲区当前的值ABCD，输出仍放在缓冲区以产生新的ABCD
 * 3. 每轮处理过程还需加上常数表T中的16个元素
 * 4. 第4轮的输出再与第1轮的输入CVq相加，相加时将CVq看作4个32比特的字，每个字与第4轮输出的对应的字做模2的32次方加法，结果作为压缩函数的输出
 * 5. 当L个分组都被处理完后，压缩函数最后的输出即为散列算法产生的消息摘要
 * 
 * MD5的压缩函数
 * 共有4轮，每轮对缓冲区ABCD进行16步迭代运算
 * X[K] = M[q * 16 + k]  表示消息第q个分组中的第k个字，k=1,2,...,16
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#define FILE_PATH "md5.cpp"

#define F(x, y, z) ((x & y) | (~x & z))
#define G(x, y, z) ((x & z) | (y & ~z))
#define H(x, y, z) (x ^ y ^ z)
#define I(x, y, z) (y ^ (x | ~z))

#define ROTATE_LEFT(x, n) ((x << n) | (x >> (32 - n)))

#define FF(a, b, c, d, x, s, t)  \
    {                            \
        a += F(b, c, d) + x + t; \
        a = ROTATE_LEFT(a, s);   \
        a += b;                  \
    }
#define GG(a, b, c, d, x, s, t)  \
    {                            \
        a += G(b, c, d) + x + t; \
        a = ROTATE_LEFT(a, s);   \
        a += b;                  \
    }
#define HH(a, b, c, d, x, s, t)  \
    {                            \
        a += H(b, c, d) + x + t; \
        a = ROTATE_LEFT(a, s);   \
        a += b;                  \
    }
#define II(a, b, c, d, x, s, t)  \
    {                            \
        a += I(b, c, d) + x + t; \
        a = ROTATE_LEFT(a, s);   \
        a += b;                  \
    }

typedef struct
{
    unsigned int count[2];    // count[1]高32位，count[0]低32位，存储总位数
    unsigned int state[4];    // 四个32位寄存器 (A, B, C, D) little-endian方式存储数据
    unsigned char buffer[64]; // 缓冲区 64 * 8位 = 512位
} MD5_CTX;

/* 填充部分 100...00 */
unsigned char PADDING[] = {0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                           0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                           0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                           0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

void MD5Init(MD5_CTX *context);
void MD5Update(MD5_CTX *context, unsigned char *input, unsigned int inputlen);
void MD5Final(MD5_CTX *context, unsigned char digest[16]);
void MD5Encode(unsigned char *output, unsigned int *input, unsigned int len);
void MD5Decode(unsigned int *output, unsigned char *input, unsigned int len);
void MD5Transform(unsigned int state[4], unsigned char block[64]);

void MD5Init(MD5_CTX *context)
{
    context->count[0] = 0;
    context->count[1] = 0;
    /* 32位寄存器ABCD的初值 little-endian方式存储 */
    context->state[0] = 0x67452301; // A = 0x01234567
    context->state[1] = 0xEFCDAB89; // B = 0X89ABCDEF
    context->state[2] = 0x98BADCFE; // C = 0XFEDCBA98
    context->state[3] = 0x10325476; // D = 0X76543210
}

/* 将input转换成16个32比特长的字存到output中，即X[0,1,...,15] */
void MD5Decode(unsigned int *output, unsigned char *input, unsigned int len)
{
    unsigned int i = 0, j = 0;
    while (j < len)
    {
        output[i] = (input[j]) | (input[j + 1] << 8) | (input[j + 2] << 16) | (input[j + 3] << 24); // 把每4个char拼接成一个int
        i++, j += 4;
    }
}

/* 64轮变换 */
void MD5Transform(unsigned int state[4], unsigned char block[64])
{
    unsigned int a = state[0];
    unsigned int b = state[1];
    unsigned int c = state[2];
    unsigned int d = state[3];
    unsigned int x[16];      // X[]长32位长
    MD5Decode(x, block, 64); // 计算X[0...15]

    FF(a, b, c, d, x[0], 7, 0xd76aa478);   /* 1 */
    FF(d, a, b, c, x[1], 12, 0xe8c7b756);  /* 2 */
    FF(c, d, a, b, x[2], 17, 0x242070db);  /* 3 */
    FF(b, c, d, a, x[3], 22, 0xc1bdceee);  /* 4 */
    FF(a, b, c, d, x[4], 7, 0xf57c0faf);   /* 5 */
    FF(d, a, b, c, x[5], 12, 0x4787c62a);  /* 6 */
    FF(c, d, a, b, x[6], 17, 0xa8304613);  /* 7 */
    FF(b, c, d, a, x[7], 22, 0xfd469501);  /* 8 */
    FF(a, b, c, d, x[8], 7, 0x698098d8);   /* 9 */
    FF(d, a, b, c, x[9], 12, 0x8b44f7af);  /* 10 */
    FF(c, d, a, b, x[10], 17, 0xffff5bb1); /* 11 */
    FF(b, c, d, a, x[11], 22, 0x895cd7be); /* 12 */
    FF(a, b, c, d, x[12], 7, 0x6b901122);  /* 13 */
    FF(d, a, b, c, x[13], 12, 0xfd987193); /* 14 */
    FF(c, d, a, b, x[14], 17, 0xa679438e); /* 15 */
    FF(b, c, d, a, x[15], 22, 0x49b40821); /* 16 */

    /* Round 2 */
    GG(a, b, c, d, x[1], 5, 0xf61e2562);   /* 17 */
    GG(d, a, b, c, x[6], 9, 0xc040b340);   /* 18 */
    GG(c, d, a, b, x[11], 14, 0x265e5a51); /* 19 */
    GG(b, c, d, a, x[0], 20, 0xe9b6c7aa);  /* 20 */
    GG(a, b, c, d, x[5], 5, 0xd62f105d);   /* 21 */
    GG(d, a, b, c, x[10], 9, 0x2441453);   /* 22 */
    GG(c, d, a, b, x[15], 14, 0xd8a1e681); /* 23 */
    GG(b, c, d, a, x[4], 20, 0xe7d3fbc8);  /* 24 */
    GG(a, b, c, d, x[9], 5, 0x21e1cde6);   /* 25 */
    GG(d, a, b, c, x[14], 9, 0xc33707d6);  /* 26 */
    GG(c, d, a, b, x[3], 14, 0xf4d50d87);  /* 27 */
    GG(b, c, d, a, x[8], 20, 0x455a14ed);  /* 28 */
    GG(a, b, c, d, x[13], 5, 0xa9e3e905);  /* 29 */
    GG(d, a, b, c, x[2], 9, 0xfcefa3f8);   /* 30 */
    GG(c, d, a, b, x[7], 14, 0x676f02d9);  /* 31 */
    GG(b, c, d, a, x[12], 20, 0x8d2a4c8a); /* 32 */

    /* Round 3 */
    HH(a, b, c, d, x[5], 4, 0xfffa3942);   /* 33 */
    HH(d, a, b, c, x[8], 11, 0x8771f681);  /* 34 */
    HH(c, d, a, b, x[11], 16, 0x6d9d6122); /* 35 */
    HH(b, c, d, a, x[14], 23, 0xfde5380c); /* 36 */
    HH(a, b, c, d, x[1], 4, 0xa4beea44);   /* 37 */
    HH(d, a, b, c, x[4], 11, 0x4bdecfa9);  /* 38 */
    HH(c, d, a, b, x[7], 16, 0xf6bb4b60);  /* 39 */
    HH(b, c, d, a, x[10], 23, 0xbebfbc70); /* 40 */
    HH(a, b, c, d, x[13], 4, 0x289b7ec6);  /* 41 */
    HH(d, a, b, c, x[0], 11, 0xeaa127fa);  /* 42 */
    HH(c, d, a, b, x[3], 16, 0xd4ef3085);  /* 43 */
    HH(b, c, d, a, x[6], 23, 0x4881d05);   /* 44 */
    HH(a, b, c, d, x[9], 4, 0xd9d4d039);   /* 45 */
    HH(d, a, b, c, x[12], 11, 0xe6db99e5); /* 46 */
    HH(c, d, a, b, x[15], 16, 0x1fa27cf8); /* 47 */
    HH(b, c, d, a, x[2], 23, 0xc4ac5665);  /* 48 */

    /* Round 4 */
    II(a, b, c, d, x[0], 6, 0xf4292244);   /* 49 */
    II(d, a, b, c, x[7], 10, 0x432aff97);  /* 50 */
    II(c, d, a, b, x[14], 15, 0xab9423a7); /* 51 */
    II(b, c, d, a, x[5], 21, 0xfc93a039);  /* 52 */
    II(a, b, c, d, x[12], 6, 0x655b59c3);  /* 53 */
    II(d, a, b, c, x[3], 10, 0x8f0ccc92);  /* 54 */
    II(c, d, a, b, x[10], 15, 0xffeff47d); /* 55 */
    II(b, c, d, a, x[1], 21, 0x85845dd1);  /* 56 */
    II(a, b, c, d, x[8], 6, 0x6fa87e4f);   /* 57 */
    II(d, a, b, c, x[15], 10, 0xfe2ce6e0); /* 58 */
    II(c, d, a, b, x[6], 15, 0xa3014314);  /* 59 */
    II(b, c, d, a, x[13], 21, 0x4e0811a1); /* 60 */
    II(a, b, c, d, x[4], 6, 0xf7537e82);   /* 61 */
    II(d, a, b, c, x[11], 10, 0xbd3af235); /* 62 */
    II(c, d, a, b, x[2], 15, 0x2ad7d2bb);  /* 63 */
    II(b, c, d, a, x[9], 21, 0xeb86d391);  /* 64 */
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
}

/* 将输入的字符串input更新同步到MD5_CTX中 */
void MD5Update(MD5_CTX *context, unsigned char *input, unsigned int inputlen)
{
    unsigned int i = 0, idx = 0, partlen = 0;
    idx = (context->count[0] >> 3) & 0x3F; // 取当前buffer中有多少字符
    // buffer缓冲区最大64位，count[0]记录总位数，count[0]/8是char的长度，取后也就是看当前buffer中的字符数
    partlen = 64 /*个字符char*/ - idx;  // 空位
    context->count[0] += inputlen << 3; // (char长度)input * 8位 = 总位数
    if (context->count[0] < (inputlen << 3))
        context->count[1]++;             // count[0]越界了，进位给count[1]
    context->count[1] += inputlen >> 29; // input再右移29位相当于总位数右移32位，超出部分存在count[1]里

    // 对缓冲区分块处理，每次处理512位，即64个字符
    if (inputlen >= partlen) /* 如果输入长度大于等于空位长 */
    {
        memcpy(&context->buffer[idx], input, partlen); // 补全空位
        MD5Transform(context->state, context->buffer);
        for (i = partlen; i + 64 <= inputlen; i += 64) // 对剩余input每64个字符即512bit分组处理
            MD5Transform(context->state, &input[i]);
        idx = 0;
    }
    else
    {
        i = 0;
    }
    memcpy(&context->buffer[idx], &input[i], inputlen - i); // 把最后剩余的input存到MD5结构体中
}

/* 把input重新编码到output里 */
void MD5Encode(unsigned char *output, unsigned int *input, unsigned int len)
{
    unsigned int i = 0, j = 0;
    while (j < len)
    {
        /* 每个input[i]分成4个8位 */
        output[j] = input[i] & 0xFF;
        output[j + 1] = (input[i] >> 8) & 0xFF;
        output[j + 2] = (input[i] >> 16) & 0xFF;
        output[j + 3] = (input[i] >> 24) & 0xFF;
        i++, j += 4;
    }
}

/* 最终结果输出一个固定长度的字符串，从MD5_CTX中输出到digest中 16*8位=128位 */
void MD5Final(MD5_CTX *context, unsigned char digest[16])
{
    unsigned int index = 0, padlen = 0;                       // padding需要填充的长度
    unsigned char bits[8];                                    // 64位待填充文件长度
    index = (context->count[0] >> 3) & 0x3F;                  // 当前buffer中的字符数
    padlen = (index < 56) ? (56 - index) : (56 + 64 - index); // 小于448，大于等于448需要再补512
    MD5Encode(bits, context->count, 8);                       // 计算文件长度
    MD5Update(context, PADDING, padlen);                      // 填充padlen长度的padding=1000...0到buffer中
    MD5Update(context, bits, 8);                              // 填充长度到buffer中
    MD5Encode(digest, context->state, 16);                    // 把ABCD四个寄存器输出到digest中，16*8位 = 128位
}

int calc_md5(char *filepath, char *dest)
{
    int i;
    long long int file_len = 0;
    int read_len = 0;
    char temp[8] = {0};
    char hexbuffer[128] = {0};       // 读入缓冲区
    unsigned char decrypt[16] = {0}; // MD5摘要结果
    unsigned char decrypt32[64] = {0};

    MD5_CTX md5;

    int fp;
    fp = open(FILE_PATH, O_RDWR);
    if (fp < 0)
    {
        printf("\"%s\" does not exist.\n", FILE_PATH);
        return -1;
    }

    MD5Init(&md5); // 初始化MD5_CTX

    while (1)
    {
        read_len = read(fp, hexbuffer, sizeof(hexbuffer)); // 一次读入1K
        if (read_len < 0)
        {
            close(fp);
            return -1;
        }
        if (read_len == 0)
            break;
        file_len += (long long int)read_len; // 统计文件总大小

        MD5Update(&md5, (unsigned char *)hexbuffer, read_len);
    }

    MD5Final(&md5, decrypt); // 最终结果存到decrypt中

    strcpy((char *)decrypt32, ""); // 清空decrypt32

    for (i = 0; i < 16; i++)
    {
        sprintf(temp, "%02x", decrypt[i]); // 8位二进制转2位十六进制
        strcat((char *)decrypt32, temp);   // 拼接到decrypt32后面
    }
    strcpy(dest, (char *)decrypt32);

    printf("md5: %s\nCharacter length = %lld\n", dest, file_len);
    close(fp);

    return file_len;
}

int main()
{
    int file_len = 0;
    char md5_str[64] = {0};

    file_len = calc_md5(FILE_PATH, md5_str);
    if (file_len < 0)
    {
        printf("MD5 calculation failed...\n");
        return -1;
    }
    return 0;
}
