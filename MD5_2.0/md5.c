#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#define FILE_PATH "123.txt"

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

/* 常数表T 32比特的字 */
const unsigned int T[] = {
    /* 1-16 */
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    /* 17-32 */
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    /* 33-48 */
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    /* 49-64 */
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391};

/* 压缩函数每部循环左移位的位数 */
const int CLSstep[] = {7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
                       5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
                       4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
                       6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};

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
        /* 把每4个字节拼接成一个int，按照little-endian方式，低位存到低地址 */
        output[i] = (input[j]) | (input[j + 1] << 8) | (input[j + 2] << 16) | (input[j + 3] << 24);
        i++, j += 4;
    }
}

void Register_shift(unsigned int *a, unsigned int *b, unsigned int *c, unsigned int *d)
{
    unsigned int tmp;
    tmp = *d;
    *d = *c;
    *c = *b;
    *b = *a;
    *a = tmp;
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
    int i;
    /* Round 1 */
    for (i = 0; i < 16; i++)
    {
        FF(a, b, c, d, x[i], CLSstep[i], T[i]);
        Register_shift(&a, &b, &c, &d);
    }
    /* Round 2 */
    for (i = 0; i < 16; i++)
    {
        GG(a, b, c, d, x[(1 + 5 * i) % 16], CLSstep[i + 16], T[i + 16]);
        Register_shift(&a, &b, &c, &d);
    }
    /* Round 3 */
    for (i = 0; i < 16; i++)
    {
        HH(a, b, c, d, x[(5 + 3 * i) % 16], CLSstep[i + 16 * 2], T[i + 16 * 2]);
        Register_shift(&a, &b, &c, &d);
    }
    /* Round 4 */
    for (i = 0; i < 16; i++)
    {
        II(a, b, c, d, x[7 * i % 16], CLSstep[i + 16 * 3], T[i + 16 * 3]);
        Register_shift(&a, &b, &c, &d);
    }
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
}

/* 将输入的字符串input更新同步到MD5_CTX中 */
void MD5Update(MD5_CTX *context, unsigned char *input, unsigned int inputlen)
{
    unsigned int i = 0, idx = 0, partlen = 0;
    idx = (context->count[0] >> 3) & 0x3F; // 取当前buffer中有多少字符; buffer缓冲区最大64位，count[0]记录总位数，count[0]/8是char的长度，取后也就是看当前buffer中的字符数
    partlen = 64 - idx;                    // 空的字节数
    context->count[0] += inputlen << 3;    // (char长度)input * 8位 = 总位数
    if (context->count[0] < (inputlen << 3))
        context->count[1]++;             // count[0]越界了，进位给count[1]
    context->count[1] += inputlen >> 29; // input再右移29位相当于总位数右移32位，超出部分存在count[1]里

    // 对缓冲区分块处理，每次处理512位，即64个字符
    if (inputlen >= partlen)
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
        /* 每个input[i]分成4个字节，按little-endian存到output[]中 */
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
