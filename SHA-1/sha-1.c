#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#define FILE_PATH "123.txt"

#define F1(x, y, z) ((x & y) | (~x & z))
#define F2(x, y, z) (x ^ y ^ z)
#define F3(x, y, z) ((x & y) | (x & z) | (y & z))
#define F4(x, y, z) (x ^ y ^ z)

#define ROTATE_LEFT(x, n) (((x) << n) | ((x) >> (32 - n)))

#define FF1(a, b, c, d, e, w, k)                      \
    {                                                 \
        e += F1(b, c, d) + ROTATE_LEFT(a, 5) + w + k; \
        b = ROTATE_LEFT(b, 30);                       \
    }
#define FF2(a, b, c, d, e, w, k)                      \
    {                                                 \
        e += F2(b, c, d) + ROTATE_LEFT(a, 5) + w + k; \
        b = ROTATE_LEFT(b, 30);                       \
    }
#define FF3(a, b, c, d, e, w, k)                      \
    {                                                 \
        e += F3(b, c, d) + ROTATE_LEFT(a, 5) + w + k; \
        b = ROTATE_LEFT(b, 30);                       \
    }
#define FF4(a, b, c, d, e, w, k)                      \
    {                                                 \
        e += F4(b, c, d) + ROTATE_LEFT(a, 5) + w + k; \
        b = ROTATE_LEFT(b, 30);                       \
    }

typedef struct
{
    unsigned int count[2];    // 总比特数，count[0]高位，count[1]地位
    unsigned int state[5];    // 五个32位寄存器 (A, B, C, D, E) big-endian方式
    unsigned char buffer[64]; // 分组缓冲区 64 * 8bit = 512bit
} SHA_1;

/* 填充部分 100...00 */
unsigned char PADDING[] = {0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                           0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                           0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                           0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

void SHA1Init(SHA_1 *context)
{
    context->count[1] = 0;
    context->count[0] = 0;
    /* 32位寄存器ABCDE的初值 big-endian方式存储 */
    context->state[0] = 0x67452301;
    context->state[1] = 0xEFCDAB89;
    context->state[2] = 0x98BADCFE;
    context->state[3] = 0x10325476;
    context->state[4] = 0xC3D2E1F0;
}

/* 计算W[] */
void SHA1Decode(unsigned int *output, unsigned char *input, unsigned int len)
{
    unsigned int i = 0, j = 0;
    while (j < len)
    {
        output[i] = (input[j] << 24) | (input[j + 1] << 16) | (input[j + 2] << 8) | (input[j + 3]); // big-endian方式
        i++, j += 4;
    }
    for (i = 16; i < 80; i++)
    {
        output[i] = (output[i - 16] ^ output[i - 14] ^ output[i - 8] ^ output[i - 3]);
        output[i] = ROTATE_LEFT(output[i], 1);
    }
}

void Register_shift(unsigned int *a, unsigned int *b, unsigned int *c, unsigned int *d, unsigned int *e)
{
    unsigned int tmp;
    tmp = *e;
    *e = *d;
    *d = *c;
    *c = *b;
    *b = *a;
    *a = tmp;
}

/* 64轮变换 */
void SHA1Transform(unsigned int state[5], unsigned char block[64])
{
    unsigned int a = state[0];
    unsigned int b = state[1];
    unsigned int c = state[2];
    unsigned int d = state[3];
    unsigned int e = state[4];
    unsigned int w[80];       // X[]长32位长
    SHA1Decode(w, block, 64); // 计算X[0...15]
    int i;
    /* Round 1 */
    for (i = 0; i < 20; i++)
    {
        FF1(a, b, c, d, e, w[i], 0x5A827999);
        Register_shift(&a, &b, &c, &d, &e);
    }
    for (i = 20; i < 40; i++)
    {
        FF2(a, b, c, d, e, w[i], 0x6ED9EBA1);
        Register_shift(&a, &b, &c, &d, &e);
    }
    for (i = 40; i < 60; i++)
    {
        FF3(a, b, c, d, e, w[i], 0x8F1BBCDC);
        Register_shift(&a, &b, &c, &d, &e);
    }
    for (i = 60; i < 80; i++)
    {
        FF4(a, b, c, d, e, w[i], 0xCA62C1D6);
        Register_shift(&a, &b, &c, &d, &e);
    }
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
}

/* 把input重新编码到output里 */
void SHA1Encode(unsigned char *output, unsigned int *input, unsigned int len)
{
    unsigned int i = 0, j = 0;
    while (j < len)
    {
        /* big-endian */
        output[j] = (input[i] >> 24) & 0xFF;
        output[j + 1] = (input[i] >> 16) & 0xFF;
        output[j + 2] = (input[i] >> 8) & 0xFF;
        output[j + 3] = input[i] & 0xFF;
        i++, j += 4;
    }
}

/* 将输入的字符串input更新同步到SHA1中 */
void SHA1Update(SHA_1 *context, unsigned char *input, unsigned int inputlen)
{
    unsigned int i = 0, idx = 0, partlen = 0;
    idx = (context->count[1] >> 3) & 0x3F; // 取当前buffer中有多少字符
    partlen = 64 - idx;
    context->count[1] += inputlen << 3;
    if (context->count[1] < (inputlen << 3))
        context->count[0]++; // count[1]越界了，进位给count[0]

    /* 对缓冲区分块处理，每次处理512位，即64个字节 */
    if (inputlen >= partlen)
    {
        memcpy(&context->buffer[idx], input, partlen); // 补全空位
        SHA1Transform(context->state, context->buffer);
        for (i = partlen; i + 64 <= inputlen; i += 64) // 对剩余input每64个字符即512bit分组处理
            SHA1Transform(context->state, &input[i]);
        idx = 0;
    }
    else
    {
        i = 0;
    }
    memcpy(&context->buffer[idx], &input[i], inputlen - i); // 把最后剩余的input存到SHA1结构体中
}

/* 最终结果输出一个固定长度的字符串，从SHA1_CTX中输出到digest中 */
void SHA1Final(SHA_1 *context, unsigned char digest[20])
{
    unsigned int index = 0, padlen = 0;                       // padding需要填充的长度
    unsigned char bits[8];                                    // 64位待填充文件长度
    index = (context->count[1] >> 3) & 0x3F;                  // 当前buffer中的字符数
    padlen = (index < 56) ? (56 - index) : (56 + 64 - index); // 小于448，大于等于448需要再补512
    SHA1Encode(bits, context->count, 8);                      // 计算文件长度
    SHA1Update(context, PADDING, padlen);                     // 填充padlen长度的padding=1000...0到buffer中
    SHA1Update(context, bits, 8);                             // 填充长度到buffer中
    SHA1Encode(digest, context->state, 20);                   // 把ABCDE五个寄存器输出到digest中
}

int calc_sha1(char *filepath, char *dest)
{
    int i;
    long long int file_len = 0;
    int read_len = 0;
    char temp[8] = {0};
    char hexbuffer[128] = {0};       // 1K缓冲区
    unsigned char decrypt[20] = {0}; // SHA1摘要结果
    unsigned char decrypt32[40] = {0};

    SHA_1 SHA1;

    int fp;
    fp = open(FILE_PATH, O_RDWR);
    if (fp < 0)
    {
        printf("\"%s\" does not exist.\n", FILE_PATH);
        return -1;
    }

    SHA1Init(&SHA1); // 初始化SHA_1

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

        SHA1Update(&SHA1, (unsigned char *)hexbuffer, read_len);
    }

    SHA1Final(&SHA1, decrypt); // 结果存到decrypt中

    strcpy((char *)decrypt32, ""); // 清空decrypt32

    for (i = 0; i < 20; i++)
    {
        sprintf(temp, "%02x", decrypt[i]); // 8位二进制转2位十六进制
        strcat((char *)decrypt32, temp);   // 拼接到decrypt32后面
    }
    strcpy(dest, (char *)decrypt32);

    printf("SHA1: %s\nCharacter length = %lld\n", dest, file_len);
    close(fp);

    return file_len;
}

int main()
{
    int file_len = 0;
    char sha1_str[40] = {0}; // 存储sha-1安全散列结果

    file_len = calc_sha1(FILE_PATH, sha1_str);
    if (file_len < 0)
    {
        printf("SHA1 calculation failed...\n");
        return -1;
    }
    return 0;
}
