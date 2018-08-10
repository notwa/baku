#include <stdio.h>
#include <stdlib.h>
#include <string.h>
//#include <assert.h>

typedef unsigned char u8;
typedef unsigned int u32;

#define MIN(a, b) ((a) <= (b) ? (a) : (b))
#define MAX(a, b) ((a) >= (b) ? (a) : (b))
#define PMOD(a, b) (((a) + (b)) % (b))

#define BUF_LEN 1024
#define MIN_LEN 3
#define MAX_LEN 66
#define BUF_START 0x3BE

char *program_name;

long compress(const u8 *bufi, long size, u8 *bufo) {
    u8 buf[BUF_LEN] = {0};
    int buf_i = BUF_START;

    int shift = 0;
    int shifted = 0;
    int last_shift_i = -1;
    long written = 0;

    int i = 0;
    while (i < size) {
        const u8 *sub = bufi + i;
        int sub_len = MIN(MAX_LEN, size - i);
        int best_i = -1;
        int best_len = -1;

        if (sub_len >= MIN_LEN) {
            for (int j = 0; j < BUF_LEN; j++) {
                int match_i = PMOD(buf_i - j, BUF_LEN);
                int match_len = 0;
                for (;;) {
                    int buf_off = (match_i + match_len) % BUF_LEN;
                    u8 b = buf[buf_off];
                    if (b != sub[match_len]) { break; }
                    // TODO: handle pseudo-writes to buffer.
                    if (buf_off == buf_i) { break; }
                    match_len++;
                    if (match_len == MAX_LEN) { break; }
                    if (match_len == sub_len) { break; }
                }

                if (match_len < MIN_LEN) { continue; }
                if (match_len > best_len) {
                    best_i = match_i;
                    best_len = match_len;
                }
            }
        }

        if (last_shift_i < 0) {
            last_shift_i = written;
            bufo[written++] = 0;
            shift = 0;
            shifted = 0;
        }

        if (best_i < 0 || best_len < 0) {
            shift >>= 1;
            shift |= 0x80;
            shifted++;

            bufo[written++] = sub[0];
            buf[buf_i] = sub[0];
            buf_i = (buf_i + 1) % BUF_LEN;
            i++;
        } else {
            shift >>= 1;
            shifted++;

            u8 a = best_i & 0xFF;
            u8 b = ((best_i & 0x300) >> 2) | (best_len - 3);
            bufo[written++] = a;
            bufo[written++] = b;

            for (int j = 0; j < best_len; j++) {
                buf[buf_i] = sub[j];
                buf_i = (buf_i + 1) % BUF_LEN;
            }
            i += best_len;
        }

        if (shifted >= 8) {
            //assert(last_shift_i != -1);
            bufo[last_shift_i] = shift;
            shift = 0;
            shifted = 0;
            last_shift_i = -1;
        }
    }

    if (last_shift_i >= 0) {
        bufo[last_shift_i] = shift >> (8 - shifted);
    }

    //assert(i == size);

    return written;
}

int compress_file(const char *fp) {
    // TODO: better error handling.
    // functions here that can fail:
    // fclose
    // fopen
    // fseek
    // ftell
    // fwrite
    // malloc
    // calloc
    // free?

    FILE *f = fopen(fp, "rb");
    if (f == NULL) {
        perror(program_name);
        return 1;
    }

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (size == 0) {
        return 0;
    }

    u8 *bufi = (u8 *)malloc(size);
    if (bufi == NULL) {
        fprintf(stderr, "failed to malloc %li bytes\n", size);
        free(bufi);
        return 2;
    }
    fread(bufi, 1, size, f);
    fclose(f);

    // allocate enough for the worst case scenario.
    size_t bufo_size = size * 9 / 8 + 8;
    u8 *bufo = (u8 *)malloc(bufo_size);

    long new_size = compress(bufi, size, bufo);
    free(bufi);
    //assert(new_size > 0 && (size_t)new_size < bufo_size);

    f = fopen(fp, "wb");
    if (f == NULL) {
        perror(program_name);
        free(bufo);
        return 3;
    }

    char fs_buf[4] = {0};
    fs_buf[0] = (size >> 24) & 0xFF;
    fs_buf[1] = (size >> 16) & 0xFF;
    fs_buf[2] = (size >> 8) & 0xFF;
    fs_buf[3] = size & 0xFF;
    fwrite(fs_buf, 1, 4, f);

    fwrite(bufo, 1, new_size, f);
    fclose(f);
    free(bufo);

    return 0;
}

int main(int argc, char *argv[]) {
    if (argc <= 0 || argv == NULL || argv[0] == NULL) {
        fprintf(stderr, "You've met with a terrible fate.\n");
        exit(1);
    }
    program_name = argv[0];

    if (argc == 1) {
        fprintf(stderr, "usage: %s {file}\n", program_name);
        exit(2);
    } else if (argc == 2) {
        const char *fp = argv[1];
        int ret = compress_file(fp);
        if (ret != 0) {
            exit(ret + 3);
        }
    } else {
        fprintf(stderr, "too many arguments\n");
        exit(3);
    }
}
