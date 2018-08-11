//#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef unsigned char u8;
typedef unsigned int u32;

#define MIN(a, b) ((a) <= (b) ? (a) : (b))
#define MAX(a, b) ((a) >= (b) ? (a) : (b))
#define PMOD(a, b) (((a) + (b)) % (b))

#ifdef _WIN32
#define FMT_SIZE "%Iu"
#else
#define FMT_SIZE "%zu"
#endif

#define lament(...) fprintf(stderr, __VA_ARGS__)
#define error_when(cond, ...) do { \
        if ((cond) || errno) { \
            lament(__VA_ARGS__); \
            lament(": %s\n", strerror(errno)); \
            goto error; \
        } \
    } while (0)

#define BUF_LEN 1024
#define MIN_LEN 3
#define MAX_LEN 66
#define BUF_START 0x3BE

#ifndef RW_OVERLAP
#define RW_OVERLAP 1
#endif

long compress(const u8 *bufi, long size, u8 *bufo) {
    // this function cannot fail.
    // just ensure bufo points to enough memory to hold the compressed data.
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
#if RW_OVERLAP
                int overlap = 0;
#endif
                for (;;) {
                    int buf_off = (match_i + match_len) % BUF_LEN;
#if RW_OVERLAP
                    if (overlap > 0 || (buf_off == buf_i && j != 0)) {
                        if (sub[overlap % j] != sub[match_len]) break;
                        overlap++;
                    } else {
                        if (buf[buf_off] != sub[match_len]) break;
                    }
#else
                    if (buf_off == buf_i && j != 0) break;
                    if (buf[buf_off] != sub[match_len]) break;
#endif
                    match_len++;
                    if (match_len == MAX_LEN) break;
                    if (match_len == sub_len) break;
                }

                if (match_len < MIN_LEN) continue;
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
    FILE *f = NULL;
    u8 *bufi = NULL;
    u8 *bufo = NULL;
    char fs_buf[4] = {0};
    long size = 0;
    long new_size = 0;

    errno = 0;

    f = fopen(fp, "rb");
    error_when(f == NULL, "Error opening file: %s", fp);

    error_when(fseek(f, 0, SEEK_END) != 0, "Error seeking in file: %s", fp);
    size = ftell(f);
    error_when(size < 0, "Error telling in file: %s", fp);
    error_when(fseek(f, 0, SEEK_SET) != 0, "Error seeking in file: %s", fp);

    if (size > 0) {
        bufi = (u8 *)malloc(size);
        error_when(bufi == NULL, "Error allocating %li bytes", size);
        error_when(fread(bufi, 1, size, f) != (size_t)size, "Error reading %li bytes from file: %s", size, fp);
    }

    error_when(fclose(f) != 0, "Error closing file: %s", fp);

    if (size > 0) {
        // allocate enough for the worst case scenario.
        size_t bufo_size = size * 9 / 8 + 8;
        bufo = (u8 *)malloc(bufo_size);
        error_when(bufo == NULL, "Error allocating " FMT_SIZE " bytes", bufo_size);

        new_size = compress(bufi, size, bufo);
        //assert(new_size > 0 && (size_t)new_size < bufo_size);
    }

    f = fopen(fp, "wb");
    error_when(f == NULL, "Error opening file: %s", fp);

    fs_buf[0] = (size >> 24) & 0xFF;
    fs_buf[1] = (size >> 16) & 0xFF;
    fs_buf[2] = (size >> 8) & 0xFF;
    fs_buf[3] = size & 0xFF;
    error_when(fwrite(fs_buf, 1, 4, f) != 4, "Error writing %i bytes to file: %s", 4, fp);

    if (new_size > 0) {
        error_when(fwrite(bufo, 1, new_size, f) != (size_t)new_size, "Error writing %i bytes to file: %s", 4, fp);
    }

    error_when(fclose(f) != 0, "Error closing file: %s", fp);

    free(bufi);
    free(bufo);
    return 0;

error:
    free(bufi);
    free(bufo);
    return 1;
}

int main(int argc, char *argv[]) {
    if (argc <= 0 || argv == NULL || argv[0] == NULL) {
        lament("You've met with a terrible fate.\n");
        return 1;
    }
    const char *name = argv[0];
    if (argc == 1) {
        lament("compressor: compress files in-place for Bomberman 64.\n");
        lament("usage: %s {file}\n", name);
        return 1;
    } else if (argc == 2) {
        const char *fp = argv[1];
        int ret = compress_file(fp);
        return ret;
    } else {
        lament("Error: too many arguments\n");
        lament("usage: %s {file}\n", name);
        return 1;
    }
}
