#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef unsigned char u8;

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

int compress(const u8 *bufi, int size, u8 *bufo) {
    int i = 0;
    int written = 0;
    while (i < size) {
        int flag_i = written;
        int flags = 0x00;
        bufo[written++] = 0;

        for (int j = 0; j < 8; j++) {
            if (i == size) break;
            int best_match = 0;
            int best_len = 0;

            for (int match = BUF_LEN; match > 0; match--) {
                int len = 0;
                int left = i - match;
                int right = i;
                while (bufi[left++] == bufi[right++]) {
                    if (left == i) left -= match;
                    len++;
                    if (right >= size) break;
                    if (len >= MAX_LEN) break;
                }
                if (len > best_len) {
                    best_len = len;
                    best_match = match;
                    if (len == MAX_LEN) break;
                }
            }

            if (best_len < MIN_LEN) {
                flags |= 1 << j;
                bufo[written++] = bufi[i++];
            } else {
                int buf_match = (i + BUF_START - best_match) & 0x3FF;
                //lament("$%03X:%i\n", buf_match, best_len);
                int a = buf_match & 0xFF;
                int b = ((buf_match & 0x300) >> 2) | (best_len - 3);
                bufo[written++] = a;
                bufo[written++] = b;
                i += best_len;
            }
        }

        bufo[flag_i] = flags;
    }
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
        bufi = (u8 *)malloc(size + BUF_LEN);
        for (int i = 0; i < BUF_LEN; i++) bufi[i] = 0;
        error_when(bufi == NULL, "Error allocating %li bytes", size + BUF_LEN);
        error_when(fread(bufi + BUF_LEN, 1, size, f) != (size_t)size, "Error reading %li bytes from file: %s", size, fp);
    }

    error_when(fclose(f) != 0, "Error closing file: %s", fp);

    if (size > 0) {
        // allocate enough for the worst case scenario.
        size_t bufo_size = size * 9 / 8 + 8;
        bufo = (u8 *)malloc(bufo_size);
        error_when(bufo == NULL, "Error allocating " FMT_SIZE " bytes", bufo_size);
        new_size = compress(bufi + BUF_LEN, size, bufo);
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
        lament("compressor: compress files in-place with LZSS\n");
        lament("compatible with Bomberman 64 and Mario Party 1\n");
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
