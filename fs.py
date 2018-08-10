#!/usr/bin/env python3

from hashlib import sha1
from io import BytesIO
import argparse
import os
import os.path
import sys

from util import *

DEBUG = False

lament = lambda *args, **kwargs: print(*args, file=sys.stderr, **kwargs)
heresay = os.path.split(sys.argv[0])[0]

# TODO: don't hardcode this? look into how the game handles it.
blocks = (
    (0x120000, 0x20000),
    (0x140000, 0x20000),
    (0x160000, 0x20000),
    (0x180000, 0x20000),
    (0x1A0000, 0x20000),
    (0x1C0000, 0x20000),
    (0x1E0000, 0x20000),
    (0x200000, 0x40000),
    (0x240000, 0x20000),
    (0x260000, 0x20000),
    (0x280000, 0x20000),
    (0x2A0000, 0x20000),
    (0x2C0000, 0x20000),
    (0x2E0000, 0x20000),
    (0x300000, 0x500000),
)

def hexdump(data):
    # for debugging.
    for i in range((len(data) + 15) // 16):
        butts = data[i * 16:i * 16 + 16]
        print(("{:06X} |" + " {:02X}" * len(butts)).format(i * 16, *butts))

def compress(data, mode="greedy"):
    assert mode in "worst greedy best".split(), f"unknown mode: {mode}"

    comp = bytearray()
    comp.extend(W4(len(data)))
    if len(data) == 0:
        return comp

    buf_len = 1024
    buf = bytearray(buf_len)
    buf_i = 0x3BE
    min_len = 0 + 3
    max_len = 0x3F + 3

    def find_match(sub):
        if mode == "worst" or len(sub) < min_len:
            return None, None
        best_i, best_len = None, None

        for i in range(buf_len):
            match_i, match_len = (buf_i - i) % buf_len, 0
            while buf[(match_i + match_len) % buf_len] == sub[match_len]:
                if (match_i + match_len) % buf_len == buf_i:
                    # TODO: handle pseudo-writes to buffer.
                    break
                match_len += 1
                if match_len == max_len:
                    break
                if match_len == len(sub):
                    break
            if match_len < min_len:
                match_i, match_len = None, None
                continue
            if best_len is None or match_len > best_len:
                best_i = match_i
                best_len = match_len
            if mode == "greedy":
                break

        if best_len is not None:
            assert min_len <= best_len <= max_len
        return best_i, best_len

    shift = 0
    shifted = 0
    last_shift_i = None

    def push_shift():
        nonlocal comp, shift, shifted
        assert last_shift_i is not None
        comp[last_shift_i] = shift
        shift = 0
        shifted = 0

    def shift_in(x):
        nonlocal shift, shifted
        assert 0 <= x <= 1
        assert shifted < 8
        shift >>= 1
        shift |= x << 7
        shifted += 1

    i = 0
    while i < len(data):
        sub = data[i:i + max_len]
        match_i, match_len = find_match(sub)

        if DEBUG:
            if len(sub) < min_len:
                print("pos {:06X}: too short to match".format(i))
            else:
                match_str = "no match"
                if match_i is not None:
                    match_str = "{:03X}:{}".format(match_i, match_len)
                fmt = "pos {:06X}: matching {:02X}{:02X}{:02X}: {}"
                print(fmt.format(i, sub[0], sub[1], sub[2], match_str))

        if last_shift_i is None:
            last_shift_i = len(comp)
            comp.append(0)
            shift = 0
            shifted = 0

        if match_i is None or match_len is None:
            shift_in(1)
            comp.append(sub[0])
            buf[buf_i] = sub[0]
            i += 1
            buf_i = (buf_i + 1) % buf_len
        else:
            shift_in(0)
            a = match_i & 0xFF
            b = ((match_i & 0x300) >> 2) | (match_len - 3)
            comp.append(a)
            comp.append(b)
            for j in range(match_len):
                buf[buf_i] = sub[j]
                buf_i = (buf_i + 1) % buf_len
            i += match_len

        if shifted == 8:
            push_shift()
            last_shift_i = None

    if last_shift_i is not None:
        comp[last_shift_i] = shift >> (8 - shifted)

    if DEBUG:
        decompress(comp[4:], len(data))

    assert i == len(data)
    return comp

def decompress(data, expected_size):
    decomp = bytearray()
    if len(data) == 0:
        return decomp

    buf = bytearray(1024)
    buf_i = 0x3BE

    def write(b):
        nonlocal decomp, buf, buf_i
        decomp.append(b)
        buf[buf_i] = b
        buf_i += 1
        buf_i %= len(buf)

    def read_buf(o):
        nonlocal buf
        o = o % len(buf)
        return buf[o]

    i = 0
    shift = 0
    while i < len(data) and len(decomp) < expected_size:
        shift >>= 1
        if shift & 0x100 == 0:
            #print(f"comm: {data[i]:02X}")
            shift = data[i] | 0xFF00
            i += 1
        if shift & 1 != 0:
            #print(f"dump: {data[i]:02X}")
            write(data[i])
            i += 1
        else:
            a, b = data[i], data[i + 1]
            copy_offset = ((b & 0xC0) << 2) | a
            copy_length = (b & 0x3F) + 3
            #print(f"copy: {copy_offset:03X}, {copy_length}")
            for ci in range(copy_length):
                write(read_buf(copy_offset + ci))
            i += 2

    if DEBUG:
        hexdump(data)
        print("-" * (6 + 2 + 3 * 16))
        hexdump(decomp)

    if len(decomp) > expected_size:
        raise Exception("decomp is larger than it said it would be.")

    return decomp

def create_rom(d):
    root, _, files = next(os.walk(d))
    files.sort()

    dirs = []
    for block_meta in blocks:
        dirs.append([])

    rom_size = 8 * 1024 * 1024
    base_offset = 0x2008
    # TODO: don't hardcode?:
    skip_14 = [
        32,  # sound or music bank?
        33,  # sound or music bank?
        220,  # ?
        221,  # ?
        267,  # ?
    ]

    with open(d + ".z64", "w+b") as f:
        # initialize with zeros
        f.write(bytearray(rom_size))
        f.seek(0)

        old_di = -1
        old_fi = -1
        for i, fn in enumerate(files):
            if fn == "misc.bin":
                with open(os.path.join(d, fn), "rb") as f2:
                    data = f2.read()

                f.seek(0)
                f.write(data)
            elif "-" in fn:
                extless = fn.split(".")[0]
                di, fi = extless.split("-")
                di, fi = int(di), int(fi)
                if di != old_di:
                    old_fi = -1
                    old_di = di
                if fi != old_fi + 1:
                    raise Exception("file indices must be consecutive")
                with open(os.path.join(d, fn), "rb") as f2:
                    data = f2.read()
                dirs[di].append(data)
                old_fi = fi
            else:
                lament("skipping unknown file:", fn)

        for di, files in enumerate(dirs):
            block_offset, block_size = blocks[di]
            f.seek(block_offset)
            f.write(W4(base_offset))
            f.write(W4(0x400))

            offset = 0
            for fi, data in enumerate(files):
                f.write(W4(offset))
                if fi == 0 and di != 14 or di == 14 and fi in skip_14:
                    new_data = data
                else:
                    new_data = compress(data, "best" if di == 14 else "greedy")
                    fmt = "compressed {:02}-{:03}.bin from {} bytes into {} ({:.2%})"
                    percent = len(new_data) / len(data) if len(data) > 0 else 1
                    print(fmt.format(di, fi, len(data), len(new_data), percent))
                size = len(new_data)
                f.write(W4(size))
                offset += size
                files[fi] = new_data

                #if fi != 0: break  # DEBUG

            while f.tell() & 0xFFFF < 0x2008:
                f.write(W4(0xFFFFFFFF))
                f.write(W4(0xFFFFFFFF))

            assert f.tell() & 0xFFFF == 0x2008
            for data in files:
                f.write(data)

            assert f.tell() - block_offset < block_size

            #break  # DEBUG

def dump_files(f):
    # TODO:
    misc = f.read(0x120000)
    dump_as(misc, "misc.bin")

    for dir_index, block_meta in enumerate(blocks):
        block_offset, block_size = block_meta
        f.seek(block_offset)

        base_offset = R4(f.read(4))
        unknown = R4(f.read(4))

        file_index = 0
        while True:
            offset = R4(f.read(4))
            size = R4(f.read(4))
            if offset == 0xFFFFFFFF or size == 0xFFFFFFFF:
                break
            if f.tell() & 0xFFFF > base_offset & 0xFFFF:
                break
            header_resume = f.tell()

            seek_to = offset + base_offset + block_offset
            #print(f"offset: {offset:08X}")
            #print(f"base_offset: {base_offset:08X}")
            #print(f"block_offset: {block_offset:08X}")
            fn = f"{dir_index:02}-{file_index:03}.bin"
            print(f"extracting file at {seek_to:06X} to {fn}")
            f.seek(seek_to)

            hint = R1(f.read(1))  # TODO: what is this really?
            if hint == 0:
                uncompressed_size = R4(b"\0" + f.read(3))
                data = decompress(f.read(size - 4), uncompressed_size)
            else:
                print("hinted:", fn)
                data = bytes([hint]) + f.read(size - 1)
            dump_as(data, fn)

            f.seek(header_resume)
            file_index += 1

def dump_rom(fp):
    with open(fp, "rb") as f:
        data = f.read()

    with BytesIO(data) as f:
        start = f.read(4)
        if start == b"\x37\x80\x40\x12":
            swap_order(f)
        elif start != b"\x80\x37\x12\x40":
            lament("not a .z64:", fp)
            return

        f.seek(0)
        romhash = sha1(f.read()).hexdigest()

        if romhash != "8a7648d8105ac4fc1ad942291b2ef89aeca921c9":
            raise Exception("unknown/unsupported ROM")

        with SubDir(romhash):
            f.seek(0)
            dump_files(f)

def run(args):
    parser = argparse.ArgumentParser(
        description="fs: construct and deconstruct Bomberman 64 ROMs")

    parser.add_argument(
        "path", metavar="ROM or folder", nargs="+",
        help="ROM to deconstruct, or folder to construct")

    a = parser.parse_args(args)

    for path in a.path:
        # directories are technically files, so check this first:
        if os.path.isdir(path):
            create_rom(path)
        elif os.path.isfile(path):
            dump_rom(path)
        else:
            lament("no-op:", path)

if __name__ == "__main__":
    try:
        ret = run(sys.argv[1:])
        sys.exit(ret)
    except KeyboardInterrupt:
        sys.exit(1)
