#!/usr/bin/env python3

from hashlib import sha1
from io import BytesIO
import argparse
import os
import os.path
import sys

from util import *

lament = lambda *args, **kwargs: print(*args, file=sys.stderr, **kwargs)
heresay = os.path.split(sys.argv[0])[0]

def create_rom(path):
    raise Exception("TODO")

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

    if len(decomp) > expected_size:
        raise Exception("decomp is larger than it said it would be.")

    return decomp

def dump_files(f):
    # TODO:
    misc = f.read(0x120000)
    dump_as(misc, "misc.bin")

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
        (0x300000, 0x4C0000),
    )

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
                uncompressed_size = R4(b'\0' + f.read(3))
                data = decompress(f.read(size - 4), uncompressed_size)
            else:
                data = bytes(hint) + f.read(size - 1)
            dump_as(data, fn)

            f.seek(header_resume)
            file_index += 1

def dump_rom(fp):
    with open(fp, 'rb') as f:
        data = f.read()

    with BytesIO(data) as f:
        start = f.read(4)
        if start == b'\x37\x80\x40\x12':
            swap_order(f)
        elif start != b'\x80\x37\x12\x40':
            lament('not a .z64:', fp)
            return

        f.seek(0)
        romhash = sha1(f.read()).hexdigest()

        if romhash != '8a7648d8105ac4fc1ad942291b2ef89aeca921c9':
            raise Exception("unknown/unsupported ROM")

        with SubDir(romhash):
            f.seek(0)
            dump_files(f)

def run(args):
    parser = argparse.ArgumentParser(
        description="fs: construct and deconstruct Bomberman 64 ROMs")

    parser.add_argument(
        'path', metavar='ROM or folder', nargs='+',
        help="ROM to deconstruct, or folder to construct")

    a = parser.parse_args(args)

    for path in a.path:
        # directories are technically files, so check this first:
        if os.path.isdir(path):
            create_rom(path)
        elif os.path.isfile(path):
            dump_rom(path)
        else:
            lament('no-op:', path)

if __name__ == '__main__':
    try:
        ret = run(sys.argv[1:])
        sys.exit(ret)
    except KeyboardInterrupt:
        sys.exit(1)
