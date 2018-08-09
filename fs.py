#!/usr/bin/env python3

from hashlib import sha1
from io import BytesIO
import argparse
import os
import os.path
import sys

from util import *

def create_rom(path):
    raise Exception("TODO")

def dump_files(f):
    pass

def dump_rom(fp):
    with open(fp, 'rb') as f:
        data = f.read()

    with BytesIO(data) as f:
        start = f.read(4)
        if start == b'\x37\x80\x40\x12':
            swap_order(f)
        elif start != b'\x80\x37\x12\x40':
            lament('not a .z64:', fn)
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
