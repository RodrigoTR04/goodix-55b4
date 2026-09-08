#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Fail closed on privileged input/destination paths. Never print file contents."""
import argparse
import os
from pathlib import Path
import stat
import re


def check(path, *, tree=False, missing=False):
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts or not re.fullmatch(r'/[A-Za-z0-9_./+-]*', str(path)):
        raise ValueError('require an absolute path without traversal or whitespace')
    for item in [*reversed(path.parents), path]:
        try:
            info = item.lstat()
        except FileNotFoundError:
            if missing:
                continue
            raise
        if (info.st_uid != 0 or info.st_mode & 0o022 or
                not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode))):
            raise ValueError(
                f'{item}: require root ownership, no group/other writes, no links or special files')
    if tree:
        for directory, dirs, files in os.walk(path, followlinks=False):
            for name in dirs + files:
                check(Path(directory) / name)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tree', action='store_true')
    parser.add_argument('--missing', action='store_true')
    parser.add_argument('paths', nargs='+')
    args = parser.parse_args()
    try:
        for path in args.paths:
            check(path, tree=args.tree, missing=args.missing)
    except (OSError, ValueError) as error:
        parser.exit(1, f'Unsafe install path: {error}\n')
