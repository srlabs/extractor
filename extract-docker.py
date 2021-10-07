#!/usr/bin/env python3

# This file is part of Extractor.

# Copyright (C) 2021 Security Research Labs GmbH
# SPDX-License-Identifier: Apache-2.0

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# 	http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import sys
import time
import argparse
import pathlib
import logging
import subprocess
import docker_image


def main():
    parser = argparse.ArgumentParser("Extract using docker extractor image")

    parser.add_argument("--in-file", type=lambda p: pathlib.Path(p).absolute(), required=True, help="Input file (e.g. Android image)")
    parser.add_argument("--out-dir", type=lambda p: pathlib.Path(p).absolute(), required=True, help="Output directory")
    parser.add_argument('--force-cleanup-and-rebuild', action='store_true')
    args = parser.parse_args()

    logging.basicConfig(format='%(levelname)s:%(asctime)s:%(message)s', level=logging.DEBUG)

    # Abort if out dir does not exist or is non-empty
    if not args.out_dir.is_dir():
        logging.error("[!] %s not a directory, exiting", args.out_dir)
        sys.exit(1)
    if any(args.out_dir.iterdir()):
        logging.error("[!] %s not empty, exiting", args.out_dir)
        sys.exit(1)

    start_time = time.time()
    image_name = docker_image.check_rebuild_docker_image(args.force_cleanup_and_rebuild)

    logging.info("[+] Running extractor with docker image %s", image_name)
    subprocess.check_call([
        "docker",
        "run",
        "--privileged",
        "--mount",
        "type=bind,src=" + str(args.in_file.parents[0]) + ",dst=/in_dir",
        "--mount",
        "type=bind,src=" + str(args.out_dir) + ",dst=/out_dir",
        "--rm",
        image_name,
        "/in_dir/" + args.in_file.name,
        "--system-dir-output",
        "/out_dir/"
    ])

    duration = time.time() - start_time
    logging.info("%s", f"[+] Output saved to {str(args.out_dir)} in {duration}s")


if __name__ == "__main__":
    main()
