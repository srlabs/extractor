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
    logging.info("[+] Check if docker image is up-to-date")
    extractor_revision = subprocess.check_output(["git", "rev-parse", "--short", "HEAD"], cwd=pathlib.Path(__file__).absolute().parents[0]).strip().decode()
    image_name = "extractor_image:" + extractor_revision
    extractor_image_exists = False

    # Check if some extractor_image exists (all versions), if not build
    extractor_image_list = subprocess.check_output(["docker", "images", "-q", "extractor_image"], stderr=subprocess.DEVNULL).splitlines()

    if not extractor_image_list:
        logging.info("[+] Building docker image %s", image_name)
        subprocess.check_output(["docker", "build", ".", "-t", image_name])
    else:
        # If extractor_image already exists, check if we want to force rebuild
        if args.force_cleanup_and_rebuild:
            # Delete all existing extractor_image images
            for image in extractor_image_list:
                subprocess.check_output(["docker", "rmi", image.decode()])
            # Build new image
            subprocess.check_output(["docker", "build", ".", "-t", image_name])
        else:
            # Stop in case we find multiple local images or an outdated image
            if len(extractor_image_list) != 1:
                logging.error("[!] Too many local extractor_images exist, please use --force-cleanup-and-rebuild to cleanup and rebuild")
                sys.exit(1)
            elif subprocess.check_output(["docker", "images", "-q", image_name], stderr=subprocess.DEVNULL).strip() not in extractor_image_list:
                logging.error("[!] Your existing local image %s is outdated, please use --force-cleanup-and-rebuild to rebuild", extractor_image_list[0].decode())
                sys.exit(1)

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
