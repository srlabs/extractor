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

import os
import subprocess
import logging
import sys
from collections import defaultdict, deque
import re
import argparse
import tempfile
from enum import Enum, auto
from Crypto.Cipher import AES
import struct
# noinspection PyPep8Naming
import xml.etree.ElementTree as ET
import json
from typing import List, Optional, DefaultDict
import shutil
import shlex
from lxml import etree
import liblp


base_dir = os.path.dirname(os.path.realpath(__file__))


def main():
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(name)-12s %(levelname)-8s:  %(message)s')
    if os.getuid() != 0:
        logging.error("Not running as root, exiting")
        sys.exit(1)
    parser = argparse.ArgumentParser(description='Android firmware extraction tool')
    parser.add_argument("input")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--tar-output", help="Path to system.tar file to generate")
    group.add_argument("--system-dir-output", help="Path to store system dir, without intermediate tar file")
    group.add_argument("--no-output", action="store_true", help="Only run extraction but ignore output")
    parser.add_argument("--boot-recovery-output", help="Directory where boot/recovery img should be stored")
    parser.add_argument("--allow-missing-vendor", action="store_true", help="Allow missing vendor partition for extraction, required for system-only updates (=> Project Treble), e.g. for some LineageOS images")
    args = parser.parse_args()
    extractor = FirmwareExtractor(args.input)
    try:
        output_boot_img_path = None
        output_recovery_img_path = None
        if args.boot_recovery_output is not None:
            output_boot_img_path = os.path.join(os.path.abspath(args.boot_recovery_output), "boot.img")
            output_recovery_img_path = os.path.join(os.path.abspath(args.boot_recovery_output), "recovery.img")
        extractor.extract(output_system_tar=args.tar_output, output_system_dir=args.system_dir_output, output_boot_img_path=output_boot_img_path, output_recovery_img_path=output_recovery_img_path, allow_missing_vendor=args.allow_missing_vendor)
    finally:
        extractor.cleanup()


class CheckFileResult(Enum):
    ARCHIVE = auto()
    SYSTEM_IMG = auto()
    VENDOR_IMG = auto()
    BOOT_IMG = auto()
    RECOVERY_IMG = auto()
    SYSTEM_OR_VENDOR = auto()
    HANDLER_NO_MATCH = auto()
    HANDLER_NO_MATCH_AND_IGNORE_SIZE_COVERAGE = auto()
    IGNORE = auto()


class ImageType(Enum):
    SYSTEM = auto()
    VENDOR = auto()


class FileHandler:
    def __init__(self, extractor: "FirmwareExtractor", input_path_rel, file_type, image_type: ImageType = None):
        self.extractor: FirmwareExtractor = extractor
        self.input_path_rel = input_path_rel
        self.abs_fn = self.extractor.abs_fn(input_path_rel)
        assert isinstance(self.abs_fn, bytes), "abs_fn must be of type bytes"
        assert isinstance(file_type, str), "file_type must be of type str"
        assert image_type in (None, ImageType.SYSTEM, ImageType.VENDOR), "Invalid image_type=%r" % image_type
        self.fn = self.abs_fn.split(b'/')[-1]
        self.file_type = file_type
        self.image_type: ImageType = image_type

    def check(self) -> CheckFileResult:
        raise NotImplementedError("check() must be implemented in subclass (%s)" % self.__class__.__name__)

    def get_extra_handled_size(self):
        return 0


class ZipHandler(FileHandler):
    """
    Generic Zip Handler, often used as top-level container format
    """
    def check(self) -> CheckFileResult:
        if not self.is_good_extension():
            return CheckFileResult.HANDLER_NO_MATCH
        if not (self.file_type.lower().startswith("zip") or self.file_type.lower().startswith("java archive data")):
            return CheckFileResult.HANDLER_NO_MATCH
        return CheckFileResult.ARCHIVE

    def is_good_extension(self) -> bool:
        if self.abs_fn.lower().endswith(b".zip"):
            return True
        if self.abs_fn.lower().endswith(b".ftf"):
            # Sony ftf format
            return True
        if self.abs_fn.lower().endswith(b".ozip"):
            # Oppo ozip, in some cases custom format (see OzipHandler), in other cases just a zip file
            return True
        if self.abs_fn.lower().endswith(b".up"):
            # Some ZTE firmwares use ".up" for zip files
            return True
        return False

    def extract_file2dir(self, output_path_rel):
        abs_output_path = self.extractor.abs_fn(output_path_rel)
        cmd = ["unzip", "-q", self.abs_fn]
        logging.info("ZipHandler: cmd=%r  cwd=%r" % (cmd, abs_output_path))
        exitcode = subprocess.call(cmd, cwd=abs_output_path, stdin=subprocess.DEVNULL)
        # 0: OK, 1: Finished with warnings
        if exitcode in (0, 1):
            return
        logging.info("Extracting zip file with 'unzip' command failed (exit code %d), retrying with 'jar xf'", exitcode)
        # unzip failed, clean up stage dir and try other extractor
        assert b'/tmp/AND' in abs_output_path, "abs_output_path %r doesn't contain /tmp/AND" % abs_output_path
        shutil.rmtree(abs_output_path)
        os.mkdir(abs_output_path)
        # Try jar as a second extractor, there is a known issue with unzip and large (>4GB) files:
        # https://stackoverflow.com/a/31084012
        cmd = ["jar", "xf", self.abs_fn]
        logging.info("ZipHandler fallback to jar: cmd=%r  cwd=%r" % (cmd, abs_output_path))
        subprocess.check_call(cmd, cwd=abs_output_path)


class TopLevelZipHandler(ZipHandler):
    """
    Generic Zip Handler for top level format, also supports arbitrary file extensions, to be used for initial input file only
    """
    def is_good_extension(self) -> bool:
        return True


class SevenZipHandler(FileHandler):
    """
    Generic 7z Handler, sometimes used as top-level container format
    """
    def check(self) -> CheckFileResult:
        good_extension = False
        if self.abs_fn.lower().endswith(b".7z"):
            good_extension = True
        if not good_extension:
            return CheckFileResult.HANDLER_NO_MATCH
        if not self.file_type.lower().startswith("7-zip archive data"):
            return CheckFileResult.HANDLER_NO_MATCH
        return CheckFileResult.ARCHIVE

    def extract_file2dir(self, output_path_rel):
        abs_output_path = self.extractor.abs_fn(output_path_rel)
        cmd = ["7z", "x", self.abs_fn]
        logging.info("ZipHandler: cmd=%r  cwd=%r" % (cmd, abs_output_path))
        subprocess.check_call(cmd, cwd=abs_output_path)


class RarHandler(FileHandler):
    """
    Generic rar Handler, sometimes used as top-level container format
    """
    def check(self) -> CheckFileResult:
        # Disabled extension check, sometimes there is no .rar extension (but the file type should be reliable enough)
        # good_extension = False
        # if self.abs_fn.lower().endswith(b".rar"):
        #     good_extension = True
        # if not good_extension:
        #     return CheckFileResult.HANDLER_NO_MATCH
        if not self.file_type.lower().startswith("rar archive data"):
            return CheckFileResult.HANDLER_NO_MATCH
        return CheckFileResult.ARCHIVE

    def extract_file2dir(self, output_path_rel):
        abs_output_path = self.extractor.abs_fn(output_path_rel)
        cmd = ["unrar", "x", "-psamdownloads.de", self.abs_fn]
        logging.info("RarHandler: cmd=%r  cwd=%r" % (cmd, abs_output_path))
        subprocess.check_call(cmd, cwd=abs_output_path)


class OzipHandler(FileHandler):
    """
    OPPO encrypted image
    """
    def check(self) -> CheckFileResult:
        good_extension = False
        if self.abs_fn.lower().endswith(b".ozip"):
            good_extension = True
        if not good_extension:
            return CheckFileResult.HANDLER_NO_MATCH
        magic = open(self.abs_fn, 'rb').read(12)
        if magic != b'OPPOENCRYPT!':
            if self.file_type.lower().startswith("java archive"):
                # Some .ozip files are actually zip, e.g. CPH1809EX_11_OTA_0180_all_OlU3r4ImvcSX_local.ozip
                return CheckFileResult.HANDLER_NO_MATCH
            assert False, "Invalid ozip magic %r" % magic
        return CheckFileResult.ARCHIVE

    def extract_and_get_next_handler(self, stage_dir_rel):
        # Replace .ozip with .zip
        assert self.abs_fn.lower().endswith(b".ozip")
        out_filename = os.path.basename(self.abs_fn)[0:-5] + b".zip"
        out_path_rel = os.path.join(stage_dir_rel, out_filename)
        abs_stage_dir = self.extractor.create_stage_dir(stage_dir_rel)
        out_path_abs = os.path.join(abs_stage_dir, out_filename)
        ozip = AES.new(b'\xD6\xDC\xCF\x0A\xD5\xAC\xD4\xE0\x29\x2E\x52\x2D\xB7\xC1\x38\x1E', AES.MODE_ECB)
        with open(self.abs_fn, 'rb') as ifs:
            ifs.seek(0x1050, 0)
            with open(out_path_abs, 'wb') as ofs:
                while True:
                    data = ifs.read(16)
                    ofs.write(ozip.decrypt(data))
                    data = ifs.read(0x4000)
                    if len(data) == 0:
                        break
                    ofs.write(data)
        return ZipHandler(self.extractor, out_path_rel, file_type=get_file_type(out_path_abs))


class PacHandler(FileHandler):
    """
    Mediatek PAC image
    """
    def check(self) -> CheckFileResult:
        good_extension = False
        if self.abs_fn.lower().endswith(b".pac"):
            good_extension = True
        if not good_extension:
            return CheckFileResult.HANDLER_NO_MATCH
        return CheckFileResult.ARCHIVE

    def extract_file2dir(self, output_path_rel):
        abs_output_path = self.extractor.abs_fn(output_path_rel)
        sr = os.stat(self.abs_fn)
        with open(self.abs_fn, 'rb') as pac:
            buf = pac.read(1024 * 1024)

            last_file_end = 0

            for pos in range(60, 69721, 2580):
                file_item = buf[pos:pos + 2580]
                name = file_item[0:0x40].decode("utf-16").replace("\x00", "")
                start_pos = struct.unpack("<I", file_item[0x40c:0x410])[0]
                length = struct.unpack("<I", file_item[0x400:0x404])[0]

                if start_pos == 0:
                    continue

                assert start_pos >= last_file_end, "start_pos >= last_file_end: %d >= %x" % (start_pos, last_file_end)

                if start_pos + length > sr.st_size:
                    continue

                if name in ("system.img", "system_raw.img", "boot.img", "recovery.img"):
                    logging.debug("Doing %s", name)
                    with open(os.path.join(abs_output_path, name.encode()), 'wb') as out:
                        pac.seek(start_pos)
                        bytes_done = 0

                        while bytes_done < length:
                            chunk_len = min(1024 * 1024, length - bytes_done)
                            out.write(pac.read(chunk_len))
                            bytes_done += chunk_len
                last_file_end = start_pos + length


class IgnoreBadTarMd5Handler(FileHandler):
    """
    Ignore same non-wanted .tar.md5 files
    """
    def check(self) -> CheckFileResult:
        good_extension = False
        if self.abs_fn.lower().endswith(b".tar.md5"):  # Samsung
            good_extension = True
        if not good_extension:
            return CheckFileResult.HANDLER_NO_MATCH
        if 'POSIX tar archive' not in self.file_type:
            return CheckFileResult.HANDLER_NO_MATCH
        if self.fn.startswith(b'USERDATA_'):
            # USERDATA_*.tar.md5 is present on some Samsung images, but it contains only useless stuff such as dalvik caches
            # Needs to be ignored so that ArchiveDirectoryHandler can accept handling only other files
            return CheckFileResult.IGNORE
        if self.fn.startswith(b'CSC_') or self.fn.startswith(b'HOME_CSC_'):
            # Needs to be ignored so that ArchiveDirectoryHandler can accept handling only other files
            return CheckFileResult.IGNORE
        return CheckFileResult.HANDLER_NO_MATCH


class TarHandler(FileHandler):
    """
    Handler for tar files (and Samsung .tar.md5 files, which are actually tar archives)
    """
    def check(self) -> CheckFileResult:
        if not self.is_good_extension():
            return CheckFileResult.HANDLER_NO_MATCH
        # Not every tar archive is a "POSIX" tar archive.
        if 'POSIX tar archive' in self.file_type or self.file_type == 'tar archive':
            if self.fn.startswith(b'USERDATA_') and self.fn.endswith(b'.tar.md5'):
                # USERDATA_*.tar.md5 is present on some Samsung images, but it contains only useless stuff such as dalvik caches
                # Needs to be ignored so that ArchiveDirectoryHandler can accept handling only other files
                return CheckFileResult.IGNORE
            return CheckFileResult.ARCHIVE
        else:
            return CheckFileResult.HANDLER_NO_MATCH

    def is_good_extension(self) -> bool:
        if self.abs_fn.lower().endswith(b".tar"):
            return True
        if self.abs_fn.lower().endswith(b".tar.md5"):  # Samsung
            return True
        return False

    def extract_file2dir(self, output_path_rel):
        abs_output_path = self.extractor.abs_fn(output_path_rel)
        cmd = ["tar", "xvf", self.abs_fn]
        logging.info("TarHandler.extract_file2dir(%r): cmd=%r  cwd=%r" % (output_path_rel, cmd, abs_output_path))
        subprocess.check_call(cmd, cwd=abs_output_path)


class TarHandlerIgnoreExtension(TarHandler):
    def is_good_extension(self) -> bool:
        return True


class HuaweiAppHandler(FileHandler):
    """
    Handler for Huawei .app images
    """
    def check(self) -> CheckFileResult:
        if not self.abs_fn.lower().endswith(b".app"):
            return CheckFileResult.HANDLER_NO_MATCH
        assert self.fn.lower().startswith(b'update')
        # No file_type check, is typically "data"
        return CheckFileResult.ARCHIVE

    def extract_file2dir(self, output_path_rel):
        abs_output_path = self.extractor.abs_fn(output_path_rel)
        cmd = ["%s/splituapp/splituapp" % base_dir, "-f", self.abs_fn, "-o", abs_output_path, "--no-crc"]
        logging.info("HuaweiAppHandler.extract_file2dir(%r): cmd=%r  cwd=%r" % (output_path_rel, cmd, abs_output_path))
        subprocess.check_call(cmd, cwd=abs_output_path)


class KdzHandler(FileHandler):
    """
    Handler for LG kdz format
    """
    def check(self) -> CheckFileResult:
        if not self.abs_fn.lower().endswith(b".kdz"):
            return CheckFileResult.HANDLER_NO_MATCH
        return CheckFileResult.ARCHIVE

    def extract_file2dir(self, output_path_rel):
        abs_output_path = self.extractor.abs_fn(output_path_rel)
        cmd = ["%s/kdzextractor/unkdz.py" % base_dir, "-x", "-f", self.abs_fn]
        logging.info("KdzHandler.extract_file2dir(%r): cmd=%r  cwd=%r" % (output_path_rel, cmd, abs_output_path))
        subprocess.check_call(cmd, cwd=abs_output_path)


class DzHandler(FileHandler):
    """
    Handler for LG kdz format
    """
    def check(self) -> CheckFileResult:
        if not self.abs_fn.lower().endswith(b".dz"):
            return CheckFileResult.HANDLER_NO_MATCH
        return CheckFileResult.ARCHIVE

    def extract_file2dir(self, output_path_rel):
        abs_output_path = self.extractor.abs_fn(output_path_rel)
        cmd = ["python", "%s/kdzextractor/undz.py" % base_dir, "-x", "-f", self.abs_fn]
        logging.info("DzHandler.extract_file2dir(%r): cmd=%r  cwd=%r" % (output_path_rel, cmd, abs_output_path))
        subprocess.check_call(cmd, cwd=abs_output_path)
        # undz creates a number of system_<num>.bin files.
        # <num> is the block number whete this file is in the final system image.
        # The block size is variable, can be found based on the size of the first image
        # and the offset of the second image.
        # pdb.set_trace()
        dzextracted_path = os.path.join(abs_output_path, b'dzextracted')
        listing = os.listdir(dzextracted_path)
        file_num_to_fn = dict()
        for fn in listing:
            if fn.startswith(b'vendor_') and fn.endswith(b'.bin'):
                assert False, "Please implement DzHandler Vendor extraction"
            if not fn.startswith(b'system_'):
                continue
            if not fn.endswith(b'.bin'):
                continue
            num = int(fn[7:-4].decode())
            file_num_to_fn[num] = os.path.join(dzextracted_path, fn)
        files_sorted = list(sorted(file_num_to_fn.keys()))
        offset = files_sorted[0]
        value = files_sorted[1] - files_sorted[0]
        info = os.stat(os.path.join(output_path_rel, file_num_to_fn[files_sorted[0]]))
        # noinspection PyUnusedLocal
        bs: int
        if (value * 512) >= info.st_size:
            bs = 512
        elif (value * 1024) >= info.st_size:
            bs = 1024
        elif (value * 2048) >= info.st_size:
            bs = 2048
        elif (value * 4096) >= info.st_size:
            bs = 4096
        else:
            assert False, "Failed to find block size"

        abs_system_img = os.path.join(abs_output_path, b'system.img')
        with open(abs_system_img, 'wb') as out_fh:
            for file_num in files_sorted:
                file_name = file_num_to_fn[file_num]
                pos = bs * (file_num - offset)
                out_fh.seek(pos)
                with open(file_name, 'rb') as in_fh:
                    while True:
                        buf = in_fh.read(1024 * 1024)
                        if len(buf) == 0:
                            break
                        out_fh.write(buf)
                os.unlink(file_name)  # Unlink is required so that the next ArchiveDirectoryHandler will not be confused by the low handled size
        # logging.info("Please check the results once")
        # pdb.set_trace()


class SinHandler(FileHandler):
    """
    Handler for system.sin files (Sony)
    """
    def check(self) -> CheckFileResult:
        if self.fn.lower() == b'system.sin':
            return CheckFileResult.ARCHIVE
        elif self.fn.lower() == b'vendor.sin':
            assert False, "TODO: Check and implement extraction of vendor.sin"
        else:
            return CheckFileResult.HANDLER_NO_MATCH

    def extract_file2dir(self, output_path_rel):
        abs_output_path = self.extractor.abs_fn(output_path_rel)
        cmd = ["%s/sinextract/sinextract" % base_dir, abs_output_path, self.abs_fn]
        logging.info("SinHandler.extract_file2dir(%r): cmd=%r  cwd=%r" % (output_path_rel, cmd, abs_output_path))
        subprocess.check_call(cmd, cwd=abs_output_path)


class RawprogramUnsparseHandler(FileHandler):
    system_parts_with_pos: List[List]
    vendor_parts_with_pos: List[List]
    super_parts_with_pos: List[List]
    extra_ignored_size: int

    def check(self) -> CheckFileResult:
        self.system_parts_with_pos = []
        self.vendor_parts_with_pos = []
        self.super_parts_with_pos = []
        self.extra_ignored_size = 0
        if self.fn == b"contents.xml":
            return self.check_contents_xml(self.abs_fn)
        else:
            xml_files_by_priority = (
                b'rawprogram_unsparse.xml',
                b'rawprogram0.xml',
                b'rawprogram_unsparse(US).xml',
                b'rawprogram0_unsparse.xml',
                b'rawprogram_unsparse0.xml',
                b'rawprogram0_unsparse_upgrade.xml',
                b'rawprogram_upgrade.xml',
                b'rawprogram_unsparse_upgrade.xml'
            )
            if self.fn not in xml_files_by_priority:
                return CheckFileResult.HANDLER_NO_MATCH
            input_dir_abs = os.path.dirname(self.abs_fn)
            direct_system_img_path = os.path.join(input_dir_abs, b'system.img')
            if os.path.exists(direct_system_img_path) and os.stat(direct_system_img_path).st_size > 128 * 1024 * 1024:
                return CheckFileResult.HANDLER_NO_MATCH_AND_IGNORE_SIZE_COVERAGE  # Some images contain a system.img file directly and some non-working xml
            # If contents.xml exists, it should be used and this handler should return HANDLER_NO_MATCH for all other
            # xml files. However, in some cases contents.xml is broken and we need to continue based on
            # xml_files_by_priority
            content_xml_path = os.path.join(input_dir_abs, b'contents.xml')
            if os.path.exists(content_xml_path):
                if self.check_contents_xml(content_xml_path) != CheckFileResult.HANDLER_NO_MATCH:
                    return CheckFileResult.HANDLER_NO_MATCH
            highest_priority_existing_file = None
            for tmp_fn in reversed(xml_files_by_priority):
                if os.path.exists(os.path.join(input_dir_abs, tmp_fn)):
                    highest_priority_existing_file = tmp_fn
            assert highest_priority_existing_file is not None
            if highest_priority_existing_file != self.fn:
                return CheckFileResult.HANDLER_NO_MATCH  # There is a better (higher priority) xml file, so let's ignore this one
            logging.info("RawprogramUnsparseHandler: Checking file %r" % self.abs_fn)
            return self.parse_xml_file(self.abs_fn)

    def check_contents_xml(self, abs_contents_xml: bytes) -> CheckFileResult:
        contents_xml_dir = os.path.dirname(abs_contents_xml)
        parser = etree.XMLParser()
        tree = etree.parse(open(abs_contents_xml), parser)
        root = tree.getroot()
        params_tags = root.xpath('//step[@filter="hlos"]/params')
        if len(params_tags) == 0:
            if len(root.xpath("/contents/product_info/product_name")) > 0:
                return CheckFileResult.HANDLER_NO_MATCH  # Some firmwares have a completely different file called "contents.xml", which isn't required for extraction.
            raise ValueError("Failed to parse contents.xml")
        result = CheckFileResult.HANDLER_NO_MATCH
        for params_tag in params_tags:
            cmd_str = params_tag.text.strip()
            assert "@rawprogram_xml" in cmd_str
            cmd = shlex.split(cmd_str)
            assert cmd[-2] == "-o"
            xml_fn = cmd[-1]
            abs_fn = os.path.join(contents_xml_dir, xml_fn.encode())
            # assert os.path.exists(abs_fn), "File %r (referenced from %r) doesn't exist" % (abs_fn, self.abs_fn)
            if os.path.exists(abs_fn):
                result = self.parse_xml_file(abs_fn)
            else:
                logging.error("File %r (referenced from %r) doesn't exist", abs_fn, abs_contents_xml)
        return result

    def parse_xml_file(self, abs_xml_fn):
        try:
            root = ET.parse(open(abs_xml_fn))
        except ET.ParseError:
            # Workaround for crappy XML, e.g. document starting with </data
            lines = open(abs_xml_fn).read().splitlines()
            lines = [x for x in lines if "<program" in x]
            logging.debug("\n".join(lines))
            root = ET.XML("<data>\n" + "\n".join(lines) + "</data>")
        program_tags = root.findall('program')
        sector_size: Optional[int] = None
        image_base_dir = os.path.dirname(abs_xml_fn)
        partition_start_sector_by_label = {}
        found_vendor_b: bool = False
        for program_tag in program_tags:
            label = program_tag.attrib["label"]
            if label in ("system", "system_a", "vendor", "vendor_a", "super"):
                logging.info("RawprogramUnsparseHandler: program_tag.attrib=%s" % json.dumps(program_tag.attrib, sort_keys=True))
                # Sparse attribute can cause problems (sector size mismatch etc.), it will be handled directly by SuperImageHandler
                if label == "super" and "sparse" in program_tag.attrib and program_tag.attrib["sparse"].lower() == "true":
                    continue
                filename = program_tag.attrib["filename"]
                abs_fn = os.path.join(image_base_dir, filename.encode())
                if not os.path.exists(abs_fn):
                    if b'image/modem/' in abs_xml_fn:
                        return CheckFileResult.IGNORE
                    raise ValueError("File %r doesn't exist (referenced from %r)" % (abs_fn, abs_xml_fn))
                if "SECTOR_SIZE_IN_BYTES" in program_tag.attrib:
                    if sector_size is None:
                        sector_size = int(program_tag.attrib["SECTOR_SIZE_IN_BYTES"])
                        assert sector_size in [512, 4096]
                    else:
                        assert int(program_tag.attrib["SECTOR_SIZE_IN_BYTES"]) == sector_size, "Inconsistent sector size: %r <=> %r" % (int(program_tag.attrib["SECTOR_SIZE_IN_BYTES"]), sector_size)
                else:
                    # Found a program tag without SECTOR_SIZE_IN_BYTES => Fall back to default 512
                    sector_size = 512
                assert os.stat(abs_fn).st_size % sector_size == 0, "File %r is not a multiple of %d bytes" % (abs_fn, sector_size)
                start_sector = int(program_tag.attrib["start_sector"])
                if label not in partition_start_sector_by_label:
                    partition_start_sector_by_label[label] = start_sector
                start_pos = sector_size * (start_sector - partition_start_sector_by_label[label])
                assert start_pos < 10 * 1024 * 1024 * 1024, "RawprogramUnsparseHandler: Sparse image too big (>10 GiB)"
                if label.startswith("system"):
                    self.system_parts_with_pos.append([abs_fn, start_pos])
                elif label.startswith("vendor"):
                    self.vendor_parts_with_pos.append([abs_fn, start_pos])
                elif label.startswith("super"):
                    self.super_parts_with_pos.append([abs_fn, start_pos])
                else:
                    raise ValueError("Bad label %r, this should not happen" % label)
            elif label == "vendor_b":
                found_vendor_b = True
            elif label.startswith("custom") or label.startswith("userdata"):
                filename = program_tag.attrib["filename"]
                abs_fn = os.path.join(image_base_dir, filename.encode())
                try:
                    self.extra_ignored_size += os.stat(abs_fn).st_size
                except FileNotFoundError:
                    pass
            else:
                # Just to make sure we aren't missing a vendor partition here
                assert 'vendor' not in label.lower(), "Found unexpected program label containing 'vendor' in %r" % program_tag.attrib["label"]
        if found_vendor_b:
            assert len(self.vendor_parts_with_pos) > 0, "XML file %r contains vendor_b but no valid vendor" % abs_xml_fn
        if len(self.system_parts_with_pos) == 0 and len(self.vendor_parts_with_pos) == 0 and len(self.super_parts_with_pos) == 0:
            return CheckFileResult.HANDLER_NO_MATCH
        return CheckFileResult.SYSTEM_OR_VENDOR

    def get_extra_handled_size(self):
        result = 0
        for (part_fn, pos) in self.system_parts_with_pos:
            result += os.stat(part_fn).st_size
        for (part_fn, pos) in self.vendor_parts_with_pos:
            result += os.stat(part_fn).st_size
        for (part_fn, pos) in self.super_parts_with_pos:
            result += os.stat(part_fn).st_size
        return result

    def has_vendor(self):
        return len(self.vendor_parts_with_pos) > 0

    def extract_and_get_next_handlers(self, stage_dir_rel) -> List[FileHandler]:
        def extract_parts_to_file(my_parts: List[List], my_abs_out_fn):
            with open(my_abs_out_fn, 'wb') as out_fh:
                for item in my_parts:
                    # logging.info("ITEM: %r" % item)
                    (part_fn, pos) = item
                    out_fh.seek(pos)
                    with open(part_fn, 'rb') as in_fh:
                        while True:
                            buf = in_fh.read(1024 * 1024)
                            if len(buf) == 0:
                                break
                            out_fh.write(buf)
        abs_stage_dir = self.extractor.create_stage_dir(stage_dir_rel)
        result: List[FileHandler] = []
        if len(self.super_parts_with_pos) > 0:
            assert len(self.system_parts_with_pos) == 0, "Can't have system and super image"
            assert len(self.vendor_parts_with_pos) == 0, "Can't have vendor and super image"
            output_fn = b'super.img'
            abs_out_fn = os.path.join(abs_stage_dir, output_fn)
            extract_parts_to_file(self.super_parts_with_pos, abs_out_fn)
            handler = SuperImageHandler(self.extractor, self.extractor.rel_path(abs_out_fn), file_type=get_file_type(abs_out_fn))
            handler_result = handler.check()
            if handler_result == CheckFileResult.HANDLER_NO_MATCH:
                raise ValueError("RawprogramUnsparseHandler: Extracted super.img but SuperImageHandler returned HANDLER_NO_MATCH")
            result.append(handler)
        else:
            for image_type in (ImageType.SYSTEM, ImageType.VENDOR):
                if image_type == ImageType.VENDOR and len(self.vendor_parts_with_pos) == 0:
                    continue
                output_fn = b'%s.img' % image_type.name.lower().encode()
                abs_out_fn = os.path.join(abs_stage_dir, output_fn)
                parts: List[List]
                if image_type == ImageType.SYSTEM:
                    parts = self.system_parts_with_pos
                elif image_type == ImageType.VENDOR:
                    parts = self.vendor_parts_with_pos
                else:
                    raise ValueError("Invalid image_type=%r" % image_type)
                extract_parts_to_file(parts, abs_out_fn)
                HANDLER_TYPES = [ExtfsHandler, ErofsHandler]
                handlers = []
                for handler_type in HANDLER_TYPES:
                    handler = handler_type(self.extractor, self.extractor.rel_path(abs_out_fn), image_type=image_type, file_type=get_file_type(abs_out_fn))
                    handler_result = handler.check()
                    if handler_result != CheckFileResult.HANDLER_NO_MATCH:
                        assert handler_result in (CheckFileResult.SYSTEM_IMG, CheckFileResult.VENDOR_IMG, CheckFileResult.SYSTEM_OR_VENDOR), "Unexpected handler_result=%r from handler %r" % (handler_result, handler.__class__.__name__)
                        handlers.append(handler)
                if len(handlers) > 1:
                    raise MultipleHandlerMatchError("File %r: %r" % (abs_out_fn, [x.__class__.__name__ for x in handlers]))
                elif len(handlers) == 0:
                    raise NoHandlerMatchError("RawprogramUnsparseHandler.extract_and_get_next_handler(): Don't know what to do with %r (file_type=%r)" % (abs_out_fn, get_file_type(abs_out_fn)))
                else:
                    result.append(handlers[0])
        return result


class IgnoreRadioHandler(FileHandler):
    """
    Handler to ignore radio-*.img files, e.g. radio-taimen-g8998-00253-1805232234.img
    """
    def check(self) -> CheckFileResult:
        if self.fn.startswith(b'radio-') and self.fn.endswith(b'.img'):
            return CheckFileResult.IGNORE
        return CheckFileResult.HANDLER_NO_MATCH


class IgnoreBootloaderHandler(FileHandler):
    """
    Handler to ignore bootloader-*.img files, e.g. bootloader-taimen-tmz20k.img
    """
    def check(self) -> CheckFileResult:
        if self.fn.startswith(b'bootloader-') and self.fn.endswith(b'.img'):
            return CheckFileResult.IGNORE
        return CheckFileResult.HANDLER_NO_MATCH


class IgnoreVmlinuxHandler(FileHandler):
    """
    Handler to ignore "vmlinux" files, helps with coverage for some images
    """
    def check(self) -> CheckFileResult:
        if self.fn.lower() == b"vmlinux":
            return CheckFileResult.IGNORE
        return CheckFileResult.HANDLER_NO_MATCH


class IgnoreOpImageHandler(FileHandler):
    """
    Handler to ignore OP_\\d+.bin files
    """
    def check(self) -> CheckFileResult:
        m = re.match(rb'op_\d+\.bin', self.fn.lower())
        if m:
            # May have various different file types, e.g. ext4 or jar. So let's just match by filename here.
            logging.info("IgnoreOpImageHandler: file %r => file_type=%r" % (self.abs_fn, self.file_type))
            return CheckFileResult.IGNORE
        m = re.match(rb'op_\w+\.img', self.fn.lower())
        if m:
            # Sample: OP_OPEN_ZA.img from H84020c_00_OPEN_ZA_OP_0630.kdz
            logging.info("IgnoreOpImageHandler: file %r => file_type=%r" % (self.abs_fn, self.file_type))
            return CheckFileResult.IGNORE
        return CheckFileResult.HANDLER_NO_MATCH


class IgnoreOemImgHandler(FileHandler):
    """
    Handler to ignore oem.img files
    """
    def check(self) -> CheckFileResult:
        if self.fn == b'oem.img':
            return CheckFileResult.IGNORE
        return CheckFileResult.HANDLER_NO_MATCH


class IgnoreProductImgHandler(FileHandler):
    """
    Handler to ignore product.img files
    """
    def check(self) -> CheckFileResult:
        if self.fn == b'product.img' or self.fn.startswith(b'product.img.'):
            return CheckFileResult.IGNORE
        return CheckFileResult.HANDLER_NO_MATCH


class IgnoreSystemExtImgHanlder(FileHandler):
    """
    Handler to ignore system_ext.img files
    """
    def check(self) -> CheckFileResult:
        if self.fn == b'system_ext.img' or self.fn.startswith(b'system_ext.img.'):
            return CheckFileResult.IGNORE
        return CheckFileResult.HANDLER_NO_MATCH


class IgnoreXromImgHanlder(FileHandler):
    """
    Handler to ignore xrom.img files
    """
    def check(self) -> CheckFileResult:
        if self.fn == b'xrom.img' or self.fn.startswith(b'xrom.img.'):
            return CheckFileResult.IGNORE
        return CheckFileResult.HANDLER_NO_MATCH


class IgnoreAppsImgHandler(FileHandler):
    """
    Handler to ignore apps.img (and apps_X.img) files
    """
    def check(self) -> CheckFileResult:
        if re.match(rb'apps(_\d+)?\.img', self.fn):
            return CheckFileResult.IGNORE
        return CheckFileResult.HANDLER_NO_MATCH


class IgnoreUpdateHwHandler(FileHandler):
    """
    Handler to ignore update_full_*_hw_*.zip files
    Only required in ArchiveDirectoryHandler Pass2
    """
    def check(self) -> CheckFileResult:
        m = re.match(rb'update_full_.*_hw_\w+\.zip', self.fn.lower())
        if m:
            return CheckFileResult.IGNORE
        return CheckFileResult.HANDLER_NO_MATCH


class IgnoreHuaweiUserdataAppHandler(FileHandler):
    """
    Handler to ignore USERDATA.APP
    Required so that the actual image (UPDATE.APP) will be >90%
    """
    def check(self) -> CheckFileResult:
        if self.fn.lower() == b"userdata.app":
            return CheckFileResult.IGNORE
        return CheckFileResult.HANDLER_NO_MATCH


class IgnoreElfHandler(FileHandler):
    """
    Handler to ignore elf files
    Required to reach size coverage threshold
    """
    def check(self) -> CheckFileResult:
        if self.file_type.startswith("ELF ") and self.fn.lower().endswith(b'.elf'):
            return CheckFileResult.IGNORE
        return CheckFileResult.HANDLER_NO_MATCH


class SparseImageHandler(FileHandler):
    abs_fn_list: List[bytes]

    def check(self) -> CheckFileResult:
        if self.file_type.startswith("Android sparse image, version: 1.0,"):
            if self.fn.lower().startswith(b"system_other"):
                return CheckFileResult.IGNORE
            if self.fn.lower().startswith(b'hidden.'):
                return CheckFileResult.IGNORE
            if self.fn.lower().startswith(b'cache'):
                return CheckFileResult.IGNORE
            if self.fn.lower().startswith(b'userdata.'):
                return CheckFileResult.IGNORE
            if self.fn.lower().startswith(b'userdata_'):
                return CheckFileResult.IGNORE
            if self.fn.lower().startswith(b'persist.'):
                return CheckFileResult.IGNORE
            if self.fn.lower().startswith(b'3rdmodem.'):
                return CheckFileResult.IGNORE
            if self.fn.lower().startswith(b'cust.'):
                return CheckFileResult.IGNORE
            if self.fn.lower().startswith(b'product.'):
                return CheckFileResult.IGNORE
            if self.fn.lower().startswith(b'odm.'):
                return CheckFileResult.IGNORE
            if self.fn.lower().startswith(b'oem.'):
                return CheckFileResult.IGNORE
            if self.fn.lower().startswith(b'container.'):
                return CheckFileResult.IGNORE
            if self.fn.lower().startswith(b'apps.'):
                # Vivo
                return CheckFileResult.IGNORE
            if self.fn.lower().endswith(b".duplicate"):
                return CheckFileResult.IGNORE  # splituapp duplicate file entries in Huawei UPDATE.APP
            if self.fn.lower().startswith(b"op_") or self.fn.lower().startswith(b"op."):
                return CheckFileResult.IGNORE
            if self.fn.lower().startswith(b"oem_"):
                return CheckFileResult.IGNORE
            if self.fn.lower().startswith(b"preas_"):
                return CheckFileResult.IGNORE
            if self.fn.lower().startswith(b"preas."):
                return CheckFileResult.IGNORE
            if self.fn.lower().startswith(b"non-hlos."):
                return CheckFileResult.IGNORE
            if self.fn.lower().startswith(b"super"):
                return CheckFileResult.HANDLER_NO_MATCH  # Will be covered by SuperImageHandler
            self.abs_fn_list = []
            if b"sparsechunk" in self.fn.lower():
                if self.fn.lower().endswith(b"sparsechunk.0"):
                    base_abs_fn = self.abs_fn[0:-2]
                    for i in range(100):
                        abs_fn = base_abs_fn + b".%d" % i
                        if os.path.exists(abs_fn):
                            self.abs_fn_list.append(abs_fn)
                        else:
                            break
                else:
                    return CheckFileResult.IGNORE
            else:
                self.abs_fn_list.append(self.abs_fn)
            if self.fn.lower().startswith(b"system.") or self.fn.lower().startswith(b"system_a.") or self.fn.lower().startswith(b"system-sign."):
                self.image_type = ImageType.SYSTEM
                return CheckFileResult.SYSTEM_IMG
            elif self.fn.lower().startswith(b"vendor.") or self.fn.lower().startswith(b"vendor_a.") or self.fn.lower().startswith(b"vendor-sign."):
                self.image_type = ImageType.VENDOR
                return CheckFileResult.VENDOR_IMG
            elif self.fn.lower().startswith(b"system_b.") or self.fn.lower().startswith(b"vendor_b."):
                return CheckFileResult.IGNORE
            elif self.fn.lower().startswith(b"system_ext."):
                return CheckFileResult.IGNORE
            elif self.fn.lower().startswith(b"system_other."):
                return CheckFileResult.IGNORE
            elif self.fn.lower().startswith(b"vendor_dlkm."):
                return CheckFileResult.IGNORE
            else:
                if os.stat(self.abs_fn).st_size < 32 * 1024 * 1024:
                    # Ignore images smaller than 32 MiB, these images can't be a valid system/vendor partition
                    return CheckFileResult.IGNORE
                assert False, "SparseImageHandler: %r does not start with system/vendor (Size %.2f MiB)" % (self.fn, os.stat(self.abs_fn).st_size / 1024**2)
        else:
            return CheckFileResult.HANDLER_NO_MATCH

    def get_extra_handled_size(self) -> int:
        result = 0
        # Only count from file 1
        for fn in self.abs_fn_list[1:]:
            result += os.stat(fn).st_size
        return result

    def extract_and_get_next_handler(self, stage_dir_rel):
        output_fn = self.fn + b".SparseImageHandler"
        abs_stage_dir = self.extractor.create_stage_dir(stage_dir_rel)
        abs_out_fn = os.path.join(abs_stage_dir, output_fn)
        cmd: List[bytes] = [b"simg2img"] + self.abs_fn_list + [abs_out_fn]
        logging.info("SparseImageHandler: cmd=%r" % cmd)
        subprocess.check_call(cmd)
        assert os.path.exists(abs_out_fn)
        HANDLER_TYPES = [ExtfsHandler, AsusMagicHandler, ErofsHandler, MotoPivHandler]
        handlers = []
        for handler_type in HANDLER_TYPES:
            handler = handler_type(self.extractor, self.extractor.rel_path(abs_out_fn), image_type=self.image_type, file_type=get_file_type(abs_out_fn))
            handler_result = handler.check()
            if handler_result != CheckFileResult.HANDLER_NO_MATCH:
                assert handler_result in (CheckFileResult.SYSTEM_IMG, CheckFileResult.VENDOR_IMG, CheckFileResult.SYSTEM_OR_VENDOR), "Unexpected handler_result=%r from handler %r" % (handler_result, handler.__class__.__name__)
                handlers.append(handler)
        if len(handlers) > 1:
            raise MultipleHandlerMatchError("File %r: %r" % (abs_out_fn, [x.__class__.__name__ for x in handlers]))
        elif len(handlers) == 0:
            raise NoHandlerMatchError("SparseImageHandler.extract_and_get_next_handler(): Don't know what to do with %r (file_type=%r)" % (abs_out_fn, get_file_type(abs_out_fn)))
        else:
            return handlers[0]


class MotoPivHandler(FileHandler):
    def check(self) -> CheckFileResult:
        with open(self.abs_fn, 'rb') as f:
            buf = f.read(32)
        if buf[0:4] == b'MOTO' and b'MOT_PIV_FULL256' in buf:
            if self.image_type == ImageType.SYSTEM:
                return CheckFileResult.SYSTEM_IMG
            elif self.image_type == ImageType.VENDOR:
                return CheckFileResult.VENDOR_IMG
            else:
                raise ValueError("Bad image_type %r" % self.image_type)
        else:
            return CheckFileResult.HANDLER_NO_MATCH

    def extract_and_get_next_handler(self, stage_dir_rel):
        output_fn = self.fn + b".MotoPivHandler"
        abs_stage_dir = self.extractor.create_stage_dir(stage_dir_rel)
        abs_out_fn = os.path.join(abs_stage_dir, output_fn)
        with open(self.abs_fn, 'rb') as input_file:
            buf = input_file.read(32)
            offset = struct.unpack("<I", buf[24:28])[0]
            assert offset <= 1024**2
            assert offset % 512 == 0  # Just to make sure it is at least aligned to 512-byte sectors
            input_file.seek(offset, 0)
            with open(abs_out_fn, 'wb') as output_file:
                while True:
                    buf = input_file.read(1024**2)
                    if buf == b'':
                        break
                    output_file.write(buf)
        # Same structure as in SparseImageHandler, maybe we need other handlers later
        HANDLER_TYPES = [ExtfsHandler]
        handlers = []
        for handler_type in HANDLER_TYPES:
            handler = handler_type(self.extractor, self.extractor.rel_path(abs_out_fn), image_type=self.image_type, file_type=get_file_type(abs_out_fn))
            handler_result = handler.check()
            if handler_result != CheckFileResult.HANDLER_NO_MATCH:
                assert handler_result in (CheckFileResult.SYSTEM_IMG, CheckFileResult.VENDOR_IMG, CheckFileResult.SYSTEM_OR_VENDOR), "Unexpected handler_result=%r from handler %r" % (handler_result, handler.__class__.__name__)
                handlers.append(handler)
        if len(handlers) > 1:
            raise MultipleHandlerMatchError("File %r: %r" % (abs_out_fn, [x.__class__.__name__ for x in handlers]))
        elif len(handlers) == 0:
            raise NoHandlerMatchError("MotoPivHandler.extract_and_get_next_handler(): Don't know what to do with %r (file_type=%r)" % (abs_out_fn, get_file_type(abs_out_fn)))
        else:
            return handlers[0]


class SuperImageHandler(FileHandler):
    is_sparse: bool

    def check(self) -> CheckFileResult:
        self.is_sparse = False
        if self.file_type.startswith("Android sparse image, version: 1.0,"):
            if self.fn.lower().startswith(b"super"):
                self.is_sparse = True
                return CheckFileResult.ARCHIVE
            else:
                return CheckFileResult.HANDLER_NO_MATCH
        else:
            with open(self.abs_fn, 'rb') as f:
                if not liblp.check_magic(f):
                    return CheckFileResult.HANDLER_NO_MATCH
            if not self.fn.lower().startswith(b'super'):
                raise ValueError(f"Found liblp magic in {self.fn} but not in super image, this should not happen")
            return CheckFileResult.ARCHIVE

    def extract_file2dir(self, output_path_rel):
        super_img_fn = self.abs_fn
        if self.is_sparse:
            super_img_fn = self.abs_fn + b'.unsparse'
            cmd: List[bytes] = [b"simg2img", self.abs_fn, super_img_fn]
            subprocess.check_call(cmd)
        super_img = liblp.SuperImage(super_img_fn)
        abs_output_path = self.extractor.abs_fn(output_path_rel)
        partition_names = super_img.get_partition_names()
        found_system = False
        for partition_name in ["system", "system_a", "system_b"]:
            if partition_name in partition_names:
                output_fn = os.path.join(abs_output_path, partition_name.encode() + b".img")
                with open(output_fn, 'wb') as f:
                    super_img.write_partition(partition_name, f)
                found_system = True
                break
        assert found_system, "Failed to find system in super.img"
        found_vendor = False
        for partition_name in ["vendor", "vendor_a", "vendor_b"]:
            if partition_name in partition_names:
                output_fn = os.path.join(abs_output_path, partition_name.encode() + b".img")
                with open(output_fn, 'wb') as f:
                    super_img.write_partition(partition_name, f)
                found_vendor = True
                break
        assert found_vendor, "Failed to find vendor in super.img"


class SignImgHandler(FileHandler):
    """
    https://github.com/R0rt1z2/signimg2img
    """
    def check(self) -> CheckFileResult:
        magic_buf: bytes
        # Read magic
        with open(self.abs_fn, 'rb') as f:
            magic_buf = f.read(4)
        if magic_buf not in (b'BFBF', b'SSSS'):
            return CheckFileResult.HANDLER_NO_MATCH
        if self.fn.lower() == b"system-sign.img":
            return CheckFileResult.SYSTEM_IMG
        elif self.fn.lower() == b"vendor-sign.img":
            return CheckFileResult.VENDOR_IMG
        # TODO: Maybe also add boot/recovery images
        assert b'system' not in self.fn, "Unexpected system image in SignImgHandler: %r" % self.fn
        assert b'vendor' not in self.fn, "Unexpected vendor image in SignImgHandler: %r" % self.fn
        return CheckFileResult.HANDLER_NO_MATCH

    def extract_and_get_next_handler(self, stage_dir_rel):
        output_fn = self.fn + b".SparseImageHandler"
        abs_stage_dir = self.extractor.create_stage_dir(stage_dir_rel)
        abs_out_fn = os.path.join(abs_stage_dir, output_fn)
        with open(self.abs_fn, 'rb') as input_fh, open(abs_out_fn, 'wb') as output_fh:
            buf = input_fh.read(1024)
            magic = buf[0:4]
            if magic == b'SSSS':
                # https://github.com/R0rt1z2/signimg2img is using 60:64, but at least some images have offset 44:48
                # Sample: TB-7305F_S000083_200703_ROW.zip
                offset = struct.unpack("<I", buf[44:48])[0]
                input_fh.seek(offset, 0)
                while True:
                    buf = input_fh.read(1024 ** 2)
                    if buf == b'':
                        break
                    output_fh.write(buf)
            else:
                raise NotImplementedError("SignImgHandler: Magic %r not yet implemented" % bytes(magic))
        HANDLER_TYPES = [SparseImageHandler]
        handlers = []
        for handler_type in HANDLER_TYPES:
            handler = handler_type(self.extractor, self.extractor.rel_path(abs_out_fn), image_type=self.image_type,
                                   file_type=get_file_type(abs_out_fn))
            handler_result = handler.check()
            if handler_result != CheckFileResult.HANDLER_NO_MATCH:
                assert handler_result in (CheckFileResult.SYSTEM_IMG, CheckFileResult.VENDOR_IMG,
                                          CheckFileResult.SYSTEM_OR_VENDOR), "Unexpected handler_result=%r from handler %r" % (
                                          handler_result, handler.__class__.__name__)
                handlers.append(handler)
        if len(handlers) > 1:
            raise MultipleHandlerMatchError("File %r: %r" % (abs_out_fn, [x.__class__.__name__ for x in handlers]))
        elif len(handlers) == 0:
            raise NoHandlerMatchError(
                "SignImgHandler.extract_and_get_next_handler(): Don't know what to do with %r (file_type=%r)" % (
                    abs_out_fn, get_file_type(abs_out_fn)))
        else:
            return handlers[0]


class AsusMagicHandler(FileHandler):
    def check(self) -> CheckFileResult:
        if self.fn.lower().startswith(b"system") or self.fn.lower().startswith(b"vendor"):
            buf = open(self.abs_fn, 'rb').read(4096)
            magic = buf[0x0:0xc]
            if magic == b'ASUS MAGIC!\n':
                if self.fn.lower().startswith(b"system"):
                    return CheckFileResult.SYSTEM_IMG
                else:
                    assert self.fn.lower().startswith(b"vendor")
                    return CheckFileResult.VENDOR_IMG
            else:
                return CheckFileResult.HANDLER_NO_MATCH
        else:
            return CheckFileResult.HANDLER_NO_MATCH

    def extract_and_get_next_handler(self, stage_dir_rel):
        output_fn = self.fn + b".AsusMagicHandler"
        abs_stage_dir = self.extractor.create_stage_dir(stage_dir_rel)
        abs_out_fn = os.path.join(abs_stage_dir, output_fn)
        with open(self.abs_fn, 'rb') as input_file:
            input_file.read(4096)
            with open(abs_out_fn, 'wb') as output_file:
                buf = input_file.read(128 * 1024)
                while len(buf) > 0:
                    output_file.write(buf)
                    buf = input_file.read(128 * 1024)
        HANDLER_TYPES = [ExtfsHandler, ErofsHandler]
        handlers = []
        for handler_type in HANDLER_TYPES:
            handler = handler_type(self.extractor, self.extractor.rel_path(abs_out_fn), image_type=self.image_type, file_type=get_file_type(abs_out_fn))
            handler_result = handler.check()
            if handler_result != CheckFileResult.HANDLER_NO_MATCH:
                assert handler_result in (CheckFileResult.SYSTEM_IMG, CheckFileResult.VENDOR_IMG, CheckFileResult.SYSTEM_OR_VENDOR), "Unexpected handler_result=%r from handler %r" % (handler_result, handler.__class__.__name__)
                handlers.append(handler)
        if len(handlers) > 1:
            raise MultipleHandlerMatchError("File %r: %r" % (abs_out_fn, [x.__class__.__name__ for x in handlers]))
        elif len(handlers) == 0:
            raise NoHandlerMatchError("AsusMagicHandler.extract_and_get_next_handler(): Don't know what to do with %r (file_type=%r)" % (abs_out_fn, get_file_type(abs_out_fn)))
        else:
            return handlers[0]


class Lz4Handler(FileHandler):
    def check(self) -> CheckFileResult:
        if self.file_type.startswith("LZ4 compressed data"):
            if not self.fn.lower().endswith(b'.lz4'):
                if os.stat(self.abs_fn).st_size > 32 * 1024 * 1024:
                    raise ValueError("Bad LZ4 filename %r" % self.fn)
                else:
                    return CheckFileResult.HANDLER_NO_MATCH
            if self.fn.lower().startswith(b"system_other"):
                return CheckFileResult.IGNORE
            if self.fn.lower() == b"boot.img.lz4":
                return CheckFileResult.HANDLER_NO_MATCH  # Handled by BootImageHandler
            if self.fn.lower() == b"recovery.img.lz4":
                return CheckFileResult.HANDLER_NO_MATCH  # Handled by RecoveryImageHandler
            if self.fn.lower() == b"super.img.lz4":
                return CheckFileResult.ARCHIVE
            if self.fn.lower().startswith(b"prism."):
                return CheckFileResult.IGNORE
            if self.fn.lower().startswith(b"persist."):
                return CheckFileResult.IGNORE
            if self.fn.lower().startswith(b"userdata."):  # userdata partition contains stuff like dalvik cache etc.
                return CheckFileResult.IGNORE
            if self.fn.lower().startswith(b"carrier."):  # userdata partition contains stuff like dalvik cache etc.
                return CheckFileResult.IGNORE
            if self.fn.lower().startswith(b"product.img"):
                return CheckFileResult.IGNORE
            if self.fn.lower().startswith(b"cache.img"):
                return CheckFileResult.IGNORE
            if self.fn.lower().startswith(b"hidden.img"):
                return CheckFileResult.IGNORE
            if self.fn.lower().startswith(b"non-hlos"):
                return CheckFileResult.IGNORE
            if self.fn.lower().startswith(b"modem"):
                return CheckFileResult.IGNORE
            if self.fn.lower().startswith(b"odm."):
                return CheckFileResult.IGNORE
            if self.fn.lower().startswith(b"system"):
                self.image_type = ImageType.SYSTEM
                return CheckFileResult.SYSTEM_IMG
            elif self.fn.lower().startswith(b"vendor"):
                self.image_type = ImageType.VENDOR
                return CheckFileResult.VENDOR_IMG
            else:
                if os.stat(self.abs_fn).st_size < 32 * 1024 * 1024:
                    # Ignore images smaller than 32 MiB, these images can't be a valid system/vendor partition
                    return CheckFileResult.IGNORE
                assert False, "Lz4Handler: %r does not start with system/vendor" % self.fn
        else:
            return CheckFileResult.HANDLER_NO_MATCH

    def extract_and_get_next_handler(self, stage_dir_rel):
        assert self.fn.endswith(b'.lz4')
        output_fn = self.fn[0:-4]
        abs_stage_dir = self.extractor.create_stage_dir(stage_dir_rel)
        abs_out_fn = os.path.join(abs_stage_dir, output_fn)
        cmd = ["lz4", "-dc", self.abs_fn]
        logging.info("Lz4Handler: cmd=%r, out=%r" % (cmd, abs_out_fn))
        # The command "lz4 -d" is behaving differently depending on whether stdout is a console or not.
        # If it is a console, it will strip the .lz4 extension and use the remaining path as output file.
        # If it is not a console (e.g. if the extractor is called from another utility and stdout is captured),
        # lz4 -d will just output the decompressed data to stdout. There is no command-line option to force output
        # to a file, so let's force output to stdout and redirect it using subprocess
        with open(abs_out_fn, 'wb') as f:
            subprocess.check_call(cmd, stdout=f)
        assert os.path.exists(abs_out_fn)
        HANDLER_TYPES = [ExtfsHandler, SparseImageHandler, ErofsHandler, SuperImageHandler]
        handlers = []
        for handler_type in HANDLER_TYPES:
            handler = handler_type(self.extractor, self.extractor.rel_path(abs_out_fn), image_type=self.image_type, file_type=get_file_type(abs_out_fn))
            handler_result = handler.check()
            if handler_result != CheckFileResult.HANDLER_NO_MATCH:
                assert handler_result in (CheckFileResult.SYSTEM_IMG, CheckFileResult.VENDOR_IMG, CheckFileResult.SYSTEM_OR_VENDOR, CheckFileResult.ARCHIVE), "Unexpected handler_result=%r from handler %r" % (handler_result, handler.__class__.__name__)
                handlers.append(handler)
        if len(handlers) > 1:
            raise MultipleHandlerMatchError("File %r: %r" % (abs_out_fn, [x.__class__.__name__ for x in handlers]))
        elif len(handlers) == 0:
            raise NoHandlerMatchError("Lz4Handler.extract_and_get_next_handler(): Don't know what to do with %r (file_type=%r)" % (abs_out_fn, get_file_type(abs_out_fn)))
        else:
            return handlers[0]


class GzipHandler(FileHandler):
    def check(self) -> CheckFileResult:
        if self.file_type.startswith("gzip compressed data"):
            assert self.fn.endswith(b'.gz') or self.fn.endswith(b'.tgz')
            return CheckFileResult.ARCHIVE
        else:
            return CheckFileResult.HANDLER_NO_MATCH

    def extract_and_get_next_handler(self, stage_dir_rel):
        if self.fn.endswith(b'.gz'):
            output_fn = self.fn[0:-3]
        elif self.fn.endswith(b'.tgz'):
            output_fn = self.fn[0:-4] + b'.tar'
        else:
            assert False, "Invalid gzip filename %r" % self.fn
        abs_stage_dir = self.extractor.create_stage_dir(stage_dir_rel)
        abs_out_fn = os.path.join(abs_stage_dir, output_fn)
        cmd = ["gzip", "-dc", self.abs_fn]
        logging.info("GzipHandler: cmd=%r  out=%r" % (cmd, abs_out_fn))
        # The command "gzip -d" has no command line option to force output to a
        # specific file.
        with open(abs_out_fn, 'wb') as f:
            retcode = subprocess.call(cmd, stdout=f)
            # Exit code 2 means warning, e.g. "trailing garbage ignored"
            assert retcode in (0, 2), "GzipHandler: command %r failed with exit code %r" % (cmd, retcode)
        assert os.path.exists(abs_out_fn)
        HANDLER_TYPES = [TarHandlerIgnoreExtension]
        handlers = []
        for handler_type in HANDLER_TYPES:
            handler = handler_type(self.extractor, self.extractor.rel_path(abs_out_fn), image_type=self.image_type, file_type=get_file_type(abs_out_fn))
            handler_result = handler.check()
            if handler_result != CheckFileResult.HANDLER_NO_MATCH:
                assert handler_result in [CheckFileResult.ARCHIVE], "Unexpected handler_result=%r from handler %r" % (handler_result, handler.__class__.__name__)
                handlers.append(handler)
        if len(handlers) > 1:
            raise MultipleHandlerMatchError("File %r: %r" % (abs_out_fn, [x.__class__.__name__ for x in handlers]))
        elif len(handlers) == 0:
            raise NoHandlerMatchError("GzipHandler.extract_and_get_next_handler(): Don't know what to do with %r (file_type=%r)" % (abs_out_fn, get_file_type(abs_out_fn)))
        else:
            return handlers[0]


class Bzip2Handler(FileHandler):
    def check(self) -> CheckFileResult:
        if self.file_type.startswith("bzip2 compressed data"):
            assert self.fn.endswith(b'.bz2')
            return CheckFileResult.ARCHIVE
        else:
            return CheckFileResult.HANDLER_NO_MATCH

    def extract_and_get_next_handler(self, stage_dir_rel):
        if self.fn.endswith(b'.bz2'):
            output_fn = self.fn[0:-4]
        else:
            assert False, "Invalid bzip2 filename %r" % self.fn
        abs_stage_dir = self.extractor.create_stage_dir(stage_dir_rel)
        abs_out_fn = os.path.join(abs_stage_dir, output_fn)
        cmd = ["bzip2", "-dc", self.abs_fn]
        logging.info("Bzip2Handler: cmd=%r  out=%r" % (cmd, abs_out_fn))
        # The command "bzip2 -d" has no command line option to force output to a
        # specific file.
        with open(abs_out_fn, 'wb') as f:
            subprocess.check_call(cmd, stdout=f)
        assert os.path.exists(abs_out_fn)
        HANDLER_TYPES = [TarHandler]
        handlers = []
        for handler_type in HANDLER_TYPES:
            handler = handler_type(self.extractor, self.extractor.rel_path(abs_out_fn), image_type=self.image_type, file_type=get_file_type(abs_out_fn))
            handler_result = handler.check()
            if handler_result != CheckFileResult.HANDLER_NO_MATCH:
                assert handler_result in [CheckFileResult.ARCHIVE], "Unexpected handler_result=%r from handler %r" % (handler_result, handler.__class__.__name__)
                handlers.append(handler)
        if len(handlers) > 1:
            raise MultipleHandlerMatchError("File %r: %r" % (abs_out_fn, [x.__class__.__name__ for x in handlers]))
        elif len(handlers) == 0:
            raise NoHandlerMatchError("Bzip2Handler.extract_and_get_next_handler(): Don't know what to do with %r (file_type=%r)" % (abs_out_fn, get_file_type(abs_out_fn)))
        else:
            return handlers[0]


class XzHandler(FileHandler):
    def check(self) -> CheckFileResult:
        if self.file_type.startswith("XZ compressed data"):
            assert self.fn.endswith(b'.xz')
            return CheckFileResult.ARCHIVE
        else:
            return CheckFileResult.HANDLER_NO_MATCH

    def extract_and_get_next_handler(self, stage_dir_rel):
        if self.fn.endswith(b'.xz'):
            output_fn = self.fn[0:-3]
        else:
            assert False, "Invalid xz filename %r" % self.fn
        abs_stage_dir = self.extractor.create_stage_dir(stage_dir_rel)
        abs_out_fn = os.path.join(abs_stage_dir, output_fn)
        cmd = ["xz", "-dc", self.abs_fn]
        logging.info("XzHandler: cmd=%r  out=%r" % (cmd, abs_out_fn))
        # The command "xz -d" has no command line option to force output to a
        # specific file.
        with open(abs_out_fn, 'wb') as f:
            subprocess.check_call(cmd, stdout=f)
        assert os.path.exists(abs_out_fn)
        HANDLER_TYPES = [TarHandler]
        handlers = []
        for handler_type in HANDLER_TYPES:
            handler = handler_type(self.extractor, self.extractor.rel_path(abs_out_fn), image_type=self.image_type, file_type=get_file_type(abs_out_fn))
            handler_result = handler.check()
            if handler_result != CheckFileResult.HANDLER_NO_MATCH:
                assert handler_result in [CheckFileResult.ARCHIVE], "Unexpected handler_result=%r from handler %r" % (handler_result, handler.__class__.__name__)
                handlers.append(handler)
        if len(handlers) > 1:
            raise MultipleHandlerMatchError("File %r: %r" % (abs_out_fn, [x.__class__.__name__ for x in handlers]))
        elif len(handlers) == 0:
            raise NoHandlerMatchError("XzHandler.extract_and_get_next_handler(): Don't know what to do with %r (file_type=%r)" % (abs_out_fn, get_file_type(abs_out_fn)))
        else:
            return handlers[0]


class BrotliHandler(FileHandler):
    def check(self) -> CheckFileResult:
        # Brotli is not recognized with file
        if self.fn == b'system.new.dat.br':
            if os.path.exists(os.path.join(os.path.dirname(self.abs_fn), b'system.transfer.list')):
                # This case is handled by TransferListHandler, which also contains brotli decompression
                return CheckFileResult.HANDLER_NO_MATCH
            self.image_type = ImageType.SYSTEM
            return CheckFileResult.SYSTEM_IMG
        elif self.fn == b'vendor.new.dat.br':
            if os.path.exists(os.path.join(os.path.dirname(self.abs_fn), b'vendor.transfer.list')):
                # This case is handled by TransferListHandler, which also contains brotli decompression
                return CheckFileResult.HANDLER_NO_MATCH
            self.image_type = ImageType.SYSTEM
            return CheckFileResult.SYSTEM_IMG
        else:
            return CheckFileResult.HANDLER_NO_MATCH

    def extract_and_get_next_handler(self, stage_dir_rel):
        output_fn = self.fn[0:-3]
        abs_stage_dir = self.extractor.create_stage_dir(stage_dir_rel)
        abs_out_fn = os.path.join(abs_stage_dir, output_fn)
        cmd = ["brotli", "--decompress", self.abs_fn, b"--output=%s" % abs_out_fn]
        logging.info("BrotliHandler: cmd=%r" % cmd)
        subprocess.check_call(cmd)
        assert os.path.exists(abs_out_fn)
        HANDLER_TYPES = [ExtfsHandler, ErofsHandler]
        handlers = []
        for handler_type in HANDLER_TYPES:
            handler = handler_type(self.extractor, self.extractor.rel_path(abs_out_fn), image_type=self.image_type, file_type=get_file_type(abs_out_fn))
            handler_result = handler.check()
            if handler_result != CheckFileResult.HANDLER_NO_MATCH:
                assert handler_result in (CheckFileResult.SYSTEM_IMG, CheckFileResult.VENDOR_IMG, CheckFileResult.SYSTEM_OR_VENDOR), "Unexpected handler_result=%r from handler %r" % (handler_result, handler.__class__.__name__)
                handlers.append(handler)
        if len(handlers) > 1:
            raise MultipleHandlerMatchError("File %r: %r" % (abs_out_fn, [x.__class__.__name__ for x in handlers]))
        elif len(handlers) == 0:
            raise NoHandlerMatchError("BrotliHandler.extract_and_get_next_handler(): Don't know what to do with %r (file_type=%r)" % (abs_out_fn, get_file_type(abs_out_fn)))
        else:
            return handlers[0]


class TransferListHandler(FileHandler):
    file_size: int
    new_commands: List[List[int]]
    data_files: List[bytes]
    image_type: ImageType
    force_single_file: bool

    BLOCK_SIZE = 4096

    def check(self) -> CheckFileResult:
        if self.fn == b"system.transfer.list":
            self.image_type = ImageType.SYSTEM
        elif self.fn == b"vendor.transfer.list":
            self.image_type = ImageType.VENDOR
        else:
            return CheckFileResult.HANDLER_NO_MATCH
        self.file_size = 0
        self.new_commands = []
        self.data_files = []
        for line in open(self.abs_fn):
            line_split = line.split(" ")
            cmd = line_split[0]
            if cmd in ("new", "erase", "zero"):
                assert len(line_split) == 2, "Not exactly 2 items in line %r" % line
                cmd_data = line_split[1]
                cmd_data_items = [int(x) for x in cmd_data.split(",")]
                # First element is number of elements
                assert cmd_data_items[0] == len(cmd_data_items) - 1
                # Find file size based on maximum block number
                for i in range(1, len(cmd_data_items), 2):
                    if cmd_data_items[i] * TransferListHandler.BLOCK_SIZE > self.file_size:
                        self.file_size = cmd_data_items[i] * TransferListHandler.BLOCK_SIZE
                if cmd == "new":
                    self.new_commands.append(cmd_data_items[1:])
        # Some firmwares append ".1", ".2", ... to the input files for individual "new" commands in system.transfer.list.
        # Other firmwares use one single file for that.
        self.force_single_file = False
        for i in range(len(self.new_commands)):
            if self.image_type == ImageType.SYSTEM:
                fn = b'system.new.dat'
            elif self.image_type == ImageType.VENDOR:
                fn = b'vendor.new.dat'
            else:
                raise ValueError("Bad image_type %r" % self.image_type)
            fn_with_index = fn + (".%d" % i).encode()
            if i == 1:
                abs_fn_with_index = os.path.join(os.path.dirname(self.abs_fn), fn_with_index)
                if not os.path.exists(abs_fn_with_index) and not os.path.exists(abs_fn_with_index + b'.br'):
                    self.force_single_file = True
            if i > 0 and not self.force_single_file:
                fn = fn_with_index
            abs_fn = os.path.join(os.path.dirname(self.abs_fn), fn)
            if os.path.exists(abs_fn):
                self.data_files.append(abs_fn)
            else:
                abs_fn += b'.br'
                assert os.path.exists(abs_fn), "File %r (referenced from %r) doesn't exist" % (abs_fn, self.abs_fn)
                self.data_files.append(abs_fn)
        assert self.file_size > 0
        if self.image_type == ImageType.SYSTEM:
            return CheckFileResult.SYSTEM_IMG
        elif self.image_type == ImageType.VENDOR:
            return CheckFileResult.VENDOR_IMG
        else:
            raise ValueError("Bad image_type %r" % self.image_type)

    def get_extra_handled_size(self) -> int:
        result = 0
        for fn in self.data_files:
            result += os.stat(fn).st_size
        return result

    def extract_and_get_next_handler(self, stage_dir_rel) -> FileHandler:
        output_fn = self.fn[0:-len(b'.transfer.list')] + b'.img'
        abs_stage_dir = self.extractor.create_stage_dir(stage_dir_rel)
        abs_out_fn = os.path.join(abs_stage_dir, output_fn)
        with open(abs_out_fn, 'wb') as output_file:
            assert len(self.new_commands) == len(self.data_files)
            if self.force_single_file:
                data_file = self.data_files[0]
                if data_file.endswith(b".br"):
                    real_data_file = data_file[0:-3]
                    cmd = ["brotli", "--decompress", data_file, b"--output=%s" % real_data_file]
                    subprocess.check_call(cmd)
                    data_file = real_data_file
                with open(data_file, 'rb') as input_file:
                    for cmd_index in range(len(self.new_commands)):
                        new_cmd = self.new_commands[cmd_index]
                        for i in range(0, len(new_cmd), 2):
                            begin_block = new_cmd[i]
                            end_block = new_cmd[i + 1]
                            block_cnt = end_block - begin_block
                            output_file.seek(begin_block * TransferListHandler.BLOCK_SIZE)
                            for _i in range(block_cnt):
                                buf = input_file.read(TransferListHandler.BLOCK_SIZE)
                                assert len(buf) == TransferListHandler.BLOCK_SIZE, "Short read from %r: %d bytes" % (data_file, len(buf))
                                output_file.write(buf)
            else:
                for cmd_index in range(len(self.new_commands)):
                    new_cmd = self.new_commands[cmd_index]
                    data_file = self.data_files[cmd_index]
                    if data_file.endswith(b".br"):
                        real_data_file = data_file[0:-3]
                        cmd = ["brotli", "--decompress", data_file, b"--output=%s" % real_data_file]
                        subprocess.check_call(cmd)
                        data_file = real_data_file
                    with open(data_file, 'rb') as input_file:
                        for i in range(0, len(new_cmd), 2):
                            begin_block = new_cmd[i]
                            end_block = new_cmd[i+1]
                            block_cnt = end_block - begin_block
                            output_file.seek(begin_block * TransferListHandler.BLOCK_SIZE)
                            for _i in range(block_cnt):
                                buf = input_file.read(TransferListHandler.BLOCK_SIZE)
                                assert len(buf) == TransferListHandler.BLOCK_SIZE, "Short read from %r: %d bytes" % (data_file, len(buf))
                                output_file.write(buf)
            if output_file.tell() < self.file_size:
                output_file.truncate(self.file_size)
        HANDLER_TYPES = [ExtfsHandler, ErofsHandler]
        handlers = []
        for handler_type in HANDLER_TYPES:
            handler = handler_type(self.extractor, self.extractor.rel_path(abs_out_fn), image_type=self.image_type, file_type=get_file_type(abs_out_fn))
            handler_result = handler.check()
            if handler_result != CheckFileResult.HANDLER_NO_MATCH:
                assert handler_result in (CheckFileResult.SYSTEM_IMG, CheckFileResult.VENDOR_IMG, CheckFileResult.SYSTEM_OR_VENDOR), "Unexpected handler_result=%r from handler %r" % (handler_result, handler.__class__.__name__)
                handlers.append(handler)
        if len(handlers) > 1:
            raise MultipleHandlerMatchError("File %r: %r" % (abs_out_fn, [x.__class__.__name__ for x in handlers]))
        elif len(handlers) == 0:
            raise NoHandlerMatchError("TransferListHandler.extract_and_get_next_handler(): Don't know what to do with %r (file_type=%r)" % (abs_out_fn, get_file_type(abs_out_fn)))
        else:
            return handlers[0]


class NokiaPayloadBinHandler(FileHandler):
    """
    Handler for Nokia payload.bin files
    """
    def check(self) -> CheckFileResult:
        if self.fn.lower() != b'payload.bin':
            return CheckFileResult.HANDLER_NO_MATCH
        # file_type is 'data' => no check for that
        assert os.stat(self.abs_fn).st_size >= 32 * 1024 * 1024
        return CheckFileResult.ARCHIVE

    def extract_file2dir(self, output_path_rel):
        global base_dir
        abs_output_path = self.extractor.abs_fn(output_path_rel)
        cmd = ["python3", "%s/nokia-dumper/payload_dumper.py" % base_dir, self.abs_fn, abs_output_path]
        logging.info("NokiaPayloadBinHandler.extract_file2dir(%r): cmd=%r" % (output_path_rel, cmd))
        subprocess.check_call(cmd)


class MountableImage(FileHandler):
    def mount(self, mountpoint):
        assert False, "Must be implemented in subclass"

    def umount(self):
        assert False, "Must be implemented in subclass"

    def check(self) -> CheckFileResult:
        raise NotImplementedError()


class ExtfsHandler(MountableImage):
    mountpoint: Optional[bytes]

    def check(self) -> CheckFileResult:
        if self.file_type.startswith("Linux rev 1.0 ext4 filesystem data") or self.file_type.startswith("Linux rev 1.0 ext2 filesystem data"):
            if self.fn.lower() in (b'system.new.dat', b'vendor.new.dat'):
                # These files are not the actual filesystem and need to be assembled based on system.transfer.list/vendor.transfer.list
                return CheckFileResult.HANDLER_NO_MATCH
            if self.image_type == ImageType.SYSTEM:
                return CheckFileResult.SYSTEM_IMG
            elif self.image_type == ImageType.VENDOR:
                return CheckFileResult.VENDOR_IMG
            # system_1.img is a potential false positive, so let's enforce filenames starting with "system."
            if self.fn.lower().startswith(b"system.") or self.fn.lower().startswith(b"system_a.") or self.fn.lower().startswith(b"system_b."):
                self.image_type = ImageType.SYSTEM
                return CheckFileResult.SYSTEM_IMG
            elif self.fn.lower().endswith(b'stock_system_image.img') and os.stat(self.abs_fn).st_size > 1024**3:
                self.image_type = ImageType.SYSTEM
                return CheckFileResult.SYSTEM_IMG
            elif self.fn.lower().endswith(b'system_raw.img') and os.stat(self.abs_fn).st_size > 256*1024**2:
                self.image_type = ImageType.SYSTEM
                return CheckFileResult.SYSTEM_IMG
            elif self.fn.lower().startswith(b"vendor.") or self.fn.lower().startswith(b"vendor_a.") or self.fn.lower().startswith(b"vendor_b."):
                self.image_type = ImageType.VENDOR
                return CheckFileResult.VENDOR_IMG
            else:
                logging.warning("ExtfsHandler: %r does not start with system/vendor" % self.abs_fn)
                return CheckFileResult.HANDLER_NO_MATCH
        else:
            return CheckFileResult.HANDLER_NO_MATCH

    def mount(self, mountpoint):
        mountpoint = self.extractor.abs_fn(mountpoint)
        assert not hasattr(self, "mountpoint") or self.mountpoint is None, "ExtfsHandler: Can only mount once"
        assert os.path.exists(mountpoint), "Mountpoint %r doesn't exist" % mountpoint
        assert os.path.isdir(mountpoint), "Mountpoint %r is not a directory" % mountpoint
        # Increase size when required
        target_size = 0
        dumpe2fs_cmd = ["dumpe2fs", "-h", self.abs_fn]
        logging.info("ExtfsHandler.mount(): dumpe2fs_cmd=%r" % dumpe2fs_cmd)
        for line in subprocess.Popen(dumpe2fs_cmd, stdout=subprocess.PIPE).communicate()[0].splitlines():
            m = re.match(r'Block count:\s*(\d+)', line.decode("ASCII"))
            if m:
                target_size = 4096 * int(m.group(1))

        logging.debug("TARGET SIZE: %d", target_size)
        logging.debug("ACTUAL SIZE: %d", os.stat(self.abs_fn).st_size)

        if target_size > os.stat(self.abs_fn).st_size:
            logging.debug("Increasing filesystem size to %d bytes (%.3fGB)",
                          target_size, target_size / (1024.0 * 1024 * 1024))
            fh = open(self.abs_fn, "rb+")
            fh.seek(target_size - 1)
            fh.write(b'\0')
            fh.close()
        check_cmd = ["e2fsck", "-y", "-f", self.abs_fn]
        logging.info("ExtfsHandler.mount(): check_cmd=%r" % check_cmd)
        retcode = subprocess.call(check_cmd)
        # 0: No errors
        # 1/2: Errors fixed
        # 8: Operational errors, e.g. new FEATURE_R14 for Android 10 images
        assert retcode in (0, 1, 2, 8), "Failed to check/fix filesystem, e2fsck returned %d" % retcode
        self.mountpoint = mountpoint
        # Some Android10 images can only be mounted read-only due to new filesystem features
        mount_cmd = ["mount", "-o", "loop,ro", self.abs_fn, mountpoint]
        logging.info("ExtfsHandler.mount(): mount_cmd=%r" % mount_cmd)
        subprocess.check_call(mount_cmd)

    def umount(self):
        cmd = ["umount", self.mountpoint]
        logging.info("MountableImage.umount: cmd=%r" % cmd)
        self.mountpoint = None
        subprocess.check_call(cmd)


class FilesystemExtractor(FileHandler):
    def check(self) -> CheckFileResult:
        raise NotImplementedError()

    def extract_filesystem(self, output_dir):
        raise NotImplementedError("Must be implemented in subclass")


class ErofsHandler(FilesystemExtractor):
    def check(self) -> CheckFileResult:
        with open(self.abs_fn, 'rb') as f:
            f.seek(0x400)
            buf = f.read(4)
            if buf == b'\xe2\xe1\xf5\xe0':
                if self.image_type == ImageType.SYSTEM:
                    return CheckFileResult.SYSTEM_IMG
                elif self.image_type == ImageType.VENDOR:
                    return CheckFileResult.VENDOR_IMG
                else:
                    raise ValueError("ErofsHandler: Detected EROFS filesystem but self.image_type is not ImageType.SYSTEM or ImageType.VENDOR")
            else:
                return CheckFileResult.HANDLER_NO_MATCH

    def extract_filesystem(self, output_dir):
        global base_dir
        erofs_tool = os.path.join(base_dir, "erofs_tool.py")
        subprocess.check_call([erofs_tool, "extract", "--verify-zip", self.abs_fn, output_dir])


class CpbHandler(FileHandler):
    def check(self) -> CheckFileResult:
        ext = self.fn.split(b'.')[-1].lower()
        if ext != b'cpb':
            return CheckFileResult.HANDLER_NO_MATCH
        with open(self.abs_fn, 'rb') as f:
            buf = f.read(4)
            if buf == b'CP\x03\x03':
                return CheckFileResult.ARCHIVE
            else:
                return CheckFileResult.HANDLER_NO_MATCH

    def extract_file2dir(self, output_path_rel):
        raise NotImplementedError("TODO: Implement CPB files, see https://github.com/scue/unpackcpb/blob/master/unpackcpb.c")


class BootImageHandler(FileHandler):
    def check(self) -> CheckFileResult:
        if self.fn.lower() == b'boot.img':
            # Some boot/recovery images have type 'data', e.g. for ryo
            # assert self.file_type.lower().startswith("android bootimg")
            return CheckFileResult.BOOT_IMG
        elif self.fn.lower() == b'boot.img.lz4':
            return CheckFileResult.BOOT_IMG
        elif self.fn.lower() == b'boot.img.p':
            # Some kind of binary patch. ignored for now
            return CheckFileResult.IGNORE
        elif self.fn.lower().startswith(b'boot.img'):
            assert False, "Potential boot image: %r (file_type=%r)" % (self.abs_fn, self.file_type)
        return CheckFileResult.HANDLER_NO_MATCH

    def write_image(self, f):
        if self.fn.lower() == b'boot.img':
            f.write(open(self.abs_fn, 'rb').read())
        elif self.fn.lower() == b'boot.img.lz4':
            f.write(subprocess.check_output(["lz4cat", self.abs_fn]))


class RecoveryImageHandler(FileHandler):
    def check(self) -> CheckFileResult:
        if self.fn.lower() == b'recovery.img':
            # Some boot/recovery images have type 'data', e.g. for ryo
            # assert self.file_type.lower().startswith("android bootimg")
            return CheckFileResult.RECOVERY_IMG
        elif self.fn.lower() == b'recovery.img.lz4':
            return CheckFileResult.BOOT_IMG
        elif self.fn.lower() == b'recovery.img.p':
            # Some kind of binary patch. ignored for now
            return CheckFileResult.IGNORE
        elif self.fn.lower().startswith(b'recovery.img'):
            assert False, "Potential recovery image: %r (file_type=%r)" % (self.abs_fn, self.file_type)
        return CheckFileResult.HANDLER_NO_MATCH

    def write_image(self, f):
        if self.fn.lower() == b'recovery.img':
            f.write(open(self.abs_fn, 'rb').read())
        elif self.fn.lower() == b'recovery.img.lz4':
            f.write(subprocess.check_output(["lz4cat", self.abs_fn]))


class MultipleHandlerMatchError(Exception):
    pass


class NoHandlerMatchError(Exception):
    pass


class ArchiveDirectoryHandler:
    def __init__(self, extractor, input_path_rel):
        self.extractor = extractor
        self.input_path_rel = input_path_rel
        self.abs_dir = self.extractor.abs_fn(input_path_rel)

    def get_next_handlers(self):
        # Pass 0: Check if the directory contains the unpacked system partition already
        if os.path.exists(os.path.join(self.abs_dir, b'system', b'build.prop')):
            filelist = [
                b'system/bin/audioserver',
                b'system/lib/libstagefright.so',
                b'system/lib64/libstagefright.so',
                b'system/bin/sh',
                b'system/framework/wifi-service.jar',
                b'system/lib/libssl.so',
                b'system/framework/services.jar',
                b'system/framework/telephony-common.jar'
            ]
            found_list = []
            for fn in filelist:
                if os.path.exists(os.path.join(self.abs_dir, fn)):
                    found_list.append(fn)
            if len(found_list) > 0:  # Some archives just contain system/build.prop but nothing else, so let's continue to normal extraction in these cases
                assert len(found_list) >= 3, "Only %d items of system partition found: %r" % (len(found_list), found_list)
                result = [SystemDirectoryHandler(self.extractor, os.path.join(self.input_path_rel, b'system'))]
                # Also allow boot.img/recovery.img
                for dirpath, dirnames, filenames in os.walk(self.abs_dir):
                    for file in filenames:
                        # We are only looking for boot images, so no need to look into system => Significant performance improvement
                        if b'system' in dirnames:
                            dirnames.remove(b'system')
                        abs_fn = os.path.join(self.abs_dir, dirpath, file)
                        rel_path = self.extractor.rel_path(os.path.join(dirpath, file))
                        file_type = get_file_type(abs_fn)
                        for handler_type in [BootImageHandler, RecoveryImageHandler]:
                            handler = handler_type(self.extractor, rel_path, file_type)
                            if handler.check() in (CheckFileResult.BOOT_IMG, CheckFileResult.RECOVERY_IMG):
                                result.append(handler)
                return result
        # Pass 0: Do rawprogram_XXX.xml, return if acceptable
        handlers_found_pass0: List[RawprogramUnsparseHandler] = list()
        total_handled_size = 0
        total_ignored_size = 0
        total_size = 0
        for dirpath, _dirnames, filenames in os.walk(self.abs_dir):
            for file in filenames:
                abs_fn = os.path.join(self.abs_dir, dirpath, file)
                rel_path = self.extractor.rel_path(os.path.join(dirpath, file))
                if os.path.isfile(abs_fn):
                    sr = os.stat(abs_fn)
                    total_size += sr.st_size
                    if file.lower().endswith(b'.xml'):
                        file_type = get_file_type(abs_fn)
                        handler_pass0 = RawprogramUnsparseHandler(self.extractor, rel_path, file_type)
                        handler_result = handler_pass0.check()
                        if handler_result not in (CheckFileResult.HANDLER_NO_MATCH, CheckFileResult.HANDLER_NO_MATCH_AND_IGNORE_SIZE_COVERAGE, CheckFileResult.IGNORE):
                            assert handler_result == CheckFileResult.SYSTEM_OR_VENDOR, "Bad handler_result %r for RawprogramUnsparseHandler" % handler_result
                            handlers_found_pass0.append(handler_pass0)
                            total_handled_size += sr.st_size
                            total_ignored_size += handler_pass0.extra_ignored_size
                            total_handled_size += handler_pass0.get_extra_handled_size()
                    elif file.lower().endswith(b".elf") or file.lower().endswith(b".mbn"):
                        total_ignored_size += sr.st_size
        if len(handlers_found_pass0) == 1:
            if total_handled_size + total_ignored_size > 0.8 * total_size - 100e6:
                return handlers_found_pass0
            elif handlers_found_pass0[0].has_vendor():
                return handlers_found_pass0
            else:
                raise ValueError("RawprogramUnsparseHandler doesn't handle enough, total_handled_size=%.2fMiB  total_size=%.2fMiB" % (total_handled_size/1024**2, total_size/1024**2))
        elif len(handlers_found_pass0) > 1:
            raise MultipleHandlerMatchError("Multiple RawprogramUnsparseHandler found: %r!" % [x.abs_fn for x in handlers_found_pass0])
        # Pass 1: Find image handlers, accept solution and return if 95% of the size is accounted for (ignored, system/vendor img, boot/recovery img
        total_size = 0
        ignored_size = 0  # Files intentionally ignored
        unmatched_size = 0  # Files not matched by any handler
        handled_size = 0
        extra_handled_size = 0  # Additional files handled by matching handler
        HANDLER_LIST_PASS1 = [
            ExtfsHandler,
            ErofsHandler,
            SparseImageHandler,
            SignImgHandler,
            TransferListHandler,
            BrotliHandler,
            Lz4Handler,
            IgnoreBadTarMd5Handler,
            IgnoreRadioHandler,
            IgnoreBootloaderHandler,
            IgnoreOpImageHandler,
            IgnoreOemImgHandler,
            IgnoreProductImgHandler,
            IgnoreSystemExtImgHanlder,
            IgnoreXromImgHanlder,
            IgnoreElfHandler,
            IgnoreVmlinuxHandler,
            BootImageHandler,
            RecoveryImageHandler,
            PacHandler,
            IgnoreAppsImgHandler,
            SuperImageHandler,
        ]
        handlers_found_pass1: List[FileHandler] = list()
        ignore_size_coverage: bool = False
        found_system_img: bool = False
        found_vendor_img: bool = False
        ignored_archive_size: int = 0
        for dirpath, dirnames, filenames in os.walk(self.abs_dir):
            for file in filenames:
                abs_fn = os.path.join(self.abs_dir, dirpath, file)
                if os.path.islink(abs_fn):
                    continue
                ext = file.split(b".")[-1]
                rel_path = self.extractor.rel_path(os.path.join(dirpath, file))
                assert os.path.exists(abs_fn), "File %r doesn't exist" % abs_fn
                if os.path.isfile(abs_fn):
                    sr = os.stat(abs_fn)
                    total_size += sr.st_size
                    handler_result_to_handlers: DefaultDict[CheckFileResult, List[FileHandler]] = defaultdict(list)
                    file_type = get_file_type(abs_fn)
                    for handler_type in HANDLER_LIST_PASS1:
                        handler = handler_type(self.extractor, rel_path, file_type)
                        handler_result = handler.check()
                        if handler_result == CheckFileResult.HANDLER_NO_MATCH:
                            pass  # Handler doesn't match, ignore it
                        elif handler_result == CheckFileResult.HANDLER_NO_MATCH_AND_IGNORE_SIZE_COVERAGE:
                            ignore_size_coverage = True
                        else:
                            handler_result_to_handlers[handler_result].append(handler)
                    if len(handler_result_to_handlers) > 1:
                        logging.error("Multiple handler results for %r" % abs_fn)
                        for (handler_result, handlers) in handler_result_to_handlers.items():
                            logging.error("%r => %r" % (handler_result, [type(x) for x in handlers]))
                        raise MultipleHandlerMatchError()
                    elif len(handler_result_to_handlers) == 1:
                        handler_result: CheckFileResult = list(handler_result_to_handlers.keys())[0]
                        handlers: List[FileHandler] = handler_result_to_handlers[handler_result]
                        if handler_result == CheckFileResult.IGNORE:
                            # Allow multiple handlers for result IGNORE
                            logging.info("Ignoring file %r due to %r" % (abs_fn, [type(x) for x in handlers]))
                            ignored_size += sr.st_size
                        elif len(handlers) > 1:
                            logging.error("Multiple handlers for %r => %r: %r" % (abs_fn, handler_result, [type(x) for x in handlers]))
                            raise MultipleHandlerMatchError()
                        else:
                            handler: FileHandler = handlers[0]
                            logging.info("Selected handler %s for %r" % (handler.__class__.__name__, abs_fn))
                            handled_size += sr.st_size
                            extra_handled_size += handler.get_extra_handled_size()
                            handlers_found_pass1.append(handler)
                            if handler_result == CheckFileResult.SYSTEM_IMG:
                                found_system_img = True
                            elif handler_result == CheckFileResult.VENDOR_IMG:
                                found_vendor_img = True
                    else:
                        logging.info("Ignoring file %r since no handler matches" % abs_fn)
                        if ext.lower() in (b"tar", b"zip", b"rar") or abs_fn.endswith(b".tar.gz"):
                            ignored_archive_size += sr.st_size
                            logging.info("ignored_archive_size += %d => %d (file %r)" % (sr.st_size, ignored_archive_size, abs_fn))
                        unmatched_size += sr.st_size
        # Check if Pass 1 solution can be accepted
        total_handled_size = (handled_size + extra_handled_size)
        total_unmatched_size = unmatched_size - extra_handled_size
        found_pac = False
        for handler in handlers_found_pass1:
            if isinstance(handler, PacHandler):
                found_pac = True
        logging.info("PASS1: total_handled_size=%r  total_unmatched_size=%r  ignored_archive_size=%r  found_system_img=%r  found_vendor_img=%r", total_handled_size, total_unmatched_size, ignored_archive_size, found_system_img, found_vendor_img)
        if total_handled_size >= 0.85 * (handled_size + total_unmatched_size) or (total_handled_size > 0 and ignore_size_coverage):
            return handlers_found_pass1
        elif found_system_img and found_vendor_img and total_handled_size > 0.85 * (handled_size + total_unmatched_size - ignored_archive_size):
            # Some firmwares contain a second copy of the firmware within an archive (tar/tar.gz/...).
            # If we have a system/vendor image, we can check if 85% of the total size is covered while ignoring
            # additional archives.
            return handlers_found_pass1
        elif found_pac and total_handled_size > 0.85 * (handled_size + total_unmatched_size - ignored_archive_size):
            # Some firmwares contain a second copy of the firmware within an archive (tar/tar.gz/...).
            # If we have a PAC image, we can check if 85% of the total size is covered while ignoring
            # additional archives.
            return handlers_found_pass1
        elif total_handled_size >= 0.1 * (handled_size + total_unmatched_size):
            logging.warning("ArchiveDirectoryHandler.get_handlers(): Rejecting pass 1 with covered percentage %.2f%%" % (100.0 * total_handled_size / (handled_size + total_unmatched_size)))
        logging.info("ArchiveDirectoryHandler.get_handlers(): Going to pass 2")
        # Pass 2: Find biggest file, check if is an archive file and it is at least 90% of total size
        # Handle boot/recovery images and intentionally ignore unwanted files
        HANDLER_LIST_PASS2 = [
            IgnoreBadTarMd5Handler,
            IgnoreRadioHandler,
            IgnoreBootloaderHandler,
            IgnoreOpImageHandler,
            IgnoreOemImgHandler,
            IgnoreProductImgHandler,
            IgnoreSystemExtImgHanlder,
            IgnoreXromImgHanlder,
            IgnoreUpdateHwHandler,  # Only for Pass 2
            IgnoreHuaweiUserdataAppHandler,
            IgnoreElfHandler,
            BootImageHandler,
            RecoveryImageHandler
        ]
        # Hanlder list for the biggest file only
        # Will only be used if the biggest file reaches a certain percentage of the total
        # size (excluding boot/recovery image and intentionally ignored files)
        # Contains all kind of archive handlers
        HANDLER_LIST_PASS2_BIGGEST_FILE = [
            ZipHandler,
            TarHandler,
            SinHandler,
            PacHandler,
            OzipHandler,
            HuaweiAppHandler,
            DzHandler,
            NokiaPayloadBinHandler,
            CpbHandler,
            SuperImageHandler
        ]
        # Find biggest file
        total_size = 0
        unmatched_size = 0  # Files not matched by any handler
        handled_size = 0
        ignored_size = 0
        # ignore_size_coverage = False
        biggest_file_size = 0
        biggest_file_abs = None
        biggest_file_rel = None
        handlers_found_pass2: List[FileHandler] = []
        for dirpath, dirnames, filenames in os.walk(self.abs_dir):
            for file in filenames:
                abs_fn = os.path.join(self.abs_dir, dirpath, file)
                if os.path.islink(abs_fn):
                    continue
                rel_path = self.extractor.rel_path(os.path.join(dirpath, file))
                assert os.path.exists(abs_fn), "File %r doesn't exist" % abs_fn
                if os.path.isfile(abs_fn):
                    sr = os.stat(abs_fn)
                    total_size += sr.st_size
                    # Find biggest file
                    if sr.st_size > biggest_file_size:
                        biggest_file_size = sr.st_size
                        biggest_file_abs = abs_fn
                        biggest_file_rel = rel_path
                    handler_result_to_handlers = defaultdict(list)
                    file_type = get_file_type(abs_fn)
                    for handler_type in HANDLER_LIST_PASS2:
                        handler = handler_type(self.extractor, rel_path, file_type)
                        handler_result = handler.check()
                        if handler_result == CheckFileResult.HANDLER_NO_MATCH:
                            pass  # Handler doesn't match, ignore it
                        elif handler_result == CheckFileResult.HANDLER_NO_MATCH_AND_IGNORE_SIZE_COVERAGE:
                            # ignore_size_coverage = True
                            pass
                        else:
                            handler_result_to_handlers[handler_result].append(handler)
                    if len(handler_result_to_handlers) > 1:
                        logging.error("PASS2: Multiple handler results for %r" % abs_fn)
                        for (handler_result, handlers) in handler_result_to_handlers.items():
                            logging.error("%r => %r" % (handler_result, [type(x) for x in handlers]))
                        raise MultipleHandlerMatchError()
                    elif len(handler_result_to_handlers) == 1:
                        handler_result = list(handler_result_to_handlers.keys())[0]
                        handlers = handler_result_to_handlers[handler_result]
                        if handler_result == CheckFileResult.IGNORE:
                            # Allow multiple handlers for result IGNORE
                            logging.info("PASS2: Ignoring file %r due to %r" % (abs_fn, [type(x) for x in handlers]))
                            ignored_size += sr.st_size
                        elif len(handlers) > 1:
                            logging.error("PASS2: Multiple handlers for %r => %r: %r" % (abs_fn, handler_result, [type(x) for x in handlers]))
                            raise MultipleHandlerMatchError()
                        else:
                            handler = handlers[0]
                            logging.info("PASS2: Selected handler %s for %r" % (handler.__class__.__name__, abs_fn))
                            handled_size += sr.st_size
                            extra_handled_size += handler.get_extra_handled_size()
                            handlers_found_pass2.append(handler)
                    else:
                        logging.info("PASS2: Ignoring file %r since no handler matches" % abs_fn)
                        unmatched_size += sr.st_size
        total_uncovered_size = total_size - ignored_size - handled_size  # ignroed_size is from pass1
        logging.info("ArchiveDirectoryHandler.get_handlers(): PASS2: Biggest file: %.3fMiB/%.3fMiB (%.2f%%): %r" % (biggest_file_size / (1024 * 1024), total_uncovered_size / (1024 * 1024), 100.0 * biggest_file_size / total_uncovered_size, biggest_file_abs))
        sr = os.stat(biggest_file_abs)
        if sr.st_size > 0.9 * total_uncovered_size:
            handler_result_to_handlers = defaultdict(list)
            for handler_type in HANDLER_LIST_PASS2_BIGGEST_FILE:
                file_type = get_file_type(biggest_file_abs)
                handler = handler_type(self.extractor, biggest_file_rel, file_type)
                handler_result = handler.check()
                if handler_result != CheckFileResult.HANDLER_NO_MATCH:
                    handler_result_to_handlers[handler_result].append(handler)
            if len(handler_result_to_handlers) > 1:
                logging.error("Multiple handler results for %r" % biggest_file_abs)
                for (handler_result, handlers) in handler_result_to_handlers.items():
                    logging.error("%r => %r" % (handler_result, [type(x) for x in handlers]))
                raise MultipleHandlerMatchError()
            elif len(handler_result_to_handlers) == 1:
                handler_result = list(handler_result_to_handlers.keys())[0]
                handlers = handler_result_to_handlers[handler_result]
                if handler_result == CheckFileResult.IGNORE:
                    raise NoHandlerMatchError("Biggest file (>90%%) is IGNORED: %r" % biggest_file_abs)
                elif len(handlers) > 1:
                    logging.error("Multiple handlers for %r => %r: %r" % (biggest_file_abs, handler_result, [type(x) for x in handlers]))
                    raise MultipleHandlerMatchError()
                else:
                    handler = handlers[0]
                    logging.info("Selected handler %r for %r" % (type(handler), biggest_file_abs))
                    # handlers_found_pass2 may contain boot/recovery handler
                    return handlers_found_pass2 + [handler]
            else:
                logging.info("Ignoring biggest file file %r since no handler matches" % biggest_file_abs)
                unmatched_size += sr.st_size
        # Still here? => Don't know what to do, just list biggest files for now
        path2size = {}
        total_size = 0
        for dirpath, dirnames, filenames in os.walk(self.abs_dir):
            for file in filenames:
                abs_fn = os.path.join(self.abs_dir, dirpath, file)
                if os.path.islink(abs_fn):
                    continue
                assert os.path.exists(abs_fn), "File %r doesn't exist" % abs_fn
                if os.path.isfile(abs_fn):
                    sr = os.stat(abs_fn)
                    path2size[os.path.join(dirpath, file)] = sr.st_size
                    total_size += sr.st_size
        logging.error("ArchiveDirectoryHandler.get_handlers(): Don't know what to do. Biggest files (sorted by size):")
        for path in sorted(path2size.keys(), key=lambda tmp_path: -path2size[tmp_path]):
            logging.error("  %.3fMiB: %s" % (path2size[path] / 1024.0 / 1024.0, path.decode(errors='ignore')))
        raise ValueError("ArchiveDirectoryHandler.get_handlers(): Don't know what to do.")


class SystemDirectoryHandler:
    def __init__(self, extractor, system_dir_rel):
        self.extractor = extractor
        self.system_dir_rel = system_dir_rel
        self.system_dir_abs = self.extractor.abs_fn(system_dir_rel)

    def get_system_dir(self):
        return self.system_dir_abs


class TopLevelFileHandler:
    def __init__(self, extractor, input_path_rel, image_type=None, top_level_file=False):
        self.extractor = extractor
        self.input_path_rel = input_path_rel
        self.abs_fn = self.extractor.abs_fn(input_path_rel)
        self.image_type = image_type
        self.top_level_file: bool = top_level_file

    def get_next_handler(self):
        handler_list = [
            TopLevelZipHandler,
            TarHandler,
            GzipHandler,
            Bzip2Handler,
            XzHandler,
            PacHandler,
            OzipHandler,
            SevenZipHandler,
            RarHandler,
            KdzHandler,
            DzHandler,
            ExtfsHandler,
            ErofsHandler,
            CpbHandler
        ]
        handlers_found = []
        for handler_type in handler_list:
            handler = handler_type(self.extractor, self.input_path_rel, file_type=get_file_type(self.abs_fn))
            check_result = handler.check()
            if check_result == CheckFileResult.HANDLER_NO_MATCH:
                continue
            handlers_found.append(handler)
        if len(handlers_found) == 0:
            raise NoHandlerMatchError("No handler for %r (file_type=%r)" % (self.abs_fn, get_file_type(self.abs_fn)))
        if len(handlers_found) > 1:
            logging.error("Multiple handlers for %r: %r" % (self.input_path_rel, [type(x) for x in handlers_found]))
            raise MultipleHandlerMatchError()
        return handlers_found[0]


class QueueItem:
    def __init__(self, handler, handler_name, stage_dir=None, handler_check_result=None):
        self.handler = handler
        self.handler_name = handler_name
        self.handler_check_result = handler_check_result
        self.stage_dir = stage_dir


class FirmwareExtractor:
    def __init__(self, firmware_file_or_dir):
        firmware_file_or_dir = os.path.abspath(firmware_file_or_dir)
        if isinstance(firmware_file_or_dir, str):
            firmware_file_or_dir = firmware_file_or_dir.encode()
        self.firmware_file_or_dir = firmware_file_or_dir
        self.tmpdir: bytes = tempfile.mkdtemp(prefix="ANDROID_EXTRACT_").encode()
        logging.info("tmpdir=%r" % self.tmpdir)
        self.stage_num: int = 0
        self.mounted_handlers = []
        self.system_handler = None
        self.vendor_handler = None
        self.boot_image_handler = None
        self.recovery_image_handler = None

    def extract(self, output_system_tar=None, output_system_dir=None, make_world_readable=True, output_boot_img_path=None, output_recovery_img_path=None, allow_missing_vendor=False):
        if output_system_dir is not None and isinstance(output_system_dir, str):
            output_system_dir = output_system_dir.encode()
        stage_queue = deque()
        if os.path.isdir(self.firmware_file_or_dir):
            handler_initial = ArchiveDirectoryHandler(self, self.firmware_file_or_dir)
            stage_queue.append(QueueItem(handler=handler_initial, handler_name="handler_initial"))
        else:
            assert os.path.isfile(self.firmware_file_or_dir)
            handler_initial = TopLevelFileHandler(self, None)
            stage_dir = self.get_stage_dir("UnknownFileHandler")
            stage_queue.append(QueueItem(handler=handler_initial, handler_name="handler_initial", stage_dir=stage_dir))
        try:
            while len(stage_queue) > 0:
                queue_item = stage_queue.popleft()
                handler = queue_item.handler
                # self.log_extraction_step("abs_stage_dir = self.create_stage_dir(%r)" % queue_item.stage_dir)
                if hasattr(handler, "extract_file2dir"):
                    self.create_stage_dir(queue_item.stage_dir)
                    self.log_extraction_step("self.create_stage_dir(%r)" % queue_item.stage_dir)
                    self.log_extraction_step("%s.extract_file2dir(%r)" % (queue_item.handler_name, queue_item.stage_dir))
                    # assert False, abs_stage_dir
                    handler.extract_file2dir(queue_item.stage_dir)
                    next_handler = ArchiveDirectoryHandler(self, queue_item.stage_dir)
                    next_stage_dir = self.get_stage_dir(next_handler.__class__.__name__)
                    next_handler_name = "handler_%s" % next_stage_dir.decode()
                    self.log_extraction_step("%s = ArchiveDirectoryHandler(self, %r)" % (next_handler_name, queue_item.stage_dir))
                    next_queue_item = QueueItem(next_handler, handler_name=next_handler_name, stage_dir=next_stage_dir)
                    stage_queue.append(next_queue_item)
                elif hasattr(handler, "get_next_handler"):
                    next_handler = handler.get_next_handler()
                    next_stage_dir = self.get_stage_dir(next_handler.__class__.__name__)
                    next_handler_name = "handler_%s" % next_stage_dir.decode()
                    self.log_extraction_step("%s = %s.get_next_handler()" % (next_handler_name, queue_item.handler_name))
                    next_queue_item = QueueItem(next_handler, handler_name=next_handler_name, stage_dir=next_stage_dir)
                    stage_queue.append(next_queue_item)
                elif hasattr(handler, "get_next_handlers"):
                    next_handlers = handler.get_next_handlers()
                    for next_handler in next_handlers:
                        next_stage_dir = self.get_stage_dir(next_handler.__class__.__name__)
                        next_handler_name = "handler_%s" % next_stage_dir.decode()
                        # TODO: Log
                        # self.log_extraction_step("%s = %s.get_next_handler()" % (next_handler_name, queue_item.handler_name))
                        next_queue_item = QueueItem(next_handler, handler_name=next_handler_name, stage_dir=next_stage_dir)
                        stage_queue.append(next_queue_item)
                elif hasattr(handler, "extract_and_get_next_handlers"):
                    next_handlers = handler.extract_and_get_next_handlers(queue_item.stage_dir)
                    for next_handler in next_handlers:
                        next_stage_dir = self.get_stage_dir(next_handler.__class__.__name__)
                        next_handler_name = "handler_%s" % next_stage_dir.decode()
                        # TODO: Log
                        # self.log_extraction_step("%s = %s.get_next_handler()" % (next_handler_name, queue_item.handler_name))
                        next_queue_item = QueueItem(next_handler, handler_name=next_handler_name, stage_dir=next_stage_dir)
                        stage_queue.append(next_queue_item)
                elif hasattr(handler, "extract_and_get_next_handler"):
                    next_handler = handler.extract_and_get_next_handler(queue_item.stage_dir)
                    next_stage_dir = self.get_stage_dir(next_handler.__class__.__name__)
                    next_handler_name = "handler_%s" % next_stage_dir.decode()
                    self.log_extraction_step("%s = %s.get_next_handler()" % (next_handler_name, queue_item.handler_name))
                    next_queue_item = QueueItem(next_handler, handler_name=next_handler_name, stage_dir=next_stage_dir)
                    stage_queue.append(next_queue_item)
                elif isinstance(handler, MountableImage) or isinstance(handler, FilesystemExtractor):
                    assert handler.image_type in (ImageType.SYSTEM, ImageType.VENDOR), "Bad handler.image_type %r for %r" % (handler.image_type, handler.__class__.__name__)
                    if handler.image_type == ImageType.SYSTEM:
                        if self.system_handler is not None:
                            logging.warning("Duplicate system_handler in firmware")
                            logging.warning("OLD: %s => %s", self.system_handler.__class__.__name__, self.system_handler.abs_fn)
                            subprocess.call(["file", self.system_handler.abs_fn])
                            logging.warning("NEW: %s => %s", handler.__class__.__name__, handler.abs_fn)
                            subprocess.call(["file", handler.abs_fn])
                            assert compare_file_contents(self.system_handler.abs_fn, handler.abs_fn), "Duplicate system_handler with non-equal contents: %s:%r <=> %s:%s" % (self.system_handler.__class__.__name__, self.vendor_handler.abs_fn, handler.__class__.__name__, handler.abs_fn)
                            logging.warning("Continuing anyway since both files are equal")
                        self.system_handler = handler
                        logging.info("Found system handler")
                    elif handler.image_type == ImageType.VENDOR:
                        if self.vendor_handler is not None:
                            logging.warning("Duplicate vendor_handler in firmware")
                            logging.warning("OLD: %s => %s", self.vendor_handler.__class__.__name__, self.vendor_handler.abs_fn)
                            subprocess.call(["file", self.vendor_handler.abs_fn])
                            logging.warning("NEW: %s => %s", handler.__class__.__name__, handler.abs_fn)
                            subprocess.call(["file", handler.abs_fn])
                            assert compare_file_contents(self.vendor_handler.abs_fn, handler.abs_fn), "Duplicate vendor_handler with non-equal contents: %s:%r <=> %s:%s" % (self.vendor_handler.__class__.__name__, self.vendor_handler.abs_fn, handler.__class__.__name__, handler.abs_fn)
                            logging.warning("Continuing anyway since both files are equal")
                        self.vendor_handler = handler
                        logging.info("Found vendor handler")
                elif isinstance(handler, SystemDirectoryHandler):
                    assert self.system_handler is None
                    logging.info("Found system handler via SystemDirectoryHandler")
                    self.system_handler = handler
                elif isinstance(handler, BootImageHandler):
                    assert self.boot_image_handler is None
                    self.boot_image_handler = handler
                elif isinstance(handler, RecoveryImageHandler):
                    assert self.recovery_image_handler is None
                    self.recovery_image_handler = handler
                else:
                    raise ValueError("Don't know what to do with handler %r" % handler.__class__.__name__)
            logging.info("Finished Queue")
            if self.system_handler is None:
                logging.error("No system_handler afer finishing queue")
                raise ValueError("No system_handler afer finishing queue")
            if output_system_dir is None:
                output_system_dir = self.create_stage_dir("system")
            else:
                assert output_system_tar is None, "Can only generate output_system_dir or output_system_tar"
            if not output_system_dir.endswith(b'/'):
                output_system_dir += b'/'
            if isinstance(self.system_handler, MountableImage):
                system_mountpoint = self.create_stage_dir("system_mnt")
                self.system_handler.mount("system_mnt")
                self.mounted_handlers.append(self.system_handler)
                mounted_system_dir = system_mountpoint
                # Some images have the root filesystem in the "system" partition, with /system/ just being a directory within the filesystem.
                if not os.path.exists(os.path.join(mounted_system_dir, b'build.prop')):
                    if os.path.exists(os.path.join(mounted_system_dir, b'system', b'build.prop')):
                        mounted_system_dir = os.path.join(mounted_system_dir, b'system')
                    assert os.path.exists(os.path.join(mounted_system_dir, b'build.prop')), "Could not find build.prop in system partition"
                # Append slash for correct rsync operation
                if not mounted_system_dir.endswith(b'/'):
                    mounted_system_dir += b'/'
                cmd = ["rsync", "-a", mounted_system_dir, output_system_dir]
                logging.info("FirmwareExtractor.extract(): system rsync cmd: %r" % cmd)
                subprocess.check_call(cmd)
            elif isinstance(self.system_handler, FilesystemExtractor):
                self.system_handler.extract_filesystem(output_system_dir)
                # Sometimes the extracted system.img contains "system/" as a directory, not in the root of the filesystem
                if (not os.path.exists(os.path.join(output_system_dir, b"build.prop"))) and \
                        os.path.isdir(os.path.join(output_system_dir, b"system")) and \
                        os.path.exists(os.path.join(output_system_dir, b"system", b"build.prop")):
                    os.mkdir(os.path.join(output_system_dir, b"system", b"rootfs"))
                    for fn in os.listdir(output_system_dir):
                        if fn == b'system':
                            continue
                        os.rename(os.path.join(output_system_dir, fn), os.path.join(output_system_dir, b"system", b"rootfs", fn))
                    os.rename(os.path.join(output_system_dir, b"system"), os.path.join(output_system_dir, b"system.tmp"))
                    for fn in os.listdir(os.path.join(output_system_dir, b"system.tmp")):
                        os.rename(os.path.join(output_system_dir, b"system.tmp", fn), os.path.join(output_system_dir, fn))
            elif isinstance(self.system_handler, SystemDirectoryHandler):
                system_dir_src = self.system_handler.get_system_dir()
                # Append slash for correct rsync operation
                if not system_dir_src.endswith(b'/'):
                    system_dir_src += b'/'
                cmd = ["rsync", "-a", system_dir_src, output_system_dir]
                logging.info("FirmwareExtractor.extract(): system rsync cmd: %r" % cmd)
                subprocess.check_call(cmd)
            else:
                assert False, "Don't know what to do with self.system_handler type %s" % self.system_handler.__class__.__name__
            output_vendor_dir = os.path.join(output_system_dir, b"vendor")
            if os.path.islink(output_vendor_dir):
                if self.vendor_handler is not None:
                    os.unlink(output_vendor_dir)
                else:
                    assert allow_missing_vendor, "System contains vendor symlink but we didn't find a vendor paritition!"
            if os.path.isdir(output_vendor_dir):
                vendor_dir_contents = os.listdir(output_vendor_dir)
                if self.vendor_handler is not None:
                    assert len(vendor_dir_contents) == 0, "sytem/vendor directory not empty: %r" % vendor_dir_contents
            else:
                assert not os.path.exists(output_vendor_dir), "system/vendor is not a directory and not a symlink"
            if self.vendor_handler is not None:
                if not os.path.exists(output_vendor_dir):
                    os.mkdir(output_vendor_dir)
                if isinstance(self.vendor_handler, MountableImage):
                    vendor_mountpoint = self.create_stage_dir("vendor_mnt")
                    self.vendor_handler.mount("vendor_mnt")
                    # Append slash for correct rsync operation
                    if not vendor_mountpoint.endswith(b'/'):
                        vendor_mountpoint += b'/'
                    if not output_vendor_dir.endswith(b'/'):
                        output_vendor_dir += b'/'
                    self.mounted_handlers.append(self.vendor_handler)
                    cmd = ["rsync", "-a", vendor_mountpoint, output_vendor_dir]
                    logging.info("FirmwareExtractor.extract(): vendor rsync cmd: %r" % cmd)
                    subprocess.check_call(cmd)
                elif isinstance(self.vendor_handler, FilesystemExtractor):
                    self.vendor_handler.extract_filesystem(output_vendor_dir)
                else:
                    assert False, "Don't know what to do with self.vendor_handler type %s" % self.vendor_handler.__class__.__name__
            if make_world_readable:
                cmd = ["chmod", "-R", "a+r", output_system_dir]
                logging.info("FirmwareExtractor.extract(): make readable cmd: %r" % cmd)
                subprocess.check_call(cmd)
            if output_system_tar is not None:
                output_system_tar = os.path.abspath(output_system_tar)
                cmd = ["tar", "cf", output_system_tar, "system/"]
                cwd = os.path.dirname(os.path.dirname(output_system_dir))  # Double dirname since output_system_dir ends with trailing slash, ".../system/"
                logging.info("FirmwareExtractor.extract(): system tar cmd: %r  cwd=%r" % (cmd, cwd))
                subprocess.check_call(cmd, cwd=cwd)
            if output_boot_img_path is not None and self.boot_image_handler is not None:
                with open(output_boot_img_path, 'wb') as f:
                    self.boot_image_handler.write_image(f)
            if output_recovery_img_path is not None and self.recovery_image_handler is not None:
                with open(output_recovery_img_path, 'wb') as f:
                    self.recovery_image_handler.write_image(f)
        finally:
            self.cleanup()

    def cleanup(self):
        assert b'ANDROID_EXTRACT_' in self.tmpdir
        for handler in self.mounted_handlers:
            # noinspection PyBroadException
            try:
                handler.umount()
            except Exception:
                logging.exception("Unmounting exception")
        self.mounted_handlers = []
        if os.path.exists(self.tmpdir):
            subprocess.call(["rm", "-rf", self.tmpdir])

    # noinspection PyMethodMayBeStatic
    def log_extraction_step(self, extraction_step):
        logging.info("EXTRACTION_STEP: %s" % extraction_step)

    def get_stage_dir(self, stage_name):
        result = ("stage_%d_%s" % (self.stage_num, stage_name))
        self.stage_num += 1
        return result.encode()

    def create_stage_dir(self, stage_dir):
        if isinstance(stage_dir, str):
            stage_dir = stage_dir.encode()
        abs_dir = os.path.join(self.tmpdir, stage_dir)
        os.mkdir(abs_dir)
        return abs_dir

    def abs_fn(self, input_path_rel) -> bytes:
        if input_path_rel is None:
            return self.firmware_file_or_dir
        if isinstance(input_path_rel, str):
            input_path_rel = input_path_rel.encode()
        assert isinstance(input_path_rel, bytes)
        assert not input_path_rel.startswith(b'/')
        return os.path.join(self.tmpdir, input_path_rel)

    def rel_path(self, abs_path):
        assert isinstance(abs_path, bytes)
        assert abs_path.startswith(b'/')
        assert abs_path.startswith(self.tmpdir)
        path = abs_path[len(self.tmpdir):]
        while path.startswith(b'/'):
            path = path[1:]
        return path


def compare_file_contents(path_a, path_b) -> bool:
    """
    Compares two files and returns whether the files are equal.
    """
    if os.stat(path_a).st_size != os.stat(path_b).st_size:
        return False
    with open(path_a, 'rb') as file_a, open(path_b, 'rb') as file_b:
        while True:
            buf_a = file_a.read(1024*1024)
            buf_b = file_b.read(1024*1024)
            if buf_a != buf_b:
                return False
            if buf_a == b'' and buf_b == b'':
                return True


def get_file_type(abs_fn):
    file_output = subprocess.check_output(["file", "-"], stdin=open(abs_fn, 'rb'))
    assert file_output.startswith(b"/dev/stdin:")
    return file_output[len(b"/dev/stdin:"):].strip().decode()


if __name__ == "__main__":
    main()
