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


import argparse
import mmap
import os

import construct
from construct import Struct, Int32ul, Int16ul, Int8ul, Int64ul, Array, Union
from enum import Enum
from typing import List, Set
import subprocess
from io import BytesIO
import math
import sys
from stat import S_IFLNK, S_IFDIR, S_IFREG, S_IFMT


# Parser for Huawei EROFS filesystem, used on some new models.
# Supported by Linux Kernel 4.19 and later
# drivers/staging/erofs
# Filesystem generation tool at https://git.kernel.org/pub/scm/linux/kernel/git/xiang/erofs-utils.git/

def main():
    parser = argparse.ArgumentParser(description='EROFS filesystem extractor')
    sp = parser.add_subparsers()
    p = sp.add_parser("debug", help="Run debug code")
    p.set_defaults(target=command_debug)
    p = sp.add_parser("check", help="Check a given filesystem")
    p.add_argument("fn", help="EROFS image file")
    p.set_defaults(target=command_check)
    p = sp.add_parser("file", help="Check a given filesystem")
    p.add_argument("fn", help="EROFS image file")
    p.add_argument("path", help="Path within erofs")
    p.add_argument("--verify", help="Path to verify file")
    p.add_argument("--extract", help="Path to save extracted file")
    p.set_defaults(target=command_file)
    p = sp.add_parser("extract", help="Extract erofs to directory")
    p.add_argument("erofs_image", help="Path to erofs image")
    p.add_argument("output_dir", help="Output directory")
    p.add_argument("--verify-zip", action="store_true", help="Run test on all zip/apk/jar files to ensure that extraction works correctly")
    p.set_defaults(target=command_extract)
    args = parser.parse_args()
    if hasattr(args, "target"):
        args.target(args)
    else:
        parser.print_help()


def command_debug(_args):
    pass


def command_extract(args):
    try:
        os.mkdir(args.output_dir)
    except FileExistsError:
        assert os.path.isdir(args.output_dir), "Output %r is not a directory" % args.output_dir
        assert len(os.listdir(args.output_dir)) == 0, "Output directory %r is not empty: %r" % (args.output_dir, os.listdir(args.output_dir))
    erofs = Erofs(args.erofs_image)
    erofs.root_inode.extract(args.output_dir.encode(), verify_zip=args.verify_zip)


def command_check(args):
    erofs = Erofs(args.fn)
    erofs.root_inode.traverse()


def command_file(args):
    erofs = Erofs(args.fn)
    file_inode = erofs.get_file(args.path.encode())
    data = file_inode.get_data(debug=True)
    if args.verify is not None:
        verify_buf = open(args.verify, 'rb').read()
        assert len(data) == len(verify_buf), "Verify length mismatch: %r <=> %r" % (len(data), len(verify_buf))
        for i in range(len(data)):
            assert data[i] == verify_buf[i], "Mismatch at 0x%x: %r <=> %r" % (i, data[i], verify_buf[i])
        print("File verified OK")
    if args.extract is not None:
        with open(args.extract, 'wb') as f:
            f.write(data)


def recursive_union_sizeof(struct) -> int:
    """
    Calculates the size of a construct struct, recursing through `subcons`.
    Will also work for unions with the assumption that all elements of the union have the same size
    """
    if isinstance(struct, Union):
        union_size = None
        for item in struct.subcons:
            item_size = recursive_union_sizeof(item)
            if union_size is None:
                union_size = item_size
            elif union_size != item_size:
                raise ValueError(f"Inconsistent Union size: {union_size} <=> {item_size}")
        return union_size
    elif isinstance(struct, Struct):
        result = 0
        for item in struct.subcons:
            item_size = recursive_union_sizeof(item)
            if item_size is None:
                breakpoint()
            result += recursive_union_sizeof(item)
        return result
    elif isinstance(struct, construct.Renamed):
        return recursive_union_sizeof(struct.subcon)
    else:
        return struct.sizeof()


# noinspection PyUnresolvedReferences
struct_erofs_super = Struct(
    "magic" / Int32ul,
    "checksum" / Int32ul,
    "features" / Int32ul,
    "blkszbits" / Int8ul,
    "reserved" / Int8ul,
    "root_nid" / Int16ul,
    "inos" / Int64ul,
    "build_time" / Int64ul,
    "build_time_nsec" / Int32ul,
    "blocks" / Int32ul,
    "meta_blkaddr" / Int32ul,
    "xattr_blkaddr" / Int32ul,
    "uuid" / Array(16, Int8ul),
    "volume_name" / Array(16, Int8ul),
    "reserved2" / Array(48, Int8ul)
)
assert struct_erofs_super.sizeof() == 128, struct_erofs_super.sizeof()


class DataMappingMode(Enum):
    EROFS_INODE_FLAT_PLAIN = 0
    EROFS_INODE_FLAT_COMPRESSION_LEGACY = 1
    EROFS_INODE_FLAT_INLINE = 2
    EROFS_INODE_FLAT_COMPRESSION = 3
    EROFS_INODE_LAYOUT_MAX = 4


# noinspection PyUnresolvedReferences
struct_erofs_inode_v1 = Struct(
    "i_advise" / Int16ul,
    "i_xattr_icount" / Int16ul,
    "i_mode" / Int16ul,
    "i_nlink" / Int16ul,
    "i_size" / Int32ul,
    "i_reserved" / Int32ul,
    "i_u" / Int32ul,
    "i_ino" / Int32ul,
    "i_uid" / Int16ul,
    "i_gid" / Int16ul,
    "checksum" / Int32ul,
)
assert struct_erofs_inode_v1.sizeof() == 32, struct_erofs_inode_v1.sizeof()


class FileType(Enum):
    EROFS_FT_UNKNOWN = 0
    EROFS_FT_REG_FILE = 1
    EROFS_FT_DIR = 2
    EROFS_FT_CHRDEV = 3
    EROFS_FT_BLKDEV = 4
    EROFS_FT_FIFO = 5
    EROFS_FT_SOCK = 6
    EROFS_FT_SYMLINK = 7
    EROFS_FT_MAX = 8


# noinspection PyUnresolvedReferences
struct_erofs_dirent = Struct(
    "nid" / Int64ul,
    "nameoff" / Int16ul,
    "file_type" / Int8ul,
    "reserved" / Int8ul
)
assert struct_erofs_dirent.sizeof() == 12, struct_erofs_dirent.sizeof()


class DecompressIndexType(Enum):
    Z_EROFS_VLE_CLUSTER_TYPE_PLAIN = 0
    Z_EROFS_VLE_CLUSTER_TYPE_HEAD = 1
    Z_EROFS_VLE_CLUSTER_TYPE_NONHEAD = 2
    Z_EROFS_VLE_CLUSTER_TYPE_RESERVED = 3


# noinspection PyUnresolvedReferences
struct_z_erofs_vle_decompressed_index = Struct(
    "di_advise" / Int16ul,
    "di_clusterofs" / Int16ul,
    "di_u" / Union(0,
                   "blkaddr" / Int32ul,
                   "delta" / Struct("delta0" / Int16ul, "delta1" / Int16ul)
                   )
)
assert recursive_union_sizeof(struct_z_erofs_vle_decompressed_index) == 8


# noinspection PyUnresolvedReferences
struct_z_erofs_map_header = Struct(
    "h_reserved1" / Int32ul,
    "h_advise" / Int16ul,
    "h_algorithmtype" / Int8ul,
    "h_clusterbits" / Int8ul
)


class Erofs:
    def __init__(self, fn: str):
        self.fn = fn
        self.file_handle = open(fn, 'rb')
        self.file_size = os.fstat(self.file_handle.fileno()).st_size
        self.mmap = mmap.mmap(self.file_handle.fileno(), 0, mmap.MAP_SHARED, mmap.PROT_READ)
        self.super = struct_erofs_super.parse(self.mmap[0x400:0x400+struct_erofs_super.sizeof()])
        print("0x%08x-0x%08x: SUPER" % (0x400, 0x400 + struct_erofs_super.sizeof()))
        assert self.super.magic == 0xe0f5e1e2, "0x%x" % self.super.magic
        assert self.super.blkszbits == 12
        print("root_nid=%r" % self.super.root_nid)
        # print("super:\n%s" % self.super)
        self.root_inode = self.get_inode(self.super.root_nid, FileType.EROFS_FT_DIR)
        print("0x%08x-0x%08x: ROOT Inode" % (self.root_inode.inode_off, self.root_inode.inode_off + struct_erofs_inode_v1.sizeof()))
        # print("root:\n%s" % self.root_inode)
        # self.root_inode.traverse()

    def get_inode(self, nid: int, file_type: FileType):
        if file_type == FileType.EROFS_FT_DIR:
            return DirInode(self, nid)
        elif file_type == FileType.EROFS_FT_SYMLINK:
            return SymlinkInode(self, nid)
        elif file_type == FileType.EROFS_FT_REG_FILE:
            return RegFileInode(self, nid)
        else:
            raise ValueError("inode type %r not supported" % file_type)

    def get_inode_header(self, nid) -> struct_erofs_inode_v1:
        inode_off = self.super.meta_blkaddr * 4096 + 32 * nid
        if inode_off + struct_erofs_inode_v1.sizeof() > self.file_size:
            raise ValueError("Inode nid 0x016%x out of range" % nid)
        inode_buf = self.mmap[inode_off:inode_off + struct_erofs_inode_v1.sizeof()]
        return struct_erofs_inode_v1.parse(inode_buf)

    def get_file(self, path: bytes) -> "Inode":
        path = path.split(b'/')
        path = [x for x in path if x != b'']
        inode: DirInode = self.root_inode
        for i in range(len(path)):
            path_elem = path[i]
            ok = False
            for dirent in inode.get_dirents():
                if dirent.filename == path_elem:
                    if i == len(path) - 1:
                        return self.get_inode(dirent.nid, dirent.file_type)
                    else:
                        next_inode = self.get_inode(dirent.nid, dirent.file_type)
                        if isinstance(inode, DirInode):
                            inode = next_inode
                            ok = True
                        else:
                            raise ValueError("Inode at %r is of type %r instead of DirInode" % (path[0:i], type(inode)))
            if not ok:
                raise FileNotFoundError("Failed to find %r in %r" % (path[i], path[0:i]))
        assert False, path


class Inode:
    def __init__(self, erofs: Erofs, nid: int):
        self.erofs = erofs
        self.nid: int = nid
        self.inode_off = erofs.super.meta_blkaddr * 4096 + 32 * nid
        inode_buf = erofs.mmap[self.inode_off:self.inode_off + struct_erofs_inode_v1.sizeof()]
        self.inode_header = struct_erofs_inode_v1.parse(inode_buf)
        self.xattr_start_off = self.inode_off + struct_erofs_inode_v1.sizeof()
        if self.inode_header.i_xattr_icount > 0:
            self.xattr_size = 12 + (self.inode_header.i_xattr_icount - 1) * 4
        else:
            self.xattr_size = 0
        self.data_mapping_mode = DataMappingMode(self.inode_header.i_advise >> 1)
        assert self.inode_header.i_advise & 0x01 == 0

    def get_data(self, debug=False) -> bytes:
        if debug:
            print("Inode(nid=%r).get_data(): data_mapping_mode=%s" % (self.nid, self.data_mapping_mode.name))
            print("0x%08x-0x%08x: get_data Inode" % (self.inode_off, self.inode_off + struct_erofs_inode_v1.sizeof()))
            print(self.inode_header)
        if self.data_mapping_mode == DataMappingMode.EROFS_INODE_FLAT_INLINE:
            # Last block of file is directly following the inode/xattr data
            # Previous blocks are following this last block
            last_block_data_off = self.xattr_start_off + self.xattr_size
            last_block_data_size = 4096 - (last_block_data_off % 4096)
            if last_block_data_size == 4096:
                raise NotImplementedError("TODO: Check manually if there is a last block following the inode or not")
            last_block_data = self.erofs.mmap[last_block_data_off: last_block_data_off + last_block_data_size]
            if self.inode_header.i_size <= last_block_data_size:
                return last_block_data[0:self.inode_header.i_size]
            else:
                # initial_blocks_data_off = last_block_data_off + last_block_data_size
                # assert initial_blocks_data_off % 4096 == 0
                initial_blocks_data_off = self.inode_header.i_u * 4096
                initial_blocks_data_size = 4096 * math.ceil((self.inode_header.i_size - last_block_data_size) / 4096)
                initial_blocks_data = self.erofs.mmap[initial_blocks_data_off:initial_blocks_data_off + initial_blocks_data_size]
                assert len(initial_blocks_data) + len(last_block_data) >= self.inode_header.i_size
                assert len(initial_blocks_data) + len(last_block_data) - self.inode_header.i_size < 4096
                return (initial_blocks_data + last_block_data)[0:self.inode_header.i_size]
        elif self.data_mapping_mode == DataMappingMode.EROFS_INODE_FLAT_COMPRESSION_LEGACY:
            # print("HEADER: %s\n" % self.inode_header)
            # i_u is number of compressed blocks for EROFS_INODE_LAYOUT_COMPRESSION
            num_compressed_blocks = self.inode_header.i_u
            if num_compressed_blocks > 30e3:
                raise ValueError("Too may compressed blocks (self.inode_header.i_u=%r" % self.inode_header.i_u)
            decompress_index_header_pos = self.xattr_start_off + self.xattr_size
            # See Z_EROFS_VLE_LEGACY_INDEX_ALIGN(size)
            # round_up to a multiple of 8 bytes
            if decompress_index_header_pos % 8 == 4:
                decompress_index_header_pos += 4
            assert decompress_index_header_pos % 8 == 0
            decompress_index_header_pos += struct_z_erofs_map_header.sizeof()
            decompress_index_header_pos += 8  # Z_EROFS_VLE_LEGACY_HEADER_PADDING
            assert decompress_index_header_pos % 8 == 0
            # assert decompress_index_header_pos == self.xattr_start_off + self.xattr_size + 20
            # assert False
            prev_clusterofs = 0
            num_decompressed_blocks = math.ceil(self.inode_header.i_size / 4096)
            with BytesIO() as out:
                prev_blkaddr = 0
                prev_reserved_blkaddr = 0
                for di_number in range(num_decompressed_blocks):
                    buf = self.erofs.mmap[decompress_index_header_pos + recursive_union_sizeof(struct_z_erofs_vle_decompressed_index) * di_number: decompress_index_header_pos + recursive_union_sizeof(struct_z_erofs_vle_decompressed_index) * (di_number + 1)]
                    # print("  %s" % codecs.encode(buf, 'hex').decode())
                    di = struct_z_erofs_vle_decompressed_index.parse(buf)
                    if debug:
                        print("DI %d/%d: adv=0x%04x %r" % (di_number, num_decompressed_blocks, di.di_advise, di))
                        print("  OFF %r" % ((2**16 + di.di_clusterofs - prev_clusterofs) % 2**16))
                    prev_clusterofs = di.di_clusterofs
                    Z_EROFS_VLE_DI_CLUSTER_TYPE_BIT = 0
                    Z_EROFS_VLE_DI_CLUSTER_TYPE_BITS = 2
                    # See vle_legacy_load_cluster_from_disk() in drivers/staging/erofs/zmap.c
                    type_int = (di.di_advise >> Z_EROFS_VLE_DI_CLUSTER_TYPE_BIT) & ((1 << Z_EROFS_VLE_DI_CLUSTER_TYPE_BITS) - 1)
                    decompress_index_type = DecompressIndexType(type_int)
                    # print("DI %r: %r" % (di_number, decompress_index_type))
                    # print("OFFSET CHECK: %r <=> %r" % (out.tell() % 4096, di.di_clusterofs))
                    if decompress_index_type == DecompressIndexType.Z_EROFS_VLE_CLUSTER_TYPE_RESERVED:
                        if di.di_u.blkaddr == prev_blkaddr:
                            decompress_index_type = DecompressIndexType.Z_EROFS_VLE_CLUSTER_TYPE_NONHEAD
                        else:
                            decompress_index_type = DecompressIndexType.Z_EROFS_VLE_CLUSTER_TYPE_HEAD
                        prev_blkaddr = di.di_u.blkaddr
                    if decompress_index_type == DecompressIndexType.Z_EROFS_VLE_CLUSTER_TYPE_PLAIN:
                        out.seek(di_number * 4096 + di.di_clusterofs)
                        assert out.tell() == di_number * 4096 + di.di_clusterofs
                        blkaddr = di.di_u.blkaddr
                        buf = self.erofs.mmap[4096 * blkaddr: 4096 * (blkaddr + 1)]
                        if self.inode_header.i_size < out.tell() + len(buf):
                            buf = buf[0:self.inode_header.i_size - out.tell()]
                        out.write(buf)
                    elif decompress_index_type == DecompressIndexType.Z_EROFS_VLE_CLUSTER_TYPE_HEAD:
                        if out.tell() % 4096 != di.di_clusterofs:
                            if di.di_clusterofs == 0:
                                out.seek(out.tell() - (out.tell() % 4096))
                            else:
                                raise ValueError("Cluster offset check failed: %r <=> %r" % (out.tell() % 4096, di.di_clusterofs))
                        # assert out.tell() % 4096 == di.di_clusterofs, "Cluster offset check failed: %r <=> %r" % (out.tell() % 4096, di.di_clusterofs)
                        blkaddr = di.di_u.blkaddr
                        compressed_buf = self.erofs.mmap[4096 * blkaddr: 4096 * (blkaddr + 1)]
                        # hd(compressed_buf)
                        # decompressed_buf = pp_decompress_lz4(compressed_buf, maxlen=self.inode_header.i_size - out.tell(), expected=open("/usr/bin/lxc", "rb").read()[out.tell():])
                        decompressed_buf = pp_decompress_lz4(compressed_buf, maxlen=self.inode_header.i_size - out.tell())
                        out.write(decompressed_buf)
                    elif decompress_index_type == DecompressIndexType.Z_EROFS_VLE_CLUSTER_TYPE_NONHEAD:
                        pass
                    elif decompress_index_type == DecompressIndexType.Z_EROFS_VLE_CLUSTER_TYPE_RESERVED:
                        blkaddr = di.di_u.blkaddr
                        if blkaddr == prev_reserved_blkaddr:
                            continue
                        else:
                            prev_reserved_blkaddr = blkaddr
                        compressed_buf = self.erofs.mmap[4096 * blkaddr: 4096 * (blkaddr + 1)]
                        # hd(compressed_buf)
                        decompressed_buf = pp_decompress_lz4(compressed_buf, maxlen=self.inode_header.i_size - out.tell())
                        print("len(decompressed_buf)=%r  decompressed_buf[0:50] = %r" % (len(decompressed_buf), decompressed_buf[0:50]))
                        out.write(decompressed_buf)
                    else:
                        raise ValueError("Unexpected decompress_index_type %r" % decompress_index_type)
                if self.inode_header.checksum != 0:
                    raise NotImplementedError("Checksum verification not yet implemented")
                if out.tell() == self.inode_header.i_size:
                    return out.getvalue()
                elif out.tell() > self.inode_header.i_size:
                    return out.getvalue()[0:self.inode_header.i_size]
                else:
                    raise ValueError("Bad file size %r (expected: %r)" % (out.tell(), self.inode_header.i_size))
        elif self.data_mapping_mode == DataMappingMode.EROFS_INODE_FLAT_PLAIN:
            # print("HEADER: %s\n" % self.inode_header)
            last_block_data_off = self.inode_header.i_u * 4096
            data_size = self.inode_header.i_size
            data = self.erofs.mmap[last_block_data_off:last_block_data_off+data_size]
            # assert False
            return data
        elif self.data_mapping_mode == DataMappingMode.EROFS_INODE_FLAT_COMPRESSION:
            raise NotImplementedError("TODO: Implement EROFS_INODE_FLAT_COMPRESSION")
        else:
            raise ValueError("Don't know how to get data for data_mapping_mode=%r" % self.data_mapping_mode)

    def get_data_dir(self, debug=False) -> bytes:
        """
        Gets the directory data (struct erofs_dirent + filename buffer).
        Separate function required since EROFS_INODE_FLAT_INLINE behaves differently for directories
        and regular files
        :param debug:
        :return:
        """
        if debug:
            print("Inode(nid=%r).get_data(): data_mapping_mode=%s" % (self.nid, self.data_mapping_mode.name))
            print("0x%08x-0x%08x: get_data Inode" % (self.inode_off, self.inode_off + struct_erofs_inode_v1.sizeof()))
            print(self.inode_header)
        if self.data_mapping_mode == DataMappingMode.EROFS_INODE_FLAT_INLINE:
            # For directories with EROFS_INODE_FLAT_INLINE, the full data is (sequentially) following the inode header/xattr.
            data_off = self.xattr_start_off + self.xattr_size
            data_size = self.inode_header.i_size
            return self.erofs.mmap[data_off: data_off + data_size]
        else:
            # Other mdoes are equal for directories and file data
            return self.get_data()


class DirEnt:
    def __init__(self, filename: bytes, file_type: FileType, nid: int):
        self.filename: bytes = filename
        self.file_type: FileType = file_type
        self.nid: int = nid

    def __repr__(self):
        return "DirEnt(%r, %r, %r)" % (self.filename, self.file_type, self.nid)


class DirInode(Inode):
    def __init__(self, erofs: Erofs, nid: int):
        super(DirInode, self).__init__(erofs, nid)
        if S_IFMT(self.inode_header.i_mode) != S_IFDIR:
            raise ValueError("DirInode at nid=0x%16x is not of type S_IFDIR, self.inode_header.i_mode=0x%08x" % (nid, self.inode_header.i_mode))
        # print("self.inode_off=0x%x" % self.inode_off)
        # print(self.inode_header)
        data = self.get_data_dir()
        self.dirents: List[DirEnt] = []
        if len(data) == 0:
            return
        # hd(data)
        dirent0 = struct_erofs_dirent.parse(data[0:12])
        # print(dirent0)
        # return
        assert dirent0.nameoff % 12 == 0
        num_dirents = int(dirent0.nameoff / 12)
        struct_dirents: List[struct_erofs_dirent] = []
        for i in range(num_dirents):
            struct_dirents.append(struct_erofs_dirent.parse(data[12*i:12*i+12]))
        self.dirents = []
        filenames_done: Set[bytes] = set()
        for i in range(num_dirents):
            struct_dirent = struct_dirents[i]
            name_end = len(data)
            if i < num_dirents - 1:
                name_end = struct_dirents[i+1].nameoff
            filename = data[struct_dirent.nameoff:name_end]
            filename = filename.split(b'\0', 1)[0]
            if filename == b'':
                raise ValueError("Empty filename")
            if filename in filenames_done:
                raise ValueError("Duplicate filename %r" % filename)
            # print("FILE %r: %r" % (filename, struct_dirent))
            assert len(filename) < 255, "Filename too long(%d bytes): %r..." % (len(filename), filename[0:50])
            if struct_dirent.file_type >= FileType.EROFS_FT_MAX.value:
                raise ValueError("Bad struct_dirent.file_type %r" % struct_dirent.file_type)
            file_type = FileType(struct_dirent.file_type)
            dirent = DirEnt(filename, file_type, struct_dirent.nid)
            self.dirents.append(dirent)
            # print("%r" % dirent)

    def get_dirents(self) -> List[DirEnt]:
        return self.dirents

    def traverse(self, prefix=b"/"):
        for dirent in self.dirents:
            print("TRAVERSE: %r => %r" % (prefix, dirent.filename))
            child_inode = self.erofs.get_inode(dirent.nid, dirent.file_type)
            if dirent.file_type == FileType.EROFS_FT_SYMLINK:
                print("%s%s: %r => %r" % (prefix.decode(errors="ignore"), dirent.filename.decode(errors="ignore"), dirent, child_inode.get_symlink_dest()))
            elif dirent.file_type == FileType.EROFS_FT_REG_FILE:
                print("%s%s: %r" % (prefix.decode(errors="ignore"), dirent.filename.decode(errors="ignore"), dirent))
            elif dirent.file_type == FileType.EROFS_FT_DIR:
                # Some versions of mkfs.erofs add entries for "." and ".."
                if dirent.filename in (b'.', b'..'):
                    continue
                print("%s%s: %r" % (prefix.decode(errors="ignore"), dirent.filename.decode(errors="ignore"), dirent))
                child_inode.traverse(prefix + dirent.filename + b'/')

    def extract(self, output_dir: bytes, verify_zip: bool = False):
        """
        Extracts this directory to output_dir.
        :param output_dir:
        Must already exist (as an empty directory)
        :param verify_zip:
        Verify all zip/jar/apk files in output (using "unzip -tqq") to detect potential extraction errors
        :return:
        """
        for dirent in self.dirents:
            out_path = os.path.join(output_dir, dirent.filename)
            print("Extracting %r" % out_path.decode())
            if os.path.exists(out_path):
                raise ValueError("Duplicate file %r" % out_path)
            child_inode = self.erofs.get_inode(dirent.nid, dirent.file_type)
            if dirent.file_type == FileType.EROFS_FT_SYMLINK:
                os.symlink(child_inode.get_symlink_dest(), out_path)
            elif dirent.file_type == FileType.EROFS_FT_DIR:
                # Some versions of mkfs.erofs add entries for "." and ".."
                if dirent.filename in (b'.', b'..'):
                    continue
                os.mkdir(out_path)
                # Always make directories mode 755
                os.chmod(out_path, 0o755)
                child_inode.extract(out_path, verify_zip=verify_zip)
            elif dirent.file_type == FileType.EROFS_FT_REG_FILE:
                with open(out_path, 'wb') as f:
                    f.write(child_inode.get_data())
                # use original mode & 0o755 => Ignore setuid/setgid bit
                mode = child_inode.inode_header.i_mode & 0o777
                # Ensure files are always readable
                mode |= 0o444
                os.chmod(out_path, mode)
                if verify_zip:
                    ext = out_path.split(b'.')[-1].lower()
                    if ext in (b'zip', b'jar', b'apk'):
                        print("Verifying %r" % out_path)
                        subprocess.check_call(["unzip", "-tqq", out_path])
            else:
                raise NotImplementedError("file_type %r not implemented" % dirent.file_type)


class SymlinkInode(Inode):
    def __init__(self, erofs: Erofs, nid: int):
        super(SymlinkInode, self).__init__(erofs, nid)
        if S_IFMT(self.inode_header.i_mode) != S_IFLNK:
            raise ValueError("SymlinkInode at nid=0x%16x is not of type S_IFLNK, self.inode_header.i_mode=0x%08x" % (nid, self.inode_header.i_mode))
        self.symlink_dest = self.get_data()

    def get_symlink_dest(self):
        return self.symlink_dest


class RegFileInode(Inode):
    def __init__(self, erofs: Erofs, nid: int):
        super(RegFileInode, self).__init__(erofs, nid)
        if S_IFMT(self.inode_header.i_mode) != S_IFREG:
            raise ValueError("RegFileInode at nid=0x%16x is not of type S_IFREG, self.inode_header.i_mode=0x%08x" % (nid, self.inode_header.i_mode))


def hd(buf: bytes):
    sys.stdout.flush()
    p = subprocess.Popen(["hd"], stdin=subprocess.PIPE)
    p.stdin.write(buf)
    p.stdin.close()
    p.wait()


def pp_decompress_lz4(buf: bytes, maxlen: int = None, expected: bytes = None) -> bytes:
    """
    https://github.com/lz4/lz4/blob/master/doc/lz4_Block_format.md
    :param buf: Compressed buffer, raw LZ4 without framing or length header
    :param maxlen: Maximum length to extract, will return buffer after extracting that amount of bytes
    :param expected: Optional known decompressed value to debug extraction errors
    :return:
    """
    with BytesIO() as out:
        pos = 0
        while pos < len(buf):
            token_byte = buf[pos]
            # print("Token 0x%02x at 0x%x" % (token_byte, pos))
            pos += 1
            # Get length of literal from input
            literal_length = token_byte >> 4
            if literal_length == 0xf:
                length_byte = buf[pos]
                pos += 1
                literal_length += length_byte
                while length_byte == 0xff:
                    length_byte = buf[pos]
                    pos += 1
                    literal_length += length_byte
            literal_buf = buf[pos: pos + literal_length]
            pos += literal_length
            if expected is not None:
                for i in range(len(literal_buf)):
                    assert literal_buf[i] == expected[out.tell() + i], "Mismatch at position 0x%x: %r <=> %r" % (out.tell() + i, literal_buf[i], expected[out.tell() + i])
            out.write(literal_buf)
            if maxlen is not None and out.tell() >= maxlen:
                return out.getvalue()[0:maxlen]
            if pos == len(buf) or pos == len(buf) - 1:
                # Reached end of input after literal => OK
                break
            # print("OFFSET POS: 0x%x" % pos)
            # Get offset for copy operation
            offset = buf[pos] + 256 * buf[pos + 1]
            pos += 2
            if offset == 0:
                continue
                # raise ValueError("Offset cannot be 0")
            # Get matchlength for copy operation
            matchlength = token_byte & 0x0f
            if matchlength == 0xf:
                length_byte = buf[pos]
                pos += 1
                matchlength += length_byte
                while length_byte == 0xff:
                    length_byte = buf[pos]
                    pos += 1
                    matchlength += length_byte
            matchlength += 4
            match_pos = out.tell() - offset
            while matchlength > 0:
                copylen = min(matchlength, out.tell() - match_pos)
                copybuf = out.getvalue()[match_pos: match_pos + copylen]
                if expected is not None:
                    for i in range(len(copybuf)):
                        assert copybuf[i] == expected[out.tell() + i], "Mismatch at position %r" % (out.tell() + i)
                out.write(copybuf)
                if maxlen is not None and out.tell() >= maxlen:
                    return out.getvalue()[0:maxlen]
                matchlength -= copylen
                # print("copylen=%r" % copylen)
                # Copy from the original position => Copy as many bytes as possible at a time
                assert copylen % offset == 0 or matchlength == 0
                # match_pos += copylen % offset
            # Old, un-optimized code:
            # for i in range(matchlength):
            #     out.write(out.getvalue()[match_pos + i:match_pos + i + 1])
        return out.getvalue()


if __name__ == "__main__":
    main()
