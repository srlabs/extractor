#!/usr/bin/python3

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


from typing import BinaryIO, List, Dict, Union
import os
import copy
import sys
import mmap
import hashlib
from construct import Struct, Int32ul, Int16ul, Int64ul, Bytes
from construct_typing import TypedContainer


def main():
    breakpoint()
    super_img = SuperImage(sys.argv[1])
    print("PARTITIONS: %r" % super_img.get_partition_names())
    for partition_name in super_img.get_partition_names():
        if partition_name in ("system", "vendor", "product"):
            with open("%s.img" % partition_name, 'wb') as f:
                super_img.write_partition(partition_name, f)


def check_magic(f: BinaryIO):
    buf = f.read(4096)
    if buf != b'\0' * 4096:
        return False
    buf = f.read(4)
    return buf == b'\x67\x44\x6c\x61'


class SuperImage:
    """
    Class to parse a liblp super image.
    More details at
    https://android.googlesource.com/platform/system/core
    => fs_mgr/liblp/include/liblp/metadata_format.h
    """
    filename: str
    file_size: int
    fh: BinaryIO
    mmap: mmap.mmap
    geometry: "LpMetadataGeometry"
    metadata_header: "Union[LpMetadataHeaderV1_0, LpMetadataHeaderV1_2]"
    partitions: List["LpMetadataPartition"]
    extents: List["LpMetadataExtent"]
    block_device: "LpMetadataBlockDevice"
    partition_name_to_nr: Dict[str, int]

    def __init__(self, filename: Union[str, bytes]):
        self.filename = filename
        self.file_size = os.stat(self.filename).st_size
        self.fh = open(self.filename, 'rb')
        self.mmap = mmap.mmap(self.fh.fileno(), 0, access=mmap.ACCESS_READ)
        # Read and validate LpMetadataGeometry
        lmg = LpMetadataGeometry.parse(self.mmap[0x1000:0x1000 + LpMetadataGeometry.sizeof()])
        lmg.validate()
        lmg_copy = LpMetadataGeometry.parse(self.mmap[0x2000:0x2000 + LpMetadataGeometry.sizeof()])
        lmg_copy.validate()
        assert lmg == lmg_copy
        # Read and validate
        tmp_metadata_header = LpMetadataHeaderV1_0.parse(self.mmap[0x3000:0x3000 + LpMetadataHeaderV1_0.sizeof()])
        if tmp_metadata_header.header_size == LpMetadataHeaderV1_0.sizeof():
            self.metadata_header = tmp_metadata_header
            self.metadata_header.validate()
        elif tmp_metadata_header.header_size == LpMetadataHeaderV1_2.sizeof():
            self.metadata_header = LpMetadataHeaderV1_2.parse(self.mmap[0x3000:0x3000 + LpMetadataHeaderV1_2.sizeof()])
            self.metadata_header.validate()
        else:
            raise ValueError(f"Invalid LpMetadataHeader.header_size={tmp_metadata_header.header_size}")
        table_data = self.mmap[0x3000 + self.metadata_header.header_size:0x3000 + self.metadata_header.header_size + self.metadata_header.tables_size]
        self.metadata_header.validate_table_data(table_data)
        # Read partitions from table_data
        self.partition_name_to_nr = {}
        self.partitions = []
        for partition_nr in range(self.metadata_header.partitions.num_entries):
            pos = self.metadata_header.partitions.offset + partition_nr * LpMetadataPartition.sizeof()
            partition = LpMetadataPartition.parse(table_data[pos:pos + LpMetadataPartition.sizeof()])
            print("partition %d: %r" % (partition_nr, partition))
            self.partitions.append(partition)
            assert partition.get_name() not in self.partition_name_to_nr, "Duplicate partition %r" % partition.get_name()
            self.partition_name_to_nr[partition.get_name()] = partition_nr
        # Read extents from table_data
        self.extents = []
        for extent_nr in range(self.metadata_header.extents.num_entries):
            pos = self.metadata_header.extents.offset + extent_nr * LpMetadataExtent.sizeof()
            extent = LpMetadataExtent.parse(table_data[pos:pos + LpMetadataExtent.sizeof()])
            print("Extent %d: %r" % (extent_nr, extent))
            self.extents.append(extent)
        # Read block devices from table_data
        assert self.metadata_header.block_devices.num_entries == 1, "Not exactly one block device: self.metadata_header.block_devices.num_entries=%r" % self.metadata_header.block_devices.num_entries
        pos = self.metadata_header.block_devices.offset
        self.block_device = LpMetadataBlockDevice.parse(table_data[pos:pos + LpMetadataBlockDevice.sizeof()])
        assert self.block_device.alignment % 512 == 0

    def get_partition_names(self) -> List[str]:
        return [partition.get_name() for partition in self.partitions]

    def close(self):
        self.mmap.close()
        self.fh.close()

    def write_partition(self, partition_name: str, f: BinaryIO):
        partition_nr = self.partition_name_to_nr[partition_name]
        partition = self.partitions[partition_nr]
        assert partition.num_extents == 1, "Not exactly one extent: %d" % partition.num_extents
        extent = self.extents[partition.first_extent_index]
        assert extent.target_source == 0
        assert extent.target_type == 0  # LP_TARGET_TYPE_LINEAR
        start_pos = extent.target_data * 512
        assert start_pos % self.block_device.alignment == 0, "Alignment error: start_pos=%d  self.block_device.alignment=%d  offset=%r" % (start_pos, self.block_device.alignment, start_pos % self.block_device.alignment)
        end_pos = start_pos + extent.num_sectors * 512
        pos = start_pos
        while pos < end_pos:
            next_pos = min(end_pos, pos + 1024**2)
            f.write(self.mmap[pos:next_pos])
            pos = next_pos


class LpMetadataGeometry(TypedContainer):
    magic: int
    struct_size: int
    checksum: bytes
    metadata_max_size: int
    metadata_slot_count: int
    logical_block_size: int
    # noinspection PyUnresolvedReferences
    construct_struct = Struct(
        "magic" / Int32ul,
        "struct_size" / Int32ul,
        "checksum" / Bytes(32),
        "metadata_max_size" / Int32ul,
        "metadata_slot_count" / Int32ul,
        "logical_block_size" / Int32ul,
    )

    def validate(self):
        assert self.magic == 0x616c4467
        assert self.struct_size == LpMetadataGeometry.sizeof()
        tmp = copy.copy(self)
        tmp.checksum = b'\0' * 32
        tmp_encoded = tmp.build()
        digest = hashlib.sha256(tmp_encoded).digest()
        assert self.checksum == digest


assert LpMetadataGeometry.sizeof() == 52


class LpMetadataTableDescriptor(TypedContainer):
    offset: int
    num_entries: int
    entry_size: int
    # noinspection PyUnresolvedReferences
    construct_struct = Struct(
        "offset" / Int32ul,
        "num_entries" / Int32ul,
        "entry_size" / Int32ul
    )


assert LpMetadataTableDescriptor.sizeof() == 12


class LpMetadataHeaderV1_0(TypedContainer):
    magic: int
    major_version: int
    minor_version: int
    header_size: int
    header_checksum: bytes
    tables_size: int
    tables_checksum: bytes
    partitions: LpMetadataTableDescriptor
    extents: LpMetadataTableDescriptor
    groups: LpMetadataTableDescriptor
    block_devices: LpMetadataTableDescriptor
    # flags: int
    # reserved: bytes
    # noinspection PyUnresolvedReferences
    construct_struct = Struct(
        "magic" / Int32ul,
        "major_version" / Int16ul,
        "minor_version" / Int16ul,
        "header_size" / Int32ul,
        "header_checksum" / Bytes(32),
        "tables_size" / Int32ul,
        "tables_checksum" / Bytes(32),
        "partitions" / LpMetadataTableDescriptor.as_inner_type(),
        "extents" / LpMetadataTableDescriptor.as_inner_type(),
        "groups" / LpMetadataTableDescriptor.as_inner_type(),
        "block_devices" / LpMetadataTableDescriptor.as_inner_type()
    )

    def validate(self):
        assert self.magic == 0x414C5030
        assert self.header_size == LpMetadataHeaderV1_0.sizeof(), "Bad LpMetadataHeaderV1_0.header_size %d, should be %d" % (self.header_size, LpMetadataHeaderV1_0.sizeof())
        tmp = copy.copy(self)
        tmp.header_checksum = b'\0' * 32
        tmp_encoded = tmp.build()
        digest = hashlib.sha256(tmp_encoded).digest()
        assert self.header_checksum == digest
        assert self.partitions.entry_size == LpMetadataPartition.sizeof(), "Bad LpMetadataHeaderV1_0.partitions.entry_size %d, should be %d" % (self.partitions.entry_size, LpMetadataPartition.sizeof())
        assert self.extents.entry_size == LpMetadataExtent.sizeof(), "Bad LpMetadataHeaderV1_0.extents.entry_size %d, should be %d" % (self.extents.entry_size, LpMetadataExtent.sizeof())
        assert self.tables_size < 1e6

    def validate_table_data(self, buf: bytes):
        assert len(buf) == self.tables_size
        digest = hashlib.sha256(buf).digest()
        assert self.tables_checksum == digest


class LpMetadataHeaderV1_2(TypedContainer):
    magic: int
    major_version: int
    minor_version: int
    header_size: int
    header_checksum: bytes
    tables_size: int
    tables_checksum: bytes
    partitions: LpMetadataTableDescriptor
    extents: LpMetadataTableDescriptor
    groups: LpMetadataTableDescriptor
    block_devices: LpMetadataTableDescriptor
    flags: int
    # flags: int
    # reserved: bytes
    # noinspection PyUnresolvedReferences
    construct_struct = Struct(
        "magic" / Int32ul,
        "major_version" / Int16ul,
        "minor_version" / Int16ul,
        "header_size" / Int32ul,
        "header_checksum" / Bytes(32),
        "tables_size" / Int32ul,
        "tables_checksum" / Bytes(32),
        "partitions" / LpMetadataTableDescriptor.as_inner_type(),
        "extents" / LpMetadataTableDescriptor.as_inner_type(),
        "groups" / LpMetadataTableDescriptor.as_inner_type(),
        "block_devices" / LpMetadataTableDescriptor.as_inner_type(),
        "flags" / Int32ul,
        "_reserved" / Bytes(124)
    )

    def validate(self):
        assert self.magic == 0x414C5030
        assert self.header_size == LpMetadataHeaderV1_2.sizeof(), "Bad LpMetadataHeaderV1_2.header_size %d, should be %d" % (self.header_size, LpMetadataHeaderV1_0.sizeof())
        tmp = copy.copy(self)
        tmp.header_checksum = b'\0' * 32
        tmp_encoded = tmp.build()
        digest = hashlib.sha256(tmp_encoded).digest()
        assert self.header_checksum == digest
        assert self.partitions.entry_size == LpMetadataPartition.sizeof(), "Bad LpMetadataHeaderV1_2.partitions.entry_size %d, should be %d" % (self.partitions.entry_size, LpMetadataPartition.sizeof())
        assert self.extents.entry_size == LpMetadataExtent.sizeof(), "Bad LpMetadataHeaderV1_2.extents.entry_size %d, should be %d" % (self.extents.entry_size, LpMetadataExtent.sizeof())
        assert self.tables_size < 1e6

    def validate_table_data(self, buf: bytes):
        assert len(buf) == self.tables_size
        digest = hashlib.sha256(buf).digest()
        assert self.tables_checksum == digest


class LpMetadataPartition(TypedContainer):
    name: bytes
    attributes: int
    first_extent_index: int
    num_extents: int
    group_index: int
    # noinspection PyUnresolvedReferences
    construct_struct = Struct(
        "name" / Bytes(36),
        "attributes" / Int32ul,
        "first_extent_index" / Int32ul,
        "num_extents" / Int32ul,
        "group_index" / Int32ul
    )

    def get_name(self) -> str:
        return self.name.rstrip(b'\0').decode()


assert LpMetadataPartition.sizeof() == 52


class LpMetadataExtent(TypedContainer):
    num_sectors: int
    target_type: int
    target_data: int
    target_source: int
    # noinspection PyUnresolvedReferences
    construct_struct = Struct(
        "num_sectors" / Int64ul,
        "target_type" / Int32ul,
        "target_data" / Int64ul,
        "target_source" / Int32ul,
    )


assert LpMetadataExtent.sizeof() == 24


class LpMetadataBlockDevice(TypedContainer):
    first_logical_sector: int
    alignment: int
    alignment_offset: int
    size: int
    partition_name: bytes
    flags: int
    # noinspection PyUnresolvedReferences
    construct_struct = Struct(
        "first_logical_sector" / Int64ul,
        "alignment" / Int32ul,
        "alignment_offset" / Int32ul,
        "size" / Int64ul,
        "partition_name" / Bytes(36),
        "flags" / Int32ul
    )


assert LpMetadataBlockDevice.sizeof() == 64


if __name__ == "__main__":
    main()
