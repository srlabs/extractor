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


from typing import TypeVar, Type
from io import BytesIO
from construct import Struct, Construct  # type: ignore


# TypeVar is required so that parse returns the right type (of the sub-class).
# https://stackoverflow.com/a/46064289
# noinspection PyTypeChecker
T = TypeVar('T', bound='TypedContainer')


class TypedContainer:
    """
    Base class for a typed struct for use with construct. Usage instructions:
    * Make your own class with TypedContainer as superclass
    * Define instance fields with typing (e.g. bytes or int)
    * Set the class variable construct_struct to the actual construct Struct() definition
    """
    construct_struct: Struct

    @classmethod
    def parse(cls: Type[T], buf: bytes) -> T:
        """
        Parses a buffer
        :param buf:
        :return:
        """
        return cls.parse_stream(BytesIO(buf))

    @classmethod
    def parse_stream(cls: Type[T], stream):
        self = cls()
        construct_container = cls.construct_struct.parse_stream(stream)
        for k, v in dict(construct_container).items():
            self.__setattr__(k, v)
        return self

    @classmethod
    def sizeof(cls):
        return cls.construct_struct.sizeof()

    def build(self) -> bytes:
        return self.__class__.construct_struct.build(self.__dict__)

    def __str__(self):
        string_list = [self.__class__.__name__]
        for k, v in sorted(self.__dict__.items()):
            string_list.append("    %s = %r" % (k, v))
        return "\n".join(string_list)

    def __repr__(self):
        field_params = []
        # Use correct order
        for field in self.construct_struct.subcons:
            field_params.append("%s=%r" % (field.name, self.__getattribute__(field.name)))
        return "%s(%s)" % (self.__class__.__name__, ", ".join(field_params))

    def __eq__(self, other: T):
        if type(self) is not type(other):
            return False
        for field in self.construct_struct.subcons:
            if self.__getattribute__(field.name) != other.__getattribute__(field.name):
                return False
        return True

    @classmethod
    def as_inner_type(cls):
        return InnerTypedContainer(cls)


class InnerTypedContainer(Construct):
    inner_type: T

    def __init__(self, inner_type):
        super().__init__()
        self.inner_type = inner_type

    def _parse(self, stream, context, path):
        return self.inner_type.parse_stream(stream)

    def _build(self, obj, stream, context, path):
        buf = obj.build()
        stream.write(buf)

    def _sizeof(self, context, path):
        return self.inner_type.sizeof()
