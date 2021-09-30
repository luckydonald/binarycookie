#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from struct import unpack
from typing import Union
from typing.io import IO, BinaryIO
from io import BytesIO


__author__ = 'luckydonald'


def parse_binary_string_on_buffer(buffer: Union[BinaryIO, BytesIO]) -> str:
    """
    Strings ends with \0.
    We parse until we reach that.
    """
    result = b''
    tmp = buffer.read(1)
    while unpack('<b', tmp)[0] != 0:
        result = result + tmp
        tmp = buffer.read(1)
    result = result.decode('utf-8')
    return result
# end def
