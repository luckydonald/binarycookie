#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from typing import List
from struct import unpack
from io import BytesIO
from time import strftime, gmtime


__author__ = 'luckydonald'


from .parse import parse_cookies as parse
from .classes import Cookie
from .version import version

__version__ = version
VERSION = version
