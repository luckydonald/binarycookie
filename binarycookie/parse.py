#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from typing import List
from struct import unpack
from io import BytesIO
from time import strftime, gmtime

from .classes import Cookie
from .utils import parse_binary_string_on_buffer


__author__ = 'luckydonald'


def parse_cookies(binary_data: bytes) -> List[Cookie]:
    """
    Parse a cookie file

    > Based on BinaryCookieReader which was written By Satishb3 (http://www.securitylearn.net, satishb3@securitylearn.net)
    > Improved (And updated for python 3) by luckydonald (https://github.com/luckydonald/binarycookie, binarycookie+code@luckydonald.de)

    :param binary_data: The raw binary data of the cookie file
    :return: list of Cookie objects found in that data.
    """
    binary_file = BytesIO(binary_data)
    file_header = binary_file.read(4)  # File Magic String:cook
    if file_header != b'cook':
        raise ValueError("Not a Cookies.binarycookie file")
    # end if

    num_pages = unpack('>i', binary_file.read(4))[0]  # Number of pages in the binary file: 4 bytes

    page_sizes = []
    for np in range(num_pages):
        page_sizes.append(unpack('>i', binary_file.read(4))[0])  # Each page size: 4 bytes*number of pages
    # end for

    pages = []
    for ps in page_sizes:
        pages.append(binary_file.read(ps))  # Grab individual pages and each page will contain >= one cookie
    # end for

    cookies = []

    for page in pages:
        page = BytesIO(page)  # Converts the string to a file. So that we can use read/write operations easily.
        page.read(4)  # page header: 4 bytes: Always 00000100
        num_cookies = unpack('<i', page.read(4))[
            0]  # Number of cookies in each page, first 4 bytes after the page header in every page.

        cookie_offsets = []
        for nc in range(num_cookies):
            cookie_offsets.append(unpack('<i', page.read(4))[
                                      0])  # Every page contains >= one cookie. Fetch cookie starting point from page starting byte

        page.read(4)  # end of page header: Always 00000000

        for offset in cookie_offsets:
            page.seek(offset)  # Move the page pointer to the cookie starting point
            cookie_size = unpack('<i', page.read(4))[0]  # fetch cookie size
            cookie = BytesIO(page.read(cookie_size))  # read the complete cookie

            cookie.read(4)  # unknown

            flags = unpack('<i', cookie.read(4))[
                0]  # Cookie flags:  1=secure, 4=httponly, 5=secure+httponly
            cookie_flags = ''
            if flags == 0:
                cookie_flags = ''
            elif flags == 1:
                cookie_flags = 'Secure'
            elif flags == 4:
                cookie_flags = 'HttpOnly'
            elif flags == 5:
                cookie_flags = 'Secure; HttpOnly'
            else:
                cookie_flags = 'Unknown'

            cookie.read(4)  # unknown

            url_offset = unpack('<i', cookie.read(4))[0]  # cookie domain offset from cookie starting point
            name_offset = unpack('<i', cookie.read(4))[0]  # cookie name offset from cookie starting point
            path_offset = unpack('<i', cookie.read(4))[0]  # cookie path offset from cookie starting point
            value_offset = unpack('<i', cookie.read(4))[0]  # cookie value offset from cookie starting point

            cookie.read(8)  # reach end of cookie

            # Expiry date is in Mac epoch format: Starts from 1/Jan/2001
            expiry_date_epoch = unpack('<d', cookie.read(8))[
                                    0] + 978307200  # 978307200 is unix epoch of 1/Jan/2001
            expiry_date = strftime("%a, %d %b %Y ", gmtime(expiry_date_epoch))[
                          :-1]  # [:-1] strips the last space

            create_date_epoch = unpack('<d', cookie.read(8))[0] + 978307200  # Cookies creation time
            create_date = strftime("%a, %d %b %Y ", gmtime(create_date_epoch))[:-1]

            cookie.seek(url_offset - 4)  # fetch domaain value from url offset
            url = parse_binary_string_on_buffer(buffer=cookie)

            cookie.seek(name_offset - 4)  # fetch cookie name from name offset
            name = parse_binary_string_on_buffer(buffer=cookie)

            cookie.seek(path_offset - 4)  # fetch cookie path from path offset
            path = parse_binary_string_on_buffer(buffer=cookie)

            cookie.seek(value_offset - 4)  # fetch cookie value from value offset
            value = parse_binary_string_on_buffer(buffer=cookie)

            cookie = Cookie(
                name=name, value=value, domain=url, path=path, create_date=create_date,
                expiry_date=expiry_date, cookie_flags=cookie_flags
            )
            cookies.append(cookie)
        # end for
    # end for
    return cookies
# end def
