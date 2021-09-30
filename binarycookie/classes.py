#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from typing import List, Optional


__author__ = 'luckydonald'


class Cookie(object):
    def __init__(
        self,
        name: Optional[str] = None,
        value: Optional[str] = None,
        domain: Optional[str] = None,
        path: Optional[str] = None,
        create_date: Optional[str] = None,
        expiry_date: Optional[str] = None,
        cookie_flags: Optional[str] = None,
    ):
        self.name = name
        self.value = value
        self.domain = domain
        self.path = path
        self.create_date = create_date
        self.expiry_date = expiry_date
        self.cookie_flags = cookie_flags
    # end def

    def as_dict(self):
        return dict(
            name=self.name, value=self.value, domain=self.domain, path=self.path,
            create_date=self.create_date, expiry_date=self.expiry_date, cookie_flags=self.cookie_flags
        )
    # end def

    def as_cookie_string(self):
        return (
            self.name + '=' + self.value + '; domain=' + self.domain + '; path=' + self.path + '; '
            + 'expires=' + self.expiry_date + '; ' + self.cookie_flags
        )
    # end def

    def __str__(self):
        return self.as_cookie_string()
    # end def

    def __repr__(self):
        return (
            "{s.__class__.__name__!s}("
            "name={s.name!r}, value={s.value!r}, domain={s.domain!r}, path={s.path!r}, "
            "create_date={s.create_date!r}, expiry_date={s.expiry_date!r}, cookie_flags={s.cookie_flags!r}"
            ")"
        ).format(s=self)
    # end def
# end class
