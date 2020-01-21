#!/usr/bin/env python
# -*- coding: utf-8 -*-


class AuthError(Exception):
    pass


class UnknownEvent(Exception):
    pass


class UnknownUser(Exception):
    pass


class SignupError(Exception):
    pass