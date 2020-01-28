#!/usr/bin/env python
# -*- coding: utf-8 -*-


class AuthError(Exception):
    pass


class NotFoundError(Exception):
    pass


class SignupError(Exception):
    pass


class RateLimitExceededError(Exception):
    pass


class UnexpectedError(Exception):
    pass