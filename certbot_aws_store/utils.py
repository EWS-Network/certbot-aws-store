# SPDX-License-Identifier: MPL-2.0
# Copyright 2022 John Mille <john@ews-network.net>

"""
Swiss Knife functions to re-use across the program
"""


def easy_read(path):
    with open(path) as file:
        contents = file.read()
    return contents
