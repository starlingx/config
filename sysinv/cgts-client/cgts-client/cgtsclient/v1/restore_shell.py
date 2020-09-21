#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# -*- encoding: utf-8 -*-
#


def do_restore_start(cc, args):
    """Start software restore."""

    print(cc.restore.start())


def do_restore_show(cc, args):
    """Show software restore."""

    print(cc.restore.get())


def do_restore_complete(cc, args):
    """Complete software restore."""

    print(cc.restore.complete())
