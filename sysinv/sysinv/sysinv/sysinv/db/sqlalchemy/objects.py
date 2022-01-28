#
# Copyright (c) 2022 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import functools

import eventlet
from oslo_db.sqlalchemy import enginefacade
from sqlalchemy.exc import InvalidRequestError
from sqlalchemy.orm.exc import UnmappedInstanceError

ALREADY_ATTACHED_STRING = 'already attached'


def _session_for_read():
    _context = eventlet.greenthread.getcurrent()
    return enginefacade.reader.using(_context)


def objectify(klass):
    """Decorator to convert database results into specified objects.
    :param klass: database results class
    """

    def the_decorator(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            first_result = fn(*args, **kwargs)

            with _session_for_read() as session:
                bound_session = True
                try:
                    session.add(first_result)
                except UnmappedInstanceError:
                    bound_session = False
                except InvalidRequestError as e:
                    if ALREADY_ATTACHED_STRING in str(e):
                        bound_session = False
                    else:
                        raise e

                try:
                    second_result = klass.from_db_object(first_result)
                except TypeError:
                    # TODO(deva): handle lists of objects better
                    #             once support for those lands and is imported.
                    second_result = [klass.from_db_object(obj) for obj in first_result]

                if bound_session:
                    session.expunge_all()

            return second_result

        return wrapper

    return the_decorator
