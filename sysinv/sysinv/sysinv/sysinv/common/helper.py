#
# Copyright (c) 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# Helper functions.

import functools
import time
import typing
from oslo_config import cfg
from oslo_log import log

LOG = log.getLogger(__name__)

performance_opts = [
    cfg.BoolOpt('performance',
                default=False,
                help='Enable performance logging'
                )
]
CONF = cfg.CONF
CONF.register_opts(performance_opts)


def ttl_cache(cache_expiry: int = 10):
    """Extends functools.lru_cache to support expiring cache.

    Args:
        cache_expiry: Time  period before cache expires in seconds.
                      Defaults to 10 seconds.
    """
    if cache_expiry <= 0:
        cache_expiry = 10

    def _generate_hash(ttl_seconds: int):
        start_time = time.time()
        # prevent divide by zero
        ttl_seconds = max(1, ttl_seconds)
        while True:
            yield ((time.time() - start_time) // ttl_seconds)

    # initialize generator
    hash = _generate_hash(cache_expiry)

    def _decorator(func: typing.Callable) -> typing.Callable:

        @functools.lru_cache
        def ttl_func(ttl_hash, *args, **kwargs) -> typing.Any:
            return func(*args, **kwargs)

        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> typing.Any:
            ttl_hash = next(hash)
            return ttl_func(ttl_hash, *args, **kwargs)

        return wrapper

    return _decorator


def measure_performance(threshold_in_seconds: int = 0):
    """Measure how long a function takes to run
       if performance is set to True in the config

    """

    threshold_in_seconds = max(0, threshold_in_seconds)

    def _decorator(func: typing.Callable) -> typing.Callable:

        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> typing.Any:

            if not CONF.performance:
                return func(*args, **kwargs)

            start = time.perf_counter()
            result, exception = None, None
            try:
                result = func(*args, **kwargs)
            except Exception as e:
                exception = e
            finally:
                duration = time.perf_counter() - start
                if duration >= threshold_in_seconds:
                    LOG.info(f"Function \"{func.__name__}()\" "
                             f"took {duration:.4f} seconds to run")
                if exception:
                    raise exception
                return result

        return wrapper
    return _decorator
