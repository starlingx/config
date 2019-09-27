StarlingX Sysinv Style Commandments
=====================================

- Step 1: Read the OpenStack style commandments
  https://docs.openstack.org/hacking/
- Step 2: Read on

Sysinv Specific Commandments
----------------------------

Code changes which affect the sysinv REST API must also be documented in
  https://docs.starlingx.io/contributor/api_contribute_guide.html

TODO vs FIXME
-------------

- TODO(name): implies that something should be done (cleanup, refactoring,
  etc), but is expected to be functional.
- FIXME(name): implies that the method/function/etc shouldn't be used until
  that code is resolved and bug fixed.


Logging
-------

Use the common logging module, and ensure you ``getLogger``::

    from oslo_log import log

    LOG = log.getLogger(__name__)

    LOG.debug('Foobar')

AssertEqual argument order
--------------------------

assertEqual method's arguments should be in ('expected', 'actual') order.


Properly Calling Callables
--------------------------

Methods, functions and classes can specify optional parameters (with default
values) using Python's keyword arg syntax. When providing a value to such a
callable we prefer that the call also uses keyword arg syntax. For example::

    def f(required, optional=None):
        pass

    # GOOD
    f(0, optional=True)

    # BAD
    f(0, True)

This gives us the flexibility to re-order arguments and more importantly
to add new required arguments. It's also more explicit and easier to read.


Creating unit tests
-------------------

For every new feature, unit tests should be created that both test and
(implicitly) document the usage of said features. If submitting a patch for a
bug that had no unit test, a new passing unit test should be added. If a
submitted bug fix does have a unit test, be sure to add a new one that fails
without the patch and passes with the patch.

All unittest classes must ultimately inherit from testtools.TestCase. In the
sysinv test suite, this should be done by inheriting from
sysinv.tests.base.TestCase.
