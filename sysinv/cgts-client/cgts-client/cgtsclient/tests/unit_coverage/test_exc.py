#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Unit tests for cgtsclient.exc module."""

import unittest

from cgtsclient import exc


class TestBaseException(unittest.TestCase):
    def test_with_message(self):
        e = exc.BaseException("test error")
        self.assertEqual(str(e), "test error")

    def test_without_message(self):
        e = exc.BaseException()
        self.assertIsInstance(str(e), str)


class TestCommandError(unittest.TestCase):
    def test_inherits_base(self):
        self.assertTrue(issubclass(exc.CommandError, exc.BaseException))

    def test_message(self):
        e = exc.CommandError("bad command")
        self.assertEqual(str(e), "bad command")


class TestInvalidEndpoint(unittest.TestCase):
    def test_inherits_base(self):
        self.assertTrue(
            issubclass(exc.InvalidEndpoint, exc.BaseException)
        )


class TestCommunicationError(unittest.TestCase):
    def test_inherits_base(self):
        self.assertTrue(
            issubclass(exc.CommunicationError, exc.BaseException)
        )


class TestHTTPException(unittest.TestCase):
    def test_default_code(self):
        e = exc.HTTPException("detail msg")
        self.assertEqual(e.code, "N/A")
        self.assertIn("detail msg", str(e))

    def test_no_details(self):
        e = exc.HTTPException()
        result = str(e)
        # With no details, str returns "None" or class name
        self.assertIsInstance(result, str)


class TestHTTPStatusCodes(unittest.TestCase):
    def test_bad_request_code(self):
        self.assertEqual(exc.BadRequest.code, 400)

    def test_unauthorized_code(self):
        self.assertEqual(exc.Unauthorized.code, 401)

    def test_forbidden_code(self):
        self.assertEqual(exc.Forbidden.code, 403)

    def test_not_found_code(self):
        self.assertEqual(exc.NotFound.code, 404)

    def test_conflict_code(self):
        self.assertEqual(exc.Conflict.code, 409)

    def test_internal_server_error_code(self):
        self.assertEqual(exc.HTTPInternalServerError.code, 500)

    def test_service_unavailable_code(self):
        self.assertEqual(exc.ServiceUnavailable.code, 503)

    def test_method_not_allowed_code(self):
        self.assertEqual(exc.HTTPMethodNotAllowed.code, 405)

    def test_over_limit_code(self):
        self.assertEqual(exc.OverLimit.code, 413)

    def test_not_implemented_code(self):
        self.assertEqual(exc.HTTPNotImplemented.code, 501)

    def test_bad_gateway_code(self):
        self.assertEqual(exc.HTTPBadGateway.code, 502)

    def test_multiple_choices_code(self):
        self.assertEqual(exc.HTTPMultipleChoices.code, 300)


class TestFromResponse(unittest.TestCase):
    def test_from_response_400(self):
        resp = type("R", (), {"status_code": 400})()
        e = exc.from_response(resp, "bad request")
        self.assertIsInstance(e, exc.BadRequest)

    def test_from_response_404(self):
        resp = type("R", (), {"status_code": 404})()
        e = exc.from_response(resp, "not found")
        self.assertIsInstance(e, exc.NotFound)

    def test_from_response_500(self):
        resp = type("R", (), {"status_code": 500})()
        e = exc.from_response(resp, "server error")
        self.assertIsInstance(e, exc.HTTPInternalServerError)

    def test_from_response_unknown_code(self):
        resp = type("R", (), {"status_code": 418})()
        e = exc.from_response(resp, "teapot")
        self.assertIsInstance(e, exc.HTTPException)

    def test_from_response_status_int(self):
        resp = type("R", (), {"status_int": 401})()
        e = exc.from_response(resp, "unauth")
        self.assertIsInstance(e, exc.Unauthorized)


class TestCgtsclientException(unittest.TestCase):
    def test_default_message(self):
        e = exc.CgtsclientException()
        self.assertIn("unknown exception", str(e).lower())

    def test_custom_message(self):
        class MyExc(exc.CgtsclientException):
            message = "Error: %(detail)s"
        e = MyExc(detail="broken")
        self.assertIn("broken", str(e))

    def test_format_message(self):
        class MyExc(exc.CgtsclientException):
            message = "Error: %(detail)s"
        e = MyExc(detail="broken")
        self.assertIn("broken", e.format_message())

    def test_default_code(self):
        e = exc.CgtsclientException()
        self.assertEqual(e.code, 500)


class TestDerivedExceptions(unittest.TestCase):
    def test_ambiguous_endpoints(self):
        self.assertTrue(
            issubclass(exc.AmbiguousEndpoints, exc.CgtsclientException)
        )

    def test_endpoint_type_not_found(self):
        self.assertTrue(
            issubclass(
                exc.EndpointTypeNotFound,
                exc.CgtsclientException))

    def test_ssl_certificate_validation_error(self):
        self.assertTrue(
            issubclass(
                exc.SslCertificateValidationError,
                exc.CgtsclientException))

    def test_endpoint_exception(self):
        self.assertTrue(
            issubclass(exc.EndpointException, exc.CgtsclientException)
        )

    def test_invalid_attribute(self):
        self.assertTrue(
            issubclass(exc.InvalidAttribute, exc.ClientException)
        )

    def test_invalid_attribute_value(self):
        self.assertTrue(
            issubclass(exc.InvalidAttributeValue, exc.ClientException)
        )

    def test_ambigious_alias(self):
        self.assertIs(exc.AmbigiousAuthSystem, exc.AmbiguousAuthSystem)


if __name__ == "__main__":
    unittest.main()
