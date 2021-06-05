#
# Copyright (c) 2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
Tests for the API /kube_clusters/ methods.
"""

import copy
import mock
import tempfile

from kubernetes.client import Configuration

from sysinv.common import utils
from sysinv.common import kubernetes

from sysinv.tests.api import base
from sysinv.tests.db import base as dbbase


FAKE_CA_CERT = (
    "-----BEGIN CERTIFICATE-----\n"
    "MIIE7TCCAtWgAwIBAgIDAODHMA0GCSqGSIb3DQEBCwUAMB8xEDAOBgNVBAoMB0V0\n"
    "Y2QgQ0ExCzAJBgNVBAMMAmNhMB4XDTIxMDIyMDE0MDcxOFoXDTMxMDIxODE0MDcx\n"
    "OFowHzEQMA4GA1UECgwHRXRjZCBDQTELMAkGA1UEAwwCY2EwggIiMA0GCSqGSIb3\n"
    "DQEBAQUAA4ICDwAwggIKAoICAQDL+NVHmb69Dl+D9M1g0eQa3uq4nThcwQ+gimbU\n"
    "GcBPBJmfDmrKvIxLde8RZ+tR+N77mT76qbHtS2KlYgIALJV0ZhujFzmytQ3r0T54\n"
    "bzrSfczfvQ5zx8kGc6KWmvi86VeuX26tEuN4Kklg1Lljrl9RJ3JJ7ck6Q92wVO1U\n"
    "kQmIWUZWclEOSBQbEj1p5CDZIRxf6ZIE57f1FoFzk9MaVVAOwZKgPiN5XSsHRmRT\n"
    "3igMP/X/seZQ7q8+Bg1pGxOwCGhxnxHGTzKXTE5VNXnLH2SYfm/RBrn3FxTE2Rp7\n"
    "hAjEnt+XZxw4Eju8oNahnIGVb0JWy1gJ6RMgtyQWs1cky7DfDQiF8RmciLuTx4Gy\n"
    "81W5RSelQDqrIQueBJrHBNF1nR7F9lu2+51ZgWeqdqLEwFzyjOFDem6vpskzMO75\n"
    "EwZMJlWi3ez/xdkYKqg38QKZRfRiIeoi8BbV4wnSXqyxBJ/DZ1NAwbumbP/GRU7j\n"
    "m6RS5wlMznwg55pXpiWLDFmJ7YFu+LU1WxYicE4qjPMYBn0OcMR4b8n/f5vGLd9O\n"
    "ZPzTLIt5B+9NqMpqoFePsS4anFFJvvhVEK4WwEFsmdii76bv7pYCBftlsEK7o1Mc\n"
    "6YFGoTpNZyDA9BFTp0CB7WArQDxQHikDLQzwpqwVZOjcJQN7Rzf0X4bHtW5NdgMJ\n"
    "NIhDCwIDAQABozIwMDANBgNVHREEBjAEggJjYTALBgNVHQ8EBAMCAoQwEgYDVR0T\n"
    "AQH/BAgwBgEB/wIBATANBgkqhkiG9w0BAQsFAAOCAgEAuKu0XyKN9ZKHT1KvP1uc\n"
    "tzChXkeqQ47ciUbUvM56XvcaoB/4/VMax/2RuNBjC7XqXM+FkwZMBHnmU+hxcZ/Z\n"
    "evbF46y/puGqgDFgRKb4iSfo9JxnU5wsMX5lPwlYEuRmbJjyFvDNZdseNtH3Ws/4\n"
    "iQUGaiHl9HfOePQlb9QDprbRu/Dp6iE6Wai5fuURIXtB9PP5OD2q333vpYolmXXa\n"
    "e9ybwYD8E1X8MLQV0Irh/dJ+5T/eqtWUrZ2YhpCuAawGU35L/1ZqDT4rXW40BcoP\n"
    "cYSSr4ryWKGynYGjrnu2EnxHkYqIsgMDS/Jq8CjrZLpZ4E4TagXoZhIOa5Y3Yq9p\n"
    "yEH4zskY30BUoP7h8Bp7hZIIJ1LyI1F04mukJdHdVH89mhIkU5RuIOJoiBPOMkQw\n"
    "GmRIG8IYQMFxplwtebQrQpE6lnnIE2EdUxxqtpqAqPxnRf6LQg/gtjlGRotKiI9D\n"
    "6ypovjCQi49X4WBjiBFnrgma9MsFL2ZOJPX6XpGZ6jqBTAtVMcdb+hsZQMm8/M2Z\n"
    "QITmxBO+A1hkXGjofbo145omm5qFcWmbvvrnviv3iShEsCoIFpFnGf8RvWwNapeN\n"
    "W4WzyAwY1pQs7Er2KEixiPG7BGaC7KUD3l1kB/IeF0rpnO8rmW/Hq23eLRqtk7mF\n"
    "8M4zFA2c4PFD35Vu9ERU20E=\n"
    "-----END CERTIFICATE-----\n")
FAKE_CLIENT_CERT = (
    "-----BEGIN CERTIFICATE-----\n"
    "MIID/DCCAeSgAwIBAgIIRdk0W8Cf6RkwDQYJKoZIhvcNAQELBQAwHzEQMA4GA1UE\n"
    "CgwHRXRjZCBDQTELMAkGA1UEAwwCY2EwHhcNMjEwMjIwMTQwNzE4WhcNMjIwMjIw\n"
    "MTQyMzU4WjA0MRcwFQYDVQQKEw5zeXN0ZW06bWFzdGVyczEZMBcGA1UEAxMQa3Vi\n"
    "ZXJuZXRlcy1hZG1pbjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJ5x\n"
    "iFIxCMDtmbbkmuxPidugAOhcq8KQ7W7xiFKxzzyxEzOyoK3zsyL+vaMKSrq19Tc+\n"
    "bFcdm/zLPPS4RtjmUK5VP0Z5dA6a06PHlXJ/CMlZIHIQJolGYfYDg4Ky7oYFQ/KP\n"
    "4rtVGvyV7mSdhBdKIelgZ/45zyy10leq2oAWChi9P7kNX2pbwBxgLu1yCuz0f9d1\n"
    "hyx+hm11RDpUJKsbqNzgvP9nJUiSIbfcNAv7ut5RcC/mpITBdyiCnMMs6DvpC3ao\n"
    "xKTks2XWpxgK3Ay1LYjkpaqtMuYK3dGps0Au5b/fSUlJqfzbD0I6wmZYlZK/x/E9\n"
    "+aAALAceGudvBovWxW0CAwEAAaMnMCUwDgYDVR0PAQH/BAQDAgWgMBMGA1UdJQQM\n"
    "MAoGCCsGAQUFBwMCMA0GCSqGSIb3DQEBCwUAA4ICAQCkVUfWJ/sHdKN++Uaw+wu2\n"
    "GFtBnk50btuKcB9vf9fGJK7LHWI5xSMs0kiCXHi3tpa/LvWj0FFWZZ/2fwaV/hfM\n"
    "VJUk0pF2Xjp9IuzFcI/SJWROX/TmZUxFSUL1LMaojdbLqPmIcBRJE9Kd/f0+hmtt\n"
    "2v9o8E52F8pTSG98dGAvWBfsaktiUos2FbYAJE2UKX5dTnLBLJws55xHx5isHkb5\n"
    "I8wb+NbSlKq2Hs4oR0SAjCo+2P+Ej3YblwitPkhV7AkzljHdyKr/f+QT29qgYrW2\n"
    "qi7Ftg/9fBsiiCLjLp+DJrfJQR1YnTVuhv8PCTO46IFzT3zxVe/A3EnKj/kps2y8\n"
    "qeMeDHvxEACoSXQoE2yZVyCKqp1FEjawXeAS3QAicFdoSAjhC5FSTnRs28UE6tXB\n"
    "VqWUUG0FY2/zwswAfIktClJ492utO0HBJt76HcRfR1699Qmfx6fLFKQUDM6fxJk6\n"
    "79QI3S2s3eiCwiPtHOUAz7LC5KV6c75Yq+LABY9eN5K4EI6fuD8cEhfDj3iBb3bB\n"
    "0jJp0bFsCpD90Nrx253XiVesHiKhLlvnNUVuAylDcvwt8xVv+uuBl4kpVv4kkyT/\n"
    "ApqqvGKcUwQp9jIdY9nSZ/SZRW8QFzf404UVeiH+Ruu6+CCqh2PLAtDnSCPVRt1e\n"
    "O+hShAzOqQGF72F6XYlx/g==\n"
    "-----END CERTIFICATE-----\n")
FAKE_CLIENT_KEY = (
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIEpAIBAAKCAQEAnnGIUjEIwO2ZtuSa7E+J26AA6FyrwpDtbvGIUrHPPLETM7Kg\n"
    "rfOzIv69owpKurX1Nz5sVx2b/Ms89LhG2OZQrlU/Rnl0DprTo8eVcn8IyVkgchAm\n"
    "iUZh9gODgrLuhgVD8o/iu1Ua/JXuZJ2EF0oh6WBn/jnPLLXSV6ragBYKGL0/uQ1f\n"
    "alvAHGAu7XIK7PR/13WHLH6GbXVEOlQkqxuo3OC8/2clSJIht9w0C/u63lFwL+ak\n"
    "hMF3KIKcwyzoO+kLdqjEpOSzZdanGArcDLUtiOSlqq0y5grd0amzQC7lv99JSUmp\n"
    "/NsPQjrCZliVkr/H8T35oAAsBx4a528Gi9bFbQIDAQABAoIBAQCJzUZ57ammWj/x\n"
    "oJvZYUgOGvgPH+JG41ONxUYCXiFWsM95jCdRg33Otu3qKl5aSz0Noh4KGnd7gqvu\n"
    "T4NWy+Fp7jyNJ763oRLnBAPHxBK5Q+oDKmbJx8wVcnLjronjSBsTkO7qbRd+jUv8\n"
    "eD7VHqWl2zI3GsJEKZLaqn9FHWYEot2s17obd//4lJPcBg6kGhHDGkJFm7xvVELa\n"
    "VXCIN1E9bAoIgv3pie+O53FH0YoXptvYG4F+ffHGk8/cbdcBJ4oLJqF2mJiwuBbf\n"
    "GYa5T/rIoPkrnc+kmGcePC6pPjPxttHvyaWIDQZj4Jcy4oz6tzFUF0oEZ2/JfMBt\n"
    "Il13gqylAoGBAMU/oaxXHM//NRQqMlL9R8LYLcnze2rnqt+T0ORUZQGETSSXaTxv\n"
    "I4T2wyy9yB583RDVJNXp4T3Js2XnweNj8pRRsCjxY1lkpSOaLVqAw/1HwK1DOSEG\n"
    "EqW8s37YOPZWGAYIhpfEbD5y960JUjVsuW71w/5cDWkoi1eyeFVbuXg7AoGBAM2i\n"
    "+0A6IrZsy/oIJoF8xmOEH78zEMv8W6Qmfb24N0hdcaFJnM48aF50wk8+/YgMNI7J\n"
    "kKR7JJAIQmIFn8tYji9zeeRny4iAclRb6ecglCspvxLzF7tci3ae1snaOFs2wz6b\n"
    "MkLSfb4nNf2u3dsJ2Z0tU8Tb7pxCDH/yEjCRA4Z3AoGAM/T58jqUFVnlMmWXEfMz\n"
    "puhoz0x6kwNpKDF4kdyFKqwd4eicSNYBpjGV4cAv6Y/8b0WlyU8tDKiHv+0XTn1y\n"
    "VY1a+L307IQtV75x+ef3OE1hPIJ7lu5RlSSqp1vvTTwKYfR2950+4ghIo2TUKcx0\n"
    "3/yO3v6CbdPHOJeDSQC7TycCgYEAq61XyaU/ecGXAaVwUEaVclvKDVxat5J2B7NC\n"
    "4vM65CVvSlIkoWF5WPJtjq9uBvj5oAPTyB4uxji/Awri/2dtPVxQ9UlaeRmTWa5q\n"
    "ttVSHj76EJ32wCthG6U8eMTArBYqJsh2y6bj567gumwVOFse3MQM3ZsnuDjEKsU0\n"
    "Pmuy370CgYAULotjgbSNBZcJu2a2urX+vtjPwpGSsiKYdVHBvspcwWcu8YaaeAde\n"
    "71781PJbFV7v45nT2thc+w9IYemXATH/cOO+JVUMYqZY0c+AOa8bvjnMY5Z6cS6Y\n"
    "WJC6NHVmvvFb1YhXjQz2GA9GGBmx9+5/vaPp4aPp+VMfdt9MkEV/NQ==\n"
    "-----END RSA PRIVATE KEY-----\n")
FAKE_TOKEN = (
    "ZXlKaGJHY2lPaUpTVXpJMU5pSXNJbXRwWkNJNklpMXpXRFZyUkVreFZqQTVUVTVU"
    "UmtOSFVuQTBVSE5PVTNWdlJFaG1RM1ozT1VGMU1UbGZZemhtVFZraWZRLmV5SnBj"
    "M01pT2lKcmRXSmxjbTVsZEdWekwzTmxjblpwWTJWaFkyTnZkVzUwSWl3aWEzVmla"
    "WEp1WlhSbGN5NXBieTl6WlhKMmFXTmxZV05qYjNWdWRDOXVZVzFsYzNCaFkyVWlP"
    "aUpyZFdKbExYTjVjM1JsYlNJc0ltdDFZbVZ5Ym1WMFpYTXVhVzh2YzJWeWRtbGpa"
    "V0ZqWTI5MWJuUXZjMlZqY21WMExtNWhiV1VpT2lKcmRXSmxjbTVsZEdWekxXRmti"
    "V2x1TFhSdmEyVnVMVFIyYzNCdElpd2lhM1ZpWlhKdVpYUmxjeTVwYnk5elpYSjJh"
    "V05sWVdOamIzVnVkQzl6WlhKMmFXTmxMV0ZqWTI5MWJuUXVibUZ0WlNJNkltdDFZ"
    "bVZ5Ym1WMFpYTXRZV1J0YVc0aUxDSnJkV0psY201bGRHVnpMbWx2TDNObGNuWnBZ"
    "MlZoWTJOdmRXNTBMM05sY25acFkyVXRZV05qYjNWdWRDNTFhV1FpT2lJMFlURm1a"
    "VEpqTlMweU5qQTJMVFJoWWpRdFlqTXlNUzB5TjJWak1HRXdZVFkyTnpnaUxDSnpk"
    "V0lpT2lKemVYTjBaVzA2YzJWeWRtbGpaV0ZqWTI5MWJuUTZhM1ZpWlMxemVYTjBa"
    "VzA2YTNWaVpYSnVaWFJsY3kxaFpHMXBiaUo5LlhyRU5hNXI5SXRwOGJjM25aMVZo"
    "ZkJlUEFaQ1l2dU5oUVFLYVhNWXlLVjZmQXFiSENIQi1kVnJUYXcxbWs5YXdIQmVz"
    "MXhKUFliVHdzU2dacTZkdFlLYjZuY2RGUUpCYjM2aGJ0NnJ4WnJsZlNYRzFVS2xy"
    "MlQ4ZW1KaFVCV3hFSzVXazRLU1ZobnVBcmJDLUU3MDNTd0hVdEU2UUhDWkRGTWFk"
    "QUoyajJDNmo2RktoLXIwUWpfQ1I4TzBVUTF4c0I0YW9ZS05rUGUxeFJZSVZKUTFW"
    "TjlFdkFaa3lUUFhORDhpUV9hQVFuSlBfUFlCS09OLTAyTnZOY3llVjZ1LWNzdzI3"
    "NVAyYXJIeGdLLXZrMG5Ec1FkTkR5S3hBY2t3Skc3bkVyVmJkNVJoY2JiN2gwX2Jx"
    "dmt4QnJmaEJ5STE4c3k1WFdQTGE4cThIVVE3d092RlpXUQ==")

FAKE_CLUSTER_VERSION = "v1.18.1"
FAKE_API_ENDPOINT = "https://localhost:6443"

FAKE_CLUSTER = {
    "cluster_name": kubernetes.KUBERNETES_CLUSTER_DEFAULT,
    "cluster_version": FAKE_CLUSTER_VERSION,
    "cluster_api_endpoint": FAKE_API_ENDPOINT,
    "cluster_ca_cert": FAKE_CA_CERT,
    "admin_client_cert": FAKE_CLIENT_CERT,
    "admin_client_key": FAKE_CLIENT_KEY,
    "admin_user": kubernetes.KUBERNETES_ADMIN_USER,
    "admin_token": FAKE_TOKEN
}


class TestKubeCluster(base.FunctionalTest):

    def setUp(self):
        super(TestKubeCluster, self).setUp()

        self.ssl_ca_file = self._create_temp_file(FAKE_CA_CERT)
        self.cert_file = self._create_temp_file(FAKE_CLIENT_CERT)
        self.key_file = self._create_temp_file(FAKE_CLIENT_KEY)

        def mock_kube_get_kubernetes_version(obj):
            return FAKE_CLUSTER_VERSION
        self.mocked_kube_get_kubernetes_version = mock.patch(
            'sysinv.common.kubernetes.KubeOperator.kube_get_kubernetes_version',
            mock_kube_get_kubernetes_version)
        self.mocked_kube_get_kubernetes_version.start()

        def mock_kube_get_kubernetes_config(obj):
            config = Configuration()
            config.host = FAKE_API_ENDPOINT
            config.ssl_ca_cert = self.ssl_ca_file.name
            config.cert_file = self.cert_file.name
            config.key_file = self.key_file.name
            return config
        self.mocked_kube_get_kubernetes_config = mock.patch(
            'sysinv.common.kubernetes.KubeOperator.kube_get_kubernetes_config',
            mock_kube_get_kubernetes_config)
        self.mocked_kube_get_kubernetes_config.start()

        def mock_kube_get_service_account_token(obj, name, namespace):
            return FAKE_TOKEN
        self.mocked_kube_get_service_account_token = mock.patch(
            'sysinv.common.kubernetes.KubeOperator.kube_get_service_account_token',
            mock_kube_get_service_account_token)
        self.mocked_kube_get_service_account_token.start()

    def tearDown(self):
        super(TestKubeCluster, self).tearDown()
        self.ssl_ca_file.close()
        self.cert_file.close()
        self.key_file.close()
        self.mocked_kube_get_kubernetes_version.stop()
        self.mocked_kube_get_kubernetes_config.stop()
        self.mocked_kube_get_service_account_token.stop()

    def _get_cluster_api_endpoint(self):
        endpoint_host = utils.format_url_address(self.oam_subnet[2])
        return "https://{}:6443".format(endpoint_host)

    def _create_temp_file(self, content):
        fp = tempfile.NamedTemporaryFile()
        fp.write(str.encode(content))
        fp.seek(0)
        return fp


class TestListKubeCluster(TestKubeCluster,
                          dbbase.ControllerHostTestCase):

    def test_list_cluster(self):

        fake_cluster = copy.deepcopy(FAKE_CLUSTER)

        # update the expected cluster_api_endpoint
        fake_cluster['cluster_api_endpoint'] = \
            self._get_cluster_api_endpoint()

        fake_clusters = [fake_cluster]

        result = self.get_json('/kube_clusters')

        self.assertEqual(len(fake_clusters), len(result['kube_clusters']))
        for index, cluster in enumerate(result['kube_clusters']):
            fake_cluster = fake_clusters[index]
            for key, value in fake_cluster.items():
                self.assertEqual(cluster[key], value)


class TestGetKubeCluster(TestKubeCluster,
                         dbbase.ControllerHostTestCase):

    def test_get_cluster(self):
        fake_cluster = copy.deepcopy(FAKE_CLUSTER)

        # update the expected cluster_api_endpoint
        fake_cluster['cluster_api_endpoint'] = \
            self._get_cluster_api_endpoint()

        result = self.get_json('/kube_clusters/%s' %
            kubernetes.KUBERNETES_CLUSTER_DEFAULT)

        for key, value in fake_cluster.items():
            self.assertEqual(result[key], value)


class TestIpv4ListKubeCluster(TestListKubeCluster):
    pass


class TestIpv6ListKubeCluster(dbbase.BaseIPv6Mixin,
                              TestListKubeCluster):
    pass


class TestIpv4GetKubeCluster(TestGetKubeCluster):
    pass


class TestIpv6GetKubeCluster(dbbase.BaseIPv6Mixin,
                             TestGetKubeCluster):
    pass
