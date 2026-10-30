# vim: tabstop=4 shiftwidth=4 softtabstop=4
# coding=utf-8

# Copyright (c) 2019, 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""Test class for Sysinv Kube App Image Parser."""

import copy
import io
import os
import mock

from sysinv.conductor import kube_app
from sysinv.common import constants
from sysinv.common.utils import get_debian_codename
from sysinv.common.utils import is_debian_bullseye
from sysinv.tests import base

codename = get_debian_codename()

# Import ruamel.yaml based on Debian version
if codename == constants.OS_DEBIAN_BULLSEYE:
    import ruamel.yaml as yaml
else:
    from ruamel.yaml import YAML

IMAGES_RESOURCE = {
    'images': {
        'tags': {
            'ks_service': 'docker.io/openstackhelm/heat:ocata',
            'cinder_db_sync': 'docker.io/openstackhelm/cinder:ocata',
            'db_drop': 'docker.io/openstackhelm/heat:ocata',
            'image_local_sync': None
        }
    },
    'Images': {
        'Tsyncd': 'quay.io/silicom/tsyncd:2.1.3.6',
        'Phc2Sys': 'quay.io/silicom/phc2sys:3.1-00193-g6bac465',
        'GrpcTsyncd': 'quay.io/silicom/grpc-tsyncd:2.1.2.18',
        'Gpsd': 'quay.io/silicom/gpsd:3.23.1'
    },
    'controller': {
        'imageTag': '0.23.0',
        'image': 'quay.io/kubernetes-ingress-controller/nginx-ingress-controller'
    },
    'defaultBackend': {
        'image': None,
        'tag': None
    },
    'exporter': {
        'logstash': {
            'test': {
                'image': 'docker.elastic.co/logstash/logstash-oss',
                'imagetag': '7.2.0'
            },
        }
    },
    'extraInitContainers': {
        'limitset': {
            'image': 'docker.elastic.co/beats/filebeat-oss:7.4.0'
        }
    },
    'openstack': {
        'images': {
            'ks_service': 'docker.io/starlingx/stx-heat:master-centos-stable-latest',
            'db_drop': 'docker.io/starlingx/stx-heat:master-centos-stable-latest',
            "image_repo_sync'": None,
            'bootstrap': 'docker.io/starlingx/stx-heat:master-centos-stable-latest',
        },
        'bootstrap': {
            'structured': {
                'images': {
                    'cirros': {
                        'properties': {
                            'os_distro': 'docker.io/cirros'
                        },
                        'name': 'docker.io/Cirros 0.3.5 64-bit',
                        'image_type': 'docker.io/qcow2',
                        'container_format': 'docker.io/bare',
                        'private': True,
                        'source_url': 'http://download.cirros-cloud.net/0.3.5/',
                        'min_disk': 1,
                        'image_file': 'cirros-0.3.5-x86_64-disk.img',
                        'id': None
                    }
                }
            }
        },
        'conf': {
            'api_audit_map': {
                'service_endpoints': {
                    'image': 'docker.io/service/storage/image'
                }
            }
        }
    },
    'image': {
        'tag': '7.4.0',
        'repository': 'docker.elastic.co/elasticsearch/elasticsearch-oss'
    },
    'metricsServer': {
        'image': {
            'registry': 'k8s.gcr.io',
            'repository': 'metrics-server/metrics-server',
            'tag': '0.6.1'
        }
    }
}


class TestKubeAppImageParser(base.TestCase):

    def setUp(self):
        super(TestKubeAppImageParser, self).setUp()
        self.image_parser = kube_app.AppImageParser()

    def test_find_images_in_dict(self):
        yaml_file = os.path.join(os.path.dirname(__file__),
                                 "data", "chart_values_sample.yaml")
        with io.open(yaml_file, 'r', encoding='utf-8') as f:
            if is_debian_bullseye():
                values = yaml.safe_load(f)
            else:
                local_yaml = YAML()
                values = local_yaml.load(f)

        expected = copy.deepcopy(IMAGES_RESOURCE)
        expected['monitoring'] = {'image': {'repository': 'docker.io/trustpilot/beat-exporter'}}
        expected['testFramework'] = {'tag': '0.4.0'}
        images_dict = self.image_parser.find_images_in_dict(values)
        self.assertEqual(expected, images_dict)

    def test_update_images_with_local_registry(self):
        images_dict = copy.deepcopy(IMAGES_RESOURCE)

        expected = {
            'images': {
                'tags': {
                    'ks_service': 'registry.local:9001/docker.io/openstackhelm/heat:ocata',
                    'cinder_db_sync': 'registry.local:9001/docker.io/openstackhelm/cinder:ocata',
                    'db_drop': 'registry.local:9001/docker.io/openstackhelm/heat:ocata',
                    'image_local_sync': None
                }
            },
            'Images': {
                'Tsyncd': 'registry.local:9001/quay.io/silicom/tsyncd:2.1.3.6',
                'Phc2Sys': 'registry.local:9001/quay.io/silicom/phc2sys:3.1-00193-g6bac465',
                'GrpcTsyncd': 'registry.local:9001/quay.io/silicom/grpc-tsyncd:2.1.2.18',
                'Gpsd': 'registry.local:9001/quay.io/silicom/gpsd:3.23.1'
            },
            'controller': {
                'imageTag': '0.23.0',
                'image': 'registry.local:9001/quay.io/kubernetes-ingress-controller/nginx-ingress-controller'
            },
            'defaultBackend': {
                'image': None,
                'tag': None
            },
            'exporter': {
                'logstash': {
                    'test': {
                        'image': 'registry.local:9001/docker.elastic.co/logstash/logstash-oss',
                        'imagetag': '7.2.0'
                    },
                }
            },
            'extraInitContainers': {
                'limitset': {
                    'image': 'registry.local:9001/docker.elastic.co/beats/filebeat-oss:7.4.0'
                }
            },
            'openstack': {
                'images': {
                    'ks_service': 'registry.local:9001/docker.io/starlingx/stx-heat:master-centos-stable-latest',
                    'db_drop': 'registry.local:9001/docker.io/starlingx/stx-heat:master-centos-stable-latest',
                    "image_repo_sync'": None,
                    'bootstrap': 'registry.local:9001/docker.io/starlingx/stx-heat:master-centos-stable-latest',
                },
                'bootstrap': {
                    'structured': {
                        'images': {
                            'cirros': {
                                'properties': {
                                    'os_distro': 'registry.local:9001/docker.io/cirros'
                                },
                                'name': 'registry.local:9001/docker.io/Cirros 0.3.5 64-bit',
                                'image_type': 'registry.local:9001/docker.io/qcow2',
                                'container_format': 'registry.local:9001/docker.io/bare',
                                'private': True,
                                'source_url': 'http://download.cirros-cloud.net/0.3.5/',
                                'min_disk': 1,
                                'image_file': 'registry.local:9001/cirros-0.3.5-x86_64-disk.img',
                                'id': None
                            }
                        }
                    }
                },
                'conf': {
                    'api_audit_map': {
                        'service_endpoints': {
                            'image': 'registry.local:9001/docker.io/service/storage/image'
                        }
                    }
                }
            },
            'image': {
                'tag': '7.4.0',
                'repository': 'registry.local:9001/docker.elastic.co/elasticsearch/elasticsearch-oss'
            },
            'metricsServer': {
                'image': {
                    'registry': 'registry.local:9001/k8s.gcr.io',
                    'repository': 'metrics-server/metrics-server',
                    'tag': '0.6.1'
                }
            }
        }

        images_dict_with_local_registry = \
           self.image_parser.update_images_with_local_registry(images_dict)
        self.assertEqual(expected, images_dict_with_local_registry)

    def test_generate_download_images_with_merge_dict(self):
        chart_imgs = copy.deepcopy(IMAGES_RESOURCE)

        override_imgs = {
            'images': {
                'tags': {
                    'cinder_db_sync': 'docker.io/starlingx/stx-cinder:latest'
                }
            },
            'Images': {
                'Tsyncd': 'quay.io/silicom/tsyncd:2.1.3.6',
                'Phc2Sys': 'quay.io/silicom/phc2sys:3.1-00193-g6bac465',
                'GrpcTsyncd': 'quay.io/silicom/grpc-tsyncd:2.1.2.18',
                'Gpsd': 'quay.io/silicom/gpsd:3.23.1'
            },
            'extraInitContainers': {
                'limitset': {
                    'image': 'docker.elastic.co/beats/filebeat-oss:7.5.1'
                }
            },
            'testFramework': {
                'image': 'docker.io/dduportal/bats',
                'imageTag': '7.2.0'
            },
            'openstack': {
                'images': {
                    'bootstrap': 'docker.io/starlingx/stx-heat:master-centos-dev-latest'
                }
            },
            'image': {
                'tag': '7.5.2'
            }
        }

        expected = {
            'images': {
                'tags': {
                    'ks_service': 'docker.io/openstackhelm/heat:ocata',
                    'cinder_db_sync': 'docker.io/starlingx/stx-cinder:latest',
                    'db_drop': 'docker.io/openstackhelm/heat:ocata',
                    'image_local_sync': None
                }
            },
            'Images': {
                'Tsyncd': 'quay.io/silicom/tsyncd:2.1.3.6',
                'Phc2Sys': 'quay.io/silicom/phc2sys:3.1-00193-g6bac465',
                'GrpcTsyncd': 'quay.io/silicom/grpc-tsyncd:2.1.2.18',
                'Gpsd': 'quay.io/silicom/gpsd:3.23.1'
            },
            'controller': {
                'imageTag': '0.23.0',
                'image': 'quay.io/kubernetes-ingress-controller/nginx-ingress-controller'
            },
            'defaultBackend': {
                'image': None,
                'tag': None
            },
            'exporter': {
                'logstash': {
                    'test': {
                        'image': 'docker.elastic.co/logstash/logstash-oss',
                        'imagetag': '7.2.0'
                    },
                }
            },
            'extraInitContainers': {
                'limitset': {
                    'image': 'docker.elastic.co/beats/filebeat-oss:7.5.1'
                }
            },
            'testFramework': {
                'image': 'docker.io/dduportal/bats',
                'imageTag': '7.2.0'
            },
            'openstack': {
                'images': {
                    'ks_service': 'docker.io/starlingx/stx-heat:master-centos-stable-latest',
                    'db_drop': 'docker.io/starlingx/stx-heat:master-centos-stable-latest',
                    "image_repo_sync'": None,
                    'bootstrap': 'docker.io/starlingx/stx-heat:master-centos-dev-latest',
                },
                'bootstrap': {
                    'structured': {
                        'images': {
                            'cirros': {
                                'properties': {
                                    'os_distro': 'docker.io/cirros'
                                },
                                'name': 'docker.io/Cirros 0.3.5 64-bit',
                                'image_type': 'docker.io/qcow2',
                                'container_format': 'docker.io/bare',
                                'private': True,
                                'source_url': 'http://download.cirros-cloud.net/0.3.5/',
                                'min_disk': 1,
                                'image_file': 'cirros-0.3.5-x86_64-disk.img',
                                'id': None
                            }
                        }
                    }
                },
                'conf': {
                    'api_audit_map': {
                        'service_endpoints': {
                            'image': 'docker.io/service/storage/image'
                        }
                    }
                }
            },
            'image': {
                'tag': '7.5.2',
                'repository': 'docker.elastic.co/elasticsearch/elasticsearch-oss'
            },
            'metricsServer': {
                'image': {
                    'registry': 'k8s.gcr.io',
                    'repository': 'metrics-server/metrics-server',
                    'tag': '0.6.1'
                }
            }
        }

        download_imgs_dict = self.image_parser.merge_dict(
            chart_imgs, override_imgs)
        self.assertEqual(expected, download_imgs_dict)

    def test_generate_download_images_list(self):
        download_imgs_dict = copy.deepcopy(IMAGES_RESOURCE)
        download_imgs_dict['image']['tag'] = None

        expected = [
            'docker.io/openstackhelm/cinder:ocata',
            'quay.io/kubernetes-ingress-controller/nginx-ingress-controller:0.23.0',
            'docker.io/openstackhelm/heat:ocata',
            'docker.elastic.co/beats/filebeat-oss:7.4.0',
            'docker.elastic.co/logstash/logstash-oss:7.2.0',
            'quay.io/silicom/tsyncd:2.1.3.6',
            'quay.io/silicom/phc2sys:3.1-00193-g6bac465',
            'quay.io/silicom/grpc-tsyncd:2.1.2.18',
            'quay.io/silicom/gpsd:3.23.1',
            'docker.io/starlingx/stx-heat:master-centos-stable-latest',
            'k8s.gcr.io/metrics-server/metrics-server:0.6.1'
        ]

        download_imgs_list = self.image_parser.generate_download_images_list(
            download_imgs_dict, [])
        self.assertEqual(set(expected), set(download_imgs_list))

    # Structure where sidecar images are nested inside the 'image' section
    # (second level or deeper), as used by the upstream topolvm chart:
    #   image:
    #     repository: <str>
    #     tag: <str>
    #     csi:
    #       csiResizer: <registry/repo:tag string>
    #       ...
    NESTED_IMAGE_RESOURCE = {
        'image': {
            'repository': 'ghcr.io/topolvm/topolvm-with-sidecar',
            'tag': '0.40.1',
            'csi': {
                'nodeDriverRegistrar':
                    'registry.k8s.io/sig-storage/csi-node-driver-registrar:v2.2.0',
                'csiProvisioner':
                    'registry.k8s.io/sig-storage/csi-provisioner:v2.2.1',
                'csiResizer':
                    'registry.k8s.io/sig-storage/csi-resizer:v1.2.0',
                'csiSnapshotter':
                    'registry.k8s.io/sig-storage/csi-snapshotter:v5.0.1',
                'livenessProbe':
                    'registry.k8s.io/sig-storage/livenessprobe:v2.3.0',
            }
        }
    }

    def test_find_images_nested_within_image(self):
        var_dict = copy.deepcopy(self.NESTED_IMAGE_RESOURCE)

        expected = {
            'image': {
                'repository': 'ghcr.io/topolvm/topolvm-with-sidecar',
                'tag': '0.40.1',
                'csi': {
                    'nodeDriverRegistrar':
                        'registry.k8s.io/sig-storage/csi-node-driver-registrar:v2.2.0',
                    'csiProvisioner':
                        'registry.k8s.io/sig-storage/csi-provisioner:v2.2.1',
                    'csiResizer':
                        'registry.k8s.io/sig-storage/csi-resizer:v1.2.0',
                    'csiSnapshotter':
                        'registry.k8s.io/sig-storage/csi-snapshotter:v5.0.1',
                    'livenessProbe':
                        'registry.k8s.io/sig-storage/livenessprobe:v2.3.0',
                }
            }
        }

        images_dict = self.image_parser.find_images_in_dict(var_dict)
        self.assertEqual(expected, images_dict)

    def test_generate_download_images_list_nested_within_image(self):
        download_imgs_dict = copy.deepcopy(self.NESTED_IMAGE_RESOURCE)

        expected = [
            'ghcr.io/topolvm/topolvm-with-sidecar:0.40.1',
            'registry.k8s.io/sig-storage/csi-node-driver-registrar:v2.2.0',
            'registry.k8s.io/sig-storage/csi-provisioner:v2.2.1',
            'registry.k8s.io/sig-storage/csi-resizer:v1.2.0',
            'registry.k8s.io/sig-storage/csi-snapshotter:v5.0.1',
            'registry.k8s.io/sig-storage/livenessprobe:v2.3.0',
        ]

        download_imgs_list = self.image_parser.generate_download_images_list(
            download_imgs_dict, [])
        self.assertEqual(set(expected), set(download_imgs_list))

    def test_update_images_with_local_registry_nested_within_image(self):
        # The local registry prefix must also be applied to images that
        # are nested within the 'image' section.
        images_dict = copy.deepcopy(self.NESTED_IMAGE_RESOURCE)

        expected = {
            'image': {
                'repository':
                    'registry.local:9001/ghcr.io/topolvm/topolvm-with-sidecar',
                'tag': '0.40.1',
                'csi': {
                    'nodeDriverRegistrar':
                        'registry.local:9001/registry.k8s.io/sig-storage/'
                        'csi-node-driver-registrar:v2.2.0',
                    'csiProvisioner':
                        'registry.local:9001/registry.k8s.io/sig-storage/'
                        'csi-provisioner:v2.2.1',
                    'csiResizer':
                        'registry.local:9001/registry.k8s.io/sig-storage/'
                        'csi-resizer:v1.2.0',
                    'csiSnapshotter':
                        'registry.local:9001/registry.k8s.io/sig-storage/'
                        'csi-snapshotter:v5.0.1',
                    'livenessProbe':
                        'registry.local:9001/registry.k8s.io/sig-storage/'
                        'livenessprobe:v2.3.0',
                }
            }
        }

        result = self.image_parser.update_images_with_local_registry(
            images_dict)
        self.assertEqual(expected, result)

    def test_find_images_nested_within_image_ignores_non_images(self):
        # Non-image string values nested within 'image' (e.g. an app name
        # or hostnames) must NOT be treated as image references.
        var_dict = {
            'image': {
                'repository': 'ghcr.io/topolvm/topolvm-with-sidecar',
                'tag': '0.40.1',
                'name': 'glance',
                'hosts': {
                    'default': 'glance-api',
                    'public': 'glance',
                },
                'csi': {
                    'csiResizer':
                        'registry.k8s.io/sig-storage/csi-resizer:v1.2.0',
                }
            }
        }

        expected = {
            'image': {
                'repository': 'ghcr.io/topolvm/topolvm-with-sidecar',
                'tag': '0.40.1',
                'csi': {
                    'csiResizer':
                        'registry.k8s.io/sig-storage/csi-resizer:v1.2.0',
                }
            }
        }

        images_dict = self.image_parser.find_images_in_dict(var_dict)
        self.assertEqual(expected, images_dict)

    def test_find_images_nested_within_image_with_image_key(self):
        # Sidecar images nested under an explicit 'image' key deeper in the
        # structure must be detected (topolvm 'corrected' layout).
        var_dict = {
            'image': {
                'csi': {
                    'nodeDriverRegistrar': {
                        'image':
                            'registry.k8s.io/sig-storage/'
                            'csi-node-driver-registrar:v2.2.0'
                    },
                    'csiResizer': {
                        'image':
                            'registry.k8s.io/sig-storage/csi-resizer:v1.2.0'
                    },
                }
            }
        }

        expected = {
            'image': {
                'csi': {
                    'nodeDriverRegistrar': {
                        'image':
                            'registry.k8s.io/sig-storage/'
                            'csi-node-driver-registrar:v2.2.0'
                    },
                    'csiResizer': {
                        'image':
                            'registry.k8s.io/sig-storage/csi-resizer:v1.2.0'
                    },
                }
            }
        }

        images_dict = self.image_parser.find_images_in_dict(var_dict)
        self.assertEqual(expected, images_dict)

        download_imgs_list = self.image_parser.generate_download_images_list(
            self.image_parser.find_images_in_dict(var_dict), [])
        self.assertEqual(
            {'registry.k8s.io/sig-storage/csi-node-driver-registrar:v2.2.0',
             'registry.k8s.io/sig-storage/csi-resizer:v1.2.0'},
            set(download_imgs_list))

    def test_find_images_deeply_nested_within_image(self):
        # Images nested three levels deep within 'image' must be detected.
        var_dict = {
            'image': {
                'components': {
                    'group': {
                        'sidecar':
                            'registry.k8s.io/sig-storage/csi-resizer:v1.2.0'
                    }
                }
            }
        }

        expected = {
            'image': {
                'components': {
                    'group': {
                        'sidecar':
                            'registry.k8s.io/sig-storage/csi-resizer:v1.2.0'
                    }
                }
            }
        }

        images_dict = self.image_parser.find_images_in_dict(var_dict)
        self.assertEqual(expected, images_dict)

    def test_find_images_nested_within_image_ignores_empty(self):
        # Unset sidecar entries (None) and non-image strings must be
        # ignored, leaving only the direct repository/tag reference.
        var_dict = {
            'image': {
                'repository': 'ghcr.io/topolvm/topolvm-with-sidecar',
                'tag': '0.40.1',
                'csi': {
                    'csiResizer': None,
                    'csiProvisioner': '',
                }
            }
        }

        expected = {
            'image': {
                'repository': 'ghcr.io/topolvm/topolvm-with-sidecar',
                'tag': '0.40.1',
            }
        }

        images_dict = self.image_parser.find_images_in_dict(var_dict)
        self.assertEqual(expected, images_dict)

    def test_find_images_nested_image_and_tag_within_image(self):
        # Nested group with separate 'image' and 'tag' fields:
        #   image:
        #     <group>:
        #       image: <image>
        #       tag: <tag>
        var_dict = {
            'image': {
                'metricsServer': {
                    'image': 'k8s.gcr.io/metrics-server/metrics-server',
                    'tag': '0.6.1',
                },
                'sidecar': {
                    'image': 'registry.k8s.io/sig-storage/csi-resizer',
                    'imageTag': 'v1.2.0',
                },
            }
        }

        expected = {
            'image': {
                'metricsServer': {
                    'image': 'k8s.gcr.io/metrics-server/metrics-server',
                    'tag': '0.6.1',
                },
                'sidecar': {
                    'image': 'registry.k8s.io/sig-storage/csi-resizer',
                    'imageTag': 'v1.2.0',
                },
            }
        }

        images_dict = self.image_parser.find_images_in_dict(var_dict)
        self.assertEqual(expected, images_dict)

    def test_generate_download_images_list_nested_image_and_tag(self):
        # The download list must combine a nested 'image' with its sibling
        # 'tag'/'imageTag' into a single '<image>:<tag>' reference.
        download_imgs_dict = {
            'image': {
                'metricsServer': {
                    'image': 'k8s.gcr.io/metrics-server/metrics-server',
                    'tag': '0.6.1',
                },
                'sidecar': {
                    'image': 'registry.k8s.io/sig-storage/csi-resizer',
                    'imageTag': 'v1.2.0',
                },
            }
        }

        expected = {
            'k8s.gcr.io/metrics-server/metrics-server:0.6.1',
            'registry.k8s.io/sig-storage/csi-resizer:v1.2.0',
        }

        download_imgs_list = self.image_parser.generate_download_images_list(
            download_imgs_dict, [])
        self.assertEqual(expected, set(download_imgs_list))

    def test_update_images_with_local_registry_nested_image_and_tag(self):
        # A nested group with separate 'image' and 'tag' fields must have
        # its 'image' reference prefixed with the local registry, so the
        # chart pulls it from registry.local instead of the public source.
        images_dict = {
            'image': {
                'metricsServer': {
                    'image': 'k8s.gcr.io/metrics-server/metrics-server',
                    'tag': '0.6.1',
                },
                'sidecar': {
                    'image': 'registry.k8s.io/sig-storage/csi-resizer',
                    'imageTag': 'v1.2.0',
                },
            }
        }

        expected = {
            'image': {
                'metricsServer': {
                    'image':
                        'registry.local:9001/k8s.gcr.io/'
                        'metrics-server/metrics-server',
                    'tag': '0.6.1',
                },
                'sidecar': {
                    'image':
                        'registry.local:9001/registry.k8s.io/'
                        'sig-storage/csi-resizer',
                    'imageTag': 'v1.2.0',
                },
            }
        }

        result = self.image_parser.update_images_with_local_registry(
            images_dict)
        self.assertEqual(expected, result)

    # Per-component 'repository'/'image'/'version' trio. Each component
    # declares its image as three sibling keys rendered by the chart as
    # '<repository>/<image>:<version>'. Components may carry extra,
    # non-image keys (e.g. a component-specific install path) that must be
    # ignored.
    REPO_IMAGE_VERSION_RESOURCE = {
        'operator': {
            'repository': 'example.io/acme',
            'image': 'acme-operator',
            'version': 'v1.2.3',
        },
        'toolkit': {
            'repository': 'example.io/acme/tools',
            'image': 'acme-toolkit',
            'version': 'v4.5.6',
            'installDir': '/var/opt/acme',
        },
        'exporter': {
            'repository': 'example.io/acme/tools',
            'image': 'acme-exporter',
            'version': '7.8.9-distroless',
        },
        # A subchart using the conventional 'image.repository' layout must
        # keep working alongside the trio format.
        'subchart': {
            'image': {
                'repository':
                    'registry.example.io/acme/subchart',
            }
        },
    }

    def test_find_images_repository_image_version_trio(self):
        var_dict = copy.deepcopy(self.REPO_IMAGE_VERSION_RESOURCE)

        expected = {
            'operator': {
                'repository': 'example.io/acme',
                'image': 'acme-operator',
                'version': 'v1.2.3',
            },
            'toolkit': {
                'repository': 'example.io/acme/tools',
                'image': 'acme-toolkit',
                'version': 'v4.5.6',
            },
            'exporter': {
                'repository': 'example.io/acme/tools',
                'image': 'acme-exporter',
                'version': '7.8.9-distroless',
            },
            'subchart': {
                'image': {
                    'repository':
                        'registry.example.io/acme/subchart',
                }
            },
        }

        images_dict = self.image_parser.find_images_in_dict(var_dict)
        self.assertEqual(expected, images_dict)

    def test_update_images_with_local_registry_repo_image_version(self):
        # The local registry prefix must be applied to the 'repository'
        # field of each 'repository'/'image'/'version' trio.
        images_dict = copy.deepcopy(self.REPO_IMAGE_VERSION_RESOURCE)
        # Drop the extra non-image key; only the mined fields are passed to
        # update_images_with_local_registry in practice.
        del images_dict['toolkit']['installDir']

        expected = {
            'operator': {
                'repository': 'registry.local:9001/example.io/acme',
                'image': 'acme-operator',
                'version': 'v1.2.3',
            },
            'toolkit': {
                'repository': 'registry.local:9001/example.io/acme/tools',
                'image': 'acme-toolkit',
                'version': 'v4.5.6',
            },
            'exporter': {
                'repository': 'registry.local:9001/example.io/acme/tools',
                'image': 'acme-exporter',
                'version': '7.8.9-distroless',
            },
            'subchart': {
                'image': {
                    'repository':
                        'registry.local:9001/registry.example.io/acme/'
                        'subchart',
                }
            },
        }

        result = self.image_parser.update_images_with_local_registry(
            images_dict)
        self.assertEqual(expected, result)

    def test_update_images_with_local_registry_repo_image_version_idempotent(self):
        # When the 'repository' already carries the local registry prefix,
        # it must not be duplicated.
        images_dict = {
            'operator': {
                'repository': 'registry.local:9001/example.io/acme',
                'image': 'acme-operator',
                'version': 'v1.2.3',
            },
        }

        expected = copy.deepcopy(images_dict)

        result = self.image_parser.update_images_with_local_registry(
            images_dict)
        self.assertEqual(expected, result)

    def test_generate_download_images_list_repo_image_version(self):
        # Each trio must be assembled into a single
        # '<repository>/<image>:<version>' download reference.
        download_imgs_dict = copy.deepcopy(self.REPO_IMAGE_VERSION_RESOURCE)
        del download_imgs_dict['toolkit']['installDir']

        expected = {
            'example.io/acme/acme-operator:v1.2.3',
            'example.io/acme/tools/acme-toolkit:v4.5.6',
            'example.io/acme/tools/acme-exporter:7.8.9-distroless',
        }

        download_imgs_list = self.image_parser.generate_download_images_list(
            download_imgs_dict, [])
        self.assertEqual(expected, set(download_imgs_list))

    # A 'repository'/'image'/'version' trio may itself contain a nested
    # component declared with the same trio. The nested image must also be
    # mined, prefixed and listed for download; non-image sibling keys
    # (e.g. enabled, imagePullPolicy) must be ignored.
    NESTED_REPO_IMAGE_VERSION_RESOURCE = {
        'component': {
            'enabled': False,
            'repository': 'example.io/acme',
            'image': 'acme-main',
            'version': '1.0.0-build1',
            'imagePullPolicy': 'Always',
            'manager': {
                'repository': 'example.io/acme/extra',
                'image': 'acme-manager',
                'version': 'v0.1.0',
            },
        },
    }

    def test_find_images_nested_repo_image_version_trio(self):
        var_dict = copy.deepcopy(self.NESTED_REPO_IMAGE_VERSION_RESOURCE)

        expected = {
            'component': {
                'repository': 'example.io/acme',
                'image': 'acme-main',
                'version': '1.0.0-build1',
                'manager': {
                    'repository': 'example.io/acme/extra',
                    'image': 'acme-manager',
                    'version': 'v0.1.0',
                },
            },
        }

        images_dict = self.image_parser.find_images_in_dict(var_dict)
        self.assertEqual(expected, images_dict)

    def test_update_images_with_local_registry_nested_trio(self):
        images_dict = copy.deepcopy(self.NESTED_REPO_IMAGE_VERSION_RESOURCE)
        del images_dict['component']['enabled']
        del images_dict['component']['imagePullPolicy']

        expected = {
            'component': {
                'repository': 'registry.local:9001/example.io/acme',
                'image': 'acme-main',
                'version': '1.0.0-build1',
                'manager': {
                    'repository':
                        'registry.local:9001/example.io/acme/extra',
                    'image': 'acme-manager',
                    'version': 'v0.1.0',
                },
            },
        }

        result = self.image_parser.update_images_with_local_registry(
            images_dict)
        self.assertEqual(expected, result)

    def test_generate_download_images_list_nested_trio(self):
        download_imgs_dict = copy.deepcopy(
            self.NESTED_REPO_IMAGE_VERSION_RESOURCE)
        del download_imgs_dict['component']['enabled']
        del download_imgs_dict['component']['imagePullPolicy']

        expected = {
            'example.io/acme/acme-main:1.0.0-build1',
            'example.io/acme/extra/acme-manager:v0.1.0',
        }

        download_imgs_list = self.image_parser.generate_download_images_list(
            download_imgs_dict, [])
        self.assertEqual(expected, set(download_imgs_list))

    def test_update_images_with_local_registry_domainless_repository(self):
        # A repository without a registry host must be qualified with an
        # explicit 'docker.io', matching the string-image behaviour.
        images_dict = {
            'plain': {'repository': 'bitnami', 'image': 'x',
                      'version': '1.0'},
            'org': {'repository': 'myorg/tools', 'image': 'y',
                    'version': '2.0'},
            'host': {'repository': 'example.io/acme', 'image': 'z',
                     'version': '3.0'},
            'port': {'repository': 'example.io:5000/acme', 'image': 'w',
                     'version': '4.0'},
        }
        expected = {
            'plain': {'repository': 'registry.local:9001/docker.io/bitnami',
                      'image': 'x', 'version': '1.0'},
            'org': {'repository': 'registry.local:9001/docker.io/myorg/tools',
                    'image': 'y', 'version': '2.0'},
            'host': {'repository': 'registry.local:9001/example.io/acme',
                     'image': 'z', 'version': '3.0'},
            'port': {'repository':
                     'registry.local:9001/example.io:5000/acme',
                     'image': 'w', 'version': '4.0'},
        }
        result = self.image_parser.update_images_with_local_registry(
            images_dict)
        self.assertEqual(expected, result)

        # Idempotent on a second pass.
        result = self.image_parser.update_images_with_local_registry(result)
        self.assertEqual(expected, result)

    def test_find_images_repo_image_version_partial_not_trio(self):
        # A component with only 'repository'+'image' (no 'version') must NOT
        # be treated as a trio; it falls back to the legacy behaviour where
        # the 'image' string is mined on its own.
        var_dict = {'comp': {'repository': 'r', 'image': 'myimg'}}
        expected = {'comp': {'image': 'myimg'}}
        self.assertEqual(expected,
                         self.image_parser.find_images_in_dict(var_dict))

    # YAML loads unquoted 'version: 2' / 'version: 1.5' as int / float. The
    # trio must still be recognized and the version converted with str().
    NUMERIC_VERSION_RESOURCE = {
        'int_comp': {
            'repository': 'example.io/acme',
            'image': 'acme-int',
            'version': 2,
        },
        'float_comp': {
            'repository': 'example.io/acme',
            'image': 'acme-float',
            'version': 1.5,
        },
    }

    def test_find_images_repo_image_version_numeric_version(self):
        var_dict = copy.deepcopy(self.NUMERIC_VERSION_RESOURCE)
        images_dict = self.image_parser.find_images_in_dict(var_dict)
        self.assertEqual(self.NUMERIC_VERSION_RESOURCE, images_dict)

    def test_update_images_with_local_registry_numeric_version(self):
        images_dict = copy.deepcopy(self.NUMERIC_VERSION_RESOURCE)
        expected = {
            'int_comp': {
                'repository': 'registry.local:9001/example.io/acme',
                'image': 'acme-int',
                'version': 2,
            },
            'float_comp': {
                'repository': 'registry.local:9001/example.io/acme',
                'image': 'acme-float',
                'version': 1.5,
            },
        }
        result = self.image_parser.update_images_with_local_registry(
            images_dict)
        self.assertEqual(expected, result)

    def test_generate_download_images_list_numeric_version(self):
        download_imgs_dict = copy.deepcopy(self.NUMERIC_VERSION_RESOURCE)
        expected = {
            'example.io/acme/acme-int:2',
            'example.io/acme/acme-float:1.5',
        }
        download_imgs_list = self.image_parser.generate_download_images_list(
            download_imgs_dict, [])
        self.assertEqual(expected, set(download_imgs_list))

    def test_repo_image_version_bool_version_not_trio(self):
        # bool is a subclass of int but is never a valid tag.
        var = {'repository': 'r', 'image': 'i', 'version': True}
        self.assertFalse(self.image_parser._is_repo_image_version(var))

    def test_repo_image_version_invalid_types_logs_warning(self):
        var = {'repository': 'r', 'image': 'i', 'version': ['1']}
        with mock.patch.object(kube_app.LOG, 'warning') as warn:
            self.assertFalse(self.image_parser._is_repo_image_version(var))
        warn.assert_called_once()
