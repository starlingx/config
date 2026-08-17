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
