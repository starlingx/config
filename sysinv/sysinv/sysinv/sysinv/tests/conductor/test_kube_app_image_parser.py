# vim: tabstop=4 shiftwidth=4 softtabstop=4
# coding=utf-8

# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""Test class for Sysinv Kube App Image Parser."""

import copy
import io
import ruamel.yaml as yaml
import os

from sysinv.conductor import kube_app
from sysinv.tests import base

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
        'Tsyncd': 'quay.io/silicom/tsyncd:2.1.2.8',
        'TsyncExtts': 'quay.io/silicom/tsync_extts:1.0.0',
        'Phc2Sys': 'quay.io/silicom/phc2sys:3.1.1',
        'GrpcTsyncd': 'quay.io/silicom/grpc-tsyncd:2.1.2.8',
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
            'tag': '0.6.1',
            'repository': 'k8s.gcr.io/metrics-server/metrics-server'
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
            values = yaml.safe_load(f)

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
                'Tsyncd': 'registry.local:9001/quay.io/silicom/tsyncd:2.1.2.8',
                'TsyncExtts': 'registry.local:9001/quay.io/silicom/tsync_extts:1.0.0',
                'Phc2Sys': 'registry.local:9001/quay.io/silicom/phc2sys:3.1.1',
                'GrpcTsyncd': 'registry.local:9001/quay.io/silicom/grpc-tsyncd:2.1.2.8',
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
                    'tag': '0.6.1',
                    'repository': 'registry.local:9001/k8s.gcr.io/metrics-server/metrics-server'
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
                'Tsyncd': 'quay.io/silicom/tsyncd:latest',
                'TsyncExtts': 'quay.io/silicom/tsync_extts:1.0.0',
                'Phc2Sys': 'quay.io/silicom/phc2sys:3.1.1',
                'GrpcTsyncd': 'quay.io/silicom/grpc-tsyncd:2.1.2.8',
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
                'Tsyncd': 'quay.io/silicom/tsyncd:latest',
                'TsyncExtts': 'quay.io/silicom/tsync_extts:1.0.0',
                'Phc2Sys': 'quay.io/silicom/phc2sys:3.1.1',
                'GrpcTsyncd': 'quay.io/silicom/grpc-tsyncd:2.1.2.8',
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
                    'tag': '0.6.1',
                    'repository': 'k8s.gcr.io/metrics-server/metrics-server'
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
            'quay.io/silicom/tsyncd:2.1.2.8',
            'quay.io/silicom/tsync_extts:1.0.0',
            'quay.io/silicom/phc2sys:3.1.1',
            'quay.io/silicom/grpc-tsyncd:2.1.2.8',
            'quay.io/silicom/gpsd:3.23.1',
            'docker.io/starlingx/stx-heat:master-centos-stable-latest',
            'k8s.gcr.io/metrics-server/metrics-server:0.6.1'
        ]

        download_imgs_list = self.image_parser.generate_download_images_list(
            download_imgs_dict, [])
        self.assertEqual(set(expected), set(download_imgs_list))
