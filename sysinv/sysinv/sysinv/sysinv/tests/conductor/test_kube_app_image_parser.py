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
    'image': {
        'tag': '7.4.0',
        'repository': 'docker.elastic.co/elasticsearch/elasticsearch-oss'
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
        self.assertEqual(images_dict, expected)

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
            'image': {
                'tag': '7.4.0',
                'repository': 'registry.local:9001/docker.elastic.co/elasticsearch/elasticsearch-oss'
            }
        }

        images_dict_with_local_registry = \
           self.image_parser.update_images_with_local_registry(images_dict)
        self.assertEqual(images_dict_with_local_registry, expected)

    def test_generate_download_images_with_merge_dict(self):
        armada_chart_imgs = copy.deepcopy(IMAGES_RESOURCE)

        override_imgs = {
            'images': {
                'tags': {
                    'cinder_db_sync': 'docker.io/starlingx/stx-cinder:latest'
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

            'image': {
                'tag': '7.5.2',
                'repository': 'docker.elastic.co/elasticsearch/elasticsearch-oss'
            }
        }

        download_imgs_dict = self.image_parser.merge_dict(
            armada_chart_imgs, override_imgs)
        self.assertEqual(download_imgs_dict, expected)

    def test_generate_download_images_list(self):
        download_imgs_dict = copy.deepcopy(IMAGES_RESOURCE)
        download_imgs_dict['image']['tag'] = None

        expected = [
            'docker.io/openstackhelm/cinder:ocata',
            'quay.io/kubernetes-ingress-controller/nginx-ingress-controller:0.23.0',
            'docker.io/openstackhelm/heat:ocata',
            'docker.elastic.co/beats/filebeat-oss:7.4.0',
            'docker.elastic.co/logstash/logstash-oss:7.2.0'
        ]

        download_imgs_list = self.image_parser.generate_download_images_list(
            download_imgs_dict, [])
        self.assertEqual(set(download_imgs_list), set(expected))
