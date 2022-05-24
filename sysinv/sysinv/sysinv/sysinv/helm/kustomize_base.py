#
# Copyright (c) 2022 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# All Rights Reserved.
#

""" System inventory FluxCD Kustomize manifest operator."""

import abc
import io
import json
import os
import ruamel.yaml as yaml
import shutil
import six
import tempfile

from copy import deepcopy
from oslo_log import log as logging
from sysinv.common import constants

LOG = logging.getLogger(__name__)


@six.add_metaclass(abc.ABCMeta)
class FluxCDKustomizeOperator(object):

    def __init__(self, manifest_fqpn=None):

        self.app_manifest_path = None            # Path to the app manifests
        self.original_kustomization_fqpn = None  # Original kustomization.yaml
        self.kustomization_fqpn = None           # Updated kustomization.yaml
        self.release_cleanup_fqpn = None         # Helm release cleanup data

        self.kustomization_content = []          # Original app manifest content
        self.chart_to_resource_map = {}          # Dict used to disable charts

        self.kustomization_resources = []        # Kustomize resource list
        self.kustomization_namespace = None      # Kustomize global namespace

        self.chart_cleanup = []                  # List of disabled charts

        if manifest_fqpn:
            self.load(manifest_fqpn)

    def __str__(self):
        return json.dumps({
            constants.APP_ROOT_KUSTOMIZE_FILE: self.kustomization_content,
            'chart_to_resource_map': self.chart_to_resource_map,
            'chart_cleanup': self.chart_cleanup,
        }, indent=2)

    def load(self, manifests_dir_fqpn):
        """ Load the application kustomization manifests for processing

        :param manifest_fqpn: fully qualified path name of the application
                              manifests directory
        """
        # Make sure that the manifests directory exists
        if not os.path.exists(manifests_dir_fqpn):
            LOG.error("Kustomize manifest directory %s does not exist" %
                      manifests_dir_fqpn)
            return

        # Save the location of the application manifests
        self.app_manifest_path = manifests_dir_fqpn

        # Make sure that the kustomization.yaml file exists
        self.kustomization_fqpn = os.path.join(
            manifests_dir_fqpn, constants.APP_ROOT_KUSTOMIZE_FILE)
        if not os.path.exists(self.kustomization_fqpn):
            LOG.error("Kustomize manifest %s does not exist" %
                      self.kustomization_fqpn)
            return

        # Save the original kustomization.yaml for
        self.original_kustomization_fqpn = "%s-orig%s" % os.path.splitext(
            self.kustomization_fqpn)

        if not os.path.exists(self.original_kustomization_fqpn):
            shutil.copy(self.kustomization_fqpn,
                        self.original_kustomization_fqpn)

        # Save the helm release cleanup data file name
        self.release_cleanup_fqpn = os.path.join(
            manifests_dir_fqpn, constants.APP_RELEASE_CLEANUP_FILE)

        # Reset the view of charts to cleanup as platform conditions may have
        # changed
        self.chart_cleanup = []

        # Read the original kustomization.yaml content
        with io.open(self.original_kustomization_fqpn, 'r', encoding='utf-8') as f:
            # The RoundTripLoader removes the superfluous quotes by default,
            # Set preserve_quotes=True to preserve all the quotes.
            self.kustomization_content = list(yaml.load_all(
                f, Loader=yaml.RoundTripLoader, preserve_quotes=True))

        # Expect the top level kustomization.yaml to only have one doc
        if len(self.kustomization_content) > 1:
            LOG.error("Malformed Kustomize manifest %s contains more than one yaml "
                      "doc." % self.kustomization_fqpn)
            return

        # Grab the app resource
        self.kustomization_resources = self.kustomization_content[0]['resources']

        # Grab the global namespace
        self.kustomization_namespace = deepcopy(
            self.kustomization_content[0]['namespace'])

        # For these resources, find the HelmRelease info and build a resource
        # map
        for resource in self.kustomization_resources:
            # expect a helrelease.yaml flle to be present in a helm resource
            # directory

            # is the resource a directory?
            resource_fqpn = os.path.join(manifests_dir_fqpn, resource)
            if not os.path.isdir(resource_fqpn):
                LOG.debug("%s is not a directory and cannot contain HelmRelease "
                          "info. skipping" % resource_fqpn)
                continue

            # is a helm release present?
            helm_release_fqpn = os.path.join(resource_fqpn, "helmrelease.yaml")
            if os.path.isfile(helm_release_fqpn):

                with io.open(helm_release_fqpn, 'r', encoding='utf-8') as f:
                    helm_release_doc = list(yaml.load_all(f,
                        Loader=yaml.RoundTripLoader, preserve_quotes=True))

                if len(helm_release_doc) > 1:
                    LOG.error("Malformed HelmRelease:  %s contains more than one "
                              "yaml doc." % helm_release_fqpn)
                    continue

                # get the HelmRelease name
                try:
                    metadata_name = helm_release_doc[0]['metadata']['name']
                except Exception:
                    LOG.error("Malformed HelmRelease: Unable to retreive the "
                              "metadata name from %s" % helm_release_fqpn)
                    continue

                # get the chart name
                try:
                    chart_name = \
                        helm_release_doc[0]['spec']['chart']['spec']['chart']
                except Exception:
                    LOG.error("Malformed HelmRelease: Unable to retreive the "
                              "chart name from %s" % helm_release_fqpn)
                    continue

                # Save pertinent data for disabling chart resources and cleaning
                # up existing helm releases after being disabled
                self.chart_to_resource_map.update({
                    chart_name: {'resource': resource,
                                 'metadata_name': metadata_name}})

            else:
                LOG.debug("Expecting to find a HelmRelease file at {}, skipping "
                          "resource {}.".format(helm_release_fqpn,
                                                resource_fqpn))

        LOG.debug("chart_to_resource_map: {}".format(self.chart_to_resource_map))

    def _delete_kustomization_file(self):
        """ Remove any previously written top level kustomization file
        """
        if self.kustomization_fqpn and os.path.exists(self.kustomization_fqpn):
            os.remove(self.kustomization_fqpn)

    def _delete_release_cleanup_file(self):
        """ Remove any previously written helm release cleanup information
        """
        if self.release_cleanup_fqpn and os.path.exists(self.release_cleanup_fqpn):
            os.remove(self.release_cleanup_fqpn)

    def _write_file(self, path, filename, pathfilename, data):
        """ Write a yaml file

        :param path: path to write the file
        :param filename: name of the file
        :param pathfilename: FQPN of the file
        :param data: file data
        """
        try:
            fd, tmppath = tempfile.mkstemp(dir=path, prefix=filename,
                                           text=True)

            with open(tmppath, 'w') as f:
                yaml.dump(data, f, Dumper=yaml.RoundTripDumper,
                          default_flow_style=False)
                os.close(fd)
                os.rename(tmppath, pathfilename)
                # Change the permission to be readable to non-root
                # users
                os.chmod(pathfilename, 0o644)
        except Exception:
            if os.path.exists(tmppath):
                os.remove(tmppath)
            LOG.exception("Failed to write meta overrides %s" % pathfilename)
            raise

    def save_kustomization_updates(self):
        """ Save an updated top level kustomization.yaml"""

        if self.kustomization_fqpn and os.path.exists(self.kustomization_fqpn):

            # remove existing kustomization file
            self._delete_kustomization_file()

            # Save the updated view of the resource to enable
            self.kustomization_content[0]['resources'] = self.kustomization_resources

            with open(self.kustomization_fqpn, 'w') as f:
                try:
                    yaml.dump_all(self.kustomization_content, f, Dumper=yaml.RoundTripDumper,
                                  explicit_start=True,
                                  default_flow_style=False)
                    LOG.debug("Updated kustomization file %s generated" %
                             self.kustomization_fqpn)
                except Exception as e:
                    LOG.error("Failed to generate updated kustomization file %s: "
                              "%s" % (self.kustomization_fqpn, e))
        else:
            LOG.error("Kustomization file %s does not exist" % self.kustomization_fqpn)

    def save_release_cleanup_data(self):
        """ Save yaml to cleanup HelmReleases that are no longer managed."""

        # remove existing helm release file
        self._delete_release_cleanup_file()

        if self.chart_cleanup:
            cleanup_dict = {'releases': self.chart_cleanup}
            self._write_file(self.app_manifest_path,
                             constants.APP_RELEASE_CLEANUP_FILE,
                             self.release_cleanup_fqpn,
                             cleanup_dict)
        else:
            LOG.info("%s is not needed. All charts are enabled." % self.release_cleanup_fqpn)

    def helm_release_resource_delete(self, chart):
        """ Delete a helm release resource

        This method will remove a chart's resource from the top level
        kustomization file which will prevent it from being created during
        application applies.

        The chart will also be added to a list of charts that will have their
        existing helm releases cleaned up

        :param chart: chart name to remove from the resource list
        """

        removed_resource = self.chart_to_resource_map.pop(chart, None)
        if removed_resource:

            # Remove the resource from the known resource list
            self.kustomization_resources.remove(removed_resource['resource'])

            # Save the info needed to clean up any existing chart release
            self.chart_cleanup.append({
                'namespace': self.kustomization_namespace,
                'name': removed_resource['metadata_name']
            })
        else:
            LOG.error("%s is an unknown chart resource to %s" % (
                chart, self.original_kustomization_fqpn))

    @abc.abstractmethod
    def platform_mode_kustomize_updates(self, dbapi, mode):
        """ Update the top-level kustomization resource list

        Make changes to the top-level kustomization resource list based on the
        platform mode

        :param dbapi: DB api object
        :param mode: mode to control when to update the resource list
        """
        pass
