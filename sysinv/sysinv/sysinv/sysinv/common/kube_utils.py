#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import json
from enum import Enum
from time import sleep
from typing import Literal
from typing import Optional

from kubernetes import client
from kubernetes import config
from kubernetes import utils
from kubernetes.watch import Watch

from eventlet import Timeout
from oslo_log import log as logging

from sysinv.common import kubernetes

LOG = logging.getLogger(__name__)


class KubeResourceType(str, Enum):
    service_account = "service_account"
    daemon_set = "daemon_set"
    deployment = "deployment"
    replica_set = "replica_set"
    stateful_set = "stateful_set"
    custom_resource_definition = "custom_resource_definition"
    custom_object = "custom_object"
    config_map = "config_map"
    persistent_volume_claim = "persistent_volume_claim"
    pod = "pod"
    secret = "secret"
    service = "service"
    namespace = "namespace"
    node = "node"
    job = "job"
    cron_job = "cron_job"
    storage_class = "storage_class"
    client = "client"


class KubeUtils(object):
    kube_clients = {
        "client": "ApiClient",
        "core": "CoreV1Api",
        "custom": "CustomObjectsApi",
        "batch": "BatchV1Api",
        "extensions": "ApiextensionsV1Api",
        "apps": "AppsV1Api",
        "storage": "StorageV1Api",
    }

    kube_client_map = {
        KubeResourceType.service_account: kube_clients["core"],
        KubeResourceType.config_map: kube_clients["core"],
        KubeResourceType.persistent_volume_claim: kube_clients["core"],
        KubeResourceType.pod: kube_clients["core"],
        KubeResourceType.secret: kube_clients["core"],
        KubeResourceType.service: kube_clients["core"],
        KubeResourceType.namespace: kube_clients["core"],
        KubeResourceType.node: kube_clients["core"],
        KubeResourceType.daemon_set: kube_clients["apps"],
        KubeResourceType.deployment: kube_clients["apps"],
        KubeResourceType.replica_set: kube_clients["apps"],
        KubeResourceType.stateful_set: kube_clients["apps"],
        KubeResourceType.job: kube_clients["batch"],
        KubeResourceType.cron_job: kube_clients["batch"],
        KubeResourceType.storage_class: kube_clients["storage"],
        KubeResourceType.custom_resource_definition: kube_clients["extensions"],
        KubeResourceType.custom_object: kube_clients["custom"],
        KubeResourceType.client: kube_clients["client"],
    }

    def __init__(self):
        self._load_kube_config()

    def _load_kube_config(self):
        config.load_kube_config(kubernetes.KUBERNETES_ADMIN_CONF)
        c = client.Configuration().get_default_copy()
        c.verify_ssl = False
        client.Configuration.set_default(c)

    def _get_client(self, resource_type: KubeResourceType):
        kube_client = self.kube_client_map[resource_type]
        if isinstance(kube_client, str):
            self.kube_client_map[resource_type] = getattr(client, kube_client)()
        return self.kube_client_map[resource_type]

    def _convert_to_dict(self, item):
        if isinstance(item, dict):
            return item
        try:
            result = item.to_dict()
            if not isinstance(result, dict):
                    return {}
            return result
        except AttributeError:
            try:
                result = json.loads(json.dumps(item, default=vars))
                if not isinstance(result, dict):
                    return {}
                return result
            except Exception:
                pass
        except Exception:
            pass
        return {}

    def _get_value_from_resource(self, resource, selector: str):
        keys = selector.split('.')
        current_value = resource
        for key in keys:
            try:
                if isinstance(current_value, list):
                    current_value = current_value[int(key)]
                elif isinstance(current_value, dict):
                    current_value = current_value[key]
                else:
                    return None
            except (KeyError, IndexError, ValueError, TypeError):
                LOG.debug(f"Path '{selector}' not found in resource. Failed at key '{key}'.")
                return None
        return current_value

    def get_resource(self, resource_type: KubeResourceType, action: Literal["read", "get"] = "read", **kwargs):
        """ Get kubernetes resource

        Resources type supported is mapped by kube_client_map variable.

        Args:
            resource_type (KubeResourceType): Type of the kubernetes resource.
            action (Literal["read", "get"], optional): Action of the method from kubernetes python client.
                                                       Defaults to "read".

        Kwargs Arguments:
            name (str, optional): Name of the kubernetes resource.
            namespace (str, optional): Namespace of the kubernetes resource.
            label_selector (str, optional): Label of the kubernetes resource.

        Returns:
            dict: Resource of the kubernetes in dict format.
        """

        resource = None
        method_infix = "_"
        if kwargs.get("namespace", None):
            method_infix = "_namespaced_"

        read_method = getattr(self._get_client(resource_type), f"{action}{method_infix}{resource_type.value}")

        try:
            resource = read_method(**kwargs)
        except client.exceptions.ApiException as err:
            if err.status != 404:
                LOG.error("Exception raised when getting %s from %s: %s",
                          resource_type.value,
                          kwargs.get("namespace", "No namespaced"),
                          err)
                raise

        return self._convert_to_dict(resource)

    def create_resource(self, resource_type: KubeResourceType, body, **kwargs):
        """ Get kubernetes resource

        Resources type supported is mapped by kube_client_map variable.

        Args:
            resource_type (KubeResourceType): Type of the kubernetes resource.
            body (Unknown): Dict with kubernetes resource.

        Kwargs Arguments:
            namespace (str): Namespace of the kubernetes resource.

        Returns:
            dict: Resource of the kubernetes in dict format.
        """

        resource = None
        method_infix = "_"
        if kwargs.get("namespace", None):
            method_infix = "_namespaced_"

        create_method = getattr(self._get_client(resource_type), f"create{method_infix}{resource_type.value}")

        try:
            resource = create_method(body=body, **kwargs)
        except client.exceptions.ApiException as err:
            if err.status != 404:
                LOG.error("Exception raised when creating %s from %s: %s",
                          resource_type.value,
                          kwargs.get("namespace", "No namespaced"),
                          err)
                raise

        return self._convert_to_dict(resource)

    def create_from_yaml(self, file_path):
        return utils.create_from_yaml(self._get_client(KubeResourceType.client), file_path)

    def list_resources(self, resource_type: KubeResourceType, **kwargs):
        """ List kubernetes resources

        Resources type supported is mapped by kube_client_map variable.

        Args:
            resource_type (KubeResourceType): Type of the kubernetes resource.

        Kwargs Arguments:
            namespace (str, optional): Namespace of the kubernetes resource.
            label_selector (str, optional): Label of the kubernetes resource.

        Returns:
            list[dict]: List of resources of the kubernetes in dict format.
        """
        resources = []

        method_infix = "_"
        if kwargs.get("namespace", None):
            method_infix = "_namespaced_"

        list_method = getattr(self._get_client(resource_type), f"list{method_infix}{resource_type.value}")

        try:
            resources = list_method(**kwargs)
        except client.exceptions.ApiException as err:
            if err.status != 404:
                LOG.error("Exception raised when listing %s from %s: %s",
                          resource_type.value,
                          kwargs.get("namespace", "No namespaced"),
                          err)
                raise

        if resources:
            resources = self._convert_to_dict(resources)
            resources = [
                self._convert_to_dict(resource)
                for resource in resources.get("items", [])
            ]

        if not isinstance(resources, list):
            return []

        return resources

    def wait_resources_for_condition(self,
                                     resource_type: KubeResourceType,
                                     selector: str,
                                     expected_value,
                                     retries=60,
                                     delay=1,
                                     **kwargs):
        """ Wait kubernetes resources to reach the expected value of selector

        Args:
            resource_type (KubeResourceType): Type of the kubernetes resource.
            selector (str): Selector of the item (split by .) you want to check inside of the kubernetes resource.
            expected_value (Any): Expected value of the selector.
            retries (int, optional): Number of retries to wait for the condition.
            delay (int, optional): Number of delay between each retry.

        Kwargs Arguments:
            name (str, optional): Name of the kubernetes resource.
            namespace (str, optional): Namespace of the kubernetes resource.
            label_selector (str, optional): Label of the kubernetes resource.

        Example:
            self.wait_resources_for_condition("deployment",
                                              name=osd_deployment.metadata.name,
                                              namespace=namespace)
        Returns:
            bool: returns True if all resources reach the expected value, otherwise, returns False.
        """
        LOG.info(
            f"Waiting for resource(s) of type '{resource_type}' with args {kwargs} "
            f"to have selector '{selector}' match value '{expected_value}'."
        )

        unmatched_resources = []
        for attempt in range(retries):
            if kwargs.get("name"):
                resources = [self.get_resource(resource_type=resource_type, **kwargs)]
            else:
                resources = self.list_resources(resource_type=resource_type, **kwargs)

            if not resources:
                LOG.warning(f"No resources found for type '{resource_type}' with args {kwargs}. "
                             "Assuming condition is met.")
                return True

            unmatched_resources = []
            for resource in resources:
                current_value = self._get_value_from_resource(resource, selector)
                if current_value != expected_value:
                    unmatched_resources.append({
                        "name": resource.get("metadata", {}).get("name", "unknown"),
                        "current_value": current_value
                    })

            if not unmatched_resources:
                LOG.info(f"All {len(resources)} resource(s) match the condition {selector}={expected_value} "
                         f"after {attempt} attempts.")
                return True

            for res in unmatched_resources:
                LOG.debug(
                    f"Resource '{res['name']}' has value '{res['current_value']}' for selector '{selector}', "
                    f"expected '{expected_value}'."
                )

            sleep(delay)

        LOG.error(
            f"Timeout after {retries} retries. {len(unmatched_resources)} resource(s) did not meet the condition."
        )

        for res in unmatched_resources:
            LOG.error(
                f"Resource '{res['name']}' has value '{res['current_value']}' for selector '{selector}', "
                f"expected '{expected_value}'."
            )

        return False

    def wait_resource_event(self, resource_type: KubeResourceType, event_type: str, timeout: int = 300, **kwargs):
        watch = Watch()
        stream = watch.stream(
            getattr(self._get_client(resource_type=resource_type), f"list_namespaced_{resource_type.value}"),
            **kwargs)

        try:
            with Timeout(timeout):
                for event in stream:
                    if event.get("type") == event_type.upper():
                        break
        except Timeout:
            LOG.error("Timeout reached while waiting for %s to be %s", resource_type.value, event_type.lower())
            watch.stop()
            return False

        return True

    def patch_resource(self, resource_type: KubeResourceType, name, **kwargs):
        """ Patch kubernetes resource

        Resources type supported is mapped by kube_client_map variable.

        Args:
            resource_type (KubeResourceType): Type of the kubernetes resource.
            name (str): Name of the kubernetes resource.

        Kwargs Arguments:
            namespace (str, optional): Namespace of the kubernetes resource.

        Returns:
            dict: Resource of the kubernetes in dict format after patched.
        """

        LOG.info("Patching %s %s/%s", resource_type.value, kwargs.get("plural"), name)

        resource = None

        method_infix = "_"
        if kwargs.get("namespace"):
            method_infix = "_namespaced_"

        patch_method = getattr(self._get_client(resource_type), f"patch{method_infix}{resource_type.value}")
        try:
            resource = patch_method(name=name, **kwargs)
        except client.exceptions.ApiException as err:
            if err.status != 404:
                LOG.error("Exception raised when patching %s/$s from %s: %s",
                          resource_type.value, name, kwargs.get("namespace"), err)
                raise

        sleep(1)

        return resource

    def delete_resource(self,
                        resource_type: KubeResourceType,
                        name: str,
                        read_action: Literal["read", "get"] = "read",
                        timeout_seconds=600,
                        **kwargs):
        """ Delete kubernetes resource

        Resources type supported is mapped by kube_client_map variable.

        Args:
            resource_type (KubeResourceType): Type of the kubernetes resource.
            name (str): Name of the kubernetes resource.
            read_action (Literal["read", "get"], optional): Action of the get_resource method. Defaults to "read".
            timeout_seconds (int, optional): Seconds waiting for the kubernetes resource to be deleted.

        Kwargs Arguments:
            namespace (str, optional): Namespace of the kubernetes resource.
            label_selector (str, optional): Label of the kubernetes resource.

        Returns:
            dict: Deleted resource of the kubernetes in dict format.
        """

        watch = Watch()

        method_infix = "_"
        if kwargs.get("namespace"):
            method_infix = "_namespaced_"

        delete_method = getattr(self._get_client(resource_type), f"delete{method_infix}{resource_type.value}")
        list_method = getattr(self._get_client(resource_type), f"list{method_infix}{resource_type.value}")

        resource = self.get_resource(resource_type=resource_type,
                                     action=read_action,
                                     name=name,
                                     **kwargs)

        if not resource:
            LOG.info("The %s %s/%s does not exist.", resource_type.value, kwargs.get("plural"), name)
            return

        LOG.info("Deleting %s %s/%s...", resource_type.value, kwargs.get("plural"), name)

        try:
            stream = watch.stream(
                list_method,
                **kwargs
            )

            # Force the stream to be initialized
            next(stream)

            delete_method(**kwargs, name=name, body=client.V1DeleteOptions(propagation_policy="Foreground",
                                                                           grace_period_seconds=0))

            with Timeout(timeout_seconds):
                for event in stream:
                    object = self._convert_to_dict(event['object'])
                    if (object.get('metadata', {}).get('name', '') == name
                            and event['type'] == "DELETED"):
                        watch.stop()
                        LOG.info("The %s %s/%s was deleted succesfully.",
                                 resource_type.value,
                                 kwargs.get("plural"),
                                 name)
                        return

        except Timeout:
            LOG.error("Timeout reached while waiting for %s %s/%s to be deleted",
                      resource_type.value,
                      kwargs.get("plural"),
                      name)
            watch.stop()
            return

        except client.exceptions.ApiException as err:
            if err.status != 404:
                LOG.error("Exception raised from deleting %s %s/%s: %s",
                          resource_type.value,
                          kwargs.get("plural"),
                          name)
                raise

        return resource

    def delete_collection_resource(self,
                                   resource_type: KubeResourceType,
                                   label_selector: Optional[str] = None,
                                   timeout_seconds=600,
                                   **kwargs):
        """ Delete kubernetes resource

        Resources type supported is mapped by kube_client_map variable.

        Args:
            resource_type (KubeResourceType): Type of the kubernetes resource.
            timeout_seconds (int, optional): Seconds waiting for the kubernetes resource to be deleted.

        Kwargs Arguments:
            name (str): Name of the kubernetes resource.
            namespace (str, optional): Namespace of the kubernetes resource.
            label_selector (str | None, optional): Label of the kubernetes resource.

        Returns:
            dict: Deleted resource of the kubernetes in dict format.
        """

        watch = Watch()

        method_infix = "_collection_"
        if kwargs.get("namespace"):
            method_infix = "_collection_namespaced_"

        list_method_infix = method_infix.replace('_collection', '')

        delete_method = getattr(self._get_client(resource_type), f"delete{method_infix}{resource_type.value}")
        list_method = getattr(self._get_client(resource_type), f"list{list_method_infix}{resource_type.value}")

        label_kwargs = {}
        if label_selector:
            label_kwargs = {"label_selector": label_selector}

        resources_to_delete = self.list_resources(resource_type=resource_type,
                                                  **label_kwargs,
                                                  **kwargs)

        if not resources_to_delete:
            LOG.info("No %s found to be deleted.", resource_type.value)
            return

        resource_names_to_delete = {item.get("metadata", {}).get("name") for item in resources_to_delete}

        try:
            stream = watch.stream(
                list_method,
                **label_kwargs,
                **kwargs
            )

            # Force the stream to be initialized
            next(stream)

            delete_method(**label_kwargs,
                          **kwargs,
                          body=client.V1DeleteOptions(propagation_policy="Foreground",
                                                      grace_period_seconds=0))

            with Timeout(timeout_seconds):
                for event in stream:
                    object = self._convert_to_dict(event['object'])
                    object_name = object.get('metadata', {}).get('name', {})
                    if (object_name in resource_names_to_delete
                            and event['type'] == "DELETED"):
                        watch.stop()
                        resource_names_to_delete.remove(object_name)
                        LOG.info("The %s %s was deleted succesfully.", object_name, resource_type.value)

        except Timeout:
            LOG.error("Timeout reached while waiting for [%s] to be deleted",
                      ", ".join(resource_names_to_delete), resource_type.value)
            watch.stop()
            return

        except client.exceptions.ApiException as err:
            if err.status != 404:
                LOG.error("Exception raised deleting using label_selector %s from %s: %s",
                          label_selector,
                          resource_type.value,
                          err)
                raise

        return resources_to_delete

    def remove_resource_finalizers(self, resource_type: KubeResourceType, name: str, **kwargs):
        """ Remove finalizers from a resource

        This function removes finalizers from a resource to allow proper cleanup

        """

        remove_finalizers_patch = {
            "metadata": {
                "finalizers": []
            }
        }

        self.patch_resource(resource_type=resource_type,
                            name=name,
                            body=remove_finalizers_patch,
                            **kwargs)
