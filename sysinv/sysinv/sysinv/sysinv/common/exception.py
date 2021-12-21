# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright (c) 2013-2021 Wind River Systems, Inc.
# Copyright 2010 United States Government as represented by the
# Administrator of the National Aeronautics and Space Administration.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""Sysinv base exception handling.

Includes decorator for re-raising Syinv-type exceptions.

SHOULD include dedicated exception logging.

"""

import six

from oslo_config import cfg
from oslo_log import log as logging
from sysinv._i18n import _

LOG = logging.getLogger(__name__)

exc_log_opts = [
    cfg.BoolOpt('fatal_exception_format_errors',
                default=False,
                help='make exception message format errors fatal'),
]

CONF = cfg.CONF
CONF.register_opts(exc_log_opts)


class ProcessExecutionError(IOError):
    def __init__(self, stdout=None, stderr=None, exit_code=None, cmd=None,
                 description=None):
        self.exit_code = exit_code
        self.stderr = stderr
        self.stdout = stdout
        self.cmd = cmd
        self.description = description

        if description is None:
            description = _('Unexpected error while running command.')
        if exit_code is None:
            exit_code = '-'
        message = (_('%(description)s\nCommand: %(cmd)s\n'
                     'Exit code: %(exit_code)s\nStdout: %(stdout)r\n'
                     'Stderr: %(stderr)r') %
                   {'description': description, 'cmd': cmd,
                    'exit_code': exit_code, 'stdout': stdout,
                    'stderr': stderr})
        IOError.__init__(self, message)


def _cleanse_dict(original):
    """Strip all admin_password, new_pass, rescue_pass keys from a dict."""
    return dict((k, v) for k, v in original.items() if "_pass" not in k)


class SysinvException(Exception):
    """Base Sysinv Exception

    To correctly use this class, inherit from it and define
    a 'message' property. That message will get printf'd
    with the keyword arguments provided to the constructor.

    """
    message = _("An unknown exception occurred.")
    code = 500
    headers = {}
    safe = False

    def __init__(self, message=None, **kwargs):
        self.kwargs = kwargs

        if 'code' not in self.kwargs:
            try:
                self.kwargs['code'] = self.code
            except AttributeError:
                pass

        if not message:
            try:
                message = self.message % kwargs  # pylint: disable=W1645

            except Exception as e:
                # kwargs doesn't match a variable in the message
                # log the issue and the kwargs
                LOG.exception(_('Exception in string format operation'))
                for name, value in kwargs.items():
                    LOG.error("%s: %s" % (name, value))

                if CONF.fatal_exception_format_errors:
                    raise e
                else:
                    # at least get the core message out if something happened
                    message = self.message  # pylint: disable=W1645

        super(SysinvException, self).__init__(message)

    def format_message(self):
        if self.__class__.__name__.endswith('_Remote'):
            return self.args[0]  # pylint: disable=unsubscriptable-object
        else:
            return six.text_type(self)


class NotAuthorized(SysinvException):
    message = _("Not authorized.")
    code = 403


class AdminRequired(NotAuthorized):
    message = _("User does not have admin privileges")


class PolicyNotAuthorized(NotAuthorized):
    message = _("Policy doesn't allow %(action)s to be performed.")


class OperationNotPermitted(NotAuthorized):
    message = _("Operation not permitted.")


class Invalid(SysinvException):
    message = _("Unacceptable parameters.")
    code = 400


class Conflict(SysinvException):
    message = _('Conflict.')
    code = 409


class CephFailure(SysinvException):
    message = _("Ceph failure: %(reason)s")
    code = 408


class CephCrushMapNotApplied(CephFailure):
    message = _("Crush map has not been applied. %(reason)s")


class CephCrushMaxRecursion(CephFailure):
    message = _("Processing crushmap failed after reaching unexpected recursion "
                "level of %(depth)s.")


class CephCrushInvalidTierUse(CephFailure):
    message = _("Cannot use tier '%(tier)s' for this operation. %(reason)s")


class CephCrushTierAlreadyExists(CephCrushInvalidTierUse):
    message = _("Tier '%(tier)s' already exists")


class CephCrushTierRenameFailure(CephCrushInvalidTierUse):
    message = _("Tier '%(tier)s' cannot be renamed. %(reason)s")


class CephCrushInvalidRuleOperation(CephFailure):
    message = _("Cannot perform operation on rule '%(rule)s'. %(reason)s")


class CephCrushRuleAlreadyExists(CephCrushInvalidRuleOperation):
    message = _("Rule '%(rule)s' for storage tier '%(tier)s' already exists")


class CephPoolCreateFailure(CephFailure):
    message = _("Creating OSD pool %(name)s failed: %(reason)s")


class CephPoolDeleteFailure(CephFailure):
    message = _("Deleting OSD pool %(name)s failed: %(reason)s")


class CephPoolListFailure(CephFailure):
    message = _("Listing OSD pools failed: %(reason)s")


class CephPoolRulesetFailure(CephFailure):
    message = _("Assigning crush ruleset to OSD pool %(name)s failed: %(reason)s")


class CephPoolSetQuotaFailure(CephFailure):
    message = _("Error seting the OSD pool quota %(name)s for %(pool)s to %(value)s") \
                + ": %(reason)s"


class CephPoolGetQuotaFailure(CephFailure):
    message = _("Error geting the OSD pool quota for %(pool)s") \
                + ": %(reason)s"


class CephGetClusterUsageFailure(CephFailure):
    message = _("Getting the cluster usage information failed: %(reason)s")


class CephGetPoolsUsageFailure(CephFailure):
    message = _("Getting the pools usage information failed: %(reason)s")


class CephGetOsdStatsFailure(CephFailure):
    message = _("Getting the osd stats information failed: %(reason)s")


class CephPoolGetParamFailure(CephFailure):
    message = _("Cannot get Ceph OSD pool parameter: "
                "pool_name=%(pool_name)s, param=%(param)s. "
                "Reason: %(reason)s")


class CephPoolApplyRestoreInProgress(CephFailure):
    message = _("Cannot apply/set Ceph OSD pool parameters. "
                "Reason: storage restore in progress (wait until "
                "all storage nodes are unlocked and available).")


class CephPoolSetParamFailure(CephFailure):
    message = _("Cannot set Ceph OSD pool parameter: "
                "pool_name=%(pool_name)s, param=%(param)s, value=%(value)s. "
                "Reason: %(reason)s")


class CephCommandUnsupported(CephFailure):
    # 503 means service unavailable which seems appropriate for commands that are unsupported
    code = 503


class InvalidCPUInfo(Invalid):
    message = _("Unacceptable CPU info") + ": %(reason)s"


class InvalidIpAddressError(Invalid):
    message = _("%(address)s is not a valid IP v4/6 address.")


class IpAddressOutOfRange(Invalid):
    message = _("%(address)s is not in the range: %(low)s to %(high)s")


class InvalidDiskFormat(Invalid):
    message = _("Disk format %(disk_format)s is not acceptable")


class InvalidUUID(Invalid):
    message = _("Expected a uuid but received %(uuid)s.")


class InvalidIPAddress(Invalid):
    message = _("Expected an IPv4 or IPv6 address but received %(address)s.")


class InvalidIdentity(Invalid):
    message = _("Expected an uuid or int but received %(identity)s.")


class PatchError(Invalid):
    message = _("Couldn't apply patch '%(patch)s'. Reason: %(reason)s")


class InvalidMAC(Invalid):
    message = _("Expected a MAC address but received %(mac)s.")


class ManagedIPAddress(Invalid):
    message = _("The infrastructure IP address for this nodetype is "
                "specified by the system configuration and cannot be "
                "modified.")


class AddressAlreadyExists(Conflict):
    message = _("Address %(address)s/%(prefix)s already "
                "exists on this interface.")


class AddressInSameSubnetExists(Conflict):
    message = _("Address %(address)s/%(prefix)s on interface %(interface)s "
                "is in same subnet")


class AddressCountLimitedToOne(Conflict):
    message = _("Interface with network type '%(iftype)s' does not support "
                "multiple static addresses")


class AddressLimitedToOneWithSDN(Conflict):
    message = _("Only one Address allowed for all interfaces with network type"
                " '%(iftype)s' when SDN is enabled")


class AddressNameExists(Conflict):
    message = _("Address already exists with name %(name)s")


class AddressAlreadyAllocated(Conflict):
    message = _("Address %(address)s is already allocated")


class AddressNetworkInvalid(Conflict):
    message = _("Address %(address)s/%(prefix)s does not match pool network")


class UnsupportedInterfaceNetworkType(Conflict):
    message = _("Interface with network type '%(networktype)s' does not "
                "support static addresses.")


class InterfaceNameAlreadyExists(Conflict):
    message = _("Interface with name %(name)s already exists.")


class InterfaceNetworkNotSet(Conflict):
    message = _("The Interface does not have any network assigned to it.")


class AddressInUseByRouteGateway(Conflict):
    message = _("Address %(address)s is in use by a route to "
                "%(network)s/%(prefix)s via %(gateway)s")


class DuplicateAddressDetectionNotSupportedOnIpv4(Conflict):
    message = _("Duplicate Address Detection (DAD) not supported on "
                "IPv4 Addresses")


class DuplicateAddressDetectionRequiredOnIpv6(Conflict):
    message = _("Duplicate Address Detection (DAD) required on "
                "IPv6 Addresses")


class RouteAlreadyExists(Conflict):
    message = _("Route %(network)s/%(prefix)s via %(gateway)s already "
                "exists on this host.")


class RouteMaxPathsForSubnet(Conflict):
    message = _("Maximum number of paths (%(count)s) already reached for "
                "%(network)s/%(prefix)s already reached.")


class RouteGatewayNotReachable(Conflict):
    message = _("Route gateway %(gateway)s is not reachable by any address "
                " on this interface")


class RouteGatewayCannotBeLocal(Conflict):
    message = _("Route gateway %(gateway)s cannot be another local interface")


class RoutesNotSupportedOnInterfaces(Conflict):
    message = _("Routes may not be configured against interfaces with network "
                "type '%(type)s'")


class DefaultRouteNotAllowedOnVRSInterface(Conflict):
    message = _("Default route not permitted on 'data-vrs' interfaces")


class CannotDeterminePrimaryNetworkType(Conflict):
    message = _("Cannot determine primary network type of interface "
                "%(iface)s from %(types)s")


class AlarmAlreadyExists(Conflict):
    message = _("An Alarm with UUID %(uuid)s already exists.")


class CPUAlreadyExists(Conflict):
    message = _("A CPU with cpu ID %(cpu)s already exists.")


class MACAlreadyExists(Conflict):
    message = _("A Port with MAC address %(mac)s already exists.")


class PCIAddrAlreadyExists(Conflict):
    message = _("A Device with PCI address %(pciaddr)s "
                "for %(host)s already exists.")


class PCIAddrNotFound(Conflict):
    message = _("A Device with PCI address %(pciaddr)s could not be found.")


class LvmLvgAlreadyExists(Conflict):
    message = _("LVM Local Volume Group %(name)s for %(host)s already exists.")


class LvmPvAlreadyExists(Conflict):
    message = _("LVM Physical Volume %(name)s for %(host)s already exists.")


class CephMonAlreadyExists(Conflict):
    message = _("A CephMon with UUID %(uuid)s already exists.")


class DiskAlreadyExists(Conflict):
    message = _("A Disk with UUID %(uuid)s already exists.")


class LoadAlreadyExists(Conflict):
    message = _("A Load with UUID %(uuid)s already exists.")


class UpgradeAlreadyExists(Conflict):
    message = _("An Upgrade with UUID %(uuid)s already exists.")


class PortAlreadyExists(Conflict):
    message = _("A Port with UUID %(uuid)s already exists.")


class RemoteLoggingAlreadyExists(Conflict):
    message = _("A RemoteLogging with UUID %(uuid)s already exists.")


class SystemAlreadyExists(Conflict):
    message = _("A System with UUID %(uuid)s already exists.")


class SensorAlreadyExists(Conflict):
    message = _("A Sensor with UUID %(uuid)s already exists.")


class SensorGroupAlreadyExists(Conflict):
    message = _("A SensorGroup with UUID %(uuid)s already exists.")


class DNSAlreadyExists(Conflict):
    message = _("A DNS with UUID %(uuid)s already exists.")


class NTPAlreadyExists(Conflict):
    message = _("A NTP with UUID %(uuid)s already exists.")


class PTPAlreadyExists(Conflict):
    message = _("A PTP with UUID %(uuid)s already exists.")


class PtpInstanceAlreadyExists(Conflict):
    message = _("A PTP instance with name '%(name)s' already exists.")


class PtpInterfaceAlreadyExists(Conflict):
    message = _("A PTP interface with UUID %(uuid)s already exists.")


class PtpParameterAlreadyExists(Conflict):
    message = _("A PTP parameter with UUID %(uuid)s already exists.")


class PtpParameterOwnershipAlreadyExists(Conflict):
    message = _("UUID %(param)s is already a PTP parameter of UUID %(owner)s.")


class PtpInstanceMapAlreadyExists(Conflict):
    message = _("PTP instance %(ptp_instance)s is already associated to host "
                "%(host)s.")


class PtpInterfaceMapAlreadyExists(Conflict):
    message = _("PTP interface %(ptp_interface)s is already associated to "
                "interface %(interface)s.")


class PMAlreadyExists(Conflict):
    message = _("A PM with UUID %(uuid)s already exists.")


class ControllerFSAlreadyExists(Conflict):
    message = _("A ControllerFS with UUID %(uuid)s already exists.")


class DRBDAlreadyExists(Conflict):
    message = _("A DRBD with UUID %(uuid)s already exists.")


class StorageBackendAlreadyExists(Conflict):
    message = _("A StorageBackend with UUID %(uuid)s already exists.")


class StorageCephAlreadyExists(Conflict):
    message = _("A StorageCeph with UUID %(uuid)s already exists.")


class StorageLvmAlreadyExists(Conflict):
    message = _("A StorageLvm with UUID %(uuid)s already exists.")


class StorageFileAlreadyExists(Conflict):
    message = _("A StorageFile with UUID %(uuid)s already exists.")


class StorageExternalAlreadyExists(Conflict):
    message = _("A StorageExternal with UUID %(uuid)s already exists.")


class UserAlreadyExists(Conflict):
    message = _("A User with UUID %(uuid)s already exists.")


class ServiceAlreadyExists(Conflict):
    message = _("A Service with UUID %(uuid)s already exists.")


class ServiceGroupAlreadyExists(Conflict):
    message = _("A ServiceGroup with UUID %(uuid)s already exists.")


class NodeAlreadyExists(Conflict):
    message = _("A Node with UUID %(uuid)s already exists.")


class MemoryAlreadyExists(Conflict):
    message = _("A Memeory with UUID %(uuid)s already exists.")


class StorAlreadyExists(Conflict):
    message = _("A Stor with UUID %(uuid)s already exists.")


class ServiceParameterAlreadyExists(Conflict):
    message = _("Service Parameter %(name)s for Service %(service)s Section "
                "%(section)s already exists")


class LLDPAgentExists(Conflict):
    message = _("An LLDP agent with uuid %(uuid)s already exists.")


class LLDPNeighbourExists(Conflict):
    message = _("An LLDP neighbour with uuid %(uuid)s already exists.")


class LLDPTlvExists(Conflict):
    message = _("An LLDP TLV with type %(type) already exists.")


class LLDPDriverError(Conflict):
    message = _("An LLDP driver error has occurred. method=%(method)")


class SDNControllerAlreadyExists(Conflict):
    message = _("An SDN Controller with uuid %(uuid)s already exists.")


class TPMConfigAlreadyExists(Conflict):
    message = _("A TPM configuration with uuid %(uuid)s already exists.")


class TPMDeviceAlreadyExists(Conflict):
    message = _("A TPM device with uuid %(uuid)s already exists.")


class CertificateAlreadyExists(Conflict):
    message = _("A Certificate with uuid %(uuid)s already exists.")


class InstanceDeployFailure(Invalid):
    message = _("Failed to deploy instance: %(reason)s")


class ImageUnacceptable(Invalid):
    message = _("Image %(image_id)s is unacceptable: %(reason)s")


class ImageConvertFailed(Invalid):
    message = _("Image %(image_id)s is unacceptable: %(reason)s")


# Cannot be templated as the error syntax varies.
# msg needs to be constructed when raised.
class InvalidParameterValue(Invalid):
    message = _("%(err)s")


class NotFound(SysinvException):
    message = _("Resource could not be found.")
    code = 404


class MultipleResults(SysinvException):
    message = _("More than one result found.")


class NTPNotFound(NotFound):
    message = _("No NTP with id %(intp_id)s found.")


class PTPNotFound(NotFound):
    message = _("No PTP with id %(uuid)s found.")


class PtpInstanceNotFound(NotFound):
    message = _("No PTP instance with id %(uuid)s found.")


class PtpInterfaceNotFound(NotFound):
    message = _("No PTP interface with id %(uuid)s found.")


class PtpParameterNotFound(NotFound):
    message = _("No PTP parameter with id %(uuid)s found.")


class PtpParameterOwnerNotFound(NotFound):
    message = _("No PTP parameter owner with id %(uuid)s found.")


class PtpParameterOwnershipNotFound(NotFound):
    message = _("No PTP parameter ownership with id %(uuid)s found.")


class PtpInstanceMapNotFound(NotFound):
    message = _("No PTP instance mapping with id %(uuid)s found.")


class PtpInterfaceMapNotFound(NotFound):
    message = _("No PTP interface mapping with id %(uuid)s found.")


class DiskNotFound(NotFound):
    message = _("No disk with id %(disk_id)s")


class DiskPartitionNotFound(NotFound):
    message = _("No disk partition with id %(partition_id)s")


class PartitionAlreadyExists(Conflict):
    message = _("Disk partition %(device_path)s already exists.")


class LvmLvgNotFound(NotFound):
    message = _("No LVM Local Volume Group with id %(lvg_id)s")


class LvmPvNotFound(NotFound):
    message = _("No LVM Physical Volume with id %(pv_id)s")


class DriverNotFound(NotFound):
    message = _("Failed to load driver %(driver_name)s.")


class ImageNotFound(NotFound):
    message = _("Image %(image_id)s could not be found.")


class HostNotFound(NotFound):
    message = _("Host %(host)s could not be found.")


class NetworkNotFound(NotFound):
    message = _("Network %(network_uuid)s could not be found.")


class NetworkTypeNotFound(NotFound):
    message = _("Network of type %(type)s could not be found.")


class NetworkIDNotFound(NotFound):
    message = _("Network with id %(id)s could not be found.")


class NetworkNameNotFound(NotFound):
    message = _("Network with name %(name)s could not be found.")


class NetworkAlreadyExists(Conflict):
    message = _("Network of type %(type)s already exists.")


class InterfaceNetworkNotFound(NotFound):
    message = _("Interface network %(uuid)s could not be found.")


class InterfaceNetworkAlreadyExists(Conflict):
    message = _("Interface network with interface ID %(interface_id)s "
                "and network ID %(network_id)s already exists.")


class InterfaceNetworkNotFoundByHostInterfaceNetwork(NotFound):
    message = _("Interface network with interface ID %(interface_id)s "
                "and network ID %(network_id)s not found")


class UnsupportedAssignedInterfaceNetworkType(Conflict):
    message = _("Cannot assign network with type '%(network_type)s' "
                "to an interface.")


class UnsupportedRemovedInterfaceNetworkType(Conflict):
    message = _("Cannot remove network with type '%(network_type)s' "
                "from an interface.")


class NetworkAddressPoolInUse(Conflict):
    message = _("Network address pool already in-use.")


class NetworkSpeedNotSupported(Invalid):
    message = _("Network speed %(speed)s not supported.")


class AddressNotFound(NotFound):
    message = _("Address %(address_uuid)s could not be found.")


class AddressNotFoundByAddress(NotFound):
    message = _("Address %(address)s could not be found.")


class AddressNotFoundByName(NotFound):
    message = _("Address could not be found for %(name)s")


class AddressNotFoundByInterfacePool(NotFound):
    message = _("Address could not be found for interface %(interface)s "
                "pool %(pool)s")


class AddressModeAlreadyExists(Conflict):
    message = _("An AddressMode with UUID %(uuid)s already exists.")


class AddressModeNotFoundByFamily(NotFound):
    message = _("%(family)s address mode could not be found for interface.")


class AddressModeNotFound(NotFound):
    message = _("Address mode %(mode_uuid)s could not be found.")


class AddressModeMustBeStatic(NotFound):
    message = _("%(family)s interface address mode must be 'static' to add addresses")


class ClonedInterfaceNotFound(NotFound):
    message = _("Cloned Interface %(intf)s could not be found.")


class StaticAddressNotConfigured(Invalid):
    message = _("The IP address for this interface is assigned "
                "dynamically as specified during system configuration.")


class AddressModeOnlyOnSupportedTypes(NotFound):
    message = _("Address mode attributes only supported on "
                "'%(types)s' interfaces")


class AddressAllocatedFromPool(Conflict):
    message = _("Address has been allocated from pool; cannot be "
                "manually deleted")


class AddressesStillExist(Conflict):
    message = _("Static %(family)s addresses still exist on interface")


class AddressPoolAlreadyExists(Conflict):
    message = _("Address pool %(uuid)s already exists")


class AddressPoolFamilyMismatch(Conflict):
    message = _("Address pool IP family does not match requested family")


class AddressPoolRequiresAddressMode(Conflict):
    message = _("Specifying an %(family)s address pool requires setting the "
                "address mode to 'pool'")


class AddressPoolRangesExcludeExistingAddress(Conflict):
    message = (_("The new address pool ranges excludes addresses that have "
                 "already been allocated."))


class AddressPoolRangeTransposed(Conflict):
    message = _("start address must be less than end address")


class AddressPoolRangeTooSmall(Conflict):
    message = _("Address pool network prefix must be at least /30")


class AddressPoolRangeVersionMismatch(Conflict):
    message = _("Address pool range IP version must match network IP version")


class AddressPoolRangeValueNotInNetwork(Conflict):
    message = _("Address %(address)s is not within network %(network)s")


class AddressPoolRangeCannotIncludeNetwork(Conflict):
    message = _("Address pool range cannot include network address")


class AddressPoolRangeCannotIncludeBroadcast(Conflict):
    message = _("Address pool range cannot include broadcast address")


class AddressPoolRangeContainsDuplicates(Conflict):
    message = _("Addresses from %(start)s-%(end)s already contained in range")


class AddressPoolExhausted(Conflict):
    message = _("Address pool %(name)s has no available addresses")


class AddressPoolInvalidAllocationOrder(Conflict):
    message = _("Address pool allocation order %(order)s is not valid")


class AddressPoolRequired(Conflict):
    message = _("%(family)s address pool name not specified")


class AddressPoolNotFound(NotFound):
    message = _("Address pool %(address_pool_uuid)s not found")


class AddressPoolNotFoundByID(NotFound):
    message = _("Address pool %(address_pool_id)s not found")


class AddressPoolNotFoundByName(NotFound):
    message = _("Address pool %(name)s not found")


class AddressPoolInUseByAddresses(Conflict):
    message = _("Address pool still in use by one or more addresses")


class AddressPoolReadonly(Conflict):
    message = _("Address pool is read-only and cannot be modified or removed")


class RouteNotFound(NotFound):
    message = _("Route %(route_uuid)s could not be found.")


class RouteNotFoundByName(NotFound):
    message = _("Route %(network)s/%(prefix)s via %(gateway)s "
                "could not be found.")


class HostLocking(SysinvException):
    message = _("Unable to complete the action because "
                "host %(host)s is undergoing action %(action)s.")


class HostLocked(SysinvException):
    message = _("Unable to complete the action %(action)s because "
                "Host %(host)s is in administrative state = unlocked.")


class HostMustBeLocked(SysinvException):
    message = _("Unable to complete the action because "
                "Host %(host)s is in administrative state = unlocked.")


class ConsoleNotFound(NotFound):
    message = _("Console %(console_id)s could not be found.")


class FileNotFound(NotFound):
    message = _("File %(file_path)s could not be found.")


class NoValidHost(NotFound):
    message = _("No valid host was found. %(reason)s")


class InstanceNotFound(NotFound):
    message = _("Instance %(instance)s could not be found.")


class NodeNotFound(NotFound):
    message = _("Node %(node)s could not be found.")


class NodeLocked(NotFound):
    message = _("Node %(node)s is locked by another process.")


class PortNotFound(NotFound):
    message = _("Port %(port)s could not be found.")


class ChassisNotFound(NotFound):
    message = _("Chassis %(chassis)s could not be found.")


class ServerNotFound(NotFound):
    message = _("Server %(server)s could not be found.")


class ServiceNotFound(NotFound):
    message = _("Service %(service)s could not be found.")


class AlarmNotFound(NotFound):
    message = _("Alarm %(alarm)s could not be found.")


class EventLogNotFound(NotFound):
    message = _("Event Log %(eventLog)s could not be found.")


class TPMConfigNotFound(NotFound):
    message = _("TPM Configuration %(uuid)s could not be found.")


class TPMDeviceNotFound(NotFound):
    message = _("TPM Device %(uuid)s could not be found.")


class CertificateNotFound(NotFound):
    message = _("No certificate with uuid %(uuid)s")


class CertificateTypeNotFound(NotFound):
    message = _("No certificate type of %(certtype)s")


class InvalidKubernetesCA(Invalid):
    message = _("Invalid certificate for kubernetes rootca")


class DockerRegistryCredentialNotFound(NotFound):
    message = _("Credentials to access local docker registry "
                "for user %(name)s could not be found.")


class DockerRegistrySSLException(SysinvException):
    message = _("Registry certificate signed by an unknown CA. "
                "Install a trusted CA with 'system certificate-install -m ssl_ca'")


class DockerRegistryAPIException(SysinvException):
    message = _("Error communicating with the docker registry")


class SDNNotEnabled(SysinvException):
    message = _("SDN configuration is not enabled.")


class SDNControllerNotFound(NotFound):
    message = _("SDN Controller %(uuid)s could not be found.")


class SDNControllerCannotUnlockCompute(NotAuthorized):
    message = _("Atleast one SDN controller needs to be added "
                "in order to unlock a Compute node on an SDN system.")


class SDNControllerMismatchedAF(SysinvException):
    message = _("The SDN controller IP %(ip_address)s does not match "
                "the address family of the OAM interface.")


class SDNControllerRequiredParamsMissing(SysinvException):
    message = _("One or more required SDN controller parameters are missing.")


class PowerStateFailure(SysinvException):
    message = _("Failed to set node power state to %(pstate)s.")


class ExclusiveLockRequired(NotAuthorized):
    message = _("An exclusive lock is required, "
                "but the current context has a shared lock.")


class NodeInUse(SysinvException):
    message = _("Unable to complete the requested action because node "
                "%(node)s is currently in use by another process.")


class NodeInWrongPowerState(SysinvException):
    message = _("Can not change instance association while node "
                "%(node)s is in power state %(pstate)s.")


class NodeNotConfigured(SysinvException):
    message = _("Can not change power state because node %(node)s "
                "is not fully configured.")


class ChassisNotEmpty(SysinvException):
    message = _("Cannot complete the requested action because chassis "
                "%(chassis)s contains nodes.")


class IPMIFailure(SysinvException):
    message = _("IPMI call failed: %(cmd)s.")


class SSHConnectFailed(SysinvException):
    message = _("Failed to establish SSH connection to host %(host)s.")


class UnsupportedObjectError(SysinvException):
    message = _('Unsupported object type %(objtype)s')


class OrphanedObjectError(SysinvException):
    message = _('Cannot call %(method)s on orphaned %(objtype)s object')


class IncompatibleObjectVersion(SysinvException):
    message = _('Version %(objver)s of %(objname)s is not supported')


class ImageNotAuthorized(SysinvException):
    message = "Not authorized for image %(image_id)s."


class LoadNotFound(NotFound):
    message = _("Load %(load)s could not be found.")


class LldpAgentNotFound(NotFound):
    message = _("LLDP agent %(agent)s could not be found")


class LldpAgentNotFoundForPort(NotFound):
    message = _("LLDP agent for port %(port)s could not be found")


class LldpNeighbourNotFound(NotFound):
    message = _("LLDP neighbour %(neighbour)s could not be found")


class LldpNeighbourNotFoundForMsap(NotFound):
    message = _("LLDP neighbour could not be found for msap %(msap)s")


class LldpTlvNotFound(NotFound):
    message = _("LLDP TLV %(type)s could not be found")


class InvalidImageRef(SysinvException):
    message = "Invalid image href %(image_href)s."
    code = 400


class ServiceUnavailable(SysinvException):
    message = "Connection failed"


class Forbidden(SysinvException):
    message = "Requested OpenStack Images API is forbidden"


class BadRequest(SysinvException):
    pass


class HTTPException(SysinvException):
    message = "Requested version of OpenStack Images API is not available."


class SysInvSignalTimeout(SysinvException):
    message = "Sysinv Timeout."


class InvalidEndpoint(SysinvException):
    message = "The provided endpoint is invalid"


class CommunicationError(SysinvException):
    message = "Unable to communicate with the server."


class HTTPForbidden(Forbidden):
    pass


class Unauthorized(SysinvException):
    pass


class HTTPNotFound(NotFound):
    pass


class ConfigNotFound(SysinvException):
    pass


class ConfigInvalid(SysinvException):
    message = _("Invalid configuration file. %(error_msg)s")


class NotSupported(SysinvException):
    message = "Action %(action)s is not supported."


class PeerAlreadyExists(Conflict):
    message = _("Peer %(uuid)s already exists")


class ClusterAlreadyExists(Conflict):
    message = _("Cluster %(uuid)s already exists")


class ClusterRequired(Conflict):
    message = _("Cluster name not specified")


class ClusterNotFound(NotFound):
    message = _("Cluster %(cluster_uuid)s not found")


class ClusterNotFoundByName(NotFound):
    message = _("Cluster %(name)s not found")


class ClusterNotFoundByType(NotFound):
    message = _("Cluster %(type)s not found")


class ClusterReadonly(Conflict):
    message = _("Cluster is read-only and cannot be modified or removed")


class ClusterInUseByPeers(Conflict):
    message = _("Cluster in use by peers with unlocked hosts "
                "%(hosts_unlocked)s")


class PeerAlreadyContainsThisHost(Conflict):
    message = _("Host %(host)s is already present in peer group %(peer_name)s")


class PeerNotFound(NotFound):
    message = _("Peer %(peer_uuid)s not found")


class PeerContainsDuplicates(Conflict):
    message = _("Peer with name % already exists")


class StoragePeerGroupUnexpected(SysinvException):
    message = _("Host %(host)s cannot be assigned to group %(peer_name)s. "
                "group-0 is reserved for storage-0 and storage-1")


class StorageTierNotFound(NotFound):
    message = _("StorageTier with UUID %(storage_tier_uuid)s not found.")


class StorageTierAlreadyExists(Conflict):
    message = _("StorageTier %(uuid)s already exists")


class StorageTierNotFoundByName(NotFound):
    message = _("StorageTier %(name)s not found")


class StorageBackendNotFoundByName(NotFound):
    message = _("StorageBackend %(name)s not found")


class HostLabelNotFound(NotFound):
    message = _("Host label %(uuid)s could not be found.")


class HostLabelAlreadyExists(Conflict):
    message = _("Host label %(label)s already "
                "exists on this host %(host)s.")


class HostLabelNotFoundByKey(NotFound):
    message = _("Host label %(label)s could not be found.")


class HostLabelInvalid(Invalid):
    message = _("Host label is invalid. Reason: %(reason)s")


class LinkSpeedInvalid(Invalid):
    message = _("Link speed is invalid. Reason: %(reason)s")


class PickleableException(Exception):
    """
    Pickleable Exception
      Used to mark custom exception classes that can be pickled.
    """
    pass


class OpenStackException(PickleableException):
    """
    OpenStack Exception
    """
    def __init__(self, message, reason):
        """
        Create an OpenStack exception
        """
        super(OpenStackException, self).__init__(message, reason)
        self._reason = reason  # a message string or another exception
        self._message = message

    def __str__(self):
        """
        Return a string representing the exception
        """
        return "[OpenStack Exception:reason=%s]" % self._reason

    def __repr__(self):
        """
        Provide a representation of the exception
        """
        return str(self)

    def __reduce__(self):
        """
        Return a tuple so that we can properly pickle the exception
        """
        return OpenStackException, (self.message, self._reason)  # pylint: disable=W1645

    @property
    def message(self):
        """
        Returns the message for the exception
        """
        return self._message

    @property
    def reason(self):
        """
        Returns the reason for the exception
        """
        return self._reason


class OpenStackRestAPIException(PickleableException):
    """
    OpenStack Rest-API Exception
    """
    message = _("An unknown exception occurred.")

    def __init__(self, message, http_status_code, reason):
        """
        Create an OpenStack Rest-API exception
        """
        super(OpenStackRestAPIException, self).__init__(message)
        self._http_status_code = http_status_code  # as defined in RFC 2616
        self._reason = reason  # a message string or another exception
        self._message = message

    def __str__(self):
        """
        Return a string representing the exception
        """
        return ("[OpenStack Rest-API Exception: code=%s, reason=%s]"
                % (self._http_status_code, self._reason))

    def __repr__(self):
        """
        Provide a representation of the exception
        """
        return str(self)

    def __reduce__(self):
        """
        Return a tuple so that we can properly pickle the exception
        """
        return OpenStackRestAPIException, (self.message,  # pylint: disable=W1645
                                           self._http_status_code,
                                           self._reason)

    @property
    def http_status_code(self):
        """
        Returns the HTTP status code
        """
        return self._http_status_code

    @property
    def reason(self):
        """
        Returns the reason for the exception
        """
        return self._reason


class InvalidStorageBackend(Invalid):
    message = _("Requested backend %(backend)s is not configured.")


class IncompleteCephMonNetworkConfig(CephFailure):
    message = _("IP address for controller-0, controller-1 and "
                "storage-0 must be allocated. Expected: %(targets)s, "
                "found: %(results)s")


class LocalManagementPersonalityNotFound(NotFound):
    message = _("Local management personality is None: "
                "config_uuid=%(config_uuid)s, config_dict=%(config_dict)s, "
                "host_personality=%(host_personality)s")


class AgentInventoryInfoNotFound(NotFound):
    message = _("Agent inventory information not found: "
                "config_uuid=%(config_uuid)s, config_dict=%(config_dict)s, "
                "host_personality=%(host_personality)s, host_uuid=%(host_uuid)s, "
                "mgmt_ip=%(mgmt_ip)s")


class LocalHostUUIDNotFound(NotFound):
    message = _("Local Host UUID not found")


# DataNetwork
class UnsupportedInterfaceDataNetworkType(Conflict):
    message = _("Interface with datanetwork type '%(datanetworktype)s' "
                "is not supported.")


class DataNetworkNotFound(NotFound):
    message = _("DataNetwork %(datanetwork_uuid)s could not be found.")


class DataNetworkTypeNotFound(NotFound):
    message = _("DataNetwork of type %(network_type)s could not be found.")


class DataNetworkIDNotFound(NotFound):
    message = _("DataNetwork with id %(id)s could not be found.")


class DataNetworkNameNotFound(NotFound):
    message = _("DataNetwork with name %(name)s could not be found.")


class DataNetworkAlreadyExists(Conflict):
    message = _("DataNetwork of name %(name)s already exists.")


class DataNetworkTypeUnsupported(Conflict):
    message = _("DataNetwork of type %(network_type)s is not supported.")


class InterfaceDataNetworkNotFound(NotFound):
    message = _("Interface datanetwork %(uuid)s could not be found.")


class InterfaceDataNetworkAlreadyExists(Conflict):
    message = _("Interface datanetwork with interface ID %(interface_id)s "
                "and datanetwork ID %(datanetwork_id)s already exists.")


class InterfaceDataNetworkNotFoundByKeys(NotFound):
    message = _("Interface datanetwork with interface ID %(interface_id)s "
                "and datanetwork ID %(datanetwork_id)s not found")


class UnsupportedAssignedInterfaceDataNetworkType(Conflict):
    message = _("Cannot assign datanetwork with type '%(network_type)s' "
                "to an interface.")


class UnsupportedRemovedInterfaceDataNetworkType(Conflict):
    message = _("Cannot remove datanetwork with type '%(network_type)s' "
                "from an interface.")


class FilesystemAlreadyExists(Conflict):
    message = _("A Host FS with name %(name)s already exists.")


class FilesystemNotFound(NotFound):
    message = _("Host FS with id %(fs_id)s not found")


# Device image
class UnsupportedDeviceImageBitstreamType(Conflict):
    message = _("Device image with bitstream type '%(bitstream_type)s' "
                "is not supported.")


class DeviceImageNotFound(NotFound):
    message = _("Device image %(deviceimage_uuid)s could not be found.")


class DeviceImageTypeNotFound(NotFound):
    message = _("Device image of type %(bitstream_type)s could not be found.")


class DeviceImageIDNotFound(NotFound):
    message = _("Device image with id %(id)s could not be found.")


class DeviceImageNameNotFound(NotFound):
    message = _("Device image with name %(name)s could not be found.")


class DeviceImageAlreadyExists(Conflict):
    message = _("Device image of name %(name)s already exists.")


class DeviceImageTypeUnsupported(Conflict):
    message = _("Device image of type %(bitstream_type)s is not supported.")


# Device Label
class DeviceLabelNotFound(NotFound):
    message = _("Device label %(uuid)s could not be found.")


class DeviceLabelAlreadyExists(Conflict):
    message = _("Device label %(label)s already "
                "exists on this host %(host)s.")


class DeviceLabelNotFoundByKey(NotFound):
    message = _("Device label %(label)s could not be found.")


class DeviceLabelInvalid(Invalid):
    message = _("Device label is invalid. Reason: %(reason)s")


# Device Image Label
class DeviceImageLabelNotFound(NotFound):
    message = _("Device image label %(uuid)s could not be found.")


class DeviceImageLabelAlreadyExists(Conflict):
    message = _("Device image is already applied to label %(uuid)s.")


class DeviceImageLabelNotFoundByKey(NotFound):
    message = _("Device image  %(image_id)s "
                "and label ID %(label_id)s not found")


# Device Image State
class DeviceImageStateAlreadyExists(Conflict):
    message = _(
        "A device to image mapping with id %(uuid)s already exists.")


class DeviceImageStateNotFound(NotFound):
    message = _("A device to image mapping with id %(id)s not found")


class DeviceImageStateNotFoundByKey(NotFound):
    message = _("Device image  %(image_id)s "
                "and device ID %(device_id)s not found")

#
# Kubernetes application and Helm related exceptions
#


class KubeAppUploadFailure(SysinvException):
    message = _("Upload of application %(name)s (%(version)s) failed: %(reason)s")


class KubeAppApplyFailure(SysinvException):
    message = _("Deployment of application %(name)s (%(version)s) failed: %(reason)s")


class KubeAppDeleteFailure(SysinvException):
    message = _("Delete of application %(name)s (%(version)s) failed: %(reason)s")


class KubeAppAbort(SysinvException):
    message = _("Operation aborted by user.")


class KubeAppAlreadyExists(Conflict):
    message = _("An application with name %(name)s %(version)s already exists.")


class KubeAppChartReleaseAlreadyExists(Conflict):
    message = _("A chart release with name %(name)s and namespace "
                "%(namespace)s for application %(app_id)s already exists.")


class KubeAppNotFound(NotFound):
    message = _("No application with name %(name)s.")


class KubeAppInactiveNotFound(NotFound):
    message = _("No inactive application with name %(name)s and version %(version)s")


class KubeAppChartReleaseNotFound(NotFound):
    message = _("No chart release with name %(name)s and "
                "namespace %(namespace)s for application %(app_id)s")


class KubeAppReleasesNotFound(NotFound):
    message = _("No releases found for application %(app_id)s")


class KubeAppProgressMonitorTimeout(SysinvException):
    message = "Armada execution progress monitor timed out."


class KubeNamespaceDeleteTimeout(SysinvException):
    message = "Namespace %(name)s deletion timeout."


class KubePodTerminateTimeout(SysinvException):
    message = "Namespace %(name)s pod termination timeout."


class KubePodDeleteTimeout(SysinvException):
    message = "Pod %(namespace)/%(name)s deletion timeout."


class KubePodDeleteUnexpected(SysinvException):
    message = "Pod %(namespace)/%(name)s was unexpectedly deleted."


class KubeVersionUnavailable(NotFound):
    message = "Getting kubeadm and kubelet versions failed"


class HelmTillerFailure(SysinvException):
    message = _("Helm operation failure: %(reason)s")


class HelmOverrideNotFound(NotFound):
    message = _("No helm override with name %(name)s and namespace "
                "%(namespace)s")


class HelmOverrideAlreadyExists(Conflict):
    message = _("A HelmOverride with name %(name)s and namespace "
                "%(namespace)s already exists.")


class InvalidHelmNamespace(Invalid):
    message = _("Invalid helm overrides namespace (%(namespace)s) for chart %(chart)s.")


class InvalidHelmDockerImageSource(Invalid):
    message = _("Invalid docker image source: %(source)s. Must be one of %(valid_srcs)s")


class ApplicationApplyFailure(SysinvException):
    message = _("Failed to apply %(name)s application.")


class IncompatibleKubeVersion(SysinvException):
    message = _("The application %(name)s (%(version)s) is incompatible with the current "
                "Kubernetes version %(kube_version)s.")

#
# Kubernetes related exceptions
#


class KubeNodeNotFound(NotFound):
    message = _("Kubernetes Node %(name)s could not be found.")


class KubeHostUpgradeAlreadyExists(Conflict):
    message = _("A Kubernetes Host Upgrade with id %(host_upgrade_id)s already exists.")


class KubeHostUpgradeNotFound(NotFound):
    message = _("Kubernetes Host Upgrade with id %(host_upgrade_id)s not found")


class KubeUpgradeAlreadyExists(Conflict):
    message = _(
        "A Kubernetes Upgrade with id %(upgrade_id)s already exists.")


class KubeUpgradeNotFound(NotFound):
    message = _("Kubernetes Upgrade with id %(upgrade_id)s not found")


class KubeVersionNotFound(NotFound):
    message = _("Kubernetes version %(version)s not found")


class KubeNotConfigured(SysinvException):
    message = _("Kubernetes is not configured. API operations "
                "will not be available.")


class RestoreAlreadyExists(Conflict):
    message = _("A Restore with UUID %(uuid)s already exists.")


class RestoreNotFound(NotFound):
    message = _("Restore with UUID %(uuid)s not found.")


class LifecycleSemanticCheckException(SysinvException):
    message = _("Semantic check hook for app failed.")


class LifecycleSemanticCheckOpererationBlocked(SysinvException):
    message = _("%(op)s is disabled for this version of %(app)s")


class LifecycleSemanticCheckOperationNotSupported(SysinvException):
    message = _("%(mode)s-%(op)s is not supported for application %(name)s")


class LifecycleMissingInfo(SysinvException):
    message = _("Lifecycle hook missing information.")


class BackupRestoreInvalidRevertOperation(SysinvException):
    message = _("Operation %(operation)s has no revert action associated.")


class ApplicationLifecycleNotificationException(Exception):
    def __init__(self, application_name, message):
        self.application_name = application_name
        super(ApplicationLifecycleNotificationException, self).__init__(message)


class KubeRootCAHostUpdateAlreadyExists(Conflict):
    message = _("A Kubernetes RootCA Host Update %(rootca_host_update_id)s "
                "on host %(host_id)s already exists.")


class KubeRootCAHostUpdateNotFound(NotFound):
    message = _("Kubernetes RootCA Host Update with id %(rootca_host_update_id)s not found")


class KubeRootCAUpdateAlreadyExists(NotFound):
    message = _("Kubernetes RootCA Update with id %(rootca_update_id)s already exists")


class KubeRootCAUpdateNotFound(NotFound):
    message = _("Kubernetes RootCA Update with id %(rootca_update_id)s not found")
