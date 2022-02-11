# Copyright 2020-2022 Foreseeti AB <https://foreseeti.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
from typing import List

class Subscription:
    def __init__(self, resourceId, name, subscriptionId, authorizationSource):
        """Required: \n
        resourceId, name, subscriptionId, authoizationSource
        """
        self.id = resourceId
        self.name = name
        self.subscriptionId = subscriptionId
        self.authorizationSource = authorizationSource


class ResourceGroup:
    def __init__(self, resourceId, subscriptionId, name, managedBy, provider):
        """Required: \n
        resourceId, subscriptionId, name
        """
        self.id = resourceId
        self.subscriptionId = subscriptionId
        self.name = name
        self.managedBy = managedBy
        self.provider = provider


class VirtualMachine:
    def __init__(
        self,
        resourceId,
        name,
        os,
        osDisk,
        dataDisks,
        managedBy,
        resourceGroup,
        sshKeys,
        networkInterfaces,
        provider,
        principalId,
        principalType,
        userAssignedIdentities,
    ):
        """Required: \n
        resourceId, name, os, resourceGroup, sshKeys, networkInterfaces
        """
        self.id = resourceId
        self.name = name
        self.os = os
        self.osDisk = osDisk
        self.dataDisks = dataDisks
        self.managedBy = managedBy
        self.resourceGroup = resourceGroup
        self.sshKeys = sshKeys
        self.networkInterfaces = networkInterfaces
        self.provider = provider
        self.principalId = principalId
        self.principalType = principalType
        self.userAssignedIdentities = userAssignedIdentities


class VirtualMachineScaleSet:
    def __init__(
        self,
        resourceId,
        name,
        os,
        osDisk,
        dataDisk,
        managedBy,
        resourceGroup,
        sshKeys,
        networkInterfaces,
        provider,
        principalId,
        principalType,
        identityIds,
    ):
        self.id = resourceId
        self.name = name
        self.os = os
        self.osDisk = osDisk
        self.dataDisk = dataDisk
        self.managedBy = managedBy
        self.resourceGroup = resourceGroup
        self.sshKeys = sshKeys
        self.networkInterfaces = networkInterfaces
        self.provider = provider
        self.principalId = principalId
        self.principalType = principalType
        self.identityIds = identityIds


class Disk:
    def __init__(
        self, resourceId, name, diskType, managedBy, resourceGroup, os, provider
    ):
        """Required: \n
        resourceId, name, diskType, managedBy, resourceGroup
        """
        self.id = resourceId
        self.name = name
        self.type = diskType
        self.managedBy = managedBy
        self.resourceGroup = resourceGroup
        self.os = os
        self.provider = provider


class RBACRole:
    def __init__(
        self, roleId, name, scope, principalId, principalType, roleName, permissions
    ):
        """Required: \n
        roleId, name, scope, principalId, principalType, roleName, permissions
        """
        self.id = roleId
        self.name = name
        self.scope = scope.lower()
        self.principalId = principalId
        self.principalType = principalType
        self.roleName = roleName
        self.permissions = permissions


class VnetGateway:
    def __init__(
        self, gwId, name, resourceGroup, ipConfigs, bgpSettings, capacity, provider
    ):
        self.id = gwId
        self.name = name
        self.resourceGroup = resourceGroup
        self.ipConfigs = ipConfigs
        self.bgpSettings = bgpSettings
        self.capacity = capacity
        self.provider = provider


class LocalNetworkGateway:
    def __init__(
        self,
        gwId,
        name,
        resourceGroup,
        localNetworkAddressSpace,
        gatewayIp,
        provider,
        bgpSettings,
    ):
        self.id = gwId
        self.name = name
        self.resourceGroup = resourceGroup
        self.localNetworkAddressSpace = localNetworkAddressSpace
        self.gatewayIp = gatewayIp
        self.provider = provider
        self.bgpSettings = bgpSettings


class Connection:
    def __init__(
        self, resourceId, name, resourceGroup, connectionType, source, target, provider
    ):
        self.id = resourceId
        self.name = name
        self.resourceGroup = resourceGroup
        self.connectionType = connectionType
        self.source = source
        self.target = target
        self.provider = provider


class SecurityPrincipal:
    def __init__(self, principalType, principalId):
        self.principalType = principalType
        self.principalId = principalId


class StorageAccountService:
    def __init__(self, name, resourceId, serviceType, allowBlobPublicAccess=None):
        """Required: \n
        name, resourceId, containerType
        """
        self.name = name
        self.id = resourceId
        self.serviceType = serviceType
        self.allowBlobPublicAccess = allowBlobPublicAccess


class StorageAccount:
    def __init__(
        self,
        resourceId,
        name,
        kind,
        resourceGroup,
        primaryEndpoints,
        services,
        provider,
        httpsOnly,
        restrictedAccess,
        privateEndpoints,
        virtualNetworkRules,
        ipRangeFilter,
        bypassServices,
    ):
        """Required: \n
        resourceId, name, kind, resourceGroup, primaryEndpoints, services, provider, httpsOnly, restrictedAccess, privateEndpoints, virtualNetworkRules, ipRangeFilter, bypassServices
        """
        self.id = resourceId
        self.name = name
        self.kind = kind
        self.resourceGroup = resourceGroup
        self.primaryEndpoints = primaryEndpoints
        self.services = services
        self.provider = provider
        self.httpsOnly = httpsOnly
        self.restrictedAccess = restrictedAccess
        self.privateEndpoints = privateEndpoints
        self.virtualNetworkRules = virtualNetworkRules
        self.ipRangeFilter = ipRangeFilter
        self.bypassServices = bypassServices


class CosmosDB:
    def __init__(
        self,
        resourceId,
        name,
        resourceGroup,
        provider,
        restrictedAccess,
        virtualNetworkRules,
        ipRangeFilter,
        apiTypes,
        disableKeyBasedMetadataWriteAccess,
    ):
        self.id = resourceId
        self.name = name
        self.resourceGroup = resourceGroup
        self.provider = provider
        self.restrictedAccess = restrictedAccess
        self.virtualNetworkRules = virtualNetworkRules
        self.ipRangeFilter = ipRangeFilter
        self.apiTypes = apiTypes
        self.disableKeyBasedMetadataWriteAccess = disableKeyBasedMetadataWriteAccess


class SecurityRule:
    def __init__(
        self,
        resourceId,
        name,
        source_port,
        dest_port,
        protocol,
        source,
        destination,
        action,
        direction,
        resourceGroup,
    ):
        """Required: \n
        resourceId, name, source_port, dest_port, source, destination, action, direction, resourceGroup
        """
        self.id = resourceId
        self.name = name
        self.sourcePort = source_port
        self.destPort = dest_port
        self.protocol = protocol
        self.source = source
        self.destination = destination
        self.action = action
        self.direction = direction
        self.resourceGroup = resourceGroup


class NetworkSecurityGroup:
    def __init__(
        self,
        resourceId,
        name,
        resourceGroup,
        inboundSecurityRules,
        outboundSecurityRules,
        subnetIds,
        provider,
    ):
        """Required: \n
        resourceId, name, kind, resourceGroup
        """
        self.id = resourceId
        self.name = name
        self.resourceGroup = resourceGroup
        self.inboundSecurityRules = inboundSecurityRules
        self.outboundSecurityRules = outboundSecurityRules
        self.subnetIds = subnetIds
        self.provider = provider


class IpAddress:
    def __init__(self, resourceId, name, resourceGroup, address, interfaceId, provider):
        """Required: \n
        id, name, resourceGroup, address, interfaceId
        """
        self.id = resourceId
        self.name = name
        self.resourceGroup = resourceGroup
        self.address = address
        self.interfaceId = interfaceId
        self.provider = provider


class NetworkInterface:
    def __init__(
        self,
        resourceId,
        name,
        resourceGroup,
        ipConfigs,
        networkSecurityGroupId,
        provider,
    ):
        """Required: \n
        resourceId, name, resourceGroup, ipConfigs, networkSecurityGroup
        """
        self.id = resourceId
        self.name = name
        self.resourceGroup = resourceGroup
        self.ipConfigs = ipConfigs
        self.networkSecurityGroupId = networkSecurityGroupId
        self.provider = provider


class IpConfig:
    def __init__(self, resourceId, name, privateIpAddress, publicIpAddressId, subnetId):
        """Required: \n
        resourceId, name, privateIpAddress, publicIpAddressId, subnetId
        """
        self.id = resourceId
        self.name = name
        self.privateIpAddress = privateIpAddress
        self.publicIpAddressId = publicIpAddressId
        self.subnetId = subnetId


class ConnectedDevice:
    def __init(self, deviceName, deviceType, vnetAddress, subnet):
        """Required: \n
        name, deviceName, deviceType, vnetAddress, subnet
        """
        self.deviceName = deviceName
        self.type = deviceType
        self.vnetAddress = vnetAddress
        self.subnet = subnet


class Subnet:
    def __init__(
        self,
        resourceId,
        name,
        ipConfigs,
        addressPrefix,
        vnetId,
        networkSecurityGroup,
    ):
        """Required: \n
        subnet_id, name, vnetId
        """
        self.id = resourceId
        self.name = name
        self.ipConfigs = ipConfigs
        self.addressPrefix = addressPrefix
        self.vnetId = vnetId
        self.networkSecurityGroup = networkSecurityGroup


class Vnet:
    def __init__(
        self,
        resourceId,
        name,
        resourceGroup,
        addressSpace,
        subnets,
        provider,
        vnetPeerings,
    ):
        """Required: \n
        resourceId, name, resourceGroup, addressSpace, subnets
        """
        self.id = resourceId
        self.name = name
        self.resourceGroup = resourceGroup
        self.addressSpace = addressSpace
        self.subnets = subnets
        self.provider = provider
        self.vnetPeerings = vnetPeerings


class RouteTable:
    def __init__(self, resourceId, name, resourceGroup, subnets, routes, provider):
        self.id = resourceId
        self.name = name
        self.resourceGroup = resourceGroup
        self.subnets = subnets
        self.routes = routes
        self.provider = provider


class Route:
    def __init__(self, routeId, name, nextHopType, addressPrefix):
        self.id = routeId
        self.name = name
        self.nextHopType = nextHopType
        self.addressPrefix = addressPrefix


class KeyVaultComponent:
    def __init__(self, resourceId, name, enabled, collection):
        """Required: \n
        name, enabled, collection
        """
        self.id = resourceId
        self.name = name
        self.enabled = enabled
        self.collection = collection


class KeyVault:
    def __init__(
        self,
        resourceId,
        name,
        resourceGroup,
        keys,
        secrets,
        certificates,
        provider,
        restrictedAccess,
        ipRules,
        virtualNetworkRules,
        purgeProtection,
        accessPolicies,
        enableRbacAuthorization: bool,
    ):
        """Required: \n
        resourceId, name, resourceGroup
        """
        self.id = resourceId
        self.name = name
        self.resourceGroup = resourceGroup
        self.keys = keys
        self.secrets = secrets
        self.certificates = certificates
        self.provider = provider
        self.restrictedAccess = restrictedAccess
        self.ipRules = ipRules
        self.virtualNetworkRules = virtualNetworkRules
        self.purgeProtection = purgeProtection
        self.accessPolicies = accessPolicies
        self.enableRbacAuthorization: bool = enableRbacAuthorization


class SshKey:
    def __init__(self, resourceId, name, resourceGroup, publicKey, provider):
        """Required: \n
        resourceId, name, resourceGroup, publicKey
        """
        self.id = resourceId
        self.name = name
        self.resourceGroup = resourceGroup
        self.publicKey = publicKey
        self.provider = provider


class RdpFile:
    def __init__(self, resourceId, name, resourceGroup, ipAddress, port):
        """Required: \n
        resourceId, name, resourceGroup, ipAddress, port
        """
        self.id = resourceId
        self.name = name
        self.resourceGroup = resourceGroup
        self.ipAddress = (ipAddress,)
        self.port = port


class Application:
    def __init__(self, resourceId, name, resourceGroup, nsgId):
        self.id = resourceId
        self.name = name
        self.resourceGroup = resourceGroup
        self.nsgId = nsgId


class ManagementGroup:
    def __init__(self, resourceId, name, scope):
        self.id = resourceId
        self.name = name
        self.scope = scope


class AppService:
    def __init__(
        self,
        resourceId,
        name,
        resourceGroup,
        provider,
        principalId,
        principalType,
        userAssignedIdentities,
        kind,
        privateEndpoints,
        outboundAddresses,
        inboundAddresses,
        httpsOnly,
        serverFarmId,
        authenticationEnabled,
        ipSecurityRestrictions,
        disabledFTPs,
        preventAnonymousAccess
    ):
        self.id = resourceId
        self.name = name
        self.resourceGroup = resourceGroup
        self.provider = provider
        self.principalId = principalId
        self.principalType = principalType
        self.userAssignedIdentities = userAssignedIdentities
        self.kind = kind
        self.privateEndpoints = privateEndpoints
        self.outboundAddresses = outboundAddresses
        self.inboundAddresses = inboundAddresses
        self.httpsOnly = httpsOnly
        self.serverFarmId = serverFarmId
        self.authenticationEnabled = authenticationEnabled
        self.ipSecurityRestrictions = ipSecurityRestrictions
        self.disabledFTPs = disabledFTPs
        self.preventAnonymousAccess = preventAnonymousAccess


class AppServicePlan:
    def __init__(self, resourceId, name, resourceGroup, provider, family):
        self.id = resourceId
        self.name = name
        self.resourceGroup = resourceGroup
        self.provider = provider
        self.family = family


class ServiceBus:
    def __init__(
        self,
        resourceId,
        name,
        resourceGroup,
        provider,
        tier,
        authorizationRules,
        queues,
        topics,
    ):
        self.id = resourceId
        self.name = name
        self.resourceGroup = resourceGroup
        self.provider = provider
        self.tier = tier
        self.authorizationRules = authorizationRules
        self.queues = queues
        self.topics = topics


class SQLServer:
    def __init__(
        self,
        resourceId,
        name,
        resourceGroup,
        provider,
        databases,
        privateEndpoints,
        publicNetworkAccess,
        virtualNetworkRules,
        firewallRules,
    ):
        self.id = resourceId
        self.name = name
        self.resourceGroup = resourceGroup
        self.provider = provider
        self.databases = databases
        self.privateEndpoints = privateEndpoints
        self.publicNetworkAccess = publicNetworkAccess
        self.virtualNetworkRules = virtualNetworkRules
        self.firewallRules = firewallRules


class ContainerRegistry:
    def __init__(
        self,
        resourceId,
        name,
        resourceGroup,
        provider,
        adminUserEnabled,
        publicNetworkEnabled,
        privateEndpoints,
        firewallRules,
        virtualNetworkRules,
        networkBypassOptions,
        defaultAction,
        tier,
        principalId,
        principalType,
        userAssignedIdentities,
    ):
        self.id = resourceId
        self.name = name
        self.resourceGroup = resourceGroup
        self.provider = provider
        self.adminUserEnabled = adminUserEnabled
        self.publicNetworkEnabled = publicNetworkEnabled
        self.privateEndpoints = privateEndpoints
        self.firewallRules = firewallRules
        self.virtualNetworkRules = virtualNetworkRules
        self.networkBypassOptions = networkBypassOptions
        self.defaultAction = defaultAction
        self.tier = tier
        self.principalId = principalId
        self.principalType = principalType
        self.userAssignedIdentities = userAssignedIdentities


class MySQLDatabase:
    def __init__(
        self,
        resourceId,
        name,
        resourceGroup,
        provider,
        privateEndpoints,
        publicNetworkAccess,
        firewallRules,
        adAdmins,
    ):
        self.id = resourceId
        self.name = name
        self.resourceGroup = resourceGroup
        self.provider = provider
        self.privateEndpoints = privateEndpoints
        self.publicNetworkAccess = publicNetworkAccess
        self.firewallRules = firewallRules
        self.adAdmins = adAdmins


class PostgreSQLDatabase:
    def __init__(
        self,
        resourceId,
        name,
        resourceGroup,
        provider,
        privateEndpoints,
        publicNetworkAccess,
        firewallRules,
        adAdmins,
    ):
        self.id = resourceId
        self.name = name
        self.resourceGroup = resourceGroup
        self.provider = provider
        self.privateEndpoints = privateEndpoints
        self.publicNetworkAccess = publicNetworkAccess
        self.firewallRules = firewallRules
        self.adAdmins = adAdmins


class MariaDBDatabase:
    def __init__(
        self,
        resourceId,
        name,
        resourceGroup,
        provider,
        privateEndpoints,
        publicNetworkAccess,
        firewallRules,
    ):
        self.id = resourceId
        self.name = name
        self.resourceGroup = resourceGroup
        self.provider = provider
        self.privateEndpoints = privateEndpoints
        self.publicNetworkAccess = publicNetworkAccess
        self.firewallRules = firewallRules


class KubernetesCluster:
    def __init__(
        self,
        resourceId,
        name,
        resourceGroup,
        provider,
        kubernetesVersion,
        nodePools,
        enableRBAC,
        firewallRules,
        privateCluster,
        tier,
        aadProfile,
        principalId,
        principalType,
    ):
        self.id = resourceId
        self.name = name
        self.resourceGroup = resourceGroup
        self.provider = provider
        self.kubernetesVersion = kubernetesVersion
        self.nodePools = nodePools
        self.enableRBAC = enableRBAC
        self.firewallRules = firewallRules
        self.privateCluster = privateCluster
        self.tier = tier
        self.aadProfile = aadProfile
        self.principalId = principalId
        self.principalType = principalType


class APIManagement:
    def __init__(
        self,
        resourceId,
        name,
        resourceGroup,
        provider,
        apis,
        products,
        subnetId,
        virtualNetworkType,
        apiManagementcertificates,
        principalId,
        principalType,
        userAssignedIdentities,
        publicIpAddresses,
        privateIpAddresses,
        apiManagementUsers,
        apiManagementSubscriptions,
    ):
        self.id = resourceId
        self.name = name
        self.resourceGroup = resourceGroup
        self.provider = provider
        self.apis = apis
        self.products = products
        self.subnetId = subnetId
        self.virtualNetworkType = virtualNetworkType
        self.apiManagementcertificates = apiManagementcertificates
        self.principalId = principalId
        self.principalType = principalType
        self.userAssignedIdentities = userAssignedIdentities
        self.publicIpAddresses = publicIpAddresses
        self.privateIpAddresses = privateIpAddresses
        self.apiManagementUsers = apiManagementUsers
        self.apiManagementSubscriptions = apiManagementSubscriptions


class Group:
    def __init__(self, groupId, members):
        self.groupId = groupId
        self.members = members


class HVA_Tag:
    def __init__(
        self: str,
        resourceId: str,
        confValue: int,
        integrityValue: int,
        availValue: int,
        scadGrps: List[str] = [], 
    ) -> None:
        self.id: str = resourceId
        self.confValue: int = confValue
        self.integrityValue: int = integrityValue
        self.availValue: int = availValue
        self.scadGrps: List[str] = scadGrps
