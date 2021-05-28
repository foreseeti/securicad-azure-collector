# Copyright 2020-2021 Foreseeti AB <https://foreseeti.com>
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

import json
from json.decoder import JSONDecodeError
import sys
import os
from azure.core.exceptions import ClientAuthenticationError
import requests
import re
import datetime
from pathlib import Path
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.subscription import SubscriptionClient
from azure.common import exceptions as azexceptions
import azure.mgmt.resourcegraph as arg
from azure.mgmt.keyvault import KeyVaultManagementClient
from azure.keyvault.keys import KeyClient as kv_KeyClient
from azure.keyvault.certificates import CertificateClient as kv_CertificateClient
from azure.keyvault.secrets import SecretClient as kv_SecretClient
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.authorization import AuthorizationManagementClient

# To authenticate the service principal connecting to the subscriptions/resources
from azure.identity import DefaultAzureCredential

import time
import cProfile
import pstats
import io
from pstats import SortKey

# Defined object classes following the json schema
from schema_classes import (
    Subscription,
    ResourceGroup,
    VirtualMachine,
    KeyVaultComponent,
    KeyVault,
    Disk,
    SshKey,
    Subnet,
    NetworkInterface,
    NetworkSecurityGroup,
    SecurityRule,
    IpAddress,
    Vnet,
    StorageAccount,
    StorageAccountService,
    VnetGateway,
    LocalNetworkGateway,
    RouteTable,
    Connection,
    ManagementGroup,
    CosmosDB,
    AppService,
    AppServicePlan,
    ServiceBus,
    SQLServer,
    ContainerRegistry,
    MySQLDatabase,
    MariaDBDatabase,
    PostgreSQLDatabase,
    KubernetesCluster,
    VirtualMachineScaleSet,
    APIManagement,
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DEBUGGING = False
# COUNTING and ASSETS are used to count known/unknown asset types. See -ca or -help flags.
COUNTING = False
ASSETS = None


def fetch_subscriptions(sub_client):
    """Fetches AD subscriptions. If the AZURE_SUBSCRIPTION_ID environment variable is set,
    only information regarding the subscription(s) will be returned. If set to "" or not set at all,
    all subscriptions the service principal has read access to is returned. \n

    Returns: Object consisting of an array of raw subscription data and an array of their corresponding subscription id
        {'subsRaw': [], 'subs_id_list': []}
    """
    try:
        azure_subscription_ids = os.environ["AZURE_SUBSCRIPTION_ID"]
    except KeyError:
        azure_subscription_ids = ""
    # If the environment variable is set, the user only wants to look at the resources in a specified subscription.
    if azure_subscription_ids not in [None, "", {}, "[]", []]:
        if "[" in azure_subscription_ids:
            try:
                azure_subscription_ids = json.loads(azure_subscription_ids)
            except JSONDecodeError:
                if DEBUGGING:
                    print(
                        f"AZURE_SUBSCRIPTION_ID seems to be the wrong format, exiting. Run the program with the --help flag for correct format."
                    )
        elif type(azure_subscription_ids) == str and "," in azure_subscription_ids:
            azure_subscription_ids = azure_subscription_ids.split(",")
        if type(azure_subscription_ids) != list:
            azure_subscription_ids = [azure_subscription_ids]
        subs_id_list = []
        subsRaw = []
        for azure_subscription_id in azure_subscription_ids:
            azure_subscription_id = str(azure_subscription_id).strip()
            try:
                subsRaw.append(
                    sub_client.subscriptions.get(azure_subscription_id).as_dict()
                )
            except azexceptions.CloudError:
                sys.exit(
                    SystemExit(
                        f"Could not access subscription: {azure_subscription_id} Confirm id and/or Service Principal RBAC read access."
                    )
                )
            subs_id_list.append(azure_subscription_id)
    else:
        subsRaw = []
        # All of the ADs subscription ids
        subs_id_list = []
        for sub in sub_client.subscriptions.list():
            subsRaw.append(sub.as_dict())
            subs_id_list.append(sub.as_dict().get("subscription_id"))
    return {"subsRaw": subsRaw, "subs_id_list": subs_id_list}


def iterate_resources_to_json(
    resources, resource_group, rg_client, sub_id, credentials
):
    """Helper function for write_ad_as_json. Handles all the resources contained wihin a resource group.\n
    Keyword arguments: \n
        resources - A list of resources within a resource group \n
        resource_group - Name of the resource group the resource is contained within. \n
        rg_client - An azure resource graph client to fetch additional resource information. \n
        sub_id - the subscription id the resource group belongs to \n
        credentials - Authentication credentials for clients \n
    Returns: \n
        A dictionary object containing resources following the schema.classes format
    """
    rg_query_options = arg.models.QueryRequestOptions(result_format="objectArray")
    json_representation = {}
    scope = "https://management.azure.com/.default"
    bearer_token = None
    try:
        access_token = credentials.get_token(scope)
        bearer_token = access_token[0]
        headers = {"Authorization": "Bearer " + bearer_token}
    except ClientAuthenticationError as e:
        if DEBUGGING:
            print(
                f"Cannot get a bearer token for type: {type(credentials)} on scope {scope}. Some azure data cannot be fetched. \n\t {e}"
            )
    for resource in resources:
        resource_type = resource.type.lower()
        name = resource.name
        resourceId = resource.id
        # Find resource type, handle accordingly
        json_key = None
        object_to_add = None
        if COUNTING:
            supported_asset = True
        try:
            if resource_type == "microsoft.compute/virtualmachines":
                managedBy = resource.managed_by
                # Fetching the hard to get properties with resource graph
                str_query = f"resources | where type == 'microsoft.compute/virtualmachines' and name == '{name}'"
                query = arg.models.QueryRequest(
                    subscriptions=[sub_id], query=str_query, options=rg_query_options,
                )
                try:
                    rg_results_as_dict = rg_client.resources(query=query).__dict__
                except:
                    if DEBUGGING:
                        print(
                            f"ERROR: Couldn't execute resource graph query of {name}, skipping asset."
                        )
                    continue
                try:
                    os = rg_results_as_dict["data"][0]["properties"]["storageProfile"][
                        "osDisk"
                    ]["osType"]
                except:
                    os = None
                try:
                    os_disk = rg_results_as_dict["data"][0]["properties"][
                        "storageProfile"
                    ]["osDisk"]["name"]
                except:
                    os_disk = None
                try:
                    data_disks = [
                        x["name"]
                        for x in rg_results_as_dict["data"][0]["properties"][
                            "storageProfile"
                        ]["dataDisks"]
                    ]
                except:
                    data_disks = []

                ssh_keys = []
                if os == "Linux":
                    linux_config = rg_results_as_dict["data"][0]["properties"][
                        "osProfile"
                    ]["linuxConfiguration"]
                    # If no public keys doesn't exist, avoid crash
                    linux_config.setdefault("ssh", {})
                    ssh_keys_raw = linux_config.get("ssh").get("publicKeys")
                    for ssh_key in ssh_keys_raw or []:
                        ssh_keys.append(ssh_key["keyData"])

                network_interface_ids = []
                networkInterfaces = rg_results_as_dict["data"][0]["properties"][
                    "networkProfile"
                ]["networkInterfaces"]
                for nwi in networkInterfaces:
                    network_interface_ids.append({"id": nwi.get("id")})

                # The principal type and system assigned managed identity
                try:
                    principal_id = rg_results_as_dict["data"][0]["identity"][
                        "principalId"
                    ]
                except (KeyError, TypeError):
                    if DEBUGGING:
                        print(
                            f"Couldn't find the principal Id of the virtual machine {name}."
                        )
                    principal_id = None
                try:
                    principal_type = rg_results_as_dict["data"][0]["identity"]["type"]
                except (KeyError, TypeError):
                    if DEBUGGING and principal_id:
                        print(
                            f"Couldn't find the principal type of the virtual machine {name}."
                        )
                    principal_type = None
                # If managed identity is activated on the resource it has a principal Id
                try:
                    raw_user_assigned_ids = rg_results_as_dict["data"][0]["identity"][
                        "userAssignedIdentities"
                    ]
                    user_assigned_ids = []
                    for key, identity in raw_user_assigned_ids.items() or []:
                        user_assigned_ids.append(
                            {
                                "identityId": key,
                                "clientId": identity["clientId"],
                                "principalId": identity["principalId"],
                            }
                        )
                except (KeyError, TypeError):
                    user_assigned_ids = []

                object_to_add = VirtualMachine(
                    resourceId=resourceId,
                    name=name,
                    os=os,
                    osDisk=os_disk,
                    dataDisks=data_disks,
                    managedBy=managedBy,
                    resourceGroup=resource_group,
                    sshKeys=ssh_keys,
                    networkInterfaces=network_interface_ids,
                    provider=resource_type,
                    principalId=principal_id,
                    principalType=principal_type,
                    userAssignedIdentities=user_assigned_ids,
                )
                json_key = "virtualMachines"

            elif resource_type == "microsoft.compute/virtualmachinescalesets":
                managedBy = resource.managed_by
                # Fetching the hard to get properties with resource graph
                str_query = f"resources | where type == 'microsoft.compute/virtualmachinescalesets' and name == '{name}'"
                query = arg.models.QueryRequest(
                    subscriptions=[sub_id], query=str_query, options=rg_query_options,
                )
                try:
                    rg_results_as_dict = rg_client.resources(query=query).__dict__
                except:
                    if DEBUGGING:
                        print(
                            f"ERROR: Couldn't execute resource graph query of {name}, skipping asset."
                        )
                    continue
                try:
                    raw_properties = rg_results_as_dict["data"][0]["properties"][
                        "virtualMachineProfile"
                    ]
                except KeyError:
                    if DEBUGGING:
                        print(
                            f"Couldn't get properties for virtual machine scale set {name}"
                        )
                    continue
                try:
                    os = raw_properties["storageProfile"]["osDisk"]["osType"]
                except:
                    if DEBUGGING:
                        print(
                            f"Couldn't find the osType of virtual machine scale set {name}"
                        )
                    os = None
                os_disk = f"{resourceId}-OSDisk"
                ssh_keys = []
                if os == "Linux":
                    try:
                        linux_config = raw_properties["osProfile"]["linuxConfiguration"]
                        # If no public keys doesn't exist, avoid crash
                        linux_config.setdefault("ssh", {})
                        ssh_keys_raw = linux_config.get("ssh").get("publicKeys")
                        for ssh_key in ssh_keys_raw or []:
                            try:
                                ssh_keys.append(ssh_key["keyData"])
                            except KeyError:
                                if DEBUGGING:
                                    print(
                                        f"Couldn't find the keyData value of ssh_key in virtual machine scale set {name}"
                                    )
                                pass
                    except KeyError:
                        if DEBUGGING:
                            print(
                                f"Couldn't find the linuxConfiguration value of virtual machine scale set {name}"
                            )
                        pass
                # Data Disk
                try:
                    data_disks = raw_properties["storageProfile"]["dataDisks"]
                    if data_disks != None:
                        data_disk = f"{resourceId}-DataDisk"
                    else:
                        data_disk = None
                except:
                    # Might not even use data profiles, no need to print debug info
                    data_disk = None
                    pass
                try:
                    network_profile = raw_properties["networkProfile"]
                except KeyError:
                    if DEBUGGING:
                        print(
                            f"Couldn't find the networkProfile value of virtual machine scale set {name}"
                        )
                    network_profile = None
                network_interface_ids = []
                if network_profile:
                    networkInterfaces = network_profile[
                        "networkInterfaceConfigurations"
                    ]
                    for nwi in networkInterfaces:
                        # see if the interface has a connected network security group
                        try:
                            nsg = nwi["properties"]["networkSecurityGroup"]["id"]
                        except KeyError:
                            nsg = None
                        try:
                            ip_configs = nwi["properties"]["ipConfigurations"]
                        except KeyError:
                            if DEBUGGING:
                                print(
                                    f"Couldn't get ip configuration for interface of virtual machine scale set {name}"
                                )
                            ip_configs = None
                        for ip_config in ip_configs or []:
                            nwi_name = ip_config.get("name")
                            properties = ip_config.get("properties")
                            if properties:
                                # See if the interface has a public ip "name"
                                try:
                                    public_ip_name = properties[
                                        "publicIPAddressConfiguration"
                                    ]["name"]
                                except KeyError:
                                    public_ip_name = None
                                try:
                                    subnet = properties["subnet"]["id"]
                                except AttributeError:
                                    if DEBUGGING:
                                        print(
                                            f"Couldn't get subnet of virtual machine scale set {name}'s network interface {nwi_name}"
                                        )
                                    subnet = None
                                if nwi_name and subnet:
                                    network_interface_ids.append(
                                        {
                                            "name": nwi_name,
                                            "subnetId": subnet,
                                            "publicIpName": public_ip_name,
                                            "secondaryNsg": nsg,
                                        }
                                    )
                            else:
                                if DEBUGGING:
                                    print(
                                        f"Couldn't get properties of virtual machine scale set {name}'s network interface {nwi_name}."
                                    )
                # If managed identity is activated on the resource it has a principal ID
                try:
                    raw_user_assigned_ids = rg_results_as_dict["data"][0]["identity"][
                        "userAssignedIdentities"
                    ]
                    user_assigned_ids = []
                    for key, identity in raw_user_assigned_ids.items() or []:
                        user_assigned_ids.append(
                            {
                                "identityId": key,
                                "clientId": identity["clientId"],
                                "principalId": identity["principalId"],
                            }
                        )
                except (KeyError, TypeError):
                    user_assigned_ids = []
                # The principal type and system assigned managed identity
                try:
                    principalId = rg_results_as_dict["data"][0]["identity"][
                        "principalId"
                    ]
                except (KeyError, TypeError):
                    if DEBUGGING:
                        print(
                            f"Couldn't find the principal Id of the app service {name}."
                        )
                    principalId = None
                try:
                    principalType = rg_results_as_dict["data"][0]["identity"]["type"]
                except (KeyError, TypeError):
                    if DEBUGGING and principal_id:
                        print(
                            f"Couldn't find the principal type of the app service {name}."
                        )
                    principalType = None

                object_to_add = VirtualMachineScaleSet(
                    resourceId=resourceId,
                    name=name,
                    os=os,
                    osDisk=os_disk,
                    dataDisk=data_disk,
                    managedBy=managedBy,
                    resourceGroup=resource_group,
                    sshKeys=ssh_keys,
                    networkInterfaces=network_interface_ids,
                    provider=resource_type,
                    principalId=principalId,
                    principalType=principalType,
                    identityIds=user_assigned_ids,
                )
                json_key = "virtualMachineScaleSets"

            elif resource_type == "microsoft.keyvault/vaults":
                str_query = f"resources | where type=~'Microsoft.Keyvault/vaults' and id == '{resourceId}'"
                query = arg.models.QueryRequest(
                    subscriptions=[sub_id], query=str_query, options=rg_query_options,
                )
                try:
                    rg_results_as_dict = rg_client.resources(query=query).__dict__
                except:
                    if DEBUGGING:
                        print(
                            f"ERROR: Couldn't execute resource graph query of {name}, skipping asset."
                        )
                    continue
                vault_url = rg_results_as_dict["data"][0]["properties"]["vaultUri"]
                keys = []
                certificates = []
                secrets = []
                kv_components = {}
                kvm_client = KeyVaultManagementClient(
                    credential=credentials, subscription_id=sub_id
                )
                all_access_policies = kvm_client.vaults.get(
                    resource_group_name=resource_group, vault_name=name
                ).properties.access_policies
                principal_data_actions = []
                for ap in all_access_policies:
                    permission_dict = {
                        "certificates": ap.permissions.__dict__.get("certificates"),
                        "secrets": ap.permissions.__dict__.get("secrets"),
                        "keys": ap.permissions.__dict__.get("keys"),
                    }
                    principal_data_actions.append(
                        {
                            "principalId": ap.object_id,
                            "tenantId": ap.tenant_id,
                            "permissions": permission_dict,
                        }
                    )
                key_client = kv_KeyClient(vault_url=vault_url, credential=credentials)
                cert_client = kv_CertificateClient(
                    vault_url=vault_url, credential=credentials
                )
                secret_client = kv_SecretClient(
                    vault_url=vault_url, credential=credentials
                )
                # Default Keys, Certificates and Secrets if access is not given to the data extractor
                try:
                    kv_keys = key_client.list_properties_of_keys()
                    kv_certs = cert_client.list_properties_of_certificates()
                    kv_secrets = secret_client.list_properties_of_secrets()
                    kv_components = {kv_keys, kv_certs, kv_secrets}
                    for item_paged in kv_components or []:
                        try:
                            for kv_component in item_paged:
                                component = KeyVaultComponent(
                                    resourceId=kv_component._id,
                                    name=kv_component._vault_id.name,
                                    enabled=kv_component.enabled,
                                    collection=kv_component._vault_id.collection,
                                )
                                if kv_component._vault_id.collection == "keys":
                                    keys.append(component.__dict__)
                                elif (
                                    kv_component._vault_id.collection == "certificates"
                                ):
                                    certificates.append(component.__dict__)
                                else:
                                    secrets.append(component.__dict__)
                        except:
                            if DEBUGGING:
                                print(
                                    f"Insufficient permissions or Firewall rules blocking access to read {name} components."
                                )
                            break
                    kv_components = None
                    kv_keys, kv_certs, kv_secrets = None, None, None
                except:
                    if DEBUGGING:
                        print(
                            f"Cannot list components on {name}, controll the access policy for the Security Principal."
                        )
                if keys == []:
                    keys = [
                        {
                            "collection": "keys",
                            "enabled": True,
                            "id": f"https://{name}.vault.azure.net/keys/default",
                            "name": "test-component",
                        },
                    ]
                if certificates == []:
                    certificates = [
                        {
                            "collection": "certificates",
                            "enabled": True,
                            "id": f"https://{name}.vault.azure.net/certificates/default",
                            "name": "test-component",
                        },
                    ]
                if secrets == []:
                    secrets = [
                        {
                            "collection": "secrets",
                            "enabled": True,
                            "id": f"https://{name}.vault.azure.net/secrets/default",
                            "name": "test-component",
                        }
                    ]
                try:
                    purge_protection = rg_results_as_dict["data"][0]["properties"][
                        "enableSoftDelete"
                    ]
                except KeyError:
                    if DEBUGGING:
                        print(
                            f"Could not get Purge Protection value from Key Vault {name}. Assuming true"
                        )
                    purge_protection = True
                endpoint = f"https://management.azure.com/subscriptions/{sub_id}/resourceGroups/{resource_group}/providers/Microsoft.KeyVault/vaults/{name}?api-version=2019-09-01"
                try:
                    resource_explorer_data = requests.get(
                        url=endpoint, headers=headers
                    ).json()
                except:
                    if DEBUGGING:
                        print(
                            f"Error running API call {endpoint}. Could be a bad authentication due to Bearer token."
                        )
                    resource_explorer_data = {}
                try:
                    vault_properties = resource_explorer_data["properties"]
                    if vault_properties.get("networkAcls"):
                        try:
                            ip_rules = [
                                x["value"]
                                for x in vault_properties["networkAcls"]["ipRules"]
                                or []
                            ]
                        except KeyError:
                            if DEBUGGING:
                                print(
                                    f"Couldn't get IP rules of {name}, assuming no specified rules."
                                )
                            ip_rules = []
                        try:
                            virtual_network_rules = [
                                x["id"]
                                for x in vault_properties["networkAcls"][
                                    "virtualNetworkRules"
                                ]
                                or []
                            ]
                        except:
                            if DEBUGGING:
                                print(
                                    f"Error while getting vnet rules from {name} running API call {endpoint}"
                                )
                            virtual_network_rules = []
                        try:
                            restricted_access = (
                                True
                                if vault_properties["networkAcls"]["defaultAction"]
                                == "Deny"
                                else False
                            )
                        except:
                            if DEBUGGING:
                                print(
                                    f"Couldn't find defaultAction on {name}'s network rules, assuming 'Allow'"
                                )
                            restricted_access = False
                    else:
                        if DEBUGGING:
                            print(
                                f"Could not see any netowrkAcl rules for {name}, assuming public internet accessible key vault."
                            )
                        ip_rules = []
                        virtual_network_rules = []
                        restricted_access = False
                except KeyError:
                    if DEBUGGING:
                        print(
                            f"Could not get NetworkAcl properties for Key Vault {name}."
                        )
                    ip_rules = []
                    virtual_network_rules = []
                    restricted_access = False

                object_to_add = KeyVault(
                    resourceId=resourceId,
                    name=name,
                    resourceGroup=resource_group,
                    keys=keys,
                    secrets=secrets,
                    certificates=certificates,
                    provider=resource_type,
                    restrictedAccess=restricted_access,
                    ipRules=ip_rules,
                    virtualNetworkRules=virtual_network_rules,
                    purgeProtection=purge_protection,
                    accessPolicies=principal_data_actions,
                )
                kv_keys, kv_certs, kv_secrets = None, None, None
                json_key = "keyVaults"

            elif resource_type == "microsoft.compute/disks":
                managed_by = resource.managed_by
                os = None
                str_query = f"resources | where type == 'microsoft.compute/disks' and name == '{name}'"
                query = arg.models.QueryRequest(
                    subscriptions=[sub_id], query=str_query, options=rg_query_options,
                )
                try:
                    rg_results_as_dict = rg_client.resources(query=query).__dict__
                    try:
                        os = rg_results_as_dict["data"][0]["properties"]["osType"]
                    except:
                        os = None
                except:
                    os = None
                kind = (
                    "OsDisk"
                    if (os != None or "osdisk" in {name.lower()})
                    else "DataDisk"
                )
                object_to_add = Disk(
                    resourceId=resourceId,
                    name=name,
                    diskType=kind,
                    managedBy=managed_by,
                    resourceGroup=resource_group,
                    os=os,
                    provider=resource_type,
                )
                json_key = "disks"

            elif resource_type == "microsoft.compute/sshpublickeys":
                str_query = f"resources | where type == 'microsoft.compute/sshpublickeys' and name == '{name}'"
                query = arg.models.QueryRequest(
                    subscriptions=[sub_id], query=str_query, options=rg_query_options,
                )
                try:
                    rg_results_as_dict = rg_client.resources(query=query).__dict__
                except:
                    if DEBUGGING:
                        print(
                            f"ERROR: Couldn't execute resource graph query of {name}, skipping asset."
                        )
                    continue
                raw_properties = rg_results_as_dict["data"][0]["properties"]

                public_key = raw_properties["publicKey"]

                object_to_add = SshKey(
                    resourceId=resourceId,
                    name=name,
                    resourceGroup=resource_group,
                    publicKey=public_key,
                    provider=resource_type,
                )
                json_key = "sshKeys"

            elif resource_type == "microsoft.network/networkinterfaces":
                str_query = f"resources | where type == 'microsoft.network/networkinterfaces' and name == '{name}'"
                query = arg.models.QueryRequest(
                    subscriptions=[sub_id], query=str_query, options=rg_query_options,
                )
                try:
                    rg_results_as_dict = rg_client.resources(query=query).__dict__
                except:
                    if DEBUGGING:
                        print(
                            f"ERROR: Couldn't execute resource graph query of {name}, skipping asset."
                        )
                    continue
                raw_properties = rg_results_as_dict["data"][0]["properties"]
                ip_configs = []
                for ip_config in raw_properties["ipConfigurations"]:
                    config_name = ip_config["name"]
                    config_id = ip_config["id"]
                    ip_config_properties = ip_config.get("properties")
                    ip_config_properties.setdefault("publicIPAddress", {"id": None})
                    comined_object = {
                        "id": config_id,
                        "name": config_name,
                        "privateIpAddress": ip_config_properties["privateIPAddress"],
                        "publicIpAddressId": ip_config_properties[
                            "publicIPAddress"
                        ].get("id"),
                        "subnetId": ip_config_properties.get("subnet").get("id"),
                    }
                    ip_configs.append(comined_object)
                network_security_group = raw_properties.get("networkSecurityGroup")
                nsg_id = (
                    network_security_group.get("id") if network_security_group else None
                )

                object_to_add = NetworkInterface(
                    resourceId=resourceId,
                    name=name,
                    resourceGroup=resource_group,
                    ipConfigs=ip_configs,
                    networkSecurityGroupId=nsg_id,
                    provider=resource_type,
                )
                comined_object = None
                json_key = "networkInterfaces"

            elif resource_type == "microsoft.network/networksecuritygroups":
                str_query = f"resources | where type =~ 'Microsoft.Network/networkSecurityGroups' and name == '{name}'"
                query = arg.models.QueryRequest(
                    subscriptions=[sub_id], query=str_query, options=rg_query_options,
                )
                try:
                    rg_results_as_dict = rg_client.resources(query=query).__dict__
                except:
                    if DEBUGGING:
                        print(
                            f"ERROR: Couldn't execute resource graph query of {name}, skipping asset."
                        )
                    continue
                raw_properties = rg_results_as_dict["data"][0]["properties"]
                subnetIds = []
                try:
                    for subnet in raw_properties["subnets"]:
                        subnetIds.append(subnet["id"])
                except KeyError:
                    subnetIds = []
                inbound_rules, outbound_rules = [], []
                combinedRules = (
                    raw_properties["defaultSecurityRules"]
                    + raw_properties["securityRules"]
                )
                for rule in combinedRules:
                    rule_id = rule["id"]
                    rule_name = rule["name"]
                    sourceport = (
                        rule["properties"]["sourcePortRange"]
                        if rule["properties"].get("sourcePortRange")
                        else rule["properties"]["sourcePortRanges"]
                    )
                    destport = (
                        rule["properties"]["destinationPortRange"]
                        if rule["properties"].get("destinationPortRange")
                        else rule["properties"]["destinationPortRanges"]
                    )
                    protocol = rule["properties"]["protocol"]
                    source = (
                        rule["properties"]["sourceAddressPrefix"]
                        if rule["properties"].get("sourceAddressPrefix")
                        else rule["properties"]["sourceAddressPrefixes"]
                    )
                    destination = (
                        rule["properties"]["destinationAddressPrefix"]
                        if rule["properties"].get("destinationAddressPrefix")
                        else rule["properties"]["destinationAddressPrefixes"]
                    )
                    action = rule["properties"]["access"]
                    direction = rule["properties"]["direction"]
                    security_rule = SecurityRule(
                        resourceId=rule_id,
                        name=rule_name,
                        source_port=sourceport,
                        dest_port=destport,
                        protocol=protocol,
                        source=source,
                        destination=destination,
                        action=action,
                        direction=direction,
                        resourceGroup=resource_group,
                    )
                    if rule["properties"]["direction"] == "Inbound":
                        inbound_rules.append(security_rule.__dict__)
                    else:
                        outbound_rules.append(security_rule.__dict__)
                combinedRules = None

                object_to_add = NetworkSecurityGroup(
                    resourceId=resourceId,
                    name=name,
                    resourceGroup=resource_group,
                    inboundSecurityRules=inbound_rules,
                    outboundSecurityRules=outbound_rules,
                    subnetIds=subnetIds,
                    provider=resource_type,
                )
                inbound_rules, outbound_rules = None, None
                json_key = "networkSecurityGroups"

            elif resource_type == "microsoft.network/publicipaddresses":
                str_query = f"resources | where type =~ 'Microsoft.Network/publicIPAddresses' and name == '{name}'"
                query = arg.models.QueryRequest(
                    subscriptions=[sub_id], query=str_query, options=rg_query_options,
                )
                try:
                    rg_results_as_dict = rg_client.resources(query=query).__dict__
                except:
                    if DEBUGGING:
                        print(
                            f"ERROR: Couldn't execute resource graph query of {name}, skipping asset."
                        )
                    continue
                raw_properties = rg_results_as_dict["data"][0]["properties"]

                address = (
                    raw_properties["ipAddress"]
                    if raw_properties.get("ipAddress")
                    else raw_properties["publicIPAllocationMethod"]
                )
                interface_id = (
                    raw_properties["ipConfiguration"]["id"]
                    if raw_properties.get("ipConfiguration")
                    else None
                )

                object_to_add = IpAddress(
                    resourceId=resourceId,
                    name=name,
                    resourceGroup=resource_group,
                    address=address,
                    interfaceId=interface_id,
                    provider=resource_type,
                )
                json_key = "publicIpAddresses"

            elif resource_type == "microsoft.network/virtualnetworks":
                str_query = f"resources | where type =~ 'Microsoft.Network/virtualNetworks' and name == '{name}'"
                query = arg.models.QueryRequest(
                    subscriptions=[sub_id], query=str_query, options=rg_query_options,
                )
                try:
                    rg_results_as_dict = rg_client.resources(query=query).__dict__
                except:
                    if DEBUGGING:
                        print(
                            f"ERROR: Couldn't execute resource graph query of {name}, skipping asset."
                        )
                    continue
                raw_properties = rg_results_as_dict["data"][0]["properties"]

                address_space = raw_properties["addressSpace"]["addressPrefixes"]
                # Cant find connected_devices in resource graph, but we reach the connection through networkInterfaces instead
                subnets = []
                for subnet in raw_properties["subnets"]:
                    subnet_name = subnet["name"]
                    subnet_id = subnet["id"]
                    ip_configs = (
                        subnet["properties"].get("ipConfigurations")
                        if subnet["properties"].get("ipConfigurations")
                        else []
                    )
                    address_prefix = (
                        subnet["properties"].get("addressPrefix")
                        if subnet["properties"].get("addressPrefix")
                        else []
                    )
                    try:
                        nsg = subnet["properties"]["networkSecurityGroup"]["id"]
                    except KeyError:
                        nsg = None
                    subnet_class = Subnet(
                        resourceId=subnet_id,
                        name=subnet_name,
                        ipConfigs=ip_configs,
                        addressPrefix=address_prefix,
                        vnetId=resourceId,
                        networkSecurityGroup=nsg,
                    )
                    subnets.append(subnet_class.__dict__)
                object_to_add = Vnet(
                    resourceId=resourceId,
                    name=name,
                    resourceGroup=resource_group,
                    addressSpace=address_space,
                    subnets=subnets,
                    provider=resource_type,
                )
                subnets = None
                json_key = "vnets"

            elif resource_type == "microsoft.network/virtualnetworkgateways":
                str_query = f"resources | where type =~ 'microsoft.network/virtualnetworkgateways' and name == '{name}'"
                query = arg.models.QueryRequest(
                    subscriptions=[sub_id], query=str_query, options=rg_query_options,
                )
                try:
                    rg_results_as_dict = rg_client.resources(query=query).__dict__
                except:
                    if DEBUGGING:
                        print(
                            f"ERROR: Couldn't execute resource graph query of {name}, skipping asset."
                        )
                    continue
                raw_properties = rg_results_as_dict["data"][0]["properties"]

                capacity = raw_properties["sku"]["capacity"]
                raw_ip_configs = raw_properties["ipConfigurations"]
                ip_configs = []
                for raw_ip_config in raw_ip_configs or []:
                    ip_config = {
                        "id": raw_ip_config["id"],
                        "name": raw_ip_config["name"],
                        "publicIpAddress": raw_ip_config["properties"][
                            "publicIPAddress"
                        ]["id"],
                        "subnet": raw_ip_config["properties"]["subnet"]["id"],
                    }
                    ip_configs.append(ip_config)
                raw_bgp_settings = raw_properties["bgpSettings"]
                bgp_settings = []
                for raw_bgp_setting in (
                    raw_bgp_settings.get("bgpPeeringAddresses") or []
                ):
                    bgp_setting = {
                        "ipConfigId": raw_bgp_setting["ipconfigurationId"],
                        "tunnelIpAddress": raw_bgp_setting["tunnelIpAddresses"]
                        if raw_bgp_setting.get("tunnelIpAddresses")
                        else [],
                        "customBgpIpAddresses": raw_bgp_setting["customBgpIpAddresses"],
                        "defaultBgpIpAddresses": raw_bgp_setting[
                            "defaultBgpIpAddresses"
                        ],
                    }
                    bgp_settings.append(bgp_setting)
                final_bgp_setting = {
                    "bgpPeeringAddresses": bgp_settings,
                    "asn": raw_bgp_settings["asn"],
                    "bgpPeeringAddress": raw_bgp_settings["bgpPeeringAddress"]
                    if raw_bgp_settings.get("bgpPeeringAddress")
                    else None,
                }

                object_to_add = VnetGateway(
                    gwId=resourceId,
                    name=name,
                    resourceGroup=resource_group,
                    ipConfigs=ip_configs,
                    bgpSettings=final_bgp_setting,
                    capacity=capacity,
                    provider=resource_type,
                )
                json_key = "vnetGateways"

            elif resource_type == "microsoft.network/localnetworkgateways":
                str_query = f"resources | where type =~ 'Microsoft.Network/localnetworkgateways' and name == '{name}'"
                query = arg.models.QueryRequest(
                    subscriptions=[sub_id], query=str_query, options=rg_query_options,
                )
                try:
                    rg_results_as_dict = rg_client.resources(query=query).__dict__
                except:
                    if DEBUGGING:
                        print(
                            f"ERROR: Couldn't execute resource graph query of {name}, skipping asset."
                        )
                    continue
                raw_properties = rg_results_as_dict["data"][0]["properties"]
                try:
                    local_Network_AddressSpace = raw_properties["localNetworkAddressSpace"]["addressPrefixes"]
                except KeyError:
                    local_Network_AddressSpace = []
                try:
                    gw_ip = raw_properties["gatewayIpAddress"]
                except KeyError:
                    gw_ip = None
                try:
                    bgp_setting = raw_properties["bgpSettings"]
                except KeyError:
                    bgp_setting = None

                object_to_add = LocalNetworkGateway(
                    gwId=resourceId,
                    name=name,
                    resourceGroup=resource_group,
                    localNetworkAddressSpace=local_Network_AddressSpace,
                    gatewayIp=gw_ip,
                    provider=resource_type,
                    bgpSettings=bgp_setting,
                )
                json_key = "localNetworkGateways"

            elif resource_type == "microsoft.network/connections":
                str_query = f"resources | where type =~ 'Microsoft.Network/connections' and name == '{name}'"
                query = arg.models.QueryRequest(
                    subscriptions=[sub_id], query=str_query, options=rg_query_options,
                )
                try:
                    rg_results_as_dict = rg_client.resources(query=query).__dict__
                except:
                    if DEBUGGING:
                        print(
                            f"ERROR: Couldn't execute resource graph query of {name}, skipping asset."
                        )
                    continue
                raw_properties = rg_results_as_dict["data"][0]["properties"]

                source, target = None, None
                connectionType = raw_properties["connectionType"]
                if connectionType == "Vnet2Vnet":
                    source = raw_properties["virtualNetworkGateway1"]["id"]
                    target = raw_properties["virtualNetworkGateway2"]["id"]
                # TODO: Add logic for the other connectionTypes

                if source and target:
                    object_to_add = Connection(
                        resourceId=resourceId,
                        name=name,
                        resourceGroup=resource_group,
                        connectionType=connectionType,
                        source=source,
                        target=target,
                        provider=resource_type,
                    )
                    json_key = "connections"

            elif resource_type == "microsoft.network/routetables":
                str_query = f"resources | where type =~ 'microsoft.network/routeTables' and name == '{name}'"
                query = arg.models.QueryRequest(
                    subscriptions=[sub_id], query=str_query, options=rg_query_options,
                )
                try:
                    rg_results_as_dict = rg_client.resources(query=query).__dict__
                except:
                    if DEBUGGING:
                        print(
                            f"ERROR: Couldn't execute resource graph query of {name}, skipping asset."
                        )
                    continue
                raw_properties = rg_results_as_dict["data"][0]["properties"]

                subnets = []
                raw_subnets = (
                    raw_properties["subnets"] if raw_properties.get("subnets") else []
                )
                for raw_subnet in raw_subnets:
                    subnets.append(raw_subnet["id"])
                raw_routes = (
                    raw_properties["routes"] if raw_properties.get("routes") else []
                )
                routes = []
                for raw_route in raw_routes:
                    route = {
                        "id": raw_route["id"],
                        "name": raw_route["name"],
                        "addressPrefix": raw_route["properties"]["addressPrefix"],
                        "nextHopType": raw_route["properties"]["nextHopType"],
                    }
                    routes.append(route)

                object_to_add = RouteTable(
                    resourceId=resourceId,
                    name=name,
                    resourceGroup=resource_group,
                    subnets=subnets,
                    routes=routes,
                    provider=resource_type,
                )
                json_key = "routeTables"

            elif resource_type == "microsoft.storage/storageaccounts":
                kind = resource.kind

                str_query = f"resources | where type =~ 'microsoft.storage/storageaccounts' and name == '{name}'"
                query = arg.models.QueryRequest(
                    subscriptions=[sub_id], query=str_query, options=rg_query_options,
                )
                try:
                    rg_results_as_dict = rg_client.resources(query=query).__dict__
                except:
                    if DEBUGGING:
                        print(
                            f"ERROR: Couldn't execute resource graph query of {name}, skipping asset."
                        )
                    continue
                raw_properties = rg_results_as_dict["data"][0]["properties"]

                primary_endpoints = raw_properties["primaryEndpoints"]

                # TODO: Add consequence of this being enabled
                allow_blob_public_access = raw_properties.get("allowBlobPublicAccess")
                if allow_blob_public_access != True:
                    allow_blob_public_access = None

                # Firewall rules
                private_endpoints = raw_properties.get("privateEndpointConnections")
                try:
                    raw_vnet_rules = raw_properties.get("networkAcls").get(
                        "virtualNetworkRules"
                    )
                    vnet_rules = [
                        x.get("id") for x in raw_vnet_rules if x.get("id") != None
                    ]
                except:
                    vnet_rules = []
                try:
                    raw_ip_rules = raw_properties.get("networkAcls").get("ipRules")
                    ip_rules = [
                        x.get("id") for x in raw_ip_rules if x.get("id") != None
                    ]
                except:
                    ip_rules = []
                bypass_services = (
                    True
                    if raw_properties.get("networkAcls").get("bypass")
                    == "AzureServices"
                    else False
                )

                # If any networks can access the storage account or not
                try:
                    restricted_access = (
                        True
                        if raw_properties.get("networkAcls").get("defaultAction")
                        == "Deny"
                        else False
                    )
                except KeyError:
                    # Default to allow all
                    restricted_access = False

                try:
                    store_client = StorageManagementClient(
                        credential=credentials, subscription_id=sub_id
                    )
                except:
                    if DEBUGGING:
                        print(
                            f"Not able to access StorageManagmentClient on subscription {sub_id}"
                        )
                    store_client = None
                services = []
                if store_client:
                    # BlobContainers
                    try:
                        blob_containers = store_client.blob_containers.list(
                            resource_group_name=resource_group, account_name=name
                        )
                        for blobcontainer in blob_containers or []:
                            try:
                                blobcontainer_dict = blobcontainer.__dict__
                                public_access_raw = blobcontainer_dict.get(
                                    "public_access"
                                )
                                allow_blob_public_access = (
                                    True
                                    if public_access_raw.lower()
                                    in ["blob", "container"]
                                    else False
                                )
                                container = StorageAccountService(
                                    name=blobcontainer_dict.get("name"),
                                    serviceType="blob",
                                    resourceId=blobcontainer_dict.get("id"),
                                    allowBlobPublicAccess=allow_blob_public_access,
                                )
                                services.append(container.__dict__)
                            except AttributeError as e:
                                print(
                                    f"Attribute Error caught when fetching blobcontainers. Check azure-mgmt-storage package for changed fields. Traceback: \n {e}"
                                )
                    except ValueError:
                        if DEBUGGING:
                            print(
                                f"Could not list blob containers on storage account: {name}. Check permissions"
                            )
                    # FileShares
                    try:
                        file_shares = store_client.file_shares.list(
                            resource_group_name=resource_group, account_name=name
                        )
                        for fs in file_shares or []:
                            file_share = StorageAccountService(
                                name=fs.name, serviceType="fileShare", resourceId=fs.id
                            )
                            services.append(file_share.__dict__)
                        file_shares = None
                    except:
                        if DEBUGGING:
                            print(
                                f"Could not list file share services on storage account: {name}"
                            )
                        pass
                    # Tables
                    try:
                        tables = store_client.table.list(
                            resource_group_name=resource_group, account_name=name
                        )
                        for table in tables or []:
                            table_service = StorageAccountService(
                                name=table.name,
                                serviceType="table",
                                resourceId=table.id,
                            )
                            services.append(table_service.__dict__)
                        tables = None
                    except:
                        if DEBUGGING:
                            print(
                                f"Could not list table services on storage account: {name}"
                            )
                        pass
                    # Queues
                    try:
                        queues = store_client.queue.list(
                            resource_group_name=resource_group, account_name=name
                        )
                        for que in queues or []:
                            queue_service = StorageAccountService(
                                name=que.name, serviceType="queue", resourceId=que.id
                            )
                            services.append(queue_service.__dict__)
                        queues = None
                    except:
                        if DEBUGGING:
                            print(
                                f"Could not list queue services on storage account: {name}"
                            )
                        pass

                object_to_add = StorageAccount(
                    resourceId=resourceId,
                    name=name,
                    kind=kind,
                    resourceGroup=resource_group,
                    primaryEndpoints=primary_endpoints,
                    services=services,
                    provider=resource_type,
                    httpsOnly=raw_properties.get("supportsHttpsTrafficOnly"),
                    restrictedAccess=restricted_access,
                    privateEndpoints=private_endpoints,
                    virtualNetworkRules=vnet_rules,
                    ipRangeFilter=ip_rules,
                    bypassServices=bypass_services,
                )

                json_key = "storageAccounts"

            elif resource_type == "microsoft.documentdb/databaseaccounts":
                str_query = f"resources | where type =~ 'microsoft.documentdb/databaseaccounts' and name == '{name}'"
                query = arg.models.QueryRequest(
                    subscriptions=[sub_id], query=str_query, options=rg_query_options,
                )
                try:
                    rg_results_as_dict = rg_client.resources(query=query).__dict__
                except:
                    if DEBUGGING:
                        print(
                            f"ERROR: Couldn't execute resource graph query of {name}, skipping asset."
                        )
                    continue
                raw_properties = rg_results_as_dict["data"][0]["properties"]

                virtual_network_rules = []
                try:
                    raw_network_rules = raw_properties["virtualNetworkRules"]
                    for raw_nwr in raw_network_rules or []:
                        nwr_id = raw_nwr.get("id")
                        if nwr_id:
                            virtual_network_rules.append(nwr_id)
                except KeyError:
                    pass

                # If any networks can access the cosmosDB account or not
                restricted_access = (
                    False
                    if raw_properties.get("isVirtualNetworkFilterEnabled") == False
                    else True
                )

                # ipRangeFilter
                try:
                    raw_iprange = raw_properties["ipRangeFilter"]
                    ip_range_filter = raw_iprange.split(",")
                except:
                    ip_range_filter = []

                # disableKeyBasedMetadataWriteAccess
                disable_key_based_metadata_write_access = (
                    False
                    if raw_properties.get("disableKeyBasedMetadataWriteAccess") == False
                    else True
                )

                raw_api_types = raw_properties.get("EnabledApiTypes")
                trimmed_api_types = str(raw_api_types).replace(" ", "")
                api_types = trimmed_api_types.split(",")

                # TODO: Try and find the actual databases, containers and so on.
                """try:
                    cosmos_client = CosmosDBManagementClient(
                        credentials=credential, subscription_id=sub_id
                    )
                except:
                    print(
                        f"Could not initialise CosmosDBClient on {resourceId} to list databases and containers"
                    )
                try:
                    sql_databases = cosmos_client.sql_resources.list_sql_databases(
                        resource_group_name=resource_group, account_name=name
                    )
                    print(sql_databases)
                    mylist = [x for x in sql_databases.next]
                    print("hello: ", mylist)
                    print(type(sql_databases))
                    for x in sql_databases.next() or []:
                        print(x)
                except:
                    print(
                        f"Could not list sql databases in cosmosdb account {name} in resource_group {resource_group}"
                    )"""

                object_to_add = CosmosDB(
                    resourceId=resourceId,
                    name=name,
                    resourceGroup=resource_group,
                    provider=resource_type,
                    restrictedAccess=restricted_access,
                    virtualNetworkRules=virtual_network_rules,
                    ipRangeFilter=ip_range_filter,
                    apiTypes=api_types,
                    disableKeyBasedMetadataWriteAccess=disable_key_based_metadata_write_access,
                )

                json_key = "cosmosDBs"

            elif resource_type == "microsoft.web/sites":
                str_query = f"resources | where type =~ 'microsoft.web/sites' and name == '{name}'"
                query = arg.models.QueryRequest(
                    subscriptions=[sub_id], query=str_query, options=rg_query_options,
                )
                try:
                    rg_results_as_dict = rg_client.resources(query=query).__dict__
                except:
                    if DEBUGGING:
                        print(
                            f"ERROR: Couldn't execute resource graph query of {name}, skipping asset."
                        )
                    continue
                kind = resource.kind
                # The principal type and system assigned managed identity
                try:
                    principal_id = rg_results_as_dict["data"][0]["identity"][
                        "principalId"
                    ]
                except (KeyError, TypeError):
                    if DEBUGGING:
                        print(
                            f"Couldn't find the principal Id of the app service {name}."
                        )
                    principal_id = None
                try:
                    principal_type = rg_results_as_dict["data"][0]["identity"]["type"]
                except (KeyError, TypeError):
                    if DEBUGGING and principal_id:
                        print(
                            f"Couldn't find the principal type of the app service {name}."
                        )
                    principal_type = None
                # If managed identity is activated on the resource it has a principal Id
                try:
                    raw_user_assigned_ids = rg_results_as_dict["data"][0]["identity"][
                        "userAssignedIdentities"
                    ]
                    user_assigned_ids = []
                    for key, identity in raw_user_assigned_ids.items() or []:
                        user_assigned_ids.append(
                            {
                                "identityId": key,
                                "clientId": identity["clientId"],
                                "principalId": identity["principalId"],
                            }
                        )
                except (KeyError, TypeError):
                    user_assigned_ids = []

                raw_properties = rg_results_as_dict["data"][0]["properties"]

                private_endpoints = raw_properties.get("privateEndpointConnections")
                try:
                    outbound_addresses = raw_properties["outboundIpAddresses"].split(
                        ","
                    )
                except KeyError:
                    outbound_addresses = []
                try:
                    inbound_addresses = raw_properties["inboundIpAddress"].split(",")
                except KeyError:
                    inbound_addresses = []
                try:
                    https_only = raw_properties["httpsOnly"]
                except KeyError:
                    https_only = False
                try:
                    app_service_plan = raw_properties["serverFarmId"]
                except:
                    app_service_plan = None
                try:
                    ip_security_restrictions = []
                    authentication_enabled = False
                    # To get Access restrictions of App Services, we need the resource explorer API
                    endpoint = f"https://management.azure.com/subscriptions/{sub_id}/resourceGroups/{resource_group}/providers/Microsoft.Web/sites/{name}/config?api-version=2020-10-01"
                    try:
                        resource_explorer_data = requests.get(
                            url=endpoint, headers=headers
                        ).json()
                    except:
                        if DEBUGGING:
                            print(f"WARNING: Not allowed API request GET {endpoint}")
                        resource_explorer_data = {}
                    try:
                        site_properties = resource_explorer_data["value"][0][
                            "properties"
                        ]
                    except:
                        if DEBUGGING:
                            print(
                                f"Error getting properties field on object returned from {resource_explorer_data}."
                            )
                        site_properties = None
                    ip_security_restrictions = []
                    if site_properties:
                        try:
                            raw_ip_restrictions = site_properties[
                                "ipSecurityRestrictions"
                            ]
                            for ip_config in raw_ip_restrictions or []:
                                if (
                                    ip_config.get("action").lower() == "allow"
                                ):  # Ignore Deny rules
                                    if ip_config.get("ipAddress") != None:
                                        if ip_config.get("ipAddress") not in [
                                            "",
                                            "undefined/undefined",
                                        ]:
                                            ip_security_restrictions.append(
                                                ip_config["ipAddress"]
                                            )
                                    elif ip_config.get("vnetSubnetResourceId") != None:
                                        ip_security_restrictions.append(
                                            ip_config["vnetSubnetResourceId"]
                                        )
                                    else:
                                        if DEBUGGING:
                                            print(
                                                f"Could not extract the ipAddress or vnetSubnetResourceId field of {ip_config} in {name}"
                                            )
                                else:
                                    if ip_config.get("action") == None and DEBUGGING:
                                        print(
                                            f"No action field in ip_config object {ip_config} when looking ad ipSecurityRestrictions of Web/Function App."
                                        )
                        except:
                            if DEBUGGING:
                                print(
                                    f"Error in fetching ipSecurityRestrictions from {site_properties} in {name}."
                                )
                            pass
                        # Get Authentication values
                        endpoint = f"https://management.azure.com/subscriptions/{sub_id}/resourceGroups/{resource_group}/providers/Microsoft.Web/sites/{name}/config/authsettings/list?api-version=2020-10-01"
                        try:
                            resource_explorer_data = requests.post(
                                url=endpoint, headers=headers
                            ).json()
                        except:
                            if DEBUGGING:
                                print(f"Not allowed API request POST {endpoint}")
                            resource_explorer_data = {}
                        try:
                            auth_properties = resource_explorer_data["properties"]
                        except:
                            if DEBUGGING:
                                print(
                                    f"Error getting properties field on object returned from {resource_explorer_data}."
                                )
                            auth_properties = None
                        try:
                            authentication_enabled = auth_properties["enabled"]
                            if authentication_enabled == None:
                                if DEBUGGING:
                                    print(
                                        f"Not allowed to list siteAuthSettings of {name}, defaulting siteAuthentication enabled value to False. Give the app Microsoft.Web/sites/config/list/action API permission to fix this issue."
                                    )
                                authentication_enabled = False
                        except KeyError:
                            authentication_enabled = False
                except:
                    pass

                object_to_add = AppService(
                    resourceId=resourceId,
                    name=name,
                    resourceGroup=resource_group,
                    provider=resource_type,
                    principalId=principal_id,
                    principalType=principal_type,
                    userAssignedIdentities=user_assigned_ids,
                    kind=kind,
                    privateEndpoints=private_endpoints,
                    outboundAddresses=outbound_addresses,
                    inboundAddresses=inbound_addresses,
                    httpsOnly=https_only,
                    serverFarmId=app_service_plan,
                    authenticationEnabled=authentication_enabled,
                    ipSecurityRestrictions=ip_security_restrictions,
                )
                json_key = "appServices"

            elif resource_type == "microsoft.web/serverfarms":
                str_query = f"resources | where type =~ 'microsoft.web/serverfarms' and name == '{name}'"
                query = arg.models.QueryRequest(
                    subscriptions=[sub_id], query=str_query, options=rg_query_options,
                )
                try:
                    rg_results_as_dict = rg_client.resources(query=query).__dict__
                except:
                    if DEBUGGING:
                        print(
                            f"ERROR: Couldn't execute resource graph query of {name}, skipping asset."
                        )
                    continue
                raw_sku = rg_results_as_dict["data"][0]["sku"]
                family = raw_sku["family"]

                object_to_add = AppServicePlan(
                    resourceId=resourceId,
                    name=name,
                    resourceGroup=resource_group,
                    provider=resource_type,
                    family=family,
                )
                json_key = "appServicePlans"

            elif resource_type == "microsoft.servicebus/namespaces":
                str_query = f"resources | where type =~ 'microsoft.servicebus/namespaces' and name == '{name}'"
                query = arg.models.QueryRequest(
                    subscriptions=[sub_id], query=str_query, options=rg_query_options,
                )
                try:
                    rg_results_as_dict = rg_client.resources(query=query).__dict__
                except:
                    if DEBUGGING:
                        print(
                            f"ERROR: Couldn't execute resource graph query of {name}, skipping asset."
                        )
                    continue
                raw_sku = rg_results_as_dict["data"][0]["sku"]
                tier = raw_sku["tier"]
                headers = {"Authorization": "Bearer " + bearer_token}
                # To get authorization rules data from resource explorer API.
                endpoint = f"https://management.azure.com/subscriptions/{sub_id}/resourceGroups/{resource_group}/providers/Microsoft.ServiceBus/namespaces/{name}/AuthorizationRules?api-version=2015-08-01"
                try:
                    resource_explorer_data = requests.get(
                        url=endpoint, headers=headers
                    ).json()
                except:
                    if DEBUGGING:
                        print(f"WARNING: Not allowed API request GET {endpoint}")
                    resource_explorer_data = {}
                authorization_rules = []
                raw_rules = resource_explorer_data["value"]
                for raw_rule in raw_rules:
                    authorization_rule = {
                        "id": raw_rule["id"],
                        "name": raw_rule["name"],
                        "rights": raw_rule["properties"]["rights"],
                    }
                    authorization_rules.append(authorization_rule)
                endpoint = f"https://management.azure.com/subscriptions/{sub_id}/resourceGroups/{resource_group}/providers/Microsoft.ServiceBus/namespaces/{name}/queues?api-version=2015-08-01"
                try:
                    resource_explorer_data = requests.get(
                        url=endpoint, headers=headers
                    ).json()
                except:
                    if DEBUGGING:
                        print(f"WARNING: Not allowed API request GET {endpoint}")
                    resource_explorer_data = {}
                queues = []
                raw_queue_data = resource_explorer_data["value"]
                if raw_queue_data:
                    for raw_queue in raw_queue_data:
                        queue = {
                            "id": raw_queue["id"],
                            "name": raw_queue["name"],
                        }
                        queues.append(queue)
                endpoint = f"https://management.azure.com/subscriptions/{sub_id}/resourceGroups/{resource_group}/providers/Microsoft.ServiceBus/namespaces/{name}/topics?api-version=2015-08-01"
                try:
                    resource_explorer_data = requests.get(
                        url=endpoint, headers=headers
                    ).json()
                except:
                    if DEBUGGING:
                        print(f"WARNING: Not allowed API request GET {endpoint}")
                    resource_explorer_data = {}
                topics = []
                raw_topic_data = resource_explorer_data["value"]
                if raw_topic_data:
                    for raw_topic in raw_topic_data:
                        topic = {
                            "id": raw_topic["id"],
                            "name": raw_topic["name"],
                        }
                        topics.append(topic)
                object_to_add = ServiceBus(
                    resourceId=resourceId,
                    name=name,
                    resourceGroup=resource_group,
                    provider=resource_type,
                    tier=tier,
                    authorizationRules=authorization_rules,
                    queues=queues,
                    topics=topics,
                )
                json_key = "serviceBuses"

            elif resource_type == "microsoft.insights/components":
                app_insights_dump = __get_application_insights(
                    sub_id=sub_id,
                    rsg_name=resource_group,
                    app_insight_name=name,
                    headers=headers,
                )
                if app_insights_dump != None:
                    try:
                        json_representation["applicationInsights"].append(
                            app_insights_dump
                        )
                    except KeyError:
                        json_representation.setdefault(
                            "applicationInsights", [app_insights_dump]
                        )
                    except AttributeError:
                        json_representation.setdefault(
                            "applicationInsights", [app_insights_dump]
                        )

            elif resource_type == "microsoft.sql/servers":
                str_query = f"resources | where type =~ 'microsoft.sql/servers' and name == '{name}'"
                query = arg.models.QueryRequest(
                    subscriptions=[sub_id], query=str_query, options=rg_query_options,
                )
                try:
                    rg_results_as_dict = rg_client.resources(query=query).__dict__
                except:
                    if DEBUGGING:
                        print(
                            f"ERROR: Couldn't execute resource graph query of {name}, skipping asset."
                        )
                    continue
                raw_properties = rg_results_as_dict["data"][0]["properties"]
                try:
                    privateEndpoints = raw_properties["privateEndpointConnections"]
                except KeyError:
                    if DEBUGGING:
                        print(
                            f"Couldn't find privateEndpointConnections of sql server {name}"
                        )
                    privateEndpoints = []
                try:
                    publicNetworkAccess = raw_properties["publicNetworkAccess"]
                except KeyError:
                    if DEBUGGING:
                        print(f"Couldn't find publicNetworkAccess of sql server {name}")
                    publicNetworkAccess = "Disabled"
                # To get database data from the resource exlporer
                endpoint = f"https://management.azure.com/subscriptions/{sub_id}/resourceGroups/{resource_group}/providers/Microsoft.Sql/servers/{name}/databases?api-version=2020-08-01-preview"
                try:
                    resource_explorer_data = requests.get(
                        url=endpoint, headers=headers
                    ).json()
                except:
                    if DEBUGGING:
                        print(
                            f"Error running API call {endpoint}. Could be a bad authentication due to Bearer token."
                        )
                    resource_explorer_data = {}
                databases = []
                raw_database_data = resource_explorer_data.get("value")
                if raw_database_data:
                    for raw_database in raw_database_data:
                        database = {
                            "id": raw_database["id"],
                            "name": raw_database["name"],
                            "tier": raw_database["sku"]["tier"],
                            "provider": raw_database["type"],
                        }
                        databases.append(database)

                # To get the virtual network rules from the resource exlporer
                endpoint = f"https://management.azure.com/subscriptions/{sub_id}/resourceGroups/{resource_group}/providers/Microsoft.Sql/servers/{name}/virtualNetworkRules?api-version=2020-08-01-preview"
                try:
                    resource_explorer_data = requests.get(
                        url=endpoint, headers=headers
                    ).json()
                except:
                    if DEBUGGING:
                        print(
                            f"Error running API call {endpoint}. Could be a bad authentication due to Bearer token."
                        )
                    resource_explorer_data = {}
                virtualNetworkRules = []
                raw_virtualNetworkRules_data = resource_explorer_data.get("value")
                if raw_virtualNetworkRules_data:
                    for raw_networkrule in raw_virtualNetworkRules_data:
                        network_rule = raw_networkrule["properties"].get(
                            "virtualNetworkSubnetId"
                        )
                        if network_rule not in [None, ""]:
                            virtualNetworkRules.append(network_rule)

                endpoint = f"https://management.azure.com/subscriptions/{sub_id}/resourceGroups/{resource_group}/providers/Microsoft.Sql/servers/{name}/firewallRules?api-version=2020-08-01-preview"
                try:
                    resource_explorer_data = requests.get(
                        url=endpoint, headers=headers
                    ).json()
                except:
                    if DEBUGGING:
                        print(
                            f"Error running API call {endpoint}. Could be a bad authentication due to Bearer token."
                        )
                    resource_explorer_data = {}
                firewallRules = []
                raw_firewallRules_data = resource_explorer_data.get("value")
                if raw_firewallRules_data:
                    for raw_firewallRule in raw_firewallRules_data:
                        try:
                            start_ip_address = raw_firewallRule["properties"][
                                "startIpAddress"
                            ]
                            start_ip_components = raw_firewallRule["properties"][
                                "startIpAddress"
                            ].split(".")
                        except KeyError:
                            start_ip_address = None
                            start_ip_components = None
                            if DEBUGGING:
                                print(
                                    f"Could not get start ip from firewall rule {raw_firewallRule} in sql-server {name}."
                                )
                        try:
                            end_ip_address = raw_firewallRule["properties"][
                                "endIpAddress"
                            ]
                            end_ip_components = raw_firewallRule["properties"][
                                "endIpAddress"
                            ].split(".")
                        except KeyError:
                            end_ip_address = None
                            end_ip_components = None
                            if DEBUGGING:
                                print(
                                    f"Could not get end ip from firewall rule {raw_firewallRule} in sql-server {name}."
                                )
                        temp_firewallRules = __handel_ip_range(
                            start_ip_components,
                            end_ip_components,
                            start_ip_address,
                            end_ip_address,
                        )
                        firewallRules = firewallRules + temp_firewallRules

                object_to_add = SQLServer(
                    resourceId=resourceId,
                    name=name,
                    resourceGroup=resource_group,
                    provider=resource_type,
                    databases=databases,
                    privateEndpoints=privateEndpoints,
                    publicNetworkAccess=publicNetworkAccess,
                    virtualNetworkRules=virtualNetworkRules,
                    firewallRules=firewallRules,
                )
                json_key = "sqlServers"

            elif resource_type == "microsoft.dbformysql/servers":
                str_query = f"resources | where type =~ 'microsoft.dbformysql/servers' and name == '{name}'"
                query = arg.models.QueryRequest(
                    subscriptions=[sub_id], query=str_query, options=rg_query_options,
                )
                try:
                    rg_results_as_dict = rg_client.resources(query=query).__dict__
                except:
                    if DEBUGGING:
                        print(
                            f"ERROR: Couldn't execute resource graph query of {name}, skipping asset."
                        )
                    continue
                raw_properties = rg_results_as_dict["data"][0]["properties"]
                try:
                    privateEndpoints = raw_properties["privateEndpointConnections"]
                except KeyError:
                    if DEBUGGING:
                        print(
                            f"Couldn't find privateEndpointConnections of MySQL database {name}"
                        )
                    privateEndpoints = []
                try:
                    publicNetworkAccess = raw_properties["publicNetworkAccess"]
                except KeyError:
                    if DEBUGGING:
                        print(
                            f"Couldn't find publicNetworkAccess of MySQL database {name}, assuming disabled"
                        )
                    publicNetworkAccess = "Disabled"

                # To get firewall data from the resource explorer
                endpoint = f"https://management.azure.com/subscriptions/{sub_id}/resourceGroups/{resource_group}/providers/Microsoft.DBforMySQL/servers/{name}/firewallRules?api-version=2017-12-01"
                try:
                    resource_explorer_data = requests.get(
                        url=endpoint, headers=headers
                    ).json()
                except:
                    resource_explorer_data = {}
                    if DEBUGGING:
                        print(
                            f"Error running API call {endpoint}. Could be a bad authentication due to Bearer token."
                        )
                firewallRules = []
                raw_firewallRules_data = resource_explorer_data.get("value")
                if raw_firewallRules_data:
                    for raw_firewallRule in raw_firewallRules_data:
                        try:
                            start_ip_address = raw_firewallRule["properties"][
                                "startIpAddress"
                            ]
                            start_ip_components = raw_firewallRule["properties"][
                                "startIpAddress"
                            ].split(".")
                        except KeyError:
                            start_ip_address = None
                            start_ip_components = None
                            if DEBUGGING:
                                print(
                                    f"Could not get start ip from firewall rule {raw_firewallRule} in sql-server {name}."
                                )
                        try:
                            end_ip_address = raw_firewallRule["properties"][
                                "endIpAddress"
                            ]
                            end_ip_components = raw_firewallRule["properties"][
                                "endIpAddress"
                            ].split(".")
                        except KeyError:
                            end_ip_address = None
                            end_ip_components = None
                            if DEBUGGING:
                                print(
                                    f"Could not get end ip from firewall rule {raw_firewallRule} in sql-server {name}."
                                )
                        temp_firewallRules = __handel_ip_range(
                            start_ip_components,
                            end_ip_components,
                            start_ip_address,
                            end_ip_address,
                        )
                        firewallRules = firewallRules + temp_firewallRules

                # To get admin data from REST API
                endpoint = f"https://management.azure.com/subscriptions/{sub_id}/resourceGroups/{resource_group}/providers/Microsoft.DBforMySQL/servers/{name}/administrators?api-version=2017-12-01"
                try:
                    resource_explorer_data = requests.get(
                        url=endpoint, headers=headers
                    ).json()
                except:
                    resource_explorer_data = {}
                    if DEBUGGING:
                        print(
                            f"Error running API call {endpoint}. Could be a bad authentication due to Bearer token."
                        )
                adAdmins = []
                raw_adAdmin_data = resource_explorer_data.get("value")
                if raw_adAdmin_data:
                    for raw_adAdmin in raw_adAdmin_data:
                        adAdmin = {
                            "id": raw_adAdmin["id"],
                            "name": raw_adAdmin["name"],
                            "principalType": raw_adAdmin["type"],
                            "principalId": raw_adAdmin["properties"]["sid"],
                        }
                        adAdmins.append(adAdmin)
                object_to_add = MySQLDatabase(
                    resourceId=resourceId,
                    name=name,
                    resourceGroup=resource_group,
                    provider=resource_type,
                    privateEndpoints=privateEndpoints,
                    publicNetworkAccess=publicNetworkAccess,
                    firewallRules=firewallRules,
                    adAdmins=adAdmins,
                )
                json_key = "mySQLDatabases"

            elif resource_type == "microsoft.dbforpostgresql/servers":
                str_query = f"resources | where type =~ 'microsoft.dbforpostgresql/servers' and name == '{name}'"
                query = arg.models.QueryRequest(
                    subscriptions=[sub_id], query=str_query, options=rg_query_options,
                )
                try:
                    rg_results_as_dict = rg_client.resources(query=query).__dict__
                except:
                    if DEBUGGING:
                        print(
                            f"ERROR: Couldn't execute resource graph query of {name}, skipping asset."
                        )
                    continue
                raw_properties = rg_results_as_dict["data"][0]["properties"]
                try:
                    privateEndpoints = raw_properties["privateEndpointConnections"]
                except KeyError:
                    if DEBUGGING:
                        print(
                            f"Couldn't find privateEndpointConnections of PostgreSQL database {name}"
                        )
                    privateEndpoints = []
                try:
                    publicNetworkAccess = raw_properties["publicNetworkAccess"]
                except KeyError:
                    if DEBUGGING:
                        print(
                            f"Couldn't find publicNetworkAccess of PostgreSQL database {name}"
                        )
                    publicNetworkAccess = "Disabled"

                # To get firewall data from the resource explorer
                endpoint = f"https://management.azure.com/subscriptions/{sub_id}/resourceGroups/{resource_group}/providers/Microsoft.DBforPostgreSQL/servers/{name}/firewallRules?api-version=2017-12-01"
                try:
                    resource_explorer_data = requests.get(
                        url=endpoint, headers=headers
                    ).json()
                except:
                    resource_explorer_data = {}
                    if DEBUGGING:
                        print(
                            f"Error running API call {endpoint}. Could be a bad authentication due to Bearer token."
                        )
                firewallRules = []
                raw_firewallRules_data = resource_explorer_data.get("value")
                if raw_firewallRules_data:
                    for raw_firewallRule in raw_firewallRules_data:
                        try:
                            start_ip_address = raw_firewallRule["properties"][
                                "startIpAddress"
                            ]
                            start_ip_components = raw_firewallRule["properties"][
                                "startIpAddress"
                            ].split(".")
                        except KeyError:
                            start_ip_address = None
                            start_ip_components = None
                            if DEBUGGING:
                                print(
                                    f"Could not get start ip from firewall rule {raw_firewallRule} in sql-server {name}."
                                )
                        try:
                            end_ip_address = raw_firewallRule["properties"][
                                "endIpAddress"
                            ]
                            end_ip_components = raw_firewallRule["properties"][
                                "endIpAddress"
                            ].split(".")
                        except KeyError:
                            end_ip_address = None
                            end_ip_components = None
                            if DEBUGGING:
                                print(
                                    f"Could not get end ip from firewall rule {raw_firewallRule} in sql-server {name}."
                                )
                        temp_firewallRules = __handel_ip_range(
                            start_ip_components,
                            end_ip_components,
                            start_ip_address,
                            end_ip_address,
                        )
                        firewallRules = firewallRules + temp_firewallRules
                # To get admin data from REST API
                endpoint = f"https://management.azure.com/subscriptions/{sub_id}/resourceGroups/{resource_group}/providers/Microsoft.DBforPostgreSQL/servers/{name}/administrators?api-version=2017-12-01"
                try:
                    resource_explorer_data = requests.get(
                        url=endpoint, headers=headers
                    ).json()
                except:
                    resource_explorer_data = {}
                    if DEBUGGING:
                        print(
                            f"Error running API call {endpoint}. Could be a bad authentication due to Bearer token."
                        )
                adAdmins = []
                raw_adAdmin_data = resource_explorer_data.get("value")
                if raw_adAdmin_data:
                    for raw_adAdmin in raw_adAdmin_data:
                        adAdmin = {
                            "id": raw_adAdmin["id"],
                            "name": raw_adAdmin["name"],
                            "principalType": raw_adAdmin["type"],
                            "principalId": raw_adAdmin["properties"]["sid"],
                        }
                        adAdmins.append(adAdmin)
                object_to_add = PostgreSQLDatabase(
                    resourceId=resourceId,
                    name=name,
                    resourceGroup=resource_group,
                    provider=resource_type,
                    privateEndpoints=privateEndpoints,
                    publicNetworkAccess=publicNetworkAccess,
                    firewallRules=firewallRules,
                    adAdmins=adAdmins,
                )
                json_key = "postgreSQLDatabases"

            elif resource_type == "microsoft.dbformariadb/servers":
                str_query = f"resources | where type =~ 'microsoft.dbformariadb/servers' and name == '{name}'"
                query = arg.models.QueryRequest(
                    subscriptions=[sub_id], query=str_query, options=rg_query_options,
                )
                try:
                    rg_results_as_dict = rg_client.resources(query=query).__dict__
                except:
                    if DEBUGGING:
                        print(
                            f"ERROR: Couldn't execute resource graph query of {name}, skipping asset."
                        )
                    continue
                raw_properties = rg_results_as_dict["data"][0]["properties"]
                try:
                    privateEndpoints = raw_properties["privateEndpointConnections"]
                except KeyError:
                    if DEBUGGING:
                        print(
                            f"Couldn't find privateEndpointConnections of MariaDB database {name}"
                        )
                    privateEndpoints = []
                try:
                    publicNetworkAccess = raw_properties["publicNetworkAccess"]
                except KeyError:
                    if DEBUGGING:
                        print(
                            f"Couldn't find publicNetworkAccess of MariaDB database {name}"
                        )
                    publicNetworkAccess = "Disabled"

                # To get firewall data from the resource explorer
                endpoint = f"https://management.azure.com/subscriptions/{sub_id}/resourceGroups/{resource_group}/providers/Microsoft.DBforMariaDB/servers/{name}/firewallRules?api-version=2017-12-01"
                try:
                    resource_explorer_data = requests.get(
                        url=endpoint, headers=headers
                    ).json()
                except:
                    resource_explorer_data = {}
                    if DEBUGGING:
                        print(
                            f"Error running API call {endpoint}. Could be a bad authentication due to Bearer token."
                        )
                firewallRules = []
                raw_firewallRules_data = resource_explorer_data.get("value")
                if raw_firewallRules_data:
                    for raw_firewallRule in raw_firewallRules_data:
                        try:
                            start_ip_address = raw_firewallRule["properties"][
                                "startIpAddress"
                            ]
                            start_ip_components = raw_firewallRule["properties"][
                                "startIpAddress"
                            ].split(".")
                        except KeyError:
                            start_ip_address = None
                            start_ip_components = None
                            if DEBUGGING:
                                print(
                                    f"Could not get start ip from firewall rule {raw_firewallRule} in sql-server {name}."
                                )
                        try:
                            end_ip_address = raw_firewallRule["properties"][
                                "endIpAddress"
                            ]
                            end_ip_components = raw_firewallRule["properties"][
                                "endIpAddress"
                            ].split(".")
                        except KeyError:
                            end_ip_address = None
                            end_ip_components = None
                            if DEBUGGING:
                                print(
                                    f"Could not get end ip from firewall rule {raw_firewallRule} in sql-server {name}."
                                )
                        temp_firewallRules = __handel_ip_range(
                            start_ip_components,
                            end_ip_components,
                            start_ip_address,
                            end_ip_address,
                        )
                        firewallRules = firewallRules + temp_firewallRules
                object_to_add = MariaDBDatabase(
                    resourceId=resourceId,
                    name=name,
                    resourceGroup=resource_group,
                    provider=resource_type,
                    privateEndpoints=privateEndpoints,
                    publicNetworkAccess=publicNetworkAccess,
                    firewallRules=firewallRules,
                )
                json_key = "mariaDBDatabases"

            elif resource_type == "microsoft.containerregistry/registries":
                str_query = f"resources | where type =~ 'microsoft.containerregistry/registries' and name == '{name}'"
                query = arg.models.QueryRequest(
                    subscriptions=[sub_id], query=str_query, options=rg_query_options,
                )
                try:
                    rg_results_as_dict = rg_client.resources(query=query).__dict__
                except:
                    if DEBUGGING:
                        print(
                            f"ERROR: Couldn't execute resource graph query of {name}, skipping asset."
                        )
                    continue
                raw_properties = rg_results_as_dict["data"][0]["properties"]
                # Access Key
                try:
                    admin_user_enabled = raw_properties["adminUserEnabled"]
                except KeyError:
                    if DEBUGGING:
                        print(
                            f"Couldn't find adminUserEnabled value of container registry {name}. Assuming disabled."
                        )
                    admin_user_enabled = False
                # Firewall Related
                try:
                    public_network_enabled = raw_properties["publicNetworkAccess"]
                except KeyError:
                    if DEBUGGING:
                        print(
                            f"Couldn't find publicNetworkAccess value of container registry {name}. Assuming default value: True."
                        )
                    public_network_enabled = "Disabled"  # Is true by default
                try:
                    private_endpoints = raw_properties["privateEndpointConnections"]
                except KeyError:
                    if DEBUGGING:
                        print(
                            f"Couldn't find privateEndpointConnections of container registry {name}"
                        )
                    private_endpoints = []
                try:
                    network_rule_set = raw_properties["networkRuleSet"]
                    try:
                        default_action = network_rule_set["defaultAction"]
                    except KeyError:
                        if DEBUGGING:
                            print(
                                f"Couldn't find defaultActions of networkRuleSet in container registry {name}"
                            )
                        default_action = "Deny"
                    try:
                        ip_rules = (
                            network_rule_set.get("ipRules")
                            if type(network_rule_set.get("ipRules")) == list
                            else []
                        )
                        firewall_rules = [
                            x["value"] for x in ip_rules if x.get("value") != None
                        ]
                    except KeyError:
                        if DEBUGGING:
                            print(f"Couldn't find ipRules of container registry {name}")
                        firewall_rules = []
                    try:
                        # Can't seem to be able to set virtual network rules just yet, but the field is within the resource graph, so let's fetch it
                        virtual_network_rules = network_rule_set["virtualNetworkRules"]
                    except KeyError:
                        if DEBUGGING:
                            print(
                                f"Couldn't find virtualNetworkRules of container registry {name}"
                            )
                        virtual_network_rules = []
                except KeyError:
                    if DEBUGGING:
                        print(
                            f"Couldn't find networkRuleSet of container registry {name}"
                        )
                    pass
                    firewall_rules = []
                    virtual_network_rules = []
                    default_action = (
                        "Allow"  # allowed by default (letting everything through)
                    )
                try:
                    network_rule_bypass_options = raw_properties[
                        "networkRuleBypassOptions"
                    ]
                except KeyError:
                    if DEBUGGING:
                        print(
                            f"Couldn't find privateEndpointConnections of container registry {name}"
                        )
                    network_rule_bypass_options = "None"
                # SKU
                try:
                    sku = rg_results_as_dict["data"][0]["sku"]
                    try:
                        tier = sku["tier"]
                    except KeyError:
                        if DEBUGGING:
                            print(
                                f"Couldn't find tier value of sku in container registry {name}. assuming Basic tier"
                            )
                        tier = "Basic"
                except KeyError:
                    if DEBUGGING:
                        print(
                            f"Couldn't find sku of container registry {name}. assuming Basic tier"
                        )
                    tier = "Basic"
                # The principal type and system assigned managed identity
                try:
                    principal_id = rg_results_as_dict["data"][0]["identity"][
                        "principalId"
                    ]
                except (KeyError, TypeError):
                    if DEBUGGING:
                        print(
                            f"Couldn't find the principal Id of the container registry {name}."
                        )
                    principal_id = None
                try:
                    principal_type = rg_results_as_dict["data"][0]["identity"]["type"]
                except (KeyError, TypeError):
                    if DEBUGGING and principal_id:
                        print(
                            f"Couldn't find the principal type of the container registry {name}."
                        )
                    principal_type = None
                # User assigned managed identity
                try:
                    raw_user_assigned_ids = rg_results_as_dict["data"][0]["identity"][
                        "userAssignedIdentities"
                    ]
                    user_assigned_ids = []
                    for key, identity in raw_user_assigned_ids.items() or []:
                        user_assigned_ids.append(
                            {
                                "identityId": key,
                                "clientId": identity["clientId"],
                                "principalId": identity["principalId"],
                            }
                        )
                except (KeyError, TypeError):
                    user_assigned_ids = []

                object_to_add = ContainerRegistry(
                    resourceId=resourceId,
                    name=name,
                    resourceGroup=resource_group,
                    provider=resource_type,
                    adminUserEnabled=admin_user_enabled,
                    publicNetworkEnabled=public_network_enabled,
                    privateEndpoints=private_endpoints,
                    firewallRules=firewall_rules,
                    virtualNetworkRules=virtual_network_rules,
                    networkBypassOptions=network_rule_bypass_options,
                    defaultAction=default_action,
                    tier=tier,
                    principalId=principal_id,
                    principalType=principal_type,
                    userAssignedIdentities=user_assigned_ids,
                )
                json_key = "containerRegistries"

            elif resource_type == "microsoft.containerservice/managedclusters":
                endpoint = f"https://management.azure.com/subscriptions/{sub_id}/resourceGroups/{resource_group}/providers/Microsoft.ContainerService/managedClusters/{name}?api-version=2020-03-01"
                resource_response = requests.get(url=endpoint, headers=headers).json()
                raw_properties = resource_response["properties"]
                # Kubernetes version
                try:
                    kubernetes_version = raw_properties["kubernetesVersion"]
                except KeyError:
                    if DEBUGGING:
                        print(
                            f"Couldn't find the kubernetes version of kubernetes cluster {name}, assuming default version."
                        )
                    kubernetes_version = "1.18.14"
                # node pools
                try:
                    raw_node_pools = raw_properties["agentPoolProfiles"]
                    node_pools = [
                        {
                            "name": x.get("name"),
                            "count": x.get("count"),
                            "nodeType": x.get("type"),
                            "osType": x.get("osType"),
                            "kubernetesVersion": x.get("orchestratorVersion"),
                        }
                        for x in raw_node_pools
                    ]
                except KeyError:
                    if DEBUGGING:
                        print(
                            f"Couldn't find the agentPoolProfiles of kubernetes cluster {name}. Assuming a single node profile"
                        )
                    node_pools = [
                        {
                            "name": "testPool",
                            "type": "VirtualMachineScaleSets",
                            "osType": "Linux",
                            "count": 1,
                            "kubernetesVersion": kubernetes_version,
                        }
                    ]
                # enableRBAC
                try:
                    enable_rbac = raw_properties["enableRBAC"]
                except KeyError:
                    if DEBUGGING:
                        print(
                            f"Couldn't find the enableRBAC value of kubernetes cluster {name}. Assuming false."
                        )
                    enable_rbac = False
                # Firewall Related
                try:
                    api_srv_access_profile = raw_properties["apiServerAccessProfile"]
                except KeyError:
                    if DEBUGGING:
                        print(
                            f"Couldn't find the apiServerAccessProfile of kubernetes cluster {name}"
                        )
                    api_srv_access_profile = None
                if api_srv_access_profile:
                    # IPRanges
                    try:
                        authorized_ip_ranges = api_srv_access_profile[
                            "authorizedIPRanges"
                        ]
                    except KeyError:
                        authorized_ip_ranges = []
                        if DEBUGGING:
                            print(
                                f"Couldn't find the authorizedIPRanges of kubernetes cluster {name}"
                            )
                    # enablePrivateCluster
                    try:
                        private_cluster = api_srv_access_profile["enablePrivateCluster"]
                    except KeyError:
                        private_cluster = False
                        if DEBUGGING:
                            print(
                                f"Couldn't find the enablePrivateCluster of kubernetes cluster {name}, assuming False"
                            )
                else:
                    authorized_ip_ranges = []
                    private_cluster = False
                # aadProfile (Admin group)
                try:
                    aad_profile = raw_properties["aadProfile"]
                except KeyError:
                    aad_profile = None
                    if DEBUGGING:
                        print(
                            f"Couldn't find the aad_profile (admin group) of kubernetes cluster {name}."
                        )
                if aad_profile:
                    try:
                        admin_groups = aad_profile["adminGroupObjectIDs"]
                    except KeyError:
                        admin_groups = []
                    try:
                        tenant_id = aad_profile["tenantID"]
                    except KeyError:
                        tenant_id = None
                    aad_profile = {"adminGroups": admin_groups, "tenantId": tenant_id}
                # If managed identity is activated on the resource it has a principal ID
                try:
                    principal_id = resource_response["identity"]["principalId"]
                except:
                    if DEBUGGING:
                        print(
                            f"Couldn't find a principalId of identity in kubernetes service {name}."
                        )
                    principal_id = None
                try:
                    principal_type = resource_response["identity"]["type"]
                except:
                    principal_type = None
                # SKU
                try:
                    sku = resource_response["sku"]
                    try:
                        tier = sku["tier"]
                    except KeyError:
                        if DEBUGGING:
                            print(
                                f"Couldn't find tier value of sku in kubernetes cluster {name}. assuming Basic tier"
                            )
                        tier = "Basic"
                except KeyError:
                    if DEBUGGING:
                        print(
                            f"Couldn't find sku of kubernetes cluster {name}. assuming Basic tier"
                        )
                    tier = "Basic"

                object_to_add = KubernetesCluster(
                    resourceId=resourceId,
                    name=name,
                    resourceGroup=resource_group,
                    provider=resource_type,
                    kubernetesVersion=kubernetes_version,
                    nodePools=node_pools,
                    enableRBAC=enable_rbac,
                    firewallRules=authorized_ip_ranges,
                    privateCluster=private_cluster,
                    tier=tier,
                    aadProfile=aad_profile,
                    principalId=principal_id,
                    principalType=principal_type,
                )
                json_key = "kubernetesClusters"

            elif resource_type == "microsoft.apimanagement/service":
                str_query = f"resources | where type =~ 'microsoft.apimanagement/service' and name == '{name}'"
                query = arg.models.QueryRequest(
                    subscriptions=[sub_id], query=str_query, options=rg_query_options,
                )
                try:
                    rg_results_as_dict = rg_client.resources(query=query).__dict__
                except:
                    if DEBUGGING:
                        print(
                            f"ERROR: Couldn't execute resource graph query of {name}, skipping asset."
                        )
                    continue
                raw_properties = rg_results_as_dict["data"][0]["properties"]
                try:
                    subnetId = raw_properties["virtualNetworkConfiguration"][
                        "subnetResourceId"
                    ]
                except (KeyError, TypeError):
                    if DEBUGGING:
                        print(
                            f"Couldn't find api managment subnet id of its virtual network configuration."
                        )
                    subnetId = None
                try:
                    virtualNetworkType = raw_properties["virtualNetworkType"]
                except KeyError:
                    if DEBUGGING:
                        print(f"Couldn't find virtual network type.")
                    virtualNetworkType = None
                try:
                    publicIpAddresses = raw_properties["publicIPAddresses"]
                except KeyError:
                    if DEBUGGING:
                        print(f"Couldn't find public Ip of the api managment {name}.")
                    publicIpAddresses = None
                try:
                    privateIpAddresses = raw_properties["privateIPAddresses"]
                except KeyError:
                    if DEBUGGING:
                        print(f"Couldn't find private Ip of the api managment {name}.")
                    privateIpAddresses = None
                try:
                    certificates = raw_properties["certificates"]
                except KeyError:
                    if DEBUGGING:
                        print(
                            f"Couldn't find the certificates of the api managment {name}."
                        )
                    certificates = []
                raw_identity = rg_results_as_dict["data"][0]["identity"]
                if raw_identity:
                    try:
                        rg_results_as_dict = rg_client.resources(query=query).__dict__
                    except:
                        if DEBUGGING:
                            print(
                                f"ERROR: Couldn't execute resource graph query of {name}, skipping asset."
                            )
                        continue
                    raw_properties = rg_results_as_dict["data"][0]["properties"]
                    try:
                        subnetId = raw_properties["virtualNetworkConfiguration"][
                            "subnetResourceId"
                        ]
                    except (KeyError, TypeError):
                        if DEBUGGING:
                            print(
                                f"Couldn't find api managment subnet id of its virtual network configuration."
                            )
                        subnetId = None
                    try:
                        virtualNetworkType = raw_properties["virtualNetworkType"]
                    except KeyError:
                        if DEBUGGING:
                            print(f"Couldn't find virtual network type.")
                        virtualNetworkType = None
                    try:
                        publicIpAddresses = raw_properties["publicIPAddresses"]
                    except KeyError:
                        if DEBUGGING:
                            print(
                                f"Couldn't find public Ip of the api managment {name}."
                            )
                        publicIpAddresses = None
                    try:
                        privateIpAddresses = raw_properties["privateIPAddresses"]
                    except KeyError:
                        if DEBUGGING:
                            print(
                                f"Couldn't find private Ip of the api managment {name}."
                            )
                        privateIpAddresses = None
                    try:
                        certificates = raw_properties["certificates"]
                    except KeyError:
                        if DEBUGGING:
                            print(
                                f"Couldn't find the certificates of the api managment {name}."
                            )
                        certificates = []
                    raw_identity = rg_results_as_dict["data"][0]["identity"]
                    if raw_identity:
                        try:
                            principalId = raw_identity["principalId"]
                        except (KeyError, TypeError):
                            if DEBUGGING:
                                print(
                                    f"Couldn't find the principal Id of the api managment {name}."
                                )
                            principalId = None
                        try:
                            principalType = raw_identity["type"]
                        except (KeyError, TypeError):
                            if DEBUGGING:
                                print(
                                    f"Couldn't find the principal type of the api managment {name}."
                                )
                            principalType = None
                        try:
                            raw_user_assigned_ids = raw_identity[
                                "userAssignedIdentities"
                            ]
                            user_assigned_ids = []
                            for key, identity in raw_user_assigned_ids.items() or []:
                                user_assigned_ids.append(
                                    {
                                        "identityId": key,
                                        "clientId": identity["clientId"],
                                        "principalId": identity["principalId"],
                                    }
                                )
                        except (KeyError, TypeError):
                            if DEBUGGING:
                                print(
                                    f"Couldn't find the user assigned identites of the api management"
                                )
                            user_assigned_ids = []
                    else:
                        if DEBUGGING:
                            print(
                                f"Couldn't get the IAM identity field of the api managment {name}."
                            )
                        principalId = None
                        principalType = None
                        user_assigned_ids = []

                    # To get api representing data from the resource explorer
                    endpoint = f"https://management.azure.com/subscriptions/{sub_id}/resourceGroups/{resource_group}/providers/Microsoft.ApiManagement/service/{name}/apis?api-version=2018-01-01"
                    try:
                        resource_explorer_data = requests.get(
                            url=endpoint, headers=headers
                        ).json()
                    except:
                        resource_explorer_data = {}
                        if DEBUGGING:
                            print(
                                f"Error running API call {endpoint}. Could be a bad authentication due to Bearer token."
                            )
                    apis = []
                    raw_apis_data = resource_explorer_data.get("value")
                    if raw_apis_data:
                        try:
                            for raw_api in raw_apis_data or []:
                                api = {
                                    "id": raw_api["id"],
                                    "name": raw_api["name"],
                                }
                                apis.append(api)
                        except KeyError:
                            pass
                    # To get certificates representing data from the resource explorer
                    endpoint = f"https://management.azure.com/subscriptions/{sub_id}/resourceGroups/{resource_group}/providers/Microsoft.ApiManagement/service/{name}/certificates?api-version=2018-01-01"
                    try:
                        resource_explorer_data = requests.get(
                            url=endpoint, headers=headers
                        ).json()
                    except:
                        resource_explorer_data = {}
                        if DEBUGGING:
                            print(
                                f"Error running API call {endpoint}. Could be a bad authentication due to Bearer token."
                            )
                    apiManagementcertificates = []
                    raw_certificates_data = resource_explorer_data.get("value")
                    if raw_certificates_data:
                        try:
                            for raw_certificate in raw_certificates_data or []:
                                certificate = {
                                    "id": raw_certificate["id"],
                                    "name": raw_certificate["name"],
                                }
                                apiManagementcertificates.append(certificate)
                        except KeyError:
                            pass
                    # To get product representing data from the resource explorer
                    endpoint = f"https://management.azure.com/subscriptions/{sub_id}/resourceGroups/{resource_group}/providers/Microsoft.ApiManagement/service/{name}/products?api-version=2018-01-01"
                    try:
                        resource_explorer_data = requests.get(
                            url=endpoint, headers=headers
                        ).json()
                    except:
                        resource_explorer_data = {}
                        if DEBUGGING:
                            print(
                                f"Error running API call {endpoint}. Could be a bad authentication due to Bearer token."
                            )
                    products_noapis = []
                    raw_products_data = resource_explorer_data.get("value")
                    if raw_products_data:
                        try:
                            for raw_product in raw_products_data or []:
                                product_noapis = {
                                    "id": raw_product["id"],
                                    "name": raw_product["name"],
                                }
                                products_noapis.append(product_noapis)
                        except KeyError:
                            pass
                    products = []
                    # To the names of apis under the product, it will be convient for connection logic in the parser
                    for product_noapis in products_noapis:
                        product_name = product_noapis.get("name")
                        endpoint = f"https://management.azure.com/subscriptions/{sub_id}/resourceGroups/{resource_group}/providers/Microsoft.ApiManagement/service/{name}/products/{product_name}/apis?api-version=2018-01-01"
                        try:
                            resource_explorer_data = requests.get(
                                url=endpoint, headers=headers
                            ).json()
                        except:
                            resource_explorer_data = {}
                            if DEBUGGING:
                                print(
                                    f"Error running API call {endpoint}. Could be a bad authentication due to Bearer token."
                                )
                        api_names = []
                        raw_product_apis_data = resource_explorer_data.get("value")
                        if raw_product_apis_data:
                            try:
                                for raw_product_api in raw_product_apis_data or []:
                                    api_names.append(raw_product_api["name"])
                            except KeyError:
                                pass
                        product = {
                            "id": product_noapis["id"],
                            "name": product_noapis["name"],
                            "apiNames": api_names,
                        }
                        products.append(product)
                    # To get the user data of the api management from the resource explorer
                    endpoint = f"https://management.azure.com/subscriptions/{sub_id}/resourceGroups/{resource_group}/providers/Microsoft.ApiManagement/service/{name}/users?api-version=2018-01-01"
                    try:
                        resource_explorer_data = requests.get(
                            url=endpoint, headers=headers
                        ).json()
                    except:
                        resource_explorer_data = {}
                        if DEBUGGING:
                            print(
                                f"Error running API call {endpoint}. Could be a bad authentication due to Bearer token."
                            )
                    apiManagementUsers = []
                    raw_users_data = resource_explorer_data.get("value")
                    if raw_users_data:
                        try:
                            for raw_user in raw_users_data or []:
                                user = {
                                    "id": raw_user["id"],
                                    "name": raw_user["name"],
                                    "userType": raw_user["properties"]["firstName"],
                                }
                                apiManagementUsers.append(user)
                        except (KeyError, TypeError):
                            pass
                    # To get the subscirption data of the api management from the resource explorer
                    endpoint = f"https://management.azure.com/subscriptions/{sub_id}/resourceGroups/{resource_group}/providers/Microsoft.ApiManagement/service/{name}/subscriptions?api-version=2019-12-01"
                    try:
                        resource_explorer_data = requests.get(
                            url=endpoint, headers=headers
                        ).json()
                    except:
                        resource_explorer_data = {}
                        if DEBUGGING:
                            print(
                                f"Error running API call {endpoint}. Could be a bad authentication due to Bearer token."
                            )
                    apiManagementSubscriptions = []
                    raw_subscriptions_data = resource_explorer_data.get("value")
                    if raw_subscriptions_data:
                        try:
                            for raw_subscription in raw_subscriptions_data or []:
                                subscription = {
                                    "id": raw_subscription["id"],
                                    "name": raw_subscription["name"],
                                    "userId": raw_subscription["properties"].get(
                                        "ownerId"
                                    ),
                                    "scope": raw_subscription["properties"].get(
                                        "scope"
                                    ),
                                }
                                apiManagementSubscriptions.append(subscription)
                        except (KeyError, TypeError):
                            pass
                    object_to_add = APIManagement(
                        resourceId=resourceId,
                        name=name,
                        resourceGroup=resource_group,
                        provider=resource_type,
                        apis=apis,
                        products=products,
                        subnetId=subnetId,
                        virtualNetworkType=virtualNetworkType,
                        apiManagementcertificates=apiManagementcertificates,
                        principalId=principalId,
                        principalType=principalType,
                        userAssignedIdentities=user_assigned_ids,
                        publicIpAddresses=publicIpAddresses,
                        privateIpAddresses=privateIpAddresses,
                        apiManagementUsers=apiManagementUsers,
                        apiManagementSubscriptions=apiManagementSubscriptions,
                    )
                    json_key = "apiManagements"

            else:
                if COUNTING:
                    supported_asset = False
            if COUNTING:
                count = ASSETS.get(resource_type, (0, supported_asset))[0]
                ASSETS[resource_type] = (count + 1, supported_asset)
            # elif resource_type == "Microsoft.Network/networkWatchers":
            if json_key not in ["", None]:
                try:
                    json_representation[json_key].append(object_to_add.__dict__)
                except (KeyError, AttributeError):
                    json_representation.setdefault(json_key, [object_to_add.__dict__])
        except requests.exceptions.ConnectionError as e:
            print(f"WARNING: {e}")
            pass
    return json_representation


def write_ad_as_json():
    """Generates the json file of the Active Directory to use as input for the parser"""
    # Authenticate the Service Principal
    credentials = authenticate()
    # Need to make regular REST API call for role definition information
    scope = "https://management.azure.com/.default"
    try:
        access_token = credentials.get_token(scope)
        bearer_token = access_token[0]
    except ClientAuthenticationError:
        sys.exit(
            SystemExit(
                f"Cannot get a bearer token for type: {type(credentials)} on scope {scope}. Cannot fetch azure data, exiting."
            )
        )

    headers = {"Authorization": "Bearer " + bearer_token}
    sub_client = SubscriptionClient(credential=credentials)
    ad_subscriptions = fetch_subscriptions(sub_client=sub_client)

    final_json_object = {"name": "Scanned_Azure_Active_Directory"}

    resource_groups_of_interest = None
    try:
        resource_groups_of_interest = os.environ["AZURE_RESOURCE_GROUP_NAMES"]
    except KeyError:
        resource_groups_of_interest = None
    # If the environment variable is set, the user only wants to look at the resources in a specified resource groups.
    if resource_groups_of_interest not in [None, "", {}]:
        if "[" in resource_groups_of_interest:
            try:
                resource_groups_of_interest = json.loads(resource_groups_of_interest)
            except JSONDecodeError:
                if DEBUGGING:
                    print(f"AZURE_RESOURCE_GROUP_NAMES seems to be the wrong format.")
        elif (
            type(resource_groups_of_interest) == str
            and "," in resource_groups_of_interest
        ):
            resource_groups_of_interest = resource_groups_of_interest.split(",")
            resource_groups_of_interest = [
                str(x).strip() for x in resource_groups_of_interest
            ]
        if type(resource_groups_of_interest) != list:
            resource_groups_of_interest = [resource_groups_of_interest]
    # Management Groups
    # Listing them
    endpoint = f"https://management.azure.com/providers/Microsoft.Management/managementGroups?api-version=2020-02-01"
    try:
        mgmt_grp_request = requests.get(url=endpoint, headers=headers)
        if mgmt_grp_request.status_code not in ["AuthorizationFailed"]:
            api_management_groups = mgmt_grp_request.json()
    except:
        if DEBUGGING:
            print(f"Couldn't fetch Management Groups for the tenant.")
        api_management_groups = {}
    queue = []
    for mg in api_management_groups.get("value") or []:
        queue.append(mg)
    management_groups = []
    while len(queue) > 0:
        try:
            mg = queue.pop()
            # Managementgroups can be nested
            management_group = __extract_management_groups(
                management_group_id=mg.get("id"),
                management_group_name=mg.get("name"),
                headers=headers,
            )
            management_groups.append(management_group.__dict__)
            for child in management_group.scope or []:
                if not child.get("scopeType"):
                    continue
                elif (
                    child["scopeType"].lower()
                    == "Microsoft.Management/managementGroups"
                ):
                    # We only need to continue the "recursion" if we have a nested management group
                    queue.append(child)
        except IndexError:
            break
    final_json_object["managementGroups"] = management_groups
    # management_groups = None
    # Subscription objects generation
    subscriptions = []
    rbac_roles = []
    for sub in ad_subscriptions["subsRaw"]:
        name = sub.get("display_name")
        subscriptionId = sub.get("subscription_id")
        authorizationSource = sub.get("authorization_source")
        resourceID = sub.get("id")
        subscription = Subscription(
            resourceId=resourceID,
            name=name,
            subscriptionId=subscriptionId,
            authorizationSource=authorizationSource,
        )
        subscriptions.append(subscription.__dict__)
        # TODO: The Restcalls below are slow, try speeding this up
        # RBAC on subscription scope
        amc = AuthorizationManagementClient(
            credentials, subscriptionId, api_version="2018-09-01-preview"
        )
        amc_rdef = AuthorizationManagementClient(
            credentials, subscriptionId, api_version="2018-01-01-preview"
        )  # Need two seperate once because one version doesn't support principal_type while the other doesn't contain role_definitions
        role_assignments = amc.role_assignments.list()
        for role_assignment in role_assignments:
            role_assignment_dict = role_assignment.__dict__
            if any(
                x["id"] == role_assignment_dict["id"]
                and x["scope"] == role_assignment_dict["scope"]
                and x["principalId"] == role_assignment_dict["principal_id"]
                for x in rbac_roles
            ):
                continue  # Role is already listed from somewhere else
            role_definition_id = role_assignment_dict["role_definition_id"]
            if role_definition_id:
                role_definition = amc_rdef.role_definitions.get_by_id(
                    role_definition_id
                )
                permissions = role_definition.permissions
                final_permissions = []
                for perm in permissions:
                    permission_to_add = {
                        "actions": (perm.actions + perm.data_actions),
                        "notActions": (perm.not_actions + perm.not_data_actions),
                    }
                    final_permissions.append(permission_to_add)
                role_to_add = {
                    "id": role_assignment_dict["id"],
                    "name": role_assignment_dict["name"],
                    "scope": role_assignment_dict["scope"],
                    "principalId": role_assignment_dict["principal_id"],
                    "principalType": role_assignment_dict["principal_type"],
                    "roleName": role_definition.role_name,
                    "permissions": final_permissions,
                }
                rbac_roles.append(role_to_add)

    final_json_object["subscriptions"] = subscriptions
    final_json_object["roleAssignments"] = rbac_roles
    subscriptions, rbac_roles = None, None

    rg_client = arg.ResourceGraphClient(credentials)

    # Resource Groups
    resource_groups = []
    for sub_id in ad_subscriptions["subs_id_list"]:
        rm_client = ResourceManagementClient(credentials, sub_id)
        resource_groups_in_subscription = rm_client.resource_groups.list()
        for resource_grp in resource_groups_in_subscription:
            try:
                managing_resource_grp = None
                if resource_grp.managed_by:
                    managing_resource_grp = resource_grp.managed_by.split("/")[4]
            except (AttributeError, SyntaxError):
                pass
            if (
                resource_groups_of_interest not in ["", None, []]
                and resource_grp.name not in resource_groups_of_interest
                and managing_resource_grp not in resource_groups_of_interest
            ):
                continue
            name = resource_grp.name
            managedBy = resource_grp.managed_by
            resource_group = ResourceGroup(
                resourceId=resource_grp.id,
                subscriptionId=sub_id,
                name=name,
                managedBy=managedBy,
                provider=resource_grp.type,
            )
            resource_groups.append(resource_group.__dict__)

            # Individual Resources handling
            resources_in_grp = rm_client.resources.list_by_resource_group(
                resource_group_name=resource_grp.name
            )
            json_representation = iterate_resources_to_json(
                resources=resources_in_grp,
                resource_group=resource_grp.name,
                rg_client=rg_client,
                sub_id=sub_id,
                credentials=credentials,
            )
            for key in json_representation.keys():
                existing_final_list = (
                    final_json_object.get(key) if final_json_object.get(key) else []
                )
                obtained_local_list = json_representation.get(key)
                for entry in obtained_local_list:
                    existing_final_list.append(entry)
                final_json_object[key] = existing_final_list
    final_json_object["resourceGroups"] = resource_groups
    resource_groups = None
    # Save Application Insights into a seperate file
    app_insights = final_json_object.get("applicationInsights")
    if app_insights != None:
        if app_insights != {}:
            with open(
                os.path.join(BASE_DIR, "environment_files/application_insights.json"),
                "w",
            ) as app_insights_file:
                json.dump(app_insights, fp=app_insights_file, indent=4, sort_keys=True)
        # Don't want to include application insights in standard environment parsing (should be optional to enrich model)
        del final_json_object["applicationInsights"]
    # print(json.dumps(obj=final_json_object, indent=4, sort_keys=True))
    with open(
        os.path.join(BASE_DIR, "environment_files/active_directory.json"), "w"
    ) as json_file:
        json.dump(obj=final_json_object, fp=json_file, indent=4, sort_keys=True)


def __handel_ip_range(
    start_ip_components: list,
    end_ip_components: list,
    start_ip_address: str,
    end_ip_address: str,
) -> list:
    firewallRules = []
    octet_start_one = int(start_ip_components[0])
    octet_end_one = int(end_ip_components[0])
    octet_start_two = int(start_ip_components[1])
    octet_end_two = int(end_ip_components[1])
    octet_start_three = int(start_ip_components[2])
    octet_end_three = int(end_ip_components[2])
    octet_start_four = int(start_ip_components[3])
    octet_end_four = int(end_ip_components[3])
    rangegap1 = octet_end_one - octet_start_one
    rangegap2 = octet_end_two - octet_start_two
    rangegap3 = octet_end_three - octet_start_three
    rangegap4 = octet_end_four - octet_start_four
    if start_ip_address == end_ip_address:
        ip = start_ip_address
        firewallRules.append(ip)
    elif rangegap4 < 10 and rangegap1 == 0 and rangegap2 == 0 and rangegap3 == 0:
        for i in range(octet_start_one, octet_end_one + 1):
            for j in range(octet_start_two, octet_end_two + 1):
                for x in range(octet_start_three, octet_end_three + 1):
                    for z in range(octet_start_four, octet_end_four + 1):
                        ip = f"{i}.{j}.{x}.{z}"
                        firewallRules.append(ip)
    elif start_ip_address and end_ip_address:
        ip = start_ip_address + " - " + end_ip_address
        firewallRules.append(ip)
    return firewallRules


def __get_application_insights(sub_id, rsg_name, app_insight_name, headers) -> dict:
    today = datetime.datetime.today()
    timedelta = datetime.timedelta(days=90)  # 90 days ago by default
    start = today - timedelta
    timespan = f"{start.isoformat()}/{today.isoformat()}"
    valid_environment_variable = False
    try:
        app_insight_interval = os.environ["APP_INSIGHTS_INTERVAL"]
        iso_date = "\d{4}(-\d{2}){2}(T(\d{2}:)((\d{2})|(\d{2}:\d{2}))(\.\d{1,3})?)?"
        pattern = re.compile(f"^{iso_date}\/{iso_date}$")
        if not pattern.search(app_insight_interval):
            if DEBUGGING:
                print(
                    f"APP_INSIGHTS_INTERVAL has wrong format, run program with -h for detailed information. Setting standard time interval for application insights topology dump."
                )
        else:
            valid_environment_variable = True
            # Still need to check for valid range (e.g. days = 32 is not valid)
            splitted_date = timespan.split("/")
            for date in splitted_date:
                try:
                    datetime.datetime.fromisoformat(date)
                except ValueError as e:
                    if DEBUGGING:
                        print(
                            f"APP_INSIGHTS_INTERVAL has numerical values that exceeds the allowed limit. Assuming normal timespan. \n\t Error: {e}."
                        )
                    valid_environment_variable = False

    except:
        if DEBUGGING:
            print(
                f"APP_INSIGHTS_INTERVAL not set, run program with -h for detailed information. Setting standard time interval for application insights topology dump."
            )
        app_insight_interval = None
    if valid_environment_variable:
        timespan = app_insight_interval if app_insight_interval else timespan
    endpoint = f"https://management.azure.com/subscriptions/{sub_id}/resourcegroups/{rsg_name}/providers/microsoft.insights/components/{app_insight_name}/providers/microsoft.insights/topology?timespan={timespan}&api-version=2019-10-17-preview&depth=1"
    try:
        app_insights_data = requests.get(url=endpoint, headers=headers).json()
    except:
        if DEBUGGING:
            print(
                f"Error running API call {endpoint}. Could be a bad authentication due to Bearer token."
            )
        app_insights_data = None
    return app_insights_data


def __extract_management_groups(management_group_id, management_group_name, headers):
    """Helper function to extract the ManagementGroup objects from azure"""
    endpoint = f"https://management.azure.com/{management_group_id}?api-version=2020-02-01&$expand=children&$recurse=True"
    connected_to = requests.get(url=endpoint, headers=headers).json()
    connected_to_children = connected_to.get("properties").get("children")
    if not connected_to_children:
        management_group = ManagementGroup(
            resourceId=management_group_id, name=management_group_name, scope=[]
        )
        return
    children = []
    for child in connected_to_children or []:
        obj = {
            "id": child.get("id"),
            "scopeType": child.get("type"),
            "name": child.get("name"),
        }
        children.append(obj)
    management_group = ManagementGroup(
        resourceId=management_group_id, name=management_group_name, scope=children
    )
    return management_group


def print_resource_groups():
    """Fetches and prints the resource groups within the resource manager client along with its containing services"""
    # Authenticate the Service Principal
    credentials = authenticate()

    sub_client = SubscriptionClient(credentials)
    subscriptions = fetch_subscriptions(sub_client)

    print("Subscription info:")
    for entry in subscriptions["subsRaw"]:
        print(f"\n{entry}\n")

    print("Resources: \n")
    for sub_id in subscriptions["subs_id_list"]:
        rm_client = ResourceManagementClient(credentials, sub_id)
        resource_groups_in_subscription = rm_client.resource_groups.list()
        for resource_grp in resource_groups_in_subscription:
            print(resource_grp)
            resources_in_grp = rm_client.resources.list_by_resource_group(
                resource_group_name=resource_grp.name
            )
            for resource in resources_in_grp:

                print(f"\n{resource}\n")


def authenticate():
    """Authenticates the application to the subscription. Confirms the exists an RBAC delegation for the app
    on the requested subscription.

    Returns: \n
        Authentication object if successfully authenticated identity. Exits otherwise
    """
    credentials = None
    try:
        credentials = DefaultAzureCredential(
            exclude_environment_credential=False
        )  # Authentication order: https://docs.microsoft.com/en-us/python/api/overview/azure/identity-readme?view=azure-python
    except:
        sys.exit(
            SystemExit(
                f"Required enviornment variables are not set and cannot authenticate as a Manage Identity. Start the program with -h for help, exiting."
            )
        )
    return credentials


def validate_arguments(argv):
    """Confirms that correct number of arguments and argument type is provided.
    Exits the program if conditions are unfulfilled.

    Keyword arguments:
        argv - Program arguments.
    """
    global DEBUGGING
    if len(argv) > 1 and any(arg in ["-h", "help", "--help"] for arg in argv):
        print(
            f"""Usage: python3 {__file__} [OPTIONS]
        Required environment variables:
            AZURE_TENANT_ID - Your AD tenant ID.
            AZURE_CLIENT_ID - Your registered application's client ID.
        
        Optional environment variables:
            AZURE_SUBSCRIPTION_ID - Set the AZURE_SUBSCRIPTION_ID if you want to examine a single specific subscription.
            AZURE_RESOURCE_GROUP_NAMES - '["rsg_one", "rsg_two"]' List the names of resource groups you only want to include. Fetches all resource groups by default
            APP_INSIGHTS_INTERVAL = Time interval following the ISO8601 standard: YYYY-MM-DDTHH-MM-SS/YYYY-MM-DDTHH-MM-SS (e.g. 2020-01-01T16:01:30.000/2021-02-20T16:01:30.000). Defaults to the latest 90 days
            
        OPTIONS:
            -h : Print out help information. same a help, --help
            -d, -D, --debugging : Enable debugging information
            -ca, -CA, --count_assets : Lists how many of each type of asset is available, and whether they are supported by azureLang or not. Results are returned in counted_assets.json
        """
        )
        raise SystemExit
    if len(argv) > 1 and any(arg in ["-d", "-D", "--debugging"] for arg in argv):
        DEBUGGING = True
    if len(argv) > 1 and any(arg in ["-ca", "-CA", "--count_assets"] for arg in argv):
        global COUNTING
        global ASSETS
        COUNTING = True
        ASSETS = {}


# converts asset count to json
# only run with -ca flag
def asset_count_to_json():
    result = {}
    known = {}
    unknown = {}
    for asset in sorted(ASSETS, key=ASSETS.get, reverse=True):
        # checks if asset is known or not
        if ASSETS[asset][1] == True:
            known[asset] = ASSETS[asset][0]
        else:
            unknown[asset] = ASSETS[asset][0]
    result["Known assets:"] = known
    result["Unknown assets:"] = unknown
    with open(os.path.join(BASE_DIR, "counted_assets.json"), "w") as json_file:
        json.dump(obj=result, fp=json_file, indent=4)


def main(argv):
    global COUNTING
    # start_time = time.time()
    # pr = cProfile.Profile()
    # pr.enable()
    validate_arguments(argv)
    write_ad_as_json()
    # print_resource_groups()
    # pr.disable()
    # s = io.StringIO()
    # ps = pstats.Stats(pr, stream=s).sort_stats(SortKey.CUMULATIVE)
    # ps.print_stats()
    # print(s.getvalue())
    # end_time = time.time() - start_time
    # print("total_time: ", end_time)
    if COUNTING:
        asset_count_to_json()


if __name__ == "__main__":
    main(sys.argv)
