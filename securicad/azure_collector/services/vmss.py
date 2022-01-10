# Copyright 2021-2022 Foreseeti AB <https://foreseeti.com>
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

from securicad.azure_collector.schema_classes import VirtualMachineScaleSet
from securicad.azure_collector.services.parser_logger import log
import azure.mgmt.resourcegraph as arg

def parse_obj(resource, resource_type, resource_group, sub_id, name, rg_client, rg_query_options, resource_id, DEBUGGING) -> VirtualMachineScaleSet:
    managedBy = resource.managed_by
    # Fetching the hard to get properties with resource graph
    str_query = f"resources | where type == 'microsoft.compute/virtualmachinescalesets' and name == '{name}'"
    query = arg.models.QueryRequest(
        subscriptions=[sub_id], query=str_query, options=rg_query_options,
    )
    try:
        rg_results_as_dict = rg_client.resources(query=query).__dict__
    except:
        log.error(
            f"Couldn't execute resource graph query of VMSS {name}, skipping asset."
        )
        return None
    try:
        raw_properties = rg_results_as_dict["data"][0]["properties"][
            "virtualMachineProfile"
        ]
    except KeyError:
        log.debug(
            f"Couldn't get properties for virtual machine scale set {name}"
        )
        return None
    try:
        os = raw_properties["storageProfile"]["osDisk"]["osType"]
    except:
        log.debug(
            f"Couldn't find the osType of virtual machine scale set {name}"
        )
        os = None
    os_disk = f"{resource_id}-OSDisk"
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
                    log.debug(
                        f"Couldn't find the keyData value of ssh_key in virtual machine scale set {name}"
                    )
                    pass
        except KeyError:
            log.debug(
                f"Couldn't find the linuxConfiguration value of virtual machine scale set {name}"
            )
            pass
    # Data Disk
    try:
        data_disks = raw_properties["storageProfile"]["dataDisks"]
        if data_disks != None:
            data_disk = f"{resource_id}-DataDisk"
        else:
            data_disk = None
    except:
        # Might not even use data profiles, no need to print debug info
        data_disk = None
        pass
    try:
        network_profile = raw_properties["networkProfile"]
    except KeyError:
        log.debug(
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
                log.debug(
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
                        log.debug(
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
                    log.debug(
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
        log.debug(f"Couldn't find any user assigned managed identities on vmss {name}")
        user_assigned_ids = []
    # The principal type and system assigned managed identity
    try:
        principal_id = rg_results_as_dict["data"][0]["identity"][
            "principalId"
        ]
    except (KeyError, TypeError):
        log.debug(
            f"Couldn't find the principal Id of the vmss {name}. Assuming no System Assigned Managed Identities"
        )
        principal_id = None
    try:
        principalType = rg_results_as_dict["data"][0]["identity"]["type"]
    except (KeyError, TypeError):
        if principal_id:
            log.debug(
                f"Couldn't find the principal type of the app service {name}."
            )
        principalType = None

    object_to_add = VirtualMachineScaleSet(
        resourceId=resource_id,
        name=name,
        os=os,
        osDisk=os_disk,
        dataDisk=data_disk,
        managedBy=managedBy,
        resourceGroup=resource_group,
        sshKeys=ssh_keys,
        networkInterfaces=network_interface_ids,
        provider=resource_type,
        principalId=principal_id,
        principalType=principalType,
        identityIds=user_assigned_ids,
    )
    return object_to_add
