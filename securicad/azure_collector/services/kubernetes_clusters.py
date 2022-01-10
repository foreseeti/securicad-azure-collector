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

from securicad.azure_collector.schema_classes import KubernetesCluster
import requests
from securicad.azure_collector.services.parser_logger import log

def parse_obj(resource_type, resource_group, sub_id, name, resource_id, DEBUGGING, headers) -> KubernetesCluster:
    endpoint = f"https://management.azure.com/subscriptions/{sub_id}/resourceGroups/{resource_group}/providers/Microsoft.ContainerService/managedClusters/{name}?api-version=2020-03-01"
    try:
        resource_response = requests.get(url=endpoint, headers=headers).json()
    except:
        log.error(f"Couldn't request GET {endpoint}. Skipping asset")
        return None
    raw_properties = resource_response["properties"]
    # Kubernetes version
    try:
        kubernetes_version = raw_properties["kubernetesVersion"]
    except KeyError:
        log.debug(
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
        log.debug(
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
        log.debug(
            f"Couldn't find the enableRBAC value of kubernetes cluster {name}. Assuming false."
        )
        enable_rbac = False
    # Firewall Related
    try:
        api_srv_access_profile = raw_properties["apiServerAccessProfile"]
    except KeyError:
        log.debug(
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
            log.debug(
                f"Couldn't find the authorizedIPRanges of kubernetes cluster {name}"
            )
        # enablePrivateCluster
        try:
            private_cluster = api_srv_access_profile["enablePrivateCluster"]
        except KeyError:
            private_cluster = False
            log.debug(
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
        log.debug(
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
        log.debug(
            f"Couldn't find a principalId of identity in kubernetes service {name}. Assuming no attached System Assigned Managed Identities"
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
            log.debug(
                f"Couldn't find tier value of sku in kubernetes cluster {name}. assuming Basic tier"
            )
            tier = "Basic"
    except KeyError:
        log.debug(
            f"Couldn't find sku of kubernetes cluster {name}. assuming Basic tier"
        )
        tier = "Basic"

    object_to_add = KubernetesCluster(
        resourceId=resource_id,
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
    return object_to_add
