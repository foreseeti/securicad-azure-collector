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

from securicad.azure_collector.schema_classes import NetworkInterface
import azure.mgmt.resourcegraph as arg
from securicad.azure_collector.services.parser_logger import log

def parse_obj(resource_type, resource_group, sub_id, name, rg_client, rg_query_options, resource_id, DEBUGGING) -> NetworkInterface:
    str_query = f"resources | where type == 'microsoft.network/networkinterfaces' and name == '{name}'"
    query = arg.models.QueryRequest(
        subscriptions=[sub_id], query=str_query, options=rg_query_options,
    )
    try:
        rg_results_as_dict = rg_client.resources(query=query).__dict__
    except:
        log.error(
            f"Couldn't execute resource graph query of network interface {name}, skipping asset."
        )
        return None
    raw_properties = rg_results_as_dict["data"][0]["properties"]
    ip_configs = []
    for ip_config in raw_properties["ipConfigurations"]:
        config_name = ip_config["name"]
        config_id = ip_config["id"]
        ip_config_properties = ip_config.get("properties")
        ip_config_properties.setdefault("publicIPAddress", {"id": None})
        combined_object = {
            "id": config_id,
            "name": config_name,
            "privateIpAddress": ip_config_properties["privateIPAddress"],
            "publicIpAddressId": ip_config_properties[
                "publicIPAddress"
            ].get("id"),
            "subnetId": ip_config_properties.get("subnet").get("id"),
        }
        ip_configs.append(combined_object)
    network_security_group = raw_properties.get("networkSecurityGroup")
    nsg_id = (
        network_security_group.get("id") if network_security_group else None
    )
    object_to_add = NetworkInterface(
        resourceId=resource_id,
        name=name,
        resourceGroup=resource_group,
        ipConfigs=ip_configs,
        networkSecurityGroupId=nsg_id,
        provider=resource_type,
    )
    return object_to_add
