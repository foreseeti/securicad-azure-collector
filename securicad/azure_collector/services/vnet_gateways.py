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

from securicad.azure_collector.schema_classes import Vnet, VnetGateway
from securicad.azure_collector.services.parser_logger import log
import azure.mgmt.resourcegraph as arg


def parse_obj(
    resource_type,
    resource_group,
    sub_id,
    name,
    rg_client,
    rg_query_options,
    resource_id,
    DEBUGGING,
) -> VnetGateway:
    str_query = f"resources | where type =~ 'microsoft.network/virtualnetworkgateways' and name == '{name}'"
    query = arg.models.QueryRequest(
        subscriptions=[sub_id],
        query=str_query,
        options=rg_query_options,
    )
    try:
        rg_results_as_dict = rg_client.resources(query=query).__dict__
    except:
        log.error(
            f"Couldn't execute resource graph query of vnet gateway {name}, skipping asset."
        )
        return None
    raw_properties = rg_results_as_dict["data"][0]["properties"]

    try:
        capacity = raw_properties["sku"]["capacity"]
    except KeyError:
        log.debug(
            f"Couldn't get ['sku']['capacity'] from virtual network gateway {name}, assuming value '1'"
        )
        capacity = 1
    raw_ip_configs = raw_properties.get("ipConfigurations")
    if not raw_ip_configs:
        log.debug(
            f"Couldn't get ipConfigurations of virtual network gateway {name}. Impact: potential missing model associations"
        )
    ip_configs = []
    for raw_ip_config in raw_ip_configs or []:
        ip_config = {
            "id": raw_ip_config.get("id"),
            "name": raw_ip_config.get("name"),
            "publicIpAddress": raw_ip_config.get("properties", {})
            .get("publicIPAddress", {})
            .get("id"),
            "subnet": raw_ip_config.get("properties", {}).get("subnet", {}).get("id"),
        }
        ip_configs.append(ip_config)
    raw_bgp_settings = raw_properties.get("bgpSettings", {})
    if not raw_bgp_settings:
        log.debug(
            f"Couldn't get bgpSettings of virtual network gateway {name}. Impact: None"  # We don't do anything with bgp regardless
        )
    bgp_settings = []
    bgp_peering_addresses = raw_bgp_settings.get("bgpPeeringAddreses", [])
    for raw_bgp_setting in bgp_peering_addresses:
        try:
            bgp_setting = {
                "ipConfigId": raw_bgp_setting.get("ipconfigurationId"),
                "tunnelIpAddress": raw_bgp_setting.get("tunnelIpAddresses", list()),
                "customBgpIpAddresses": raw_bgp_setting.get(
                    "customBgpIpAddresses", list()
                ),
                "defaultBgpIpAddresses": raw_bgp_setting.get(
                    "defaultBgpIpAddresses", list()
                ),
            }
        except AttributeError:
            log.error(
                f"Couldn't get bgp_setting from raw_bgp_setting for virtual network gateway {name}."
            )
            bgp_setting = {}
        bgp_settings.append(bgp_setting)
    try:
        final_bgp_setting = {
            "bgpPeeringAddresses": bgp_settings,
            "asn": raw_bgp_settings.get("asn"),
            "bgpPeeringAddress": raw_bgp_settings.get("bgpPeeringAddress"),
        }
    except AttributeError:
        final_bgp_setting = {}
        log.debug(f"Couldn't get bgpSettings for virtual network gateway {name}.")
    object_to_add = VnetGateway(
        gwId=resource_id,
        name=name,
        resourceGroup=resource_group,
        ipConfigs=ip_configs,
        bgpSettings=final_bgp_setting,
        capacity=capacity,
        provider=resource_type,
    )
    return object_to_add
