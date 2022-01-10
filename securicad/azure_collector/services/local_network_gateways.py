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

from securicad.azure_collector.schema_classes import LocalNetworkGateway
import azure.mgmt.resourcegraph as arg
from securicad.azure_collector.services.parser_logger import log

def parse_obj(resource_type, resource_group, sub_id, name, rg_client, rg_query_options, resource_id, DEBUGGING) -> LocalNetworkGateway:
    str_query = f"resources | where type =~ 'Microsoft.Network/localnetworkgateways' and name == '{name}'"
    query = arg.models.QueryRequest(
        subscriptions=[sub_id], query=str_query, options=rg_query_options,
    )
    try:
        rg_results_as_dict = rg_client.resources(query=query).__dict__
    except:
        log.error(
            f"Couldn't execute resource graph query of local network gateway {name}, skipping asset."
        )
        return None
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
        gwId=resource_id,
        name=name,
        resourceGroup=resource_group,
        localNetworkAddressSpace=local_Network_AddressSpace,
        gatewayIp=gw_ip,
        provider=resource_type,
        bgpSettings=bgp_setting,
    )
    return object_to_add