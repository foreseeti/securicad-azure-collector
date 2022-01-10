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

from securicad.azure_collector.schema_classes import SQLServer
from . import network_handling
from securicad.azure_collector.services.parser_logger import log
import azure.mgmt.resourcegraph as arg
import requests

def parse_obj(resource_type, resource_group, sub_id, name, rg_client, rg_query_options, resource_id, DEBUGGING, headers) -> SQLServer:
    str_query = f"resources | where type =~ 'microsoft.sql/servers' and name == '{name}'"
    query = arg.models.QueryRequest(
        subscriptions=[sub_id], query=str_query, options=rg_query_options,
    )
    try:
        rg_results_as_dict = rg_client.resources(query=query).__dict__
    except:
        log.error(
            f"Couldn't execute resource graph query of SQL server {name}, skipping asset."
        )
        return None
    raw_properties = rg_results_as_dict["data"][0]["properties"]
    try:
        privateEndpoints = raw_properties["privateEndpointConnections"]
    except KeyError:
        log.debug(
            f"Couldn't find privateEndpointConnections of sql server {name}"
        )
        privateEndpoints = []
    try:
        publicNetworkAccess = raw_properties["publicNetworkAccess"]
    except KeyError:
        log.debug(f"Couldn't find publicNetworkAccess of sql server {name}")
        publicNetworkAccess = "Disabled"
    # To get database data from the resource exlporer
    endpoint = f"https://management.azure.com/subscriptions/{sub_id}/resourceGroups/{resource_group}/providers/Microsoft.Sql/servers/{name}/databases?api-version=2020-08-01-preview"
    try:
        resource_explorer_data = requests.get(
            url=endpoint, headers=headers
        ).json()
    except:
        log.error(
            f"Couldn't request GET {endpoint}. Could be a bad authentication due to Bearer token."
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
        log.error(
            f"Couldn't request GET {endpoint}. Could be a bad authentication due to Bearer token."
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
        log.error(
            f"Couldn't request GET {endpoint}. Could be a bad authentication due to Bearer token."
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
                log.debug(
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
                log.debug(
                    f"Could not get end ip from firewall rule {raw_firewallRule} in sql-server {name}."
                )
            temp_firewallRules = network_handling.handle_ip_range(
                start_ip_components,
                end_ip_components,
                start_ip_address,
                end_ip_address,
            )
            firewallRules = firewallRules + temp_firewallRules

    object_to_add = SQLServer(
        resourceId=resource_id,
        name=name,
        resourceGroup=resource_group,
        provider=resource_type,
        databases=databases,
        privateEndpoints=privateEndpoints,
        publicNetworkAccess=publicNetworkAccess,
        virtualNetworkRules=virtualNetworkRules,
        firewallRules=firewallRules,
    )
    return object_to_add
