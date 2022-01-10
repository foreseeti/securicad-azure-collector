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

from securicad.azure_collector.schema_classes import MySQLDatabase
import securicad.azure_collector.main as main
from . import network_handling
import azure.mgmt.resourcegraph as arg
import requests
from securicad.azure_collector.services.parser_logger import log


def parse_obj(resource_type, resource_group, sub_id, name, rg_client, rg_query_options, resource_id, DEBUGGING, headers) -> MySQLDatabase:
    str_query = f"resources | where type =~ 'microsoft.dbformysql/servers' and name == '{name}'"
    query = arg.models.QueryRequest(
        subscriptions=[sub_id], query=str_query, options=rg_query_options,
    )
    try:
        rg_results_as_dict = rg_client.resources(query=query).__dict__
    except:
        log.error(
            f"Couldn't execute resource graph query of db for mysql {name}, skipping asset."
        )
        return None
    raw_properties = rg_results_as_dict["data"][0]["properties"]
    try:
        privateEndpoints = raw_properties["privateEndpointConnections"]
    except KeyError:
        log.debug(
            f"Couldn't find privateEndpointConnections of MySQL database {name}"
        )
        privateEndpoints = []
    try:
        publicNetworkAccess = raw_properties["publicNetworkAccess"]
    except KeyError:
        log.debug(
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
        log.error(
            f"Couldn't request GET {endpoint}. Could be a bad authentication due to Bearer token."
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
                log.debug(
                    f"Could not get start ip from firewall rule {raw_firewallRule} in MySQL-server {name}."
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
                    f"Could not get end ip from firewall rule {raw_firewallRule} in MySQL-server {name}."
                )
            temp_firewallRules = network_handling.handle_ip_range(
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
        log.error(
            f"couldn't request GET {endpoint}. Could be a bad authentication due to Bearer token."
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
        resourceId=resource_id,
        name=name,
        resourceGroup=resource_group,
        provider=resource_type,
        privateEndpoints=privateEndpoints,
        publicNetworkAccess=publicNetworkAccess,
        firewallRules=firewallRules,
        adAdmins=adAdmins,
    )
    return object_to_add
