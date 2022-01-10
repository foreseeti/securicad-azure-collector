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

from securicad.azure_collector.schema_classes import CosmosDB
import azure.mgmt.resourcegraph as arg
from securicad.azure_collector.services.parser_logger import log

def parse_obj(resource_type, resource_group, sub_id, name, rg_client, rg_query_options, resource_id, DEBUGGING) -> CosmosDB:
    str_query = f"resources | where type =~ 'microsoft.documentdb/databaseaccounts' and name == '{name}'"
    query = arg.models.QueryRequest(
        subscriptions=[sub_id], query=str_query, options=rg_query_options,
    )
    try:
        rg_results_as_dict = rg_client.resources(query=query).__dict__
    except:
        log.error(
            f"Couldn't execute resource graph query of cosmos db {name}, skipping asset."
        )
        return None
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
        mylist = [x for x in sql_databases.next]
    except:
        print(
            f"Could not list sql databases in cosmosdb account {name} in resource_group {resource_group}"
        )"""

    object_to_add = CosmosDB(
        resourceId=resource_id,
        name=name,
        resourceGroup=resource_group,
        provider=resource_type,
        restrictedAccess=restricted_access,
        virtualNetworkRules=virtual_network_rules,
        ipRangeFilter=ip_range_filter,
        apiTypes=api_types,
        disableKeyBasedMetadataWriteAccess=disable_key_based_metadata_write_access,
    )
    return object_to_add
