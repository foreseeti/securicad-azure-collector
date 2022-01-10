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

from securicad.azure_collector.schema_classes import ServiceBus
from securicad.azure_collector.services.parser_logger import log
import azure.mgmt.resourcegraph as arg
import requests

def parse_obj(resource_type, resource_group, sub_id, name, rg_client, rg_query_options, resource_id, DEBUGGING, bearer_token) -> ServiceBus:
    str_query = f"resources | where type =~ 'microsoft.servicebus/namespaces' and name == '{name}'"
    query = arg.models.QueryRequest(
        subscriptions=[sub_id], query=str_query, options=rg_query_options,
    )
    try:
        rg_results_as_dict = rg_client.resources(query=query).__dict__
    except:
        log.error(
            f"ERROR: Couldn't execute resource graph query of service bus {name}, skipping asset."
        )
        return None
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
        log.warning(f"Not allowed API request GET {endpoint}.")
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
        log.error(f"Not allowed API request GET {endpoint}.")
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
        log.error(f"Not allowed API request GET {endpoint}")
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
        resourceId=resource_id,
        name=name,
        resourceGroup=resource_group,
        provider=resource_type,
        tier=tier,
        authorizationRules=authorization_rules,
        queues=queues,
        topics=topics,
    )
    return object_to_add
