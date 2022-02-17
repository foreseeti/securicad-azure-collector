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


import azure.mgmt.resourcegraph as arg
import azure.mgmt.logic as logic
from securicad.azure_collector.schema_classes import (
    Logic_App,
    Integration_Account,
    API_Connection,
)
from securicad.azure_collector.services.parser_logger import log


def parse_logic_app(resource, resource_group, credentials, sub_id) -> Logic_App:
    logic_client = logic.LogicManagementClient(
        credential=credentials, subscription_id=sub_id
    )
    principal_id = (
        resource.managed_by if resource.managed_by else ""
    )  # this doesn't seem to be assigned, find principalId elsewhere?
    logic_app = logic_client.workflows.get(resource_group, resource.name).as_dict()
    try:
        integration_account = logic_app["integration_account"]["id"]
    except (TypeError, KeyError):
        integration_account = None
    connection_ids = []
    for connection in logic_app["parameters"]["$connections"]["value"]:
        try:
            connection_ids.append(
                logic_app["parameters"]["$connections"]["value"][connection][
                    "connectionId"
                ]
            )
        except (TypeError, KeyError):
            continue
    object_to_add = Logic_App(
        resourceId=resource.id,
        name=resource.name,
        resourceGroup=resource_group,
        principalId=principal_id,
        integrationAccount=integration_account,
        apiConnections=connection_ids,
    )
    return object_to_add


def parse_integration_acc() -> Integration_Account:
    return None


def parse_api_connection() -> API_Connection:
    return None
