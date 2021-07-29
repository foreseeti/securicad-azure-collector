# Copyright 2020-2021 Foreseeti AB <https://foreseeti.com>
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

import json
from json.decoder import JSONDecodeError
import sys
import os
from azure.core.exceptions import ClientAuthenticationError
import requests
import re
import datetime
from pathlib import Path
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.subscription import SubscriptionClient
from azure.common import exceptions as azexceptions
import azure.mgmt.resourcegraph as arg
from azure.mgmt.authorization import AuthorizationManagementClient

# To authenticate the service principal connecting to the subscriptions/resources
from azure.identity import DefaultAzureCredential

import time
import cProfile
import pstats
import io
from pstats import SortKey
from typing import Dict, List

# Defined object classes following the json schema
from schema_classes import (
    Subscription,
    ResourceGroup,
    ManagementGroup,
)

from services import (
    application_insights,
    ad_groups,
    virtual_machines,
    vmss,
    key_vaults,
    disks,
    ssh_public_keys,
    network_interfaces,
    network_security_groups,
    public_ip_addresses,
    vnets,
    vnet_gateways,
    local_network_gateways,
    connections,
    route_tables,
    storage_accounts,
    cosmos_databases,
    app_services,
    app_service_plans,
    service_buses,
    sql_servers,
    mysql_servers,
    postgresql_servers,
    mariadb_servers,
    container_registries,
    kubernetes_clusters,
    api_management,
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DEBUGGING = False
# COUNTING and ASSETS are used to count known/unknown asset types. See -ca or -help flags.
COUNTING = False
ASSETS = None


def fetch_subscriptions(sub_client):
    """Fetches AD subscriptions. If the AZURE_SUBSCRIPTION_ID environment variable is set,
    only information regarding the subscription(s) will be returned. If set to "" or not set at all,
    all subscriptions the service principal has read access to is returned. \n

    Returns: Object consisting of an array of raw subscription data and an array of their corresponding subscription id
        {'subsRaw': [], 'subs_id_list': []}
    """
    try:
        azure_subscription_ids = os.environ["AZURE_SUBSCRIPTION_ID"]
    except KeyError:
        azure_subscription_ids = ""
    # If the environment variable is set, the user only wants to look at the resources in a specified subscription.
    if azure_subscription_ids not in [None, "", {}, "[]", []]:
        if "[" in azure_subscription_ids:
            try:
                azure_subscription_ids = json.loads(azure_subscription_ids)
            except JSONDecodeError:
                if DEBUGGING:
                    print(
                        f"AZURE_SUBSCRIPTION_ID seems to be the wrong format, exiting. Run the program with the --help flag for correct format."
                    )
        elif type(azure_subscription_ids) == str and "," in azure_subscription_ids:
            azure_subscription_ids = azure_subscription_ids.split(",")
        if type(azure_subscription_ids) != list:
            azure_subscription_ids = [azure_subscription_ids]
        subs_id_list = []
        subsRaw = []
        for azure_subscription_id in azure_subscription_ids:
            azure_subscription_id = str(azure_subscription_id).strip()
            try:
                subsRaw.append(
                    sub_client.subscriptions.get(azure_subscription_id).as_dict()
                )
            except azexceptions.CloudError:
                sys.exit(
                    SystemExit(
                        f"Could not access subscription: {azure_subscription_id} Confirm id and/or Service Principal RBAC read access."
                    )
                )
            subs_id_list.append(azure_subscription_id)
    else:
        subsRaw = []
        # All of the ADs subscription ids
        subs_id_list = []
        for sub in sub_client.subscriptions.list():
            subsRaw.append(sub.as_dict())
            subs_id_list.append(sub.as_dict().get("subscription_id"))
    return {"subsRaw": subsRaw, "subs_id_list": subs_id_list}


def iterate_resources_to_json(
    resources, resource_group, rg_client, sub_id, credentials
):
    """Helper function for write_ad_as_json. Handles all the resources contained wihin a resource group.\n
    Keyword arguments: \n
        resources - A list of resources within a resource group \n
        resource_group - Name of the resource group the resource is contained within. \n
        rg_client - An azure resource graph client to fetch additional resource information. \n
        sub_id - the subscription id the resource group belongs to \n
        credentials - Authentication credentials for clients \n
    Returns: \n
        A dictionary object containing resources following the schema.classes format
    """
    rg_query_options = arg.models.QueryRequestOptions(result_format="objectArray")
    json_representation = {}
    scope = "https://management.azure.com/.default"
    bearer_token = None
    try:
        access_token = credentials.get_token(scope)
        bearer_token = access_token[0]
        headers = {"Authorization": "Bearer " + bearer_token}
    except ClientAuthenticationError as e:
        if DEBUGGING:
            print(
                f"Cannot get a bearer token for type: {type(credentials)} on scope {scope}. Some azure data cannot be fetched. \n\t {e}"
            )
    for resource in resources:
        resource_type = resource.type.lower()
        name = resource.name
        resource_id = resource.id
        # Find resource type, handle accordingly
        json_key = None
        object_to_add = None
        if COUNTING:
            supported_asset = True
        try:
            if resource_type == "microsoft.compute/virtualmachines":
                object_to_add = virtual_machines.parse_obj(
                    resource,
                    resource_type,
                    resource_group,
                    sub_id,
                    name,
                    rg_client,
                    rg_query_options,
                    resource_id,
                    DEBUGGING,
                )
                json_key = "virtualMachines"

            elif resource_type == "microsoft.compute/virtualmachinescalesets":
                object_to_add = vmss.parse_obj(
                    resource,
                    resource_type,
                    resource_group,
                    sub_id,
                    name,
                    rg_client,
                    rg_query_options,
                    resource_id,
                    DEBUGGING,
                )
                json_key = "virtualMachineScaleSets"

            elif resource_type == "microsoft.keyvault/vaults":
                object_to_add = key_vaults.parse_obj(
                    resource_type,
                    resource_group,
                    sub_id,
                    name,
                    rg_client,
                    rg_query_options,
                    resource_id,
                    DEBUGGING,
                    credentials,
                    headers,
                )
                json_key = "keyVaults"

            elif resource_type == "microsoft.compute/disks":
                object_to_add = disks.parse_obj(
                    resource,
                    resource_type,
                    resource_group,
                    sub_id,
                    name,
                    rg_client,
                    rg_query_options,
                    resource_id,
                )
                json_key = "disks"

            elif resource_type == "microsoft.compute/sshpublickeys":
                object_to_add = ssh_public_keys.parse_obj(
                    resource_type,
                    resource_group,
                    sub_id,
                    name,
                    rg_client,
                    rg_query_options,
                    resource_id,
                    DEBUGGING,
                )
                json_key = "sshKeys"

            elif resource_type == "microsoft.network/networkinterfaces":
                object_to_add = network_interfaces.parse_obj(
                    resource_type,
                    resource_group,
                    sub_id,
                    name,
                    rg_client,
                    rg_query_options,
                    resource_id,
                    DEBUGGING,
                )
                json_key = "networkInterfaces"

            elif resource_type == "microsoft.network/networksecuritygroups":
                object_to_add = network_security_groups.parse_obj(
                    resource_type,
                    resource_group,
                    sub_id,
                    name,
                    rg_client,
                    rg_query_options,
                    resource_id,
                    DEBUGGING,
                )
                json_key = "networkSecurityGroups"

            elif resource_type == "microsoft.network/publicipaddresses":
                object_to_add = public_ip_addresses.parse_obj(
                    resource_type,
                    resource_group,
                    sub_id,
                    name,
                    rg_client,
                    rg_query_options,
                    resource_id,
                    DEBUGGING,
                )
                json_key = "publicIpAddresses"

            elif resource_type == "microsoft.network/virtualnetworks":
                object_to_add = vnets.parse_obj(
                    resource_type,
                    resource_group,
                    sub_id,
                    name,
                    rg_client,
                    rg_query_options,
                    resource_id,
                    DEBUGGING,
                )
                json_key = "vnets"

            elif resource_type == "microsoft.network/virtualnetworkgateways":
                object_to_add = vnet_gateways.parse_obj(
                    resource_type,
                    resource_group,
                    sub_id,
                    name,
                    rg_client,
                    rg_query_options,
                    resource_id,
                    DEBUGGING,
                )
                json_key = "vnetGateways"

            elif resource_type == "microsoft.network/localnetworkgateways":
                object_to_add = local_network_gateways.parse_obj(
                    resource_type,
                    resource_group,
                    sub_id,
                    name,
                    rg_client,
                    rg_query_options,
                    resource_id,
                    DEBUGGING,
                )
                json_key = "localNetworkGateways"

            elif resource_type == "microsoft.network/connections":
                object_to_add = connections.parse_obj(
                    resource_type,
                    resource_group,
                    sub_id,
                    name,
                    rg_client,
                    rg_query_options,
                    resource_id,
                    DEBUGGING,
                )
                json_key = "connections"

            elif resource_type == "microsoft.network/routetables":
                object_to_add = route_tables.parse_obj(
                    resource_type,
                    resource_group,
                    sub_id,
                    name,
                    rg_client,
                    rg_query_options,
                    resource_id,
                    DEBUGGING,
                )
                json_key = "routeTables"

            elif resource_type == "microsoft.storage/storageaccounts":
                object_to_add = storage_accounts.parse_obj(
                    resource,
                    resource_type,
                    resource_group,
                    sub_id,
                    name,
                    rg_client,
                    rg_query_options,
                    resource_id,
                    DEBUGGING,
                    credentials,
                )
                json_key = "storageAccounts"

            elif resource_type == "microsoft.documentdb/databaseaccounts":
                object_to_add = cosmos_databases.parse_obj(
                    resource_type,
                    resource_group,
                    sub_id,
                    name,
                    rg_client,
                    rg_query_options,
                    resource_id,
                    DEBUGGING,
                )
                json_key = "cosmosDBs"

            elif resource_type == "microsoft.web/sites":
                object_to_add = app_services.parse_obj(
                    resource,
                    resource_type,
                    resource_group,
                    sub_id,
                    name,
                    rg_client,
                    rg_query_options,
                    resource_id,
                    DEBUGGING,
                    headers,
                )
                json_key = "appServices"

            elif resource_type == "microsoft.web/serverfarms":
                object_to_add = app_service_plans.parse_obj(
                    resource_type,
                    resource_group,
                    sub_id,
                    name,
                    rg_client,
                    rg_query_options,
                    resource_id,
                    DEBUGGING,
                )
                json_key = "appServicePlans"

            elif resource_type == "microsoft.servicebus/namespaces":
                object_to_add = service_buses.parse_obj(
                    resource_type,
                    resource_group,
                    sub_id,
                    name,
                    rg_client,
                    rg_query_options,
                    resource_id,
                    DEBUGGING,
                    bearer_token,
                )
                json_key = "serviceBuses"

            elif resource_type == "microsoft.insights/components":
                app_insights_dump = application_insights.get_application_insights(
                    sub_id=sub_id,
                    rsg_name=resource_group,
                    app_insight_name=name,
                    headers=headers,
                    DEBUGGING=DEBUGGING,
                )
                if app_insights_dump != None:
                    try:
                        json_representation["applicationInsights"].append(
                            app_insights_dump
                        )
                    except KeyError:
                        json_representation.setdefault(
                            "applicationInsights", [app_insights_dump]
                        )
                    except AttributeError:
                        json_representation.setdefault(
                            "applicationInsights", [app_insights_dump]
                        )

            elif resource_type == "microsoft.sql/servers":
                object_to_add = sql_servers.parse_obj(
                    resource_type,
                    resource_group,
                    sub_id,
                    name,
                    rg_client,
                    rg_query_options,
                    resource_id,
                    DEBUGGING,
                    headers,
                )
                json_key = "sqlServers"

            elif resource_type == "microsoft.dbformysql/servers":
                object_to_add = mysql_servers.parse_obj(
                    resource_type,
                    resource_group,
                    sub_id,
                    name,
                    rg_client,
                    rg_query_options,
                    resource_id,
                    DEBUGGING,
                    headers,
                )
                json_key = "mySQLDatabases"

            elif resource_type == "microsoft.dbforpostgresql/servers":
                object_to_add = postgresql_servers.parse_obj(
                    resource_type,
                    resource_group,
                    sub_id,
                    name,
                    rg_client,
                    rg_query_options,
                    resource_id,
                    DEBUGGING,
                    headers,
                )
                json_key = "postgreSQLDatabases"

            elif resource_type == "microsoft.dbformariadb/servers":
                object_to_add = mariadb_servers.parse_obj(
                    resource_type,
                    resource_group,
                    sub_id,
                    name,
                    rg_client,
                    rg_query_options,
                    resource_id,
                    DEBUGGING,
                    headers,
                )
                json_key = "mariaDBDatabases"

            elif resource_type == "microsoft.containerregistry/registries":
                object_to_add = container_registries.parse_obj(
                    resource_type,
                    resource_group,
                    sub_id,
                    name,
                    rg_client,
                    rg_query_options,
                    resource_id,
                    DEBUGGING,
                )
                json_key = "containerRegistries"

            elif resource_type == "microsoft.containerservice/managedclusters":
                object_to_add = kubernetes_clusters.parse_obj(
                    resource_type,
                    resource_group,
                    sub_id,
                    name,
                    resource_id,
                    DEBUGGING,
                    headers,
                )
                json_key = "kubernetesClusters"

            elif resource_type == "microsoft.apimanagement/service":
                object_to_add = api_management.parse_obj(
                    resource_type,
                    resource_group,
                    sub_id,
                    name,
                    rg_client,
                    rg_query_options,
                    resource_id,
                    DEBUGGING,
                    headers,
                )
                json_key = "apiManagements"
            else:
                if COUNTING:
                    supported_asset = False
            if COUNTING:
                count = ASSETS.get(resource_type, (0, supported_asset))[0]
                ASSETS[resource_type] = (count + 1, supported_asset)
            if object_to_add is None:
                continue
            if json_key not in ["", None]:
                try:
                    json_representation[json_key].append(object_to_add.__dict__)
                except (KeyError, AttributeError):
                    json_representation.setdefault(json_key, [object_to_add.__dict__])
        except requests.exceptions.ConnectionError as e:
            print(f"WARNING: {e}")
            pass
    return json_representation


def write_ad_as_json():
    """Generates the json file of the Active Directory to use as input for the parser"""
    # Authenticate the Service Principal
    credentials = authenticate()
    # Need to make regular REST API call for role definition information
    scope = "https://management.azure.com/.default"
    try:
        access_token = credentials.get_token(scope)
        bearer_token = access_token[0]
    except ClientAuthenticationError:
        sys.exit(
            SystemExit(
                f"Cannot get a bearer token for type: {type(credentials)} on scope {scope}. Cannot fetch azure data, exiting."
            )
        )

    headers = {"Authorization": "Bearer " + bearer_token}
    sub_client = SubscriptionClient(credential=credentials)
    ad_subscriptions = fetch_subscriptions(sub_client=sub_client)

    final_json_object = {"name": "Scanned_Azure_Active_Directory"}

    resource_groups_of_interest = None
    try:
        resource_groups_of_interest = os.environ["AZURE_RESOURCE_GROUP_NAMES"]
    except KeyError:
        resource_groups_of_interest = None
    # If the environment variable is set, the user only wants to look at the resources in a specified resource groups.
    if resource_groups_of_interest not in [None, "", {}]:
        if "[" in resource_groups_of_interest:
            try:
                resource_groups_of_interest = json.loads(resource_groups_of_interest)
            except JSONDecodeError:
                if DEBUGGING:
                    print(f"AZURE_RESOURCE_GROUP_NAMES seems to be the wrong format.")
        elif (
            type(resource_groups_of_interest) == str
            and "," in resource_groups_of_interest
        ):
            resource_groups_of_interest = resource_groups_of_interest.split(",")
            resource_groups_of_interest = [
                str(x).strip() for x in resource_groups_of_interest
            ]
        if type(resource_groups_of_interest) != list:
            resource_groups_of_interest = [resource_groups_of_interest]
    # Management Groups
    # Listing them
    endpoint = f"https://management.azure.com/providers/Microsoft.Management/managementGroups?api-version=2020-02-01"
    try:
        mgmt_grp_request = requests.get(url=endpoint, headers=headers)
        if mgmt_grp_request.status_code not in ["AuthorizationFailed"]:
            api_management_groups = mgmt_grp_request.json()
    except:
        if DEBUGGING:
            print(f"Couldn't fetch Management Groups for the tenant.")
        api_management_groups = {}
    queue = []
    for mg in api_management_groups.get("value") or []:
        queue.append(mg)
    management_groups = []
    while len(queue) > 0:
        try:
            mg = queue.pop()
            # Managementgroups can be nested
            management_group = __extract_management_groups(
                management_group_id=mg.get("id"),
                management_group_name=mg.get("name"),
                headers=headers,
            )
            management_groups.append(management_group.__dict__)
            for child in management_group.scope or []:
                if not child.get("scopeType"):
                    continue
                elif (
                    child["scopeType"].lower()
                    == "Microsoft.Management/managementGroups"
                ):
                    # We only need to continue the "recursion" if we have a nested management group
                    queue.append(child)
        except IndexError:
            break
    final_json_object["managementGroups"] = management_groups
    # management_groups = None
    # Subscription objects generation
    subscriptions = []
    rbac_roles = []
    for sub in ad_subscriptions["subsRaw"]:
        name = sub.get("display_name")
        subscriptionId = sub.get("subscription_id")
        authorizationSource = sub.get("authorization_source")
        resource_id = sub.get("id")
        subscription = Subscription(
            resourceId=resource_id,
            name=name,
            subscriptionId=subscriptionId,
            authorizationSource=authorizationSource,
        )
        subscriptions.append(subscription.__dict__)
        # TODO: The Restcalls below are slow, try speeding this up
        # RBAC on subscription scope
        amc = AuthorizationManagementClient(
            credentials, subscriptionId, api_version="2018-09-01-preview"
        )
        amc_rdef = AuthorizationManagementClient(
            credentials, subscriptionId, api_version="2018-01-01-preview"
        )  # Need two seperate once because one version doesn't support principal_type while the other doesn't contain role_definitions
        role_assignments = amc.role_assignments.list()
        groups: List[
            Dict[str, "Group"]
        ] = []  # Will map any principal Group to all its members
        checked_groups: set = (
            set()
        )  # Keeps track of which groups we have checked members for, to not be stuck forever
        for role_assignment in role_assignments:
            role_assignment_dict = role_assignment.__dict__
            if any(
                x["id"] == role_assignment_dict["id"]
                and x["scope"] == role_assignment_dict["scope"]
                and x["principalId"] == role_assignment_dict["principal_id"]
                for x in rbac_roles
            ):
                continue  # Role is already listed from somewhere else
            role_definition_id = role_assignment_dict["role_definition_id"]
            if role_definition_id:
                role_definition = amc_rdef.role_definitions.get_by_id(
                    role_definition_id
                )
                permissions = role_definition.permissions
                final_permissions = []
                for perm in permissions:
                    permission_to_add = {
                        "actions": perm.actions,
                        "notActions": perm.not_actions,
                        "dataActions": perm.data_actions,
                        "notDataActions": perm.not_data_actions,
                    }
                    final_permissions.append(permission_to_add)
                role_to_add = {
                    "id": role_assignment_dict["id"],
                    "name": role_assignment_dict["name"],
                    "scope": role_assignment_dict["scope"],
                    "principalId": role_assignment_dict["principal_id"],
                    "principalType": role_assignment_dict["principal_type"],
                    "roleName": role_definition.role_name,
                    "permissions": final_permissions,
                }
                if role_assignment_dict["principal_type"] == "Group":
                    if (
                        not os.environ.get("AZURE_TENANT_ID")
                        or not os.environ.get("AZURE_CLIENT_ID")
                        or not os.environ.get("AZURE_CLIENT_SECRET")
                    ):
                        print(
                            f"ERROR: AZURE environment variable(s) not set. Impact: Cannot read group members of group {role_assignment_dict['principal_id']}. Run python3 fetch_subscription_resources.py -h for more info."
                        )
                    else:
                        tenant_id = os.environ.get("AZURE_TENANT_ID")
                        client_id = os.environ.get("AZURE_CLIENT_ID")
                        auth_data = {
                            "client_id": os.environ.get("AZURE_CLIENT_ID"),
                            "scope": "https://graph.microsoft.com/.default",
                            "grant_type": "client_credentials",
                            "client_secret": os.environ.get("AZURE_CLIENT_SECRET"),
                        }
                        graph_headers = {}
                        graph_res = requests.post(
                            url=f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token",
                            data=auth_data,
                            headers={
                                "Content-Type": "application/x-www-form-urlencoded"
                            },
                        )
                        access_token = graph_res.json().get("access_token")
                        try:
                            graph_headers.update(
                                {"Authorization": f"Bearer {access_token}"}
                            )
                        except:
                            if DEBUGGING:
                                print(
                                    f"ERROR: Couldn't get access_token for Microsoft Graph. Impact: Cannot read group members of group {role_assignment_dict['principal_id']}"
                                )
                        nested_groups = [role_assignment_dict["principal_id"]]
                        while len(nested_groups) > 0:
                            group_id = nested_groups.pop()
                            if (
                                group_id not in checked_groups
                            ):  # Group membership can be cyclic, we don't want to go on forever
                                checked_groups.add(group_id)
                                members = ad_groups.collect_group_memberships(
                                    group_id, tenant_id, graph_headers, DEBUGGING
                                )
                                group_members = []
                                for member in members:
                                    group_members.append(member)
                                    if (
                                        member["memberType"] == "group"
                                        and member["id"] not in checked_groups
                                    ):
                                        nested_groups.append(member["id"])
                                groups.append(
                                    {"groupId": group_id, "members": group_members}
                                )
                rbac_roles.append(role_to_add)
    final_json_object["groups"] = groups
    final_json_object["subscriptions"] = subscriptions
    final_json_object["roleAssignments"] = rbac_roles
    subscriptions, rbac_roles = None, None

    rg_client = arg.ResourceGraphClient(credentials)

    # Resource Groups
    resource_groups = []
    for sub_id in ad_subscriptions["subs_id_list"]:
        rm_client = ResourceManagementClient(credentials, sub_id)
        resource_groups_in_subscription = rm_client.resource_groups.list()
        for resource_grp in resource_groups_in_subscription:
            try:
                managing_resource_grp = None
                if resource_grp.managed_by:
                    managing_resource_grp = resource_grp.managed_by.split("/")[4]
            except (AttributeError, SyntaxError):
                pass
            if (
                resource_groups_of_interest not in ["", None, []]
                and resource_grp.name not in resource_groups_of_interest
                and managing_resource_grp not in resource_groups_of_interest
            ):
                continue
            name = resource_grp.name
            managedBy = resource_grp.managed_by
            resource_group = ResourceGroup(
                resourceId=resource_grp.id,
                subscriptionId=sub_id,
                name=name,
                managedBy=managedBy,
                provider=resource_grp.type,
            )
            resource_groups.append(resource_group.__dict__)

            # Individual Resources handling
            resources_in_grp = rm_client.resources.list_by_resource_group(
                resource_group_name=resource_grp.name
            )
            json_representation = iterate_resources_to_json(
                resources=resources_in_grp,
                resource_group=resource_grp.name,
                rg_client=rg_client,
                sub_id=sub_id,
                credentials=credentials,
            )
            for key in json_representation.keys():
                existing_final_list = (
                    final_json_object.get(key) if final_json_object.get(key) else []
                )
                obtained_local_list = json_representation.get(key)
                for entry in obtained_local_list:
                    existing_final_list.append(entry)
                final_json_object[key] = existing_final_list
    final_json_object["resourceGroups"] = resource_groups
    resource_groups = None
    # Save Application Insights into a seperate file
    app_insights = final_json_object.get("applicationInsights")
    timestamp = datetime.datetime.today().strftime('%Y-%m-%d_%H-%M')
    if app_insights != None:
        if app_insights != {}:
            with open(
                os.path.join(BASE_DIR, f"environment_files/application_insights_{timestamp}.json"),
                "w",
            ) as app_insights_file:
                json.dump(app_insights, fp=app_insights_file, indent=4, sort_keys=True)
        # Don't want to include application insights in standard environment parsing (should be optional to enrich model)
        del final_json_object["applicationInsights"]
    # print(json.dumps(obj=final_json_object, indent=4, sort_keys=True))
    with open(
        os.path.join(BASE_DIR, f"environment_files/active_directory_{timestamp}.json"), "w"
    ) as json_file:
        json.dump(obj=final_json_object, fp=json_file, indent=4, sort_keys=True)


def __extract_management_groups(management_group_id, management_group_name, headers):
    """Helper function to extract the ManagementGroup objects from azure"""
    endpoint = f"https://management.azure.com/{management_group_id}?api-version=2020-02-01&$expand=children&$recurse=True"
    connected_to = requests.get(url=endpoint, headers=headers).json()
    connected_to_children = connected_to.get("properties").get("children")
    if not connected_to_children:
        management_group = ManagementGroup(
            resourceId=management_group_id, name=management_group_name, scope=[]
        )
        return
    children = []
    for child in connected_to_children or []:
        obj = {
            "id": child.get("id"),
            "scopeType": child.get("type"),
            "name": child.get("name"),
        }
        children.append(obj)
    management_group = ManagementGroup(
        resourceId=management_group_id, name=management_group_name, scope=children
    )
    return management_group


def print_resource_groups():
    """Fetches and prints the resource groups within the resource manager client along with its containing services"""
    # Authenticate the Service Principal
    credentials = authenticate()

    sub_client = SubscriptionClient(credentials)
    subscriptions = fetch_subscriptions(sub_client)

    print("Subscription info:")
    for entry in subscriptions["subsRaw"]:
        print(f"\n{entry}\n")

    print("Resources: \n")
    for sub_id in subscriptions["subs_id_list"]:
        rm_client = ResourceManagementClient(credentials, sub_id)
        resource_groups_in_subscription = rm_client.resource_groups.list()
        for resource_grp in resource_groups_in_subscription:
            print(resource_grp)
            resources_in_grp = rm_client.resources.list_by_resource_group(
                resource_group_name=resource_grp.name
            )
            for resource in resources_in_grp:

                print(f"\n{resource}\n")


def authenticate():
    """Authenticates the application to the subscription. Confirms the exists an RBAC delegation for the app
    on the requested subscription.

    Returns: \n
        Authentication object if successfully authenticated identity. Exits otherwise
    """
    credentials = None
    try:
        credentials = DefaultAzureCredential(
            exclude_environment_credential=False
        )  # Authentication order: https://docs.microsoft.com/en-us/python/api/overview/azure/identity-readme?view=azure-python
    except:
        sys.exit(
            SystemExit(
                f"Required enviornment variables are not set and cannot authenticate as a Manage Identity. Start the program with -h for help, exiting."
            )
        )
    return credentials


def validate_arguments(argv):
    """Confirms that correct number of arguments and argument type is provided.
    Exits the program if conditions are unfulfilled.

    Keyword arguments:
        argv - Program arguments.
    """
    global DEBUGGING
    if len(argv) > 1 and any(arg in ["-h", "help", "--help"] for arg in argv):
        print(
            f"""Usage: python3 {__file__} [OPTIONS]
        Required environment variables:
            AZURE_TENANT_ID - Your AD tenant ID.
            AZURE_CLIENT_ID - Your registered application's client ID.
        
        Optional environment variables:
            AZURE_SUBSCRIPTION_ID - Set the AZURE_SUBSCRIPTION_ID if you want to examine a single specific subscription.
            AZURE_RESOURCE_GROUP_NAMES - '["rsg_one", "rsg_two"]' List the names of resource groups you only want to include. Fetches all resource groups by default
            APP_INSIGHTS_INTERVAL = Time interval following the ISO8601 standard: YYYY-MM-DDTHH-MM-SS/YYYY-MM-DDTHH-MM-SS (e.g. 2020-01-01T16:01:30.000/2021-02-20T16:01:30.000). Defaults to the latest 90 days
            
        OPTIONS:
            -h : Print out help information. same a help, --help
            -d, -D, --debugging : Enable debugging information
            -ca, -CA, --count_assets : Lists how many of each type of asset is available, and whether they are supported by azureLang or not. Results are returned in counted_assets.json
        """
        )
        raise SystemExit
    if len(argv) > 1 and any(arg in ["-d", "-D", "--debugging"] for arg in argv):
        DEBUGGING = True
    if len(argv) > 1 and any(arg in ["-ca", "-CA", "--count_assets"] for arg in argv):
        global COUNTING
        global ASSETS
        COUNTING = True
        ASSETS = {}


# converts asset count to json
# only run with -ca flag
def asset_count_to_json():
    result = {}
    known = {}
    unknown = {}
    for asset in sorted(ASSETS, key=ASSETS.get, reverse=True):
        # checks if asset is known or not
        if ASSETS[asset][1] == True:
            known[asset] = ASSETS[asset][0]
        else:
            unknown[asset] = ASSETS[asset][0]
    result["Known assets:"] = known
    result["Unknown assets:"] = unknown
    with open(os.path.join(BASE_DIR, "counted_assets.json"), "w") as json_file:
        json.dump(obj=result, fp=json_file, indent=4)


def main(argv):
    global COUNTING
    # start_time = time.time()
    # pr = cProfile.Profile()
    # pr.enable()
    validate_arguments(argv)
    write_ad_as_json()
    # print_resource_groups()
    # pr.disable()
    # s = io.StringIO()
    # ps = pstats.Stats(pr, stream=s).sort_stats(SortKey.CUMULATIVE)
    # ps.print_stats()
    # print(s.getvalue())
    # end_time = time.time() - start_time
    # print("total_time: ", end_time)
    if COUNTING:
        asset_count_to_json()


if __name__ == "__main__":
    main(sys.argv)
