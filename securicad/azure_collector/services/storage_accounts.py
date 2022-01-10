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

from securicad.azure_collector.schema_classes import StorageAccount, StorageAccountService
from securicad.azure_collector.services.parser_logger import log
import azure.mgmt.resourcegraph as arg
from azure.mgmt.storage import StorageManagementClient

def parse_obj(resource, resource_type, resource_group, sub_id, name, rg_client, rg_query_options, resource_id, DEBUGGING, credentials) -> StorageAccount:
    kind = resource.kind
    str_query = f"resources | where type =~ 'microsoft.storage/storageaccounts' and name == '{name}'"
    query = arg.models.QueryRequest(
        subscriptions=[sub_id], query=str_query, options=rg_query_options,
    )
    try:
        rg_results_as_dict = rg_client.resources(query=query).__dict__
    except:
        log.error(
            f"Couldn't execute resource graph query of Storage Account {name}, skipping asset."
        )
        return None
    raw_properties = rg_results_as_dict["data"][0]["properties"]

    primary_endpoints = raw_properties["primaryEndpoints"]

    # TODO: Add consequence of this being enabled
    allow_blob_public_access = raw_properties.get("allowBlobPublicAccess")
    if allow_blob_public_access != True:
        allow_blob_public_access = None

    # Firewall rules
    private_endpoints = raw_properties.get("privateEndpointConnections")
    try:
        raw_vnet_rules = raw_properties.get("networkAcls").get(
            "virtualNetworkRules"
        )
        vnet_rules = [
            x.get("id") for x in raw_vnet_rules if x.get("id") != None
        ]
    except:
        vnet_rules = []
    try:
        raw_ip_rules = raw_properties.get("networkAcls").get("ipRules")
        ip_rules = [
            x.get("id") for x in raw_ip_rules if x.get("id") != None
        ]
    except:
        ip_rules = []
    bypass_services = (
        True
        if raw_properties.get("networkAcls").get("bypass")
        == "AzureServices"
        else False
    )

    # If any networks can access the storage account or not
    try:
        restricted_access = (
            True
            if raw_properties.get("networkAcls").get("defaultAction")
            == "Deny"
            else False
        )
    except KeyError:
        # Default to allow all
        restricted_access = False

    try:
        store_client = StorageManagementClient(
            credential=credentials, subscription_id=sub_id
        )
    except:
        log.warning(
            f"Not able to access StorageManagmentClient on subscription {sub_id}"
        )
        store_client = None
    services = []
    if store_client:
        # BlobContainers
        try:
            blob_containers = store_client.blob_containers.list(
                resource_group_name=resource_group, account_name=name
            )
            for blobcontainer in blob_containers or []:
                try:
                    blobcontainer_dict = blobcontainer.__dict__
                    public_access_raw = blobcontainer_dict.get(
                        "public_access"
                    )
                    allow_blob_public_access = (
                        True
                        if public_access_raw.lower()
                        in ["blob", "container"]
                        else False
                    )
                    container = StorageAccountService(
                        name=blobcontainer_dict.get("name"),
                        serviceType="blob",
                        resourceId=blobcontainer_dict.get("id"),
                        allowBlobPublicAccess=allow_blob_public_access,
                    )
                    services.append(container.__dict__)
                except AttributeError as e:
                    log.error(
                        f"Attribute Error caught when fetching blobcontainers. Check azure-mgmt-storage package for changed fields. Traceback: \n {e}"
                    )
        except:
            log.debug(
                f"Could not list blob containers on storage account: {name}. Check permissions"
            )
        # FileShares
        try:
            file_shares = store_client.file_shares.list(
                resource_group_name=resource_group, account_name=name
            )
            for fs in file_shares or []:
                file_share = StorageAccountService(
                    name=fs.name, serviceType="fileShare", resourceId=fs.id
                )
                services.append(file_share.__dict__)
            file_shares = None
        except:
            log.debug(
                f"Could not list file share services on storage account: {name}"
            )
            pass
        # Tables
        try:
            tables = store_client.table.list(
                resource_group_name=resource_group, account_name=name
            )
            for table in tables or []:
                table_service = StorageAccountService(
                    name=table.name,
                    serviceType="table",
                    resourceId=table.id,
                )
                services.append(table_service.__dict__)
            tables = None
        except:
            log.debug(
                f"Could not list table services on storage account: {name}"
            )
            pass
        # Queues
        try:
            queues = store_client.queue.list(
                resource_group_name=resource_group, account_name=name
            )
            for que in queues or []:
                queue_service = StorageAccountService(
                    name=que.name, serviceType="queue", resourceId=que.id
                )
                services.append(queue_service.__dict__)
            queues = None
        except:
            log.debug(
                f"Could not list queue services on storage account: {name}"
            )
            pass

    object_to_add = StorageAccount(
        resourceId=resource_id,
        name=name,
        kind=kind,
        resourceGroup=resource_group,
        primaryEndpoints=primary_endpoints,
        services=services,
        provider=resource_type,
        httpsOnly=raw_properties.get("supportsHttpsTrafficOnly"),
        restrictedAccess=restricted_access,
        privateEndpoints=private_endpoints,
        virtualNetworkRules=vnet_rules,
        ipRangeFilter=ip_rules,
        bypassServices=bypass_services,
    )
    return object_to_add
