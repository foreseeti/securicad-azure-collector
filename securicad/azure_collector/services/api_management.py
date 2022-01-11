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

from requests import api
from securicad.azure_collector.schema_classes import APIManagement
from securicad.azure_collector.services.parser_logger import log
import azure.mgmt.resourcegraph as arg
import requests

def parse_obj(resource_type, resource_group, sub_id, name, rg_client, rg_query_options, resource_id, DEBUGGING, headers) -> APIManagement:
    str_query = f"resources | where type =~ 'microsoft.apimanagement/service' and name == '{name}'"
    query = arg.models.QueryRequest(
        subscriptions=[sub_id],
        query=str_query,
        options=rg_query_options,
    )
    try:
        rg_results_as_dict = rg_client.resources(query=query).__dict__
    except:
        log.error(
            f"Couldn't execute resource graph query of api management {name}, skipping asset."
        )
        return None
    try:
        raw_properties = rg_results_as_dict["data"][0]["properties"]
    except IndexError:
        log.error(
            f"Couldn't get resource graph data from api management {name}. Impact: missing infrastructure"
        )
        return None
    try:
        subnetId = raw_properties["virtualNetworkConfiguration"][
            "subnetResourceId"
        ]
    except (KeyError, TypeError):
        log.debug(
            f"Couldn't find api managment subnet id of its virtual network configuration."
        )
        subnetId = None
    try:
        virtualNetworkType = raw_properties["virtualNetworkType"]
    except KeyError:
        log.debug(f"Couldn't find virtual network type.")
        virtualNetworkType = None
    try:
        publicipAddresses = raw_properties["publicIPAddresses"]
    except KeyError:
        log.debug(f"Couldn't find public ip of the api managment resource {name}.")
        publicipAddresses = None
    try:
        privateipAddresses = raw_properties["privateIPAddresses"]
    except KeyError:
        log.debug(f"Couldn't find private ip of the api managment resource {name}.")
        privateipAddresses = None
    try:
        certificates = raw_properties["certificates"]
    except KeyError:
        log.debug(
            f"Couldn't find any certificates of the api managment resource {name}."
        )
        certificates = []
    raw_identity = rg_results_as_dict["data"][0]["identity"]
    if raw_identity:
        try:
            principalId = raw_identity["principalId"]
        except (KeyError, TypeError):
            log.debug(
                f"Couldn't find a principal id of the api managment resource {name}. Assuming no system assigned managed identity"
            )
            principalId = None
        try:
            principalType = raw_identity["type"]
        except (KeyError, TypeError):
            principalType = None
        try:
            raw_user_assigned_ids = raw_identity[
                "userAssignedIdentities"
            ]
            user_assigned_ids = []
            for key, identity in raw_user_assigned_ids.items() or []:
                user_assigned_ids.append(
                    {
                        "identityId": key,
                        "clientId": identity["clientId"],
                        "principalId": identity["principalId"],
                    }
                )
        except (KeyError, TypeError):
            log.debug(
                f"Couldn't find any user assigned identites of the api management resource {name}"
            )
            user_assigned_ids = []
    else:
        log.debug(
            f"Couldn't get the IAM identity field of the api managment resource {name}. Assuming no attached Managed Identities"
        )
        principalId = None
        principalType = None
        user_assigned_ids = []
    try:
        subnetId = raw_properties["virtualNetworkConfiguration"][
            "subnetResourceId"
        ]
    except (KeyError, TypeError):
        log.debug(
            f"Couldn't find the subnet id in the virtual network configuration of the api management resource {name}."
        )
        subnetId = None
    try:
        certificates = raw_properties["certificates"]
    except KeyError:
        """log.debug(
            f"Couldn't find the certificates of the api managment resource {name}."
        )""" # Not using this attribute from what I can see regardless atm, no point warning
        certificates = []
    # To get api representing data from the resource explorer
    endpoint = f"https://management.azure.com/subscriptions/{sub_id}/resourceGroups/{resource_group}/providers/Microsoft.ApiManagement/service/{name}/apis?api-version=2018-01-01"
    try:
        resource_explorer_data = requests.get(
            url=endpoint, headers=headers
        ).json()
    except:
        resource_explorer_data = {}
        log.error(
            f"Couldn't get API call {endpoint}. Could be due to a bad bearer token."
        )
    apis = []
    raw_apis_data = resource_explorer_data.get("value")
    if raw_apis_data:
        try:
            for raw_api in raw_apis_data or []:
                api = {
                    "id": raw_api["id"],
                    "name": raw_api["name"],
                }
                apis.append(api)
        except KeyError:
            pass
    # To get certificates representing data from the resource explorer
    endpoint = f"https://management.azure.com/subscriptions/{sub_id}/resourceGroups/{resource_group}/providers/Microsoft.ApiManagement/service/{name}/certificates?api-version=2018-01-01"
    try:
        resource_explorer_data = requests.get(
            url=endpoint, headers=headers
        ).json()
    except:
        resource_explorer_data = {}
        log.error(
            f"Couldn't get API call {endpoint}. Could be due to a bad bearer token."
        )
    apiManagementcertificates = []
    raw_certificates_data = resource_explorer_data.get("value")
    if raw_certificates_data:
        try:
            for raw_certificate in raw_certificates_data or []:
                certificate = {
                    "id": raw_certificate["id"],
                    "name": raw_certificate["name"],
                }
                apiManagementcertificates.append(certificate)
        except KeyError:
            pass
    # To get product representing data from the resource explorer
    endpoint = f"https://management.azure.com/subscriptions/{sub_id}/resourceGroups/{resource_group}/providers/Microsoft.ApiManagement/service/{name}/products?api-version=2018-01-01"
    try:
        resource_explorer_data = requests.get(
            url=endpoint, headers=headers
        ).json()
    except:
        resource_explorer_data = {}
        log.error(
            f"Couldn't get API call {endpoint}. Could be due to a bad bearer token."
        )
    products_noapis = []
    raw_products_data = resource_explorer_data.get("value")
    if raw_products_data:
        try:
            for raw_product in raw_products_data or []:
                product_noapis = {
                    "id": raw_product["id"],
                    "name": raw_product["name"],
                }
                products_noapis.append(product_noapis)
        except KeyError:
            pass
    products = []
    # To the names of apis under the product, it will be convient for connection logic in the parser
    for product_noapis in products_noapis:
        product_name = product_noapis.get("name")
        endpoint = f"https://management.azure.com/subscriptions/{sub_id}/resourceGroups/{resource_group}/providers/Microsoft.ApiManagement/service/{name}/products/{product_name}/apis?api-version=2018-01-01"
        try:
            resource_explorer_data = requests.get(
                url=endpoint, headers=headers
            ).json()
        except:
            resource_explorer_data = {}
            log.error(
                f"Couldn't get API call {endpoint}. Could be due to a bad bearer token."
            )
        api_names = []
        raw_product_apis_data = resource_explorer_data.get("value")
        if raw_product_apis_data:
            try:
                for raw_product_api in raw_product_apis_data or []:
                    api_names.append(raw_product_api["name"])
            except KeyError:
                pass
        product = {
            "id": product_noapis["id"],
            "name": product_noapis["name"],
            "apiNames": api_names,
        }
        products.append(product)
    # To get the user data of the api management from the resource explorer
    endpoint = f"https://management.azure.com/subscriptions/{sub_id}/resourceGroups/{resource_group}/providers/Microsoft.ApiManagement/service/{name}/users?api-version=2018-01-01"
    try:
        resource_explorer_data = requests.get(
            url=endpoint, headers=headers
        ).json()
    except:
        resource_explorer_data = {}
        log.error(
            f"Couldn't get API call {endpoint}. Could be due to a bad bearer token."
        )
    apiManagementUsers = []
    raw_users_data = resource_explorer_data.get("value")
    if raw_users_data:
        try:
            for raw_user in raw_users_data or []:
                user = {
                    "id": raw_user["id"],
                    "name": raw_user["name"],
                    "userType": raw_user["properties"]["firstName"],
                }
                apiManagementUsers.append(user)
        except (KeyError, TypeError):
            pass
    # To get the subscirption data of the api management from the resource explorer
    endpoint = f"https://management.azure.com/subscriptions/{sub_id}/resourceGroups/{resource_group}/providers/Microsoft.ApiManagement/service/{name}/subscriptions?api-version=2019-12-01"
    try:
        resource_explorer_data = requests.get(
            url=endpoint, headers=headers
        ).json()
    except:
        resource_explorer_data = {}
        log.error(
            f"Couldn't get API call {endpoint}. Could be due to a bad bearer token."
        )
    apiManagementSubscriptions = []
    raw_subscriptions_data = resource_explorer_data.get("value")
    if raw_subscriptions_data:
        try:
            for raw_subscription in raw_subscriptions_data or []:
                subscription = {
                    "id": raw_subscription["id"],
                    "name": raw_subscription["name"],
                    "userId": raw_subscription["properties"].get(
                        "ownerId"
                    ),
                    "scope": raw_subscription["properties"].get(
                        "scope"
                    ),
                }
                apiManagementSubscriptions.append(subscription)
        except (KeyError, TypeError):
            pass
    object_to_add = APIManagement(
        resourceId=resource_id,
        name=name,
        resourceGroup=resource_group,
        provider=resource_type,
        apis=apis,
        products=products,
        subnetId=subnetId,
        virtualNetworkType=virtualNetworkType,
        apiManagementcertificates=apiManagementcertificates,
        principalId=principalId,
        principalType=principalType,
        userAssignedIdentities=user_assigned_ids,
        publicIpAddresses=publicipAddresses,
        privateIpAddresses=privateipAddresses,
        apiManagementUsers=apiManagementUsers,
        apiManagementSubscriptions=apiManagementSubscriptions,
    )
    return object_to_add
