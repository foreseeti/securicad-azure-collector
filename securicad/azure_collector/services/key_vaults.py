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

from securicad.azure_collector.schema_classes import KeyVault, KeyVaultComponent
from azure.mgmt.keyvault import KeyVaultManagementClient
from azure.keyvault.keys import KeyClient as kv_KeyClient
from azure.keyvault.certificates import CertificateClient as kv_CertificateClient
from azure.keyvault.secrets import SecretClient as kv_SecretClient
from securicad.azure_collector.services.parser_logger import log
import azure.mgmt.resourcegraph as arg
import requests

def parse_obj(resource_type, resource_group, sub_id, name, rg_client, rg_query_options, resource_id, DEBUGGING, credentials, headers) -> KeyVault:
    str_query = f"resources | where type=~'Microsoft.Keyvault/vaults' and id == '{resource_id}'"
    query = arg.models.QueryRequest(
        subscriptions=[sub_id], query=str_query, options=rg_query_options,
    )
    try:
        rg_results_as_dict = rg_client.resources(query=query).__dict__
    except:
        log.error(
            f"Couldn't execute resource graph query of key vault {name}, skipping asset."
        )
        return None
    vault_url = rg_results_as_dict["data"][0]["properties"]["vaultUri"]
    keys = []
    certificates = []
    secrets = []
    kv_components = {}
    try:
        enable_rbac_authorization = rg_results_as_dict["data"][0]["properties"]["enabledForDeployment"]
    except KeyError:
        enable_rbac_authorization = False # Default value
    kvm_client = KeyVaultManagementClient(
        credential=credentials, subscription_id=sub_id
    )
    all_access_policies = kvm_client.vaults.get(
        resource_group_name=resource_group, vault_name=name
    ).properties.access_policies
    principal_data_actions = []
    for ap in all_access_policies:
        permission_dict = {
            "certificates": ap.permissions.__dict__.get("certificates"),
            "secrets": ap.permissions.__dict__.get("secrets"),
            "keys": ap.permissions.__dict__.get("keys"),
        }
        principal_data_actions.append(
            {
                "objectId": ap.object_id,
                "tenantId": ap.tenant_id,
                "permissions": permission_dict,
            }
        )
    key_client = kv_KeyClient(vault_url=vault_url, credential=credentials)
    cert_client = kv_CertificateClient(
        vault_url=vault_url, credential=credentials
    )
    secret_client = kv_SecretClient(
        vault_url=vault_url, credential=credentials
    )
    # Default Keys, Certificates and Secrets if access is not given to the data extractor
    try:
        kv_keys = key_client.list_properties_of_keys()
        kv_certs = cert_client.list_properties_of_certificates()
        kv_secrets = secret_client.list_properties_of_secrets()
        kv_components = {kv_keys, kv_certs, kv_secrets}
        for item_paged in kv_components or []:
            try:
                for kv_component in item_paged:
                    component = KeyVaultComponent(
                        resourceId=kv_component._id,
                        name=kv_component._vault_id.name,
                        enabled=kv_component.enabled,
                        collection=kv_component._vault_id.collection,
                    )
                    if kv_component._vault_id.collection == "keys":
                        keys.append(component.__dict__)
                    elif (
                        kv_component._vault_id.collection == "certificates"
                    ):
                        certificates.append(component.__dict__)
                    else:
                        secrets.append(component.__dict__)
            except:
                log.warning(
                    f"Insufficient permissions or Firewall rules blocking access to read {name}'s key vault components."
                )
                break
        kv_components = None
        kv_keys, kv_certs, kv_secrets = None, None, None
    except:
        log.warning(
            f"Cannot list components on Key vault {name}, controll the access policy for the Security Principal."
        )
    if keys == []:
        keys = [
            {
                "collection": "keys",
                "enabled": True,
                "id": f"https://{name}.vault.azure.net/keys/default",
                "name": "test-component",
            },
        ]
    if certificates == []:
        certificates = [
            {
                "collection": "certificates",
                "enabled": True,
                "id": f"https://{name}.vault.azure.net/certificates/default",
                "name": "test-component",
            },
        ]
    if secrets == []:
        secrets = [
            {
                "collection": "secrets",
                "enabled": True,
                "id": f"https://{name}.vault.azure.net/secrets/default",
                "name": "test-component",
            }
        ]
    try:
        purge_protection = rg_results_as_dict["data"][0]["properties"][
            "enableSoftDelete"
        ]
    except KeyError:
        log.debug(
            f"Could not get Purge Protection value from Key Vault {name}. Assuming true"
        )
        purge_protection = True
    endpoint = f"https://management.azure.com/subscriptions/{sub_id}/resourceGroups/{resource_group}/providers/Microsoft.KeyVault/vaults/{name}?api-version=2019-09-01"
    try:
        resource_explorer_data = requests.get(
            url=endpoint, headers=headers
        ).json()
    except:
        log.error(
            f"Couldn't perform GET resquest on {endpoint}. Could be a bad authentication due to Bearer token."
        )
        resource_explorer_data = {}
    try:
        vault_properties = resource_explorer_data["properties"]
        if vault_properties.get("networkAcls"):
            try:
                ip_rules = [
                    x["value"]
                    for x in vault_properties["networkAcls"]["ipRules"]
                    or []
                ]
            except KeyError:
                log.debug(
                    f"Couldn't get IP rules of Key Vault {name}, assuming no specified rules."
                )
                ip_rules = []
            try:
                virtual_network_rules = [
                    x["id"]
                    for x in vault_properties["networkAcls"][
                        "virtualNetworkRules"
                    ]
                    or []
                ]
            except:
                log.debug(
                    f"Error while getting vnet rules from Key Vault {name} running API call {endpoint}"
                )
                virtual_network_rules = []
            try:
                restricted_access = (
                    True
                    if vault_properties["networkAcls"]["defaultAction"]
                    == "Deny"
                    else False
                )
            except:
                log.debug(
                    f"Couldn't find defaultAction on Key Vault {name}'s network rules, assuming 'Allow'"
                )
                restricted_access = False
        else:
            log.debug(
                f"Could not see any netowrkAcl rules for Key Vault {name}, assuming public internet accessible key vault."
            )
            ip_rules = []
            virtual_network_rules = []
            restricted_access = False
    except KeyError:
        log.debug(
            f"Could not get NetworkAcl properties for Key Vault {name}."
        )
        ip_rules = []
        virtual_network_rules = []
        restricted_access = False

    object_to_add = KeyVault(
        resourceId=resource_id,
        name=name,
        resourceGroup=resource_group,
        keys=keys,
        secrets=secrets,
        certificates=certificates,
        provider=resource_type,
        restrictedAccess=restricted_access,
        ipRules=ip_rules,
        virtualNetworkRules=virtual_network_rules,
        purgeProtection=purge_protection,
        accessPolicies=principal_data_actions,
        enableRbacAuthorization=enable_rbac_authorization
    )
    return object_to_add
