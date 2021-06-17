from schema_classes import AppService
import azure.mgmt.resourcegraph as arg
import requests

def parse_obj(resource, resource_type, resource_group, sub_id, name, rg_client, rg_query_options, resource_id, DEBUGGING, headers) -> AppService:
    str_query = f"resources | where type =~ 'microsoft.web/sites' and name == '{name}'"
    query = arg.models.QueryRequest(
        subscriptions=[sub_id], query=str_query, options=rg_query_options,
    )
    try:
        rg_results_as_dict = rg_client.resources(query=query).__dict__
    except:
        if DEBUGGING:
            print(
                f"ERROR: Couldn't execute resource graph query of {name}, skipping asset."
            )
        return None
    kind = resource.kind
    # The principal type and system assigned managed identity
    try:
        principal_id = rg_results_as_dict["data"][0]["identity"][
            "principalId"
        ]
    except (KeyError, TypeError):
        if DEBUGGING:
            print(
                f"Couldn't find the principal Id of the app service {name}."
            )
        principal_id = None
    try:
        principal_type = rg_results_as_dict["data"][0]["identity"]["type"]
    except (KeyError, TypeError):
        if DEBUGGING and principal_id:
            print(
                f"Couldn't find the principal type of the app service {name}."
            )
        principal_type = None
    # If managed identity is activated on the resource it has a principal Id
    try:
        raw_user_assigned_ids = rg_results_as_dict["data"][0]["identity"][
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
        user_assigned_ids = []

    raw_properties = rg_results_as_dict["data"][0]["properties"]

    private_endpoints = raw_properties.get("privateEndpointConnections")
    try:
        outbound_addresses = raw_properties["outboundIpAddresses"].split(
            ","
        )
    except KeyError:
        outbound_addresses = []
    try:
        inbound_addresses = raw_properties["inboundIpAddress"].split(",")
    except KeyError:
        inbound_addresses = []
    try:
        https_only = raw_properties["httpsOnly"]
    except KeyError:
        https_only = False
    try:
        app_service_plan = raw_properties["serverFarmId"]
    except:
        app_service_plan = None
    try:
        ip_security_restrictions = []
        authentication_enabled = False
        # To get Access restrictions of App Services, we need the resource explorer API
        endpoint = f"https://management.azure.com/subscriptions/{sub_id}/resourceGroups/{resource_group}/providers/Microsoft.Web/sites/{name}/config?api-version=2020-10-01"
        try:
            resource_explorer_data = requests.get(
                url=endpoint, headers=headers
            ).json()
        except:
            if DEBUGGING:
                print(f"WARNING: Not allowed API request GET {endpoint}")
            resource_explorer_data = {}
        try:
            site_properties = resource_explorer_data["value"][0][
                "properties"
            ]
        except:
            if DEBUGGING:
                print(
                    f"Error getting properties field on object returned from {resource_explorer_data}."
                )
            site_properties = None
        ip_security_restrictions = []
        if site_properties:
            try:
                raw_ip_restrictions = site_properties[
                    "ipSecurityRestrictions"
                ]
                for ip_config in raw_ip_restrictions or []:
                    if (
                        ip_config.get("action").lower() == "allow"
                    ):  # Ignore Deny rules
                        if ip_config.get("ipAddress") != None:
                            if ip_config.get("ipAddress") not in [
                                "",
                                "undefined/undefined",
                            ]:
                                ip_security_restrictions.append(
                                    ip_config["ipAddress"]
                                )
                        elif ip_config.get("vnetSubnetResourceId") != None:
                            ip_security_restrictions.append(
                                ip_config["vnetSubnetResourceId"]
                            )
                        else:
                            if DEBUGGING:
                                print(
                                    f"Could not extract the ipAddress or vnetSubnetResourceId field of {ip_config} in {name}"
                                )
                    else:
                        if ip_config.get("action") == None and DEBUGGING:
                            print(
                                f"No action field in ip_config object {ip_config} when looking ad ipSecurityRestrictions of Web/Function App."
                            )
            except:
                if DEBUGGING:
                    print(
                        f"Error in fetching ipSecurityRestrictions from {site_properties} in {name}."
                    )
                pass
            # Get Authentication values
            endpoint = f"https://management.azure.com/subscriptions/{sub_id}/resourceGroups/{resource_group}/providers/Microsoft.Web/sites/{name}/config/authsettings/list?api-version=2020-10-01"
            try:
                resource_explorer_data = requests.post(
                    url=endpoint, headers=headers
                ).json()
            except:
                if DEBUGGING:
                    print(f"Not allowed API request POST {endpoint}")
                resource_explorer_data = {}
            try:
                auth_properties = resource_explorer_data["properties"]
            except:
                if DEBUGGING:
                    print(
                        f"Error getting properties field on object returned from {resource_explorer_data}."
                    )
                auth_properties = None
            try:
                authentication_enabled = auth_properties["enabled"]
                if authentication_enabled == None:
                    if DEBUGGING:
                        print(
                            f"Not allowed to list siteAuthSettings of {name}, defaulting siteAuthentication enabled value to False. Give the app Microsoft.Web/sites/config/list/action API permission to fix this issue."
                        )
                    authentication_enabled = False
            except KeyError:
                authentication_enabled = False
    except:
        pass

    object_to_add = AppService(
        resourceId=resource_id,
        name=name,
        resourceGroup=resource_group,
        provider=resource_type,
        principalId=principal_id,
        principalType=principal_type,
        userAssignedIdentities=user_assigned_ids,
        kind=kind,
        privateEndpoints=private_endpoints,
        outboundAddresses=outbound_addresses,
        inboundAddresses=inbound_addresses,
        httpsOnly=https_only,
        serverFarmId=app_service_plan,
        authenticationEnabled=authentication_enabled,
        ipSecurityRestrictions=ip_security_restrictions,
    )
    return object_to_add
