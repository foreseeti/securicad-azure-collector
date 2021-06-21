from schema_classes import ContainerRegistry
import azure.mgmt.resourcegraph as arg


def parse_obj(resource_type, resource_group, sub_id, name, rg_client, rg_query_options, resource_id, DEBUGGING) -> ContainerRegistry:
    str_query = f"resources | where type =~ 'microsoft.containerregistry/registries' and name == '{name}'"
    query = arg.models.QueryRequest(
        subscriptions=[sub_id],
        query=str_query,
        options=rg_query_options,
    )
    try:
        rg_results_as_dict = rg_client.resources(query=query).__dict__
    except:
        if DEBUGGING:
            print(
                f"ERROR: Couldn't execute resource graph query of {name}, skipping asset."
            )
        return None
    raw_properties = rg_results_as_dict["data"][0]["properties"]
    # Access Key
    try:
        admin_user_enabled = raw_properties["adminUserEnabled"]
    except KeyError:
        if DEBUGGING:
            print(
                f"Couldn't find adminUserEnabled value of container registry {name}. Assuming disabled."
            )
        admin_user_enabled = False
    # Firewall Related
    try:
        public_network_enabled = raw_properties["publicNetworkAccess"]
    except KeyError:
        if DEBUGGING:
            print(
                f"Couldn't find publicNetworkAccess value of container registry {name}. Assuming default value: True."
            )
        public_network_enabled = "Disabled"  # Is true by default
    try:
        private_endpoints = raw_properties["privateEndpointConnections"]
    except KeyError:
        if DEBUGGING:
            print(
                f"Couldn't find privateEndpointConnections of container registry {name}"
            )
        private_endpoints = []
    try:
        network_rule_set = raw_properties["networkRuleSet"]
        try:
            default_action = network_rule_set["defaultAction"]
        except KeyError:
            if DEBUGGING:
                print(
                    f"Couldn't find defaultActions of networkRuleSet in container registry {name}"
                )
            default_action = "Deny"
        try:
            ip_rules = (
                network_rule_set.get("ipRules")
                if type(network_rule_set.get("ipRules")) == list
                else []
            )
            firewall_rules = [
                x["value"] for x in ip_rules if x.get("value") != None
            ]
        except KeyError:
            if DEBUGGING:
                print(f"Couldn't find ipRules of container registry {name}")
            firewall_rules = []
        try:
            # Can't seem to be able to set virtual network rules just yet, but the field is within the resource graph, so let's fetch it
            virtual_network_rules = network_rule_set["virtualNetworkRules"]
        except KeyError:
            if DEBUGGING:
                print(
                    f"Couldn't find virtualNetworkRules of container registry {name}"
                )
            virtual_network_rules = []
    except KeyError:
        if DEBUGGING:
            print(
                f"Couldn't find networkRuleSet of container registry {name}"
            )
        pass
        firewall_rules = []
        virtual_network_rules = []
        default_action = (
            "Allow"  # allowed by default (letting everything through)
        )
    try:
        network_rule_bypass_options = raw_properties[
            "networkRuleBypassOptions"
        ]
    except KeyError:
        if DEBUGGING:
            print(
                f"Couldn't find privateEndpointConnections of container registry {name}"
            )
        network_rule_bypass_options = "None"
    # SKU
    try:
        sku = rg_results_as_dict["data"][0]["sku"]
        try:
            tier = sku["tier"]
        except KeyError:
            if DEBUGGING:
                print(
                    f"Couldn't find tier value of sku in container registry {name}. assuming Basic tier"
                )
            tier = "Basic"
    except KeyError:
        if DEBUGGING:
            print(
                f"Couldn't find sku of container registry {name}. assuming Basic tier"
            )
        tier = "Basic"
    # The principal type and system assigned managed identity
    try:
        principal_id = rg_results_as_dict["data"][0]["identity"][
            "principalId"
        ]
    except (KeyError, TypeError):
        if DEBUGGING:
            print(
                f"Couldn't find the principal Id of the container registry {name}."
            )
        principal_id = None
    try:
        principal_type = rg_results_as_dict["data"][0]["identity"]["type"]
    except (KeyError, TypeError):
        if DEBUGGING and principal_id:
            print(
                f"Couldn't find the principal type of the container registry {name}."
            )
        principal_type = None
    # User assigned managed identity
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

    object_to_add = ContainerRegistry(
        resourceId=resource_id,
        name=name,
        resourceGroup=resource_group,
        provider=resource_type,
        adminUserEnabled=admin_user_enabled,
        publicNetworkEnabled=public_network_enabled,
        privateEndpoints=private_endpoints,
        firewallRules=firewall_rules,
        virtualNetworkRules=virtual_network_rules,
        networkBypassOptions=network_rule_bypass_options,
        defaultAction=default_action,
        tier=tier,
        principalId=principal_id,
        principalType=principal_type,
        userAssignedIdentities=user_assigned_ids,
    )
    return object_to_add
