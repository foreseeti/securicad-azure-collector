from schema_classes import NetworkSecurityGroup, SecurityRule
import azure.mgmt.resourcegraph as arg

def parse_obj(resource_type, resource_group, sub_id, name, rg_client, rg_query_options, resource_id, DEBUGGING) -> NetworkSecurityGroup:
    str_query = f"resources | where type =~ 'Microsoft.Network/networkSecurityGroups' and name == '{name}'"
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
    raw_properties = rg_results_as_dict["data"][0]["properties"]
    subnetIds = []
    try:
        for subnet in raw_properties["subnets"]:
            subnetIds.append(subnet["id"])
    except KeyError:
        subnetIds = []
    inbound_rules, outbound_rules = [], []
    combinedRules = (
        raw_properties["defaultSecurityRules"]
        + raw_properties["securityRules"]
    )
    for rule in combinedRules:
        rule_id = rule["id"]
        rule_name = rule["name"]
        sourceport = (
            rule["properties"]["sourcePortRange"]
            if rule["properties"].get("sourcePortRange")
            else rule["properties"]["sourcePortRanges"]
        )
        destport = (
            rule["properties"]["destinationPortRange"]
            if rule["properties"].get("destinationPortRange")
            else rule["properties"]["destinationPortRanges"]
        )
        protocol = rule["properties"]["protocol"]
        source = (
            rule["properties"]["sourceAddressPrefix"]
            if rule["properties"].get("sourceAddressPrefix")
            else rule["properties"]["sourceAddressPrefixes"]
        )
        destination = (
            rule["properties"]["destinationAddressPrefix"]
            if rule["properties"].get("destinationAddressPrefix")
            else rule["properties"]["destinationAddressPrefixes"]
        )
        action = rule["properties"]["access"]
        direction = rule["properties"]["direction"]
        security_rule = SecurityRule(
            resourceId=rule_id,
            name=rule_name,
            source_port=sourceport,
            dest_port=destport,
            protocol=protocol,
            source=source,
            destination=destination,
            action=action,
            direction=direction,
            resourceGroup=resource_group,
        )
        if rule["properties"]["direction"] == "Inbound":
            inbound_rules.append(security_rule.__dict__)
        else:
            outbound_rules.append(security_rule.__dict__)
    object_to_add = NetworkSecurityGroup(
        resourceId=resource_id,
        name=name,
        resourceGroup=resource_group,
        inboundSecurityRules=inbound_rules,
        outboundSecurityRules=outbound_rules,
        subnetIds=subnetIds,
        provider=resource_type,
    )
    return object_to_add
