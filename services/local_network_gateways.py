from schema_classes import LocalNetworkGateway
import azure.mgmt.resourcegraph as arg

def parse_obj(resource_type, resource_group, sub_id, name, rg_client, rg_query_options, resource_id, DEBUGGING) -> LocalNetworkGateway:
    str_query = f"resources | where type =~ 'Microsoft.Network/localnetworkgateways' and name == '{name}'"
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
    try:
        local_Network_AddressSpace = raw_properties["localNetworkAddressSpace"]["addressPrefixes"]
    except KeyError:
        local_Network_AddressSpace = []
    try:
        gw_ip = raw_properties["gatewayIpAddress"]
    except KeyError:
        gw_ip = None
    try:
        bgp_setting = raw_properties["bgpSettings"]
    except KeyError:
        bgp_setting = None

    object_to_add = LocalNetworkGateway(
        gwId=resource_id,
        name=name,
        resourceGroup=resource_group,
        localNetworkAddressSpace=local_Network_AddressSpace,
        gatewayIp=gw_ip,
        provider=resource_type,
        bgpSettings=bgp_setting,
    )
    return object_to_add