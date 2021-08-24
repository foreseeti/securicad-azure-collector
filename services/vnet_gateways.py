from schema_classes import Vnet, VnetGateway
import azure.mgmt.resourcegraph as arg


def parse_obj(resource_type, resource_group, sub_id, name, rg_client, rg_query_options, resource_id, DEBUGGING) -> VnetGateway:
    str_query = f"resources | where type =~ 'microsoft.network/virtualnetworkgateways' and name == '{name}'"
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
        capacity = raw_properties["sku"]["capacity"]
    except KeyError:
        if DEBUGGING:
            print(
                f"WARNING: Couldn't get ['sku']['capacity'] from virtual network gateway {name}, assuming value '1'"
            )
        capacity = 1
    raw_ip_configs = raw_properties.get("ipConfigurations")
    if not raw_ip_configs:
        if DEBUGGING:
            print(
                f"WARNING: Couldn't get ipConfigurations of virtual network gateway {name}. Impact: potential missing model associations"
            )
    ip_configs = []
    for raw_ip_config in raw_ip_configs or []:
        ip_config = {
            "id": raw_ip_config.get("id"),
            "name": raw_ip_config.get("name"),
            "publicIpAddress": raw_ip_config.get("properties", {}).get(
                "publicIPAddress", {}).get("id"),
            "subnet": raw_ip_config.get("properties",{}).get("subnet",{}).get("id"),
        }
        ip_configs.append(ip_config)
    raw_bgp_settings = raw_properties.get("bgpSettings")
    if not raw_bgp_settings:
        if DEBUGGING:
            print(
                f"WARNING: Couldn't get bgpSettings of virtual network gateway {name}. Impact: potential missing model associations"
            )
    bgp_settings = []
    for raw_bgp_setting in (
        raw_bgp_settings.get("bgpPeeringAddresses", [])
    ):
        bgp_setting = {
            "ipConfigId": raw_bgp_setting.get("ipconfigurationId"),
            "tunnelIpAddress": raw_bgp_setting.get("tunnelIpAddresses", list()),
            "customBgpIpAddresses": raw_bgp_setting.get("customBgpIpAddresses", list()),
            "defaultBgpIpAddresses": raw_bgp_setting.get(
                "defaultBgpIpAddresses", list()
            ),
        }
        bgp_settings.append(bgp_setting)
    final_bgp_setting = {
        "bgpPeeringAddresses": bgp_settings,
        "asn": raw_bgp_settings.get("asn"),
        "bgpPeeringAddress": raw_bgp_settings.get("bgpPeeringAddress")
    }

    object_to_add = VnetGateway(
        gwId=resource_id,
        name=name,
        resourceGroup=resource_group,
        ipConfigs=ip_configs,
        bgpSettings=final_bgp_setting,
        capacity=capacity,
        provider=resource_type,
    )
    return object_to_add
