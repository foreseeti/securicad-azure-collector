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

    capacity = raw_properties["sku"]["capacity"]
    raw_ip_configs = raw_properties["ipConfigurations"]
    ip_configs = []
    for raw_ip_config in raw_ip_configs or []:
        ip_config = {
            "id": raw_ip_config["id"],
            "name": raw_ip_config["name"],
            "publicIpAddress": raw_ip_config["properties"][
                "publicIPAddress"
            ]["id"],
            "subnet": raw_ip_config["properties"]["subnet"]["id"],
        }
        ip_configs.append(ip_config)
    raw_bgp_settings = raw_properties["bgpSettings"]
    bgp_settings = []
    for raw_bgp_setting in (
        raw_bgp_settings.get("bgpPeeringAddresses") or []
    ):
        bgp_setting = {
            "ipConfigId": raw_bgp_setting["ipconfigurationId"],
            "tunnelIpAddress": raw_bgp_setting["tunnelIpAddresses"]
            if raw_bgp_setting.get("tunnelIpAddresses")
            else [],
            "customBgpIpAddresses": raw_bgp_setting["customBgpIpAddresses"],
            "defaultBgpIpAddresses": raw_bgp_setting[
                "defaultBgpIpAddresses"
            ],
        }
        bgp_settings.append(bgp_setting)
    final_bgp_setting = {
        "bgpPeeringAddresses": bgp_settings,
        "asn": raw_bgp_settings["asn"],
        "bgpPeeringAddress": raw_bgp_settings["bgpPeeringAddress"]
        if raw_bgp_settings.get("bgpPeeringAddress")
        else None,
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
