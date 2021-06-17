from schema_classes import Vnet, Subnet
import azure.mgmt.resourcegraph as arg

def parse_obj(resource_type, resource_group, sub_id, name, rg_client, rg_query_options, resource_id, DEBUGGING) -> Vnet:
    str_query = f"resources | where type =~ 'Microsoft.Network/virtualNetworks' and name == '{name}'"
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

    address_space = raw_properties["addressSpace"]["addressPrefixes"]
    # Cant find connected_devices in resource graph, but we reach the connection through networkInterfaces instead
    subnets = []
    for subnet in raw_properties["subnets"]:
        subnet_name = subnet["name"]
        subnet_id = subnet["id"]
        ip_configs = (
            subnet["properties"].get("ipConfigurations")
            if subnet["properties"].get("ipConfigurations")
            else []
        )
        address_prefix = (
            subnet["properties"].get("addressPrefix")
            if subnet["properties"].get("addressPrefix")
            else []
        )
        try:
            nsg = subnet["properties"]["networkSecurityGroup"]["id"]
        except KeyError:
            nsg = None
        subnet_class = Subnet(
            resourceId=subnet_id,
            name=subnet_name,
            ipConfigs=ip_configs,
            addressPrefix=address_prefix,
            vnetId=resource_id,
            networkSecurityGroup=nsg,
        )
        subnets.append(subnet_class.__dict__)
    vnet_peerings = []
    raw_vnet_peerings = raw_properties.get("virtualNetworkPeerings")
    for raw_vnet_peering in raw_vnet_peerings or []:
        vnet_peering = {
            "id": raw_vnet_peering.get("id"),
            "peering_name": raw_vnet_peering.get("name"),
            "remote_network": raw_vnet_peering.get("properties", {}).get("remoteVirtualNetwork",{}).get("id")
        }
        vnet_peerings.append(vnet_peering)
    object_to_add = Vnet(
        resourceId=resource_id,
        name=name,
        resourceGroup=resource_group,
        addressSpace=address_space,
        subnets=subnets,
        vnetPeerings=vnet_peerings,
        provider=resource_type,
    )
    return object_to_add
