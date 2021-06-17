from schema_classes import IpAddress
import azure.mgmt.resourcegraph as arg

def parse_obj(resource_type, resource_group, sub_id, name, rg_client, rg_query_options, resource_id, DEBUGGING) -> IpAddress:
    str_query = f"resources | where type =~ 'Microsoft.Network/publicIPAddresses' and name == '{name}'"
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

    address = (
        raw_properties["ipAddress"]
        if raw_properties.get("ipAddress")
        else raw_properties["publicIPAllocationMethod"]
    )
    interface_id = (
        raw_properties["ipConfiguration"]["id"]
        if raw_properties.get("ipConfiguration")
        else None
    )

    object_to_add = IpAddress(
        resourceId=resource_id,
        name=name,
        resourceGroup=resource_group,
        address=address,
        interfaceId=interface_id,
        provider=resource_type,
    )
    return object_to_add