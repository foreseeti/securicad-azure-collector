from schema_classes import Connection
import azure.mgmt.resourcegraph as arg

def parse_obj(resource_type, resource_group, sub_id, name, rg_client, rg_query_options, resource_id, DEBUGGING) -> Connection:
    str_query = f"resources | where type =~ 'Microsoft.Network/connections' and name == '{name}'"
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

    source, target = None, None
    connectionType = raw_properties["connectionType"]
    if connectionType == "Vnet2Vnet":
        source = raw_properties["virtualNetworkGateway1"]["id"]
        target = raw_properties["virtualNetworkGateway2"]["id"]
    # TODO: Add logic for the other connectionTypes

    if source and target:
        object_to_add = Connection(
            resourceId=resource_id,
            name=name,
            resourceGroup=resource_group,
            connectionType=connectionType,
            source=source,
            target=target,
            provider=resource_type,
        )
        return object_to_add
    return None
