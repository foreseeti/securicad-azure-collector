from schema_classes import RouteTable
import azure.mgmt.resourcegraph as arg

def parse_obj(resource_type, resource_group, sub_id, name, rg_client, rg_query_options, resource_id, DEBUGGING) -> RouteTable:
    str_query = f"resources | where type =~ 'microsoft.network/routeTables' and name == '{name}'"
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

    subnets = []
    raw_subnets = (
        raw_properties["subnets"] if raw_properties.get("subnets") else []
    )
    for raw_subnet in raw_subnets:
        subnets.append(raw_subnet["id"])
    raw_routes = (
        raw_properties["routes"] if raw_properties.get("routes") else []
    )
    routes = []
    for raw_route in raw_routes:
        route = {
            "id": raw_route["id"],
            "name": raw_route["name"],
            "addressPrefix": raw_route["properties"]["addressPrefix"],
            "nextHopType": raw_route["properties"]["nextHopType"],
        }
        routes.append(route)

    object_to_add = RouteTable(
        resourceId=resource_id,
        name=name,
        resourceGroup=resource_group,
        subnets=subnets,
        routes=routes,
        provider=resource_type,
    )
    return object_to_add
