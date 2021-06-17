from schema_classes import AppServicePlan
import azure.mgmt.resourcegraph as arg

def parse_obj(resource_type, resource_group, sub_id, name, rg_client, rg_query_options, resource_id, DEBUGGING) -> AppServicePlan:
    str_query = f"resources | where type =~ 'microsoft.web/serverfarms' and name == '{name}'"
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
    raw_sku = rg_results_as_dict["data"][0]["sku"]
    family = raw_sku["family"]

    object_to_add = AppServicePlan(
        resourceId=resource_id,
        name=name,
        resourceGroup=resource_group,
        provider=resource_type,
        family=family,
    )
    return object_to_add