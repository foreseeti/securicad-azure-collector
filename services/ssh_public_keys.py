from schema_classes import SshKey
import azure.mgmt.resourcegraph as arg

def parse_obj(resource_type, resource_group, sub_id, name, rg_client, rg_query_options, resource_id, DEBUGGING) -> SshKey:
    str_query = f"resources | where type == 'microsoft.compute/sshpublickeys' and name == '{name}'"
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

    public_key = raw_properties["publicKey"]

    object_to_add = SshKey(
        resourceId=resource_id,
        name=name,
        resourceGroup=resource_group,
        publicKey=public_key,
        provider=resource_type,
    )
    return object_to_add