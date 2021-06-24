from schema_classes import Disk
import azure.mgmt.resourcegraph as arg

def parse_obj(resource, resource_type, resource_group, sub_id, name, rg_client, rg_query_options, resource_id) -> Disk:
    managed_by = resource.managed_by
    os = None
    str_query = f"resources | where type == 'microsoft.compute/disks' and name == '{name}'"
    query = arg.models.QueryRequest(
        subscriptions=[sub_id], query=str_query, options=rg_query_options,
    )
    try:
        rg_results_as_dict = rg_client.resources(query=query).__dict__
        try:
            os = rg_results_as_dict["data"][0]["properties"]["osType"]
        except:
            os = None
    except:
        os = None
    kind = (
        "OsDisk"
        if (os != None or "osdisk" in {name.lower()})
        else "DataDisk"
    )
    object_to_add = Disk(
        resourceId=resource_id,
        name=name,
        diskType=kind,
        managedBy=managed_by,
        resourceGroup=resource_group,
        os=os,
        provider=resource_type,
    )
    return object_to_add
