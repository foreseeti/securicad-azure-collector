from schema_classes import VirtualMachine
import azure.mgmt.resourcegraph as arg

def iterate(resource, resource_type, resource_group, sub_id, name, rg_client, rg_query_options, resourceId, DEBUGGING) -> VirtualMachine:
    managedBy = resource.managed_by
    # Fetching the hard to get properties with resource graph
    str_query = f"resources | where type == 'microsoft.compute/virtualmachines' and name == '{name}'"
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
    try:
        os = rg_results_as_dict["data"][0]["properties"]["storageProfile"][
            "osDisk"
        ]["osType"]
    except:
        os = None
    try:
        os_disk = rg_results_as_dict["data"][0]["properties"][
            "storageProfile"
        ]["osDisk"]["name"]
    except:
        os_disk = None
    try:
        data_disks = [
            x["name"]
            for x in rg_results_as_dict["data"][0]["properties"][
                "storageProfile"
            ]["dataDisks"]
        ]
    except:
        data_disks = []

    ssh_keys = []
    if os == "Linux":
        try:
            linux_config = rg_results_as_dict["data"][0]["properties"][
                "osProfile"
            ]["linuxConfiguration"]
            # If no public keys doesn't exist, avoid crash
            linux_config.setdefault("ssh", {})
            ssh_keys_raw = linux_config.get("ssh").get("publicKeys")
            for ssh_key in ssh_keys_raw or []:
                ssh_keys.append(ssh_key["keyData"])
        except KeyError:
            print("Couldn't fetch the ssh keys metadata from the {name} VM.")

    network_interface_ids = []
    networkInterfaces = rg_results_as_dict["data"][0]["properties"][
        "networkProfile"
    ]["networkInterfaces"]
    for nwi in networkInterfaces:
        network_interface_ids.append({"id": nwi.get("id")})

    # The principal type and system assigned managed identity
    try:
        principal_id = rg_results_as_dict["data"][0]["identity"][
            "principalId"
        ]
    except (KeyError, TypeError):
        if DEBUGGING:
            print(
                f"Couldn't find the principal Id of the virtual machine {name}."
            )
        principal_id = None
    try:
        principal_type = rg_results_as_dict["data"][0]["identity"]["type"]
    except (KeyError, TypeError):
        if DEBUGGING and principal_id:
            print(
                f"Couldn't find the principal type of the virtual machine {name}."
            )
        principal_type = None
    # If managed identity is activated on the resource it has a principal Id
    try:
        raw_user_assigned_ids = rg_results_as_dict["data"][0]["identity"][
            "userAssignedIdentities"
        ]
        user_assigned_ids = []
        for key, identity in raw_user_assigned_ids.items() or []:
            user_assigned_ids.append(
                {
                    "identityId": key,
                    "clientId": identity["clientId"],
                    "principalId": identity["principalId"],
                }
            )
    except (KeyError, TypeError):
        user_assigned_ids = []

    object_to_add = VirtualMachine(
        resourceId=resourceId,
        name=name,
        os=os,
        osDisk=os_disk,
        dataDisks=data_disks,
        managedBy=managedBy,
        resourceGroup=resource_group,
        sshKeys=ssh_keys,
        networkInterfaces=network_interface_ids,
        provider=resource_type,
        principalId=principal_id,
        principalType=principal_type,
        userAssignedIdentities=user_assigned_ids,
    )
    return object_to_add