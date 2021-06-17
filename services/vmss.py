from schema_classes import VirtualMachineScaleSet
import azure.mgmt.resourcegraph as arg

def parse_obj(resource, resource_type, resource_group, sub_id, name, rg_client, rg_query_options, resource_id, DEBUGGING) -> VirtualMachineScaleSet:
    managedBy = resource.managed_by
    # Fetching the hard to get properties with resource graph
    str_query = f"resources | where type == 'microsoft.compute/virtualmachinescalesets' and name == '{name}'"
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
        raw_properties = rg_results_as_dict["data"][0]["properties"][
            "virtualMachineProfile"
        ]
    except KeyError:
        if DEBUGGING:
            print(
                f"Couldn't get properties for virtual machine scale set {name}"
            )
        return None
    try:
        os = raw_properties["storageProfile"]["osDisk"]["osType"]
    except:
        if DEBUGGING:
            print(
                f"Couldn't find the osType of virtual machine scale set {name}"
            )
        os = None
    os_disk = f"{resource_id}-OSDisk"
    ssh_keys = []
    if os == "Linux":
        try:
            linux_config = raw_properties["osProfile"]["linuxConfiguration"]
            # If no public keys doesn't exist, avoid crash
            linux_config.setdefault("ssh", {})
            ssh_keys_raw = linux_config.get("ssh").get("publicKeys")
            for ssh_key in ssh_keys_raw or []:
                try:
                    ssh_keys.append(ssh_key["keyData"])
                except KeyError:
                    if DEBUGGING:
                        print(
                            f"Couldn't find the keyData value of ssh_key in virtual machine scale set {name}"
                        )
                    pass
        except KeyError:
            if DEBUGGING:
                print(
                    f"Couldn't find the linuxConfiguration value of virtual machine scale set {name}"
                )
            pass
    # Data Disk
    try:
        data_disks = raw_properties["storageProfile"]["dataDisks"]
        if data_disks != None:
            data_disk = f"{resource_id}-DataDisk"
        else:
            data_disk = None
    except:
        # Might not even use data profiles, no need to print debug info
        data_disk = None
        pass
    try:
        network_profile = raw_properties["networkProfile"]
    except KeyError:
        if DEBUGGING:
            print(
                f"Couldn't find the networkProfile value of virtual machine scale set {name}"
            )
        network_profile = None
    network_interface_ids = []
    if network_profile:
        networkInterfaces = network_profile[
            "networkInterfaceConfigurations"
        ]
        for nwi in networkInterfaces:
            # see if the interface has a connected network security group
            try:
                nsg = nwi["properties"]["networkSecurityGroup"]["id"]
            except KeyError:
                nsg = None
            try:
                ip_configs = nwi["properties"]["ipConfigurations"]
            except KeyError:
                if DEBUGGING:
                    print(
                        f"Couldn't get ip configuration for interface of virtual machine scale set {name}"
                    )
                ip_configs = None
            for ip_config in ip_configs or []:
                nwi_name = ip_config.get("name")
                properties = ip_config.get("properties")
                if properties:
                    # See if the interface has a public ip "name"
                    try:
                        public_ip_name = properties[
                            "publicIPAddressConfiguration"
                        ]["name"]
                    except KeyError:
                        public_ip_name = None
                    try:
                        subnet = properties["subnet"]["id"]
                    except AttributeError:
                        if DEBUGGING:
                            print(
                                f"Couldn't get subnet of virtual machine scale set {name}'s network interface {nwi_name}"
                            )
                        subnet = None
                    if nwi_name and subnet:
                        network_interface_ids.append(
                            {
                                "name": nwi_name,
                                "subnetId": subnet,
                                "publicIpName": public_ip_name,
                                "secondaryNsg": nsg,
                            }
                        )
                else:
                    if DEBUGGING:
                        print(
                            f"Couldn't get properties of virtual machine scale set {name}'s network interface {nwi_name}."
                        )
    # If managed identity is activated on the resource it has a principal ID
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
    # The principal type and system assigned managed identity
    try:
        principal_id = rg_results_as_dict["data"][0]["identity"][
            "principalId"
        ]
    except (KeyError, TypeError):
        if DEBUGGING:
            print(
                f"Couldn't find the principal Id of the app service {name}."
            )
        principal_id = None
    try:
        principalType = rg_results_as_dict["data"][0]["identity"]["type"]
    except (KeyError, TypeError):
        if DEBUGGING and principal_id:
            print(
                f"Couldn't find the principal type of the app service {name}."
            )
        principalType = None

    object_to_add = VirtualMachineScaleSet(
        resourceId=resource_id,
        name=name,
        os=os,
        osDisk=os_disk,
        dataDisk=data_disk,
        managedBy=managedBy,
        resourceGroup=resource_group,
        sshKeys=ssh_keys,
        networkInterfaces=network_interface_ids,
        provider=resource_type,
        principalId=principal_id,
        principalType=principalType,
        identityIds=user_assigned_ids,
    )
    return object_to_add
