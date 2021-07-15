from schema_classes import HVA_Tag


def handle_hva_tag(
    hva_tag: str, resource_id: str, class_name: str, debugging: bool
) -> HVA_Tag:
    components = hva_tag.split(",")
    c_val, i_val, a_val = 0, 0, 0
    for component in components:
        try:
            string = component.split(":")
            category = string[0]
            try:
                number = int(string[1])
            except ValueError:
                if debugging:
                    print(
                        f"HVA value '{string[1]}' for resource '{resource_id}' should be numeric but isn't. Skipping assignment."
                    )
                    continue
            if number > 10:
                if debugging:
                    print(
                        f"HVA consequence cannot be above 10, but resource '{resource_id}' is assigned {number}. Defaulting consequence to 10."
                    )
                number = 10
            elif number < 0:
                if debugging:
                    print(
                        f"HVA consequence cannot be below 0, but resource '{resource_id}' is assigned {number}. Defaulting consequence to 0."
                    )
                number = 0
            if category.lower() == "c":
                c_val = number
            elif category.lower() == "i":
                i_val = number
            elif category.lower() == "a":
                a_val = number
            else:
                if debugging:
                    print(
                        f"Incorrectly formatted HVA tag: {hva_tag}. Valid prefixes are only c, i or a (case-insensitive)."
                    )
        except IndexError:
            if debugging:
                print(
                    f"Parsing HVA tag {component} resulted in IndexError. Make sure each pair is formatted as 'prefix:suffix' and separated by a comma."
                )
    return HVA_Tag(
        resourceId=resource_id,
        className=class_name,
        confValue=c_val,
        integrityValue=i_val,
        availValue=a_val,
    )
