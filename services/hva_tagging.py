from typing import Dict
from schema_classes import HVA_Tag


def handle_hva_tag(hva_tag: str, resource_id: str, debugging: bool) -> Dict[str, str]:
    components = hva_tag.split(",")
    c_val, i_val, a_val = "0", "0", "0"
    for component in components:
        try:
            string = component.split(":")
            category = string[0]
            number = string[1]
            try:
                if int(number) > 10 or int(number) < 0:
                    if debugging:
                        print(
                            f"HVA value '{number}' for resource '{resource_id}' is incorrect. Should be a number between 0 and 10."
                        )
                        continue
            except ValueError as e:
                if debugging:
                    print(
                        f"HVA value '{number}' for resource '{resource_id}' should be numeric but isn't."
                    )
                    continue
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
                    f"Parsing HVA tag {component} resulted in index error. Make sure each pair is formatted as 'prefix:suffix' and separated by a comma."
                )
    return HVA_Tag(
        resourceId=resource_id,
        confValue=c_val,
        integrityValue=i_val,
        availValue=a_val,
    )
