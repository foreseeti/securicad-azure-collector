from typing import Dict
from schema_classes import HVA_Tag


def handle_hva_tag(hva_tag: str, resource_id: str, debugging: bool) -> Dict[str, str]:
    values = hva_tag.split(",")
    c_val, i_val, a_val = "0", "0", "0"
    for val in values:
        value = val.split(":")
        category = value[0]
        if category.lower() == "c":
            c_val = value[1]
        elif category.lower() == "i":
            i_val = value[1]
        elif category.lower() == "a":
            a_val = value[1]
        else:
            if debugging:
                print(
                    "Incorrect format on HVA tag. Format should be: 'c:n,i:n,a:n' where n is the corresponding Confidentiality, Integrity or Availability value for the asset, between 0 and 10."
                )
    return HVA_Tag(
        resourceId=resource_id,
        confValue=c_val,
        integrityValue=i_val,
        availValue=a_val,
    )
