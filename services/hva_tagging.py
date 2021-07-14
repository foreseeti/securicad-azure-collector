from typing import Dict
from schema_classes import HVA_Tag


def handle_hva_tag(
    hva_tag: str,
    resource_id: str,
) -> Dict[str, str]:
    values = hva_tag.split(",")
    c_val = values[0].split(":")[1]
    i_val = values[1].split(":")[1]
    a_val = values[2].split(":")[1]
    if c_val or i_val or a_val:
        return HVA_Tag(
            resourceId=resource_id,
            confValue=c_val,
            integrityValue=i_val,
            availValue=a_val,
        )
    else:
        return None
