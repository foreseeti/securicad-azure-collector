# Copyright 2021-2022 Foreseeti AB <https://foreseeti.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from securicad.azure_collector.schema_classes import HVA_Tag
from securicad.azure_collector.services.parser_logger import log
from typing import Optional


def handle_hva_tag(hva_tag: str, resource_id: str, debugging: bool) -> HVA_Tag:
    components = hva_tag.split(",")
    c_val, i_val, a_val = 0, 0, 0
    groups=set()
    for component in components:
        try:
            string = component.split(":")
            category = string[0].lower()
            if category == "group":
                value = str(string[1]).lower()
                if any (x in value for x in ["[","]"]):
                    values = value.replace("[","").replace("]","").split(",")
                    for group in values:
                        groups.add(group)
                else:
                    groups.add(value)
                continue
            try:
                number = int(string[1])
            except ValueError:
                log.error(
                    f"HVA value '{string[1]}' for key '{category}' on resource '{resource_id}' should be numeric but isn't. Skipping assignment."
                )
                continue
            if number > 10:
                log.warning(
                    f"HVA consequence cannot be above 10, but resource '{resource_id}' is assigned {number}. Defaulting consequence to 10."
                )
                number = 10
            elif number < 0:
                log.warning(
                    f"HVA consequence cannot be below 0, but resource '{resource_id}' is assigned {number}. Defaulting consequence to 0."
                )
                number = 0
            if category == "c":
                c_val = number
            elif category == "i":
                i_val = number
            elif category == "a":
                a_val = number
            else:
                log.warning(
                    f"Incorrectly formatted HVA tag: {hva_tag}. Valid keys are c, i, a and group (case-insensitive)"
                )
        except IndexError as e:
            log.debug(
                f"Parsing HVA tag {component} resulted in IndexError. Make sure each pair is formatted as 'prefix:suffix' and separated by a comma. \n Error message: {e}"
            )
    return HVA_Tag(
        resourceId=resource_id,
        confValue=c_val,
        integrityValue=i_val,
        availValue=a_val,
        scadGrps=list(groups)
    )
