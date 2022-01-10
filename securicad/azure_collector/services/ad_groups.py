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

import requests
from typing import Dict, Set
from securicad.azure_collector.services.parser_logger import log
from requests.api import head

def collect_group_memberships(group_id: str, tenant_id: str, headers: dict, debugging: bool) -> Dict[str, Set[str]]:
    """ Given an azure group object_id, find its members using Microsoft Graph. \n 
    Keyword arguments \n:
    \t group_id: the object_id of an Azure AD group
    \t tenant_id: tenant id in which the group lies
    \t headers: HTTP headers to authenticate the request
    """
    url = f"https://graph.microsoft.com/v1.0/{tenant_id}/groups/{group_id}/members"
    res = requests.get(url=url,headers=headers)
    members = []
    if res.status_code == 200:
        try:
            data = res.json()
            for entry in data.get("value", []):
                id = entry.get("id")
                if not id:
                    continue
                try:
                    member_type = entry.get("@odata.type", "").split(".")[-1]
                except IndexError:
                    log.warning(f"WARNING: Couldn't see member type of member {id} in {group_id}. Impact: Possibly missing association between security principal and group." )
                members.append({"id": id, "memberType": member_type})
        except:
            log.error(f"Couldn't json-encode the request response https://graph.microsoft.com/v1.0/{tenant_id}/groups/{group_id}/members")
    else:
        log.warning(f"WARNING: Status code {res.status_code} on {url}. Impact: Couldn't get members of {group_id}, ensure correct API permissions for the collector on Microsoft Graph.")
    return members