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

def handle_ip_range(
    start_ip_components: list,
    end_ip_components: list,
    start_ip_address: str,
    end_ip_address: str,
) -> list:
    firewallRules = []
    octet_start_one = int(start_ip_components[0])
    octet_end_one = int(end_ip_components[0])
    octet_start_two = int(start_ip_components[1])
    octet_end_two = int(end_ip_components[1])
    octet_start_three = int(start_ip_components[2])
    octet_end_three = int(end_ip_components[2])
    octet_start_four = int(start_ip_components[3])
    octet_end_four = int(end_ip_components[3])
    rangegap1 = octet_end_one - octet_start_one
    rangegap2 = octet_end_two - octet_start_two
    rangegap3 = octet_end_three - octet_start_three
    rangegap4 = octet_end_four - octet_start_four
    if start_ip_address == end_ip_address:
        ip = start_ip_address
        firewallRules.append(ip)
    elif rangegap4 < 10 and rangegap1 == 0 and rangegap2 == 0 and rangegap3 == 0:
        for i in range(octet_start_one, octet_end_one + 1):
            for j in range(octet_start_two, octet_end_two + 1):
                for x in range(octet_start_three, octet_end_three + 1):
                    for z in range(octet_start_four, octet_end_four + 1):
                        ip = f"{i}.{j}.{x}.{z}"
                        firewallRules.append(ip)
    elif start_ip_address and end_ip_address:
        ip = start_ip_address + " - " + end_ip_address
        firewallRules.append(ip)
    return firewallRules
