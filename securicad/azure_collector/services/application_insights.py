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

import datetime
import requests
import re
import os
from securicad.azure_collector.services.parser_logger import log


def get_application_insights(sub_id, rsg_name, app_insight_name, headers, DEBUGGING) -> dict:
    today = datetime.datetime.today()
    timedelta = datetime.timedelta(days=90)  # 90 days ago by default
    start = today - timedelta
    timespan = f"{start.isoformat()}/{today.isoformat()}"
    valid_environment_variable = False
    app_insight_interval = os.environ.get("APP_INSIGHTS_INTERVAL")
    if app_insight_interval:
        iso_date = "\d{4}(-\d{2}){2}(T(\d{2}:){2}\d{2}(\.\d{1,6})?)?"
        pattern = re.compile(f"^{iso_date}\/{iso_date}$")
        if not pattern.search(app_insight_interval):
            log.warning(f"APP_INSIGHTS_INTERVAL has wrong format, run program with -h for detailed information. Setting standard time interval for application insights topology dump.")
        else:
            valid_environment_variable = True
            # Still need to check for valid range (e.g. days = 32 is not valid)
            splitted_date = timespan.split("/")
            for date in splitted_date:
                try:
                    datetime.datetime.fromisoformat(date)
                except ValueError as e:
                    log.warning(
                        f"APP_INSIGHTS_INTERVAL has numerical values that exceeds the allowed limit. Assuming normal timespan. \n\tError: {e}."
                    )
                    valid_environment_variable = False
    else:
        log.debug(
            f"APP_INSIGHTS_INTERVAL not set, run program with -h for detailed information. Setting standard time interval for application insights topology dump."
        )
    if valid_environment_variable:
        timespan = app_insight_interval if app_insight_interval else timespan
    endpoint = f"https://management.azure.com/subscriptions/{sub_id}/resourcegroups/{rsg_name}/providers/microsoft.insights/components/{app_insight_name}/providers/microsoft.insights/topology?timespan={timespan}&api-version=2019-10-17-preview&depth=1"
    try:
        app_insights_data = requests.get(url=endpoint, headers=headers).json()
    except:
        log.error(
            f"Cannot execute GET request on {endpoint}. \n\tImpact: Potentially missing model enrichment information."
        )
        app_insights_data = None
    return app_insights_data
