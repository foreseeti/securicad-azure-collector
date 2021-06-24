import datetime
import requests
import re
import os


def get_application_insights(sub_id, rsg_name, app_insight_name, headers, DEBUGGING) -> dict:
    today = datetime.datetime.today()
    timedelta = datetime.timedelta(days=90)  # 90 days ago by default
    start = today - timedelta
    timespan = f"{start.isoformat()}/{today.isoformat()}"
    valid_environment_variable = False
    try:
        app_insight_interval = os.environ["APP_INSIGHTS_INTERVAL"]
        iso_date = "\d{4}(-\d{2}){2}(T(\d{2}:)((\d{2})|(\d{2}:\d{2}))(\.\d{1,3})?)?"
        pattern = re.compile(f"^{iso_date}\/{iso_date}$")
        if not pattern.search(app_insight_interval):
            if DEBUGGING:
                print(
                    f"APP_INSIGHTS_INTERVAL has wrong format, run program with -h for detailed information. Setting standard time interval for application insights topology dump."
                )
        else:
            valid_environment_variable = True
            # Still need to check for valid range (e.g. days = 32 is not valid)
            splitted_date = timespan.split("/")
            for date in splitted_date:
                try:
                    datetime.datetime.fromisoformat(date)
                except ValueError as e:
                    if DEBUGGING:
                        print(
                            f"APP_INSIGHTS_INTERVAL has numerical values that exceeds the allowed limit. Assuming normal timespan. \n\t Error: {e}."
                        )
                    valid_environment_variable = False
    except:
        if DEBUGGING:
            print(
                f"APP_INSIGHTS_INTERVAL not set, run program with -h for detailed information. Setting standard time interval for application insights topology dump."
            )
        app_insight_interval = None
    if valid_environment_variable:
        timespan = app_insight_interval if app_insight_interval else timespan
    endpoint = f"https://management.azure.com/subscriptions/{sub_id}/resourcegroups/{rsg_name}/providers/microsoft.insights/components/{app_insight_name}/providers/microsoft.insights/topology?timespan={timespan}&api-version=2019-10-17-preview&depth=1"
    try:
        app_insights_data = requests.get(url=endpoint, headers=headers).json()
    except:
        if DEBUGGING:
            print(
                f"Error running API call {endpoint}. Could be a bad authentication due to Bearer token."
            )
        app_insights_data = None
    return app_insights_data
