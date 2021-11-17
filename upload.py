# Copyright 2020-2021 Foreseeti AB <https://foreseeti.com>
# This file showcases how you can use securicad enterprise SDK to upload and simulate your azure environment 
# by data files from the securicad-azure-collector or .sCAD models from azure-resource-parser

from securicad.enterprise.client import Client # type: ignore pylint: disable=import-error
from pathlib import Path
from typing import TYPE_CHECKING, Tuple, Optional, List, Dict, Any
import configparser
import argparse
from datetime import datetime
import logging
import json
import sys

if TYPE_CHECKING:
    from securicad.enterprise.client import Client # type: ignore pylint: disable=import-error
    from securicad.enterprise.models import ModelInfo # type: ignore pylint: disable=import-error
    from securicad.enterprise.projects import Project # type: ignore pylint: disable=import-error
log = logging.getLogger(__name__)


def get_credentials() -> Tuple[Optional[str], Optional[str]]:
    config = configparser.ConfigParser()
    config.read(get_configpath())
    if "AUTH" not in config:
        return None, None, None
    return (
        config["AUTH"].get("username"),
        config["AUTH"].get("password"),
        config["AUTH"].get("organization"),
    )


def get_urls() -> Tuple[Optional[str], Optional[str]]:
    config = configparser.ConfigParser()
    config.read(get_configpath())
    if "URL" not in config:
        return (
            None,
            None,
        )
    return (
        config["URL"].get("authserviceurl"),
        config["URL"].get("serviceurl"),
    )


def get_certs() -> Tuple[Optional[str], Optional[str], Optional[str]]:
    config = configparser.ConfigParser()
    config.read(get_configpath())
    if "CERT" not in config:
        return (
            None,
            None,
            None,
        )
    return (
        config["CERT"].get("cacert"),
        config["CERT"].get("clientcert"),
        config["CERT"].get("clientcertkey"),
    )


def get_configpath() -> str:
    return str(Path(__file__).resolve().parent.parent.joinpath("lib", "conf.ini"))


def setup(project: Optional[str]):
    """Returns a tuple of an enterprise client along with a project object. \n
    Keyword arguments: \n
    \t project - The project you wish to upload your model to. Defaults to "Default." \n
    Returns: \n
        (Client, Project)
    """
    creds = get_credentials()
    urls = get_urls()
    certs = get_certs()

    username = creds[0]
    password = creds[1]
    org = creds[2]
    cacert = False if certs[0] in ["", None] else certs[0]
    url = urls[1][:-13]
    log(f"Connecting to securiCAD Enterprise")
    es_client = Client(
        base_url=url,
        username=username,
        password=password,
        organization=org,
        cacert=cacert,
    )
    # Check that the organization exists
    if not org:
        org = "default"
    if org:
        try:
            organization = es_client.organizations.get_organization_by_name(org)
        except ValueError:
            organization = es_client.organizations.create_organization(org)
        log(f"Entering organization: {org}")
    # Project where the model will be added
    if not project:
        project = "Default"
    try:
        log(f"Entering project {project}")
        project = es_client.projects.get_project_by_name(project)
    except ValueError:
        project = es_client.projects.create_project(
            name=project, organization=organization
        )
    return (es_client, project)


def upload_json(
    project: "Project",
    es_client: "Client",
    environment: Path,
    app_insights: Optional[Path],
    tunings: Optional[Dict[str, List["Tuning"]]],
    lang: "Lang"
) -> None:
    """Uploads the active_directory.json and application_insights.json file provided by the collector to enterprise
    and parses a model to the specified project. \n
    Keyword arguments: \n
    \tproject - The enterprise project object to upload the file to. \n
    \tes_client - A Client object, connected to an enterprise instance. \n
    \tenvironment - The full path to the active_directory.json file to be uploaded. \n
    \tapp_insights - (Optional) The full path to the application_insights.json file to be uploaded. \n
    \ttunings - (Optional) Scenarios to run on the model. \n
    \tlang - The lang file that was used to generate the model
    Returns - None
    \t
    """
    ad_filename = environment.as_posix().split("/")[-1]
    insights_filename = app_insights.as_posix().split("/")[-1] if app_insights else ""
    active_directory_data: List[Dict[str, Any]] = []
    application_insights_data: List[Dict[str, Any]] = []
    try:
        f = open(file=environment, mode="rb")
        active_directory_data.append(json.load(f))
        f.close()
    except FileNotFoundError as e:
        log(f"{e}")
        log(f"Cannot parse without a valid active_directory.json. Exiting")
        sys.exit()
    if app_insights:
        try:
            f = open(file=app_insights, mode="rb")
            application_insights_data.append(json.load(f))
            f.close()
        except FileNotFoundError as e:
            log(f"{e}")
    # Make the data enterprise compatible
    if application_insights_data:
        log(
            f"Generating model from environment file {ad_filename} and application insights file {insights_filename}"
        )
    else:
        log(f"Generating model from {ad_filename}")
    res = es_client.parsers.generate_azure_model(
        project=project,
        name=ad_filename,
        az_active_directory_files = active_directory_data,
        application_insight_files = application_insights_data
    )
    if not res.is_valid:
        log(
            f"Uploaded model {res.name} is not valid, reasons: \n {res.validation_issues}"
        )
    model = res.get_dict()
    __apply_tunings(
        tunings=tunings,
        es_client=es_client,
        project=project,
        model=model,
        model_info=res,
    )
    log(f"Done")


def __apply_tunings(tunings, es_client, project, model, model_info):
    log(f"Applying tunings to model")
    for name, tuningslist in tunings.items():
        tuning_objects = []
        for tuning in tuningslist:
            try:
                tuning_obj = es_client.tunings.create_tuning(
                    project=project, **tuning
                )
                tuning_objects.append(tuning_obj)
            except (TypeError, ValueError) as e:
                log(f"{tuning} is not a valid tuning. {e}")
        # Apply any tunings
        scenario_name = f"{name} {datetime.now().strftime('%Y-%m-%D')}"
        simulation_name = datetime.now().strftime("T%H:%M:%S")
        log(f"Starting simulation in {scenario_name}")
        try:
            scenario = es_client.scenarios.get_scenario_by_name(
                project=project, name=scenario_name
            )
            create_simulation(
                es_client=es_client, scenario=scenario, name=simulation_name, model=model, tunings=tuning_objects
            )
        except ValueError:
            scenario = create_scenario(
                es_client=es_client, name=scenario_name, project=project, model_info=model_info, tunings=tuning_objects
            )



def create_simulation(es_client: "Client", scenario: "Scenario", name: "Project", model: "Model", tunings: List["Tuning"]):
    data = {
        "pid": scenario.pid,
        "tid": scenario.tid,
    }
    if name:
        data["name"] = name
    if model:
        data["blob"] = model
    if tunings:
        data["cids"] = [t.tuning_id for t in tunings]
    res = es_client._put(
        "simulation",
        data
    )


def create_scenario(es_client: "Client", name: str, project: "Project", model_info: "ModelInfo", tunings: List["Tuning"]):
    data: Dict[str, Any] = {
        "pid": project.pid,
        "mid": model_info.mid,
        "name": name,
        "description": ""
    }
    if tunings:
        data["cids"] = [t.tuning_id for t in tunings]
    es_client._put("scenario", data)


def log(message: str):
    time = datetime.now().strftime("%Y-%m-%D-%T")
    print(f"{time} {__file__}: {message}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-e",
        "--environment",
        action="store",
        default=None,
        type=Path,
        required=False,
        help="active_directory.json file path",
        metavar="FILE",
        dest="ad_file",
    )
    parser.add_argument(
        "-i",
        "--insights",
        action="store",
        default=None,
        type=Path,
        required=False,
        help="application_insights.json file path",
        metavar="FILE",
        dest="ai_file",
    )
    parser.add_argument(
        "-t",
        "--tuning",
        action="store",
        default=None,
        type=Path,
        required=False,
        help="json file containing tuning objects",
        metavar="FILE",
        dest="tunings",
    )
    parser.add_argument(
        "-p",
        "--project",
        action="store",
        default=None,
        type=str,
        required=False,
        help="Project name that the model will be uploaded to. Will use date as default if not provided",
        dest="project",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    project = args.project if args.project else "Default"
    (es_client, project) = setup(args.project)
    if args.tunings:
        tunings = {}
        try:
            with open(args.tunings, "rb") as f:
                data = f.read()
                try:
                    tunings = json.loads(data.decode("utf-8"))
                except:
                    pass
        except FileNotFoundError as e:
            log(e)
    else:
        tunings = {}
    if args.ad_file:
        upload_json(
            project=project,
            es_client=es_client,
            environment=args.ad_file,
            app_insights=args.ai_file,
            tunings=tunings
        )
    else:
        log(
            "Need to provide either an active_directory.json (together with optional application_insights.json file). Run the program with -h for more info"
        )


if __name__ == "__main__":
    main()
