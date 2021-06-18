from securicad import enterprise
from securicad.enterprise import organizations
from pathlib import Path
from typing import TYPE_CHECKING, Tuple, Optional, List, Dict, Any
import configparser
import argparse
from datetime import datetime
import logging
import json
import io

if TYPE_CHECKING:
    from securicad.enterprise.client import Client
    from securicad.enterprise.models import ModelInfo
    from securicad.enterprise.projects import Project

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
    print(str(Path(__file__).resolve().parent.joinpath("", "conf.ini")))
    return str(Path(__file__).resolve().parent.joinpath("", "conf.ini"))

def setup(project: Optional[str]):
    """ Returns a tuple of an enterprise client along with a project object. \n
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
    es_client = enterprise.client(
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


def upload_scad(project: "Project", es_client: "Client", scad: Path, tunings: Optional[Dict[str, List["Tuning"]]]) -> None:
    """Uploads an .scad file to enterprise to a specified project. \n
    Keyword arguments: \n
    \tproject - The enterprise project object to upload the file to. \n
    \tes_client - A Client object, connected to an enterprise instance. \n
    \tscad - The full path to the .sCAD file to be uploaded
    Returns - None
    """
    try:
        filename = scad.as_posix().split("/")[-1]
    except IndexError:
        filename = datetime.now().strftime("%D-%T") + ".sCAD"
    with open(file=scad, mode="rb") as file_io:
        log(f"Uploading model {filename}")
        res = es_client.models.upload_scad_model(
            project=project, filename=filename, file_io=file_io
        )
        if not res.is_valid:
            log(
                f"Uploaded model {res.name} is not valid, reasons: \n {res.validation_issues}"
            )
        model = res.get_model()
        __apply_tunings(tunings = tunings, es_client=es_client, project=project, model=model, model_info=res)


def upload_json(project: "Project", es_client: "Client", environment: Path, app_insights: Optional[Path], tunings: Optional[Dict[str, List["Tuning"]]]) -> None:
    """ Uploads the active_directory.json and application_insights.json file provided by the collector to enterprise
    and parses a model to the specified project. \n
    Keyword arguments: \n
    \tproject - The enterprise project object to upload the file to. \n
    \tes_client - A Client object, connected to an enterprise instance. \n
    \tenvironment - The full path to the active_directory.json file to be uploaded. \n
    \app_insights - (Optional) The full path to the application_insights.json file to be uploaded. \n
    Returns - None
    \t 
    """
    def get_file_io(dict_file: Dict[str, Any]) -> io.BytesIO:
        file_str = json.dumps(dict_file, allow_nan=False, indent=2)
        file_bytes = file_str.encode("utf-8")
        return io.BytesIO(file_bytes)
    
    def get_file(
            sub_parser: str, name: str, dict_file: Dict[str, Any]
        ) -> Dict[str, Any]:
            return {
                "sub_parser": sub_parser,
                "name": name,
                "file": get_file_io(dict_file),
            }

    active_directory_data: Dict = {}
    application_insights_data: Dict = {}
    try:
        f = open(file=environment, mode="rb")
        active_directory_data = json.load(f)
        f.close()
    except FileNotFoundError as e:
        log(f"{e}")
        log(f"Cannot parse without a valid active_directory.json. Exiting")
        return None
    if app_insights:
        try:
            f = open(file=app_insights, mode="rb")
            application_insights_data = json.load(f)
            f.close()
        except FileNotFoundError as e:
            log(f"{e}")
    # Make the data enterprise compatible
    files = []
    ad_filename = environment.as_posix().split("/")[-1]
    insights_filename = app_insights.as_posix().split("/")[-1] if app_insights else ""
    files.append(get_file(sub_parser="azure-active-directory-parser", name=ad_filename, dict_file=active_directory_data ))
    if app_insights:
        files.append(get_file(sub_parser="azure-application-insights-parser", name=insights_filename, dict_file=application_insights_data))
        log(f"Generating model from environment file {ad_filename} and application insights file {insights_filename}")
    else:
        log(f"Generating model from {ad_filename}")
    res: "ModelInfo" = es_client.models.generate_model(project=project,parser="azure-parser", name=ad_filename, files=files) 
    if not res.is_valid:
        log(
            f"Uploaded model {res.name} is not valid, reasons: \n {res.validation_issues}"
        )
    model = res.get_model()
    __apply_tunings(tunings = tunings, es_client=es_client, project=project, model=model, model_info=res)


def __apply_tunings(tunings, es_client, project, model, model_info):
    log(f"Applying tunings to model")
    for name, tuningslist in tunings.items():
        tuning_objects = []
        for tuning in tuningslist:
            try:
                tuning_objects.append(
                    es_client.tunings.create_tuning(
                        project=project, model=model, **tuning
                    )
                )
            except (TypeError, ValueError):
                log(f"{tuning} is not a valid tuning")
        # res.save(model)
        # Apply any tunings
        scenario_name = f"{name} {datetime.now().strftime('%Y-%m-%D')}"
        try:
            scenario = es_client.scenarios.get_scenario_by_name(
                project=project, name=scenario_name
            )
        except ValueError:
            scenario = es_client.scenarios.create_scenario(
                project=project, model_info=model_info, name=scenario_name
            )
        simulation_name = datetime.now().strftime("T%H:%M:%S")
        log(f"Starting simulation in {scenario_name}")
        es_client.simulations.create_simulation(
            scenario=scenario, name=simulation_name, model=model, tunings=tuning_objects
        )
        log(f"Done")


def log(message: str):
    time = datetime.now().strftime("%Y-%m-%D-%T")
    print(f"{time} {__file__}: {message}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-s",
        "--scad",
        action="store",
        default=None,
        type=Path,
        required=False,
        help="securicad .scad model file path",
        metavar="FILE",
        dest="scad_file",
    )
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
    if args.scad_file:
        try:
            scad = Path(args.scad_file)
            if scad.suffix != ".sCAD":
                log(f"Invalid file type {args.scad_file}. input file needs to be a .sCAD file")
                return
            upload_scad(project = project, es_client=es_client, scad=args.scad_file, tunings=tunings)
        except:
            log(f"Invalid input {args.scad_file} . input file needs to be a path")
            return
    elif args.ad_file:
        upload_json(project=project, es_client=es_client, environment=args.ad_file, app_insights=args.ai_file, tunings=tunings)
    else:
        log("Need to provide either a .sCAD file or an active_directory.json (together with optional application_insights.json file). Run the program with -h for more info")

if __name__ == "__main__":
    main()