# securicad-azure-collector


# Configuration on the Azure environment 

The extractor program needs to assume the identity of a security principal assigned a Reader role on a subscription level to be able to extract your environment. We suggest you either register a new application under ___App registrations___ in the Azure Active Directory to create a new Service Principal, or by assigning a system wide ___Managed Identity___ for an azure virtual machine (possibly the same machine running securiCAD Enterprise) and give the security principal this permission. The first option is required if you are running locally. 

## Optional roles

Below are optional role assignments / access policies you may give your security principal to enrich the model with additional information.

___azureDataExtractor___ - A new custom role given the "List Web App Security Sensitive Settings" operation. This allows the program to see if the site authentication managed by Azure for the app is enabled or not on an App Service. The extractor will assume this value is False when ignoring this assignment.

Key Vault Access Policies - You may assign the security principal key, secret and certificate ___List___ permission to enrich the model with the actual key vault components. This assignment is not reading any actual secrets, merely the component names. Opting out of this assignment will create a default component for each type called ___test-component___ to capture the attack logic on the key vault. 

## Optional: Application Insights - data enrichment
Application Insights records the traffic in your azure environment and can be used to enrich the securiCAD model by making us of its topology mapping. The topology dump allows the parser to connect services that are communicating to each other through connection strings/keys, as it sees that there are some sort of communication between these services that are not relying on RBAC assignments. To make use of this, set up an Application Insights component in your azure environment, and attach the services that you are about to analyze in securiCAD in their respective configuration page, and let the entire system run for some time.

# Installation of the data-exctractor

## Setting up the environment

Prerequisites: Python 3.8.5 or above

At the top level of the repository, create a python virtual environment and activate it with the commands:

1: Creating the virtual environment
```bash
python3 -m venv .venv
```

2: Activate the virtual enviroment

```bash
source .venv/bin/activate
```

3: Install the program requirements from requirements.txt

```bash
pip3 install -r requirements.txt
```

# Dumping the Azure Active Directory to json

To begin generating a securiCAD model of your Azure environment, we have to first get a json representation of it.

## Limiting the analyzed scope
The program is reliant on environment variables, which allows you to limit the dump to a specified subset of your environment.

### Subscription scope
Export the ```AZURE_SUBSCRIPTION_ID``` if you wish to use the program on a specific azure subscription. Otherwise if not set, or set to ```''```, the proram defaults to work on every AD subscription that the Security Principal has ``Read`` permission on. 

Accepted formats:
```bash
empty: '' / Not Applied 
comma separated string: "<sub_id_one>, <sub_id_two>"
list representation as a string: '["<sub_id_one>","sub_id_two>"]' # Note the structure of this environment variable, single qoutation marks wrapping the array and double qouatation marks for each item. 
```

```bash
 <space>export AZURE_SUBSCRIPTION_ID='your subscription id that the security princiapl has read access to.'
```

**NOTE: insert a space before export so that the command doesn't show up in bash history.** These ids are not very sensitive, but there's no reason for outsiders to know them. In case you forgot and don't want anyone with access to your machine to see them in your history, use the following command to clear your bash history:

```bash
history -c
```

### Resource Group scope
Export the ```AZURE_RESOURCE_GROUP_NAMES``` if you wish only wish to include specified resource groups and its corresponding resources to be extracted. If not set or set to ```''``` all the resource groups are fetched and extracted (within the scope of the subscriptions). 

Accepted format: 
```bash
comma separated string: "<rsg_name_one>, <rsg_name_two>"
list representation as a string: '["<rsg_name_one>","rsg_name_two>"]'
empty: '' / "[]" / Not Applied
```

```bash
 <space>export AZURE_RESOURCE_GROUP_NAMES='["<rsg_name_one>", "<rsg_name_two>"]'
```

### Limiting the Application Insights interval
export the ```APP_INSIGHTS_INTERVAL``` variable if you wish to include a custom scope on your application insights' topology data. This is a time interval following the ISO8601 standard: YYYY-MM-DDTHH-MM-SS/YYYY-MM-DDTHH-MM-SS (e.g. 2020-01-01T16:01:30.000/2021-02-20T16:01:30.000). If not set, or set to something other than the required time format, the collector defaults to latest 90 days. Make sure to include the resource group where the application insights resources resides ```AZURE_RESOURCE_GROUP_NAMES``` to fetch application insights data.

Accepted Format:
```bash
 <space>export APP_INSIGHTS_INTERVAL = '2020-01-01T16:30:50.000/2021-02-20T16:01:30.000'.
```

## Authentication against Azure

The ```data extractor``` uses the ```DefaultAzureCredentials``` class to authenticate itself against azure (read more [here](https://docs.microsoft.com/en-us/python/api/azure-identity/azure.identity.defaultazurecredential?view=azure-python)). We suggest you use a Managed Identity via an Azure VM, or set up an App Registration as a Service Principal.

### Through a Managed Identity
Using a Managed Identity is most likely the easiest route if you are hosting securiCAD enterprise for azure yourself, or if you don't have administration access to create an App Registration in your Azure Active Directory. Simply run the program on an Azure VM with a system assigned managed identity with a Read role on the subscription. Important here is to unset the environment variable ___AZURE_CLIENT_ID___ by running ```unset AZURE_CLIENT_ID``` so that it doesn't try to use environment variables as means of authentication.

### Through a Service Principal

Environment variables has to be set if you are using an app registration. Configure the variables seen below. 

```bash
<space>export AZURE_TENANT_ID='your tenant id'

<space>export AZURE_CLIENT_ID='your client id'

<space>export AZURE_CLIENT_SECRET='your client secret'
```

## Optional
Every time you start up a new shell the environment variables that the program relies on have to be exported. This might be tedious, so a suggestion is to 
create a script called ```./envvariables.sh``` and add the following lines:

```bash
#!/bin/sh
export AZURE_SUBSCRIPTION_ID='<sub_id>'
export AZURE_RESOURCE_GROUP_NAMES='["<rsg_name_one>", "<rsg_name_two>"]'
export APP_INSIGHTS_INTERVAL = 'YYYY-MM-DDTHH-MM-SS/YYYY-MM-DDTHH-MM-SS'
# Add the following environment variables below if you are using a Service Principal (App registration)
export AZURE_TENANT_ID='<tenant_id>'
export AZURE_CLIENT_ID='<client_id>'
export AZURE_CLIENT_SECRET='<client_secret>'
```

In case you use another name, add it to the .gitignore file to prevent the ids leaking out on GitHub. Or simply add it anywhere else in your filesystem and ignore this step. 

Next up, add permissions to the script.

```bash
chmod 700 ./envvariables.sh
```

make sure you run the script within the same scope as your current shell to save the environment variables to it by either command:

```bash
source ./envvariables.sh
. ./envvariables.sh
```

## Running the data extractor
Now you can run the data extrator to generate a json dump of your Azure environment.
```
python3 fetch_subscription_resources.py
```

The program will dump a timestamped ```active_directory_YYYY-mm-dd_HH:MM.json``` file under the `environment_files` directory, and a file called ```application_insights_YYYY-mm-dd_HH:MM.json``` under the same directory if an _application insights_ resource was found within the scope of the provided Azure environment. Again, the ```application_insights.json``` can be used to enrich the model by connecting services that communicate to each other through connection strings / keys. This data file is optional, but we suggest running if you are using App Services and Function Apps that are communicating with Azure backend resources where Managed Identities are not used. Use these files as input for our `securiCAD azure parser`. 

## Parsing the generated data
Parsing the files can be done with our `azure-resource-parser` repo or by sending the generated .json files to an active enterprise instance using `upload.py`. 

### Using upload.py

```
python3 upload.py -e /path/to/active_directory.json [-i /path/to/application_insights.json] [-t /path/to/tuningsfile.json] [-p projectname]
```

The model will be added to enterprise below `projectname` or the `Default` project if none is provided. Scenarios and simulations are also started automatically, depending on the contents of `tuningsfile.json`.

For more information:
```
path/to/securicad-azure-collector/upload.py -h
```

#### Prerequisites 
To use `upload.py`, create a `conf.ini` at the top level of this directory (`securicad-azure-collector`), with the following format (replace the ip and credentials with your own configuration):

```
[URL]
authserviceurl = https://192.168.122.128/api/v1/auth/login
serviceurl = https://192.168.122.128/modelbuilder

[CERT]
cacert =
clientcert =
clientcertkey =

[AUTH]
username = user
password = Password123
organization = org
```

## Docs page
For additional information regarding usage of this collector and the securiCAD azure solution, please visit our [docs](https://docs.foreseeti.com/docs/integrating-with-azure) page.
