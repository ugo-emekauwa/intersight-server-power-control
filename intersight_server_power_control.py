"""
Automated Server Power Control Tool for Cisco Intersight, v1
Author: Ugo Emekauwa
Contact: uemekauw@cisco.com, uemekauwa@gmail.com
Summary: The Automated Server Power Control Tool for Cisco Intersight automates
         the power state of multiple UCS servers managed by Intersight.
GitHub Repository: https://github.com/ugo-emekauwa/intersight-server-power-control
"""


import sys
import traceback
import json
import copy
import intersight
import re
import urllib3
import time

########################
# MODULE REQUIREMENT 1 #
########################
"""
For the following variable below named key_id, please fill in between
the quotes your Intersight API Key ID.

Here is an example:
key_id = "5c89885075646127773ec143/5c82fc477577712d3088eb2f/5c8987b17577712d302eaaff"

"""
key_id = ""


########################
# MODULE REQUIREMENT 2 #
########################
"""
For the following variable below named key, please fill in between
the quotes your system's file path to your Intersight API key "SecretKey.txt"
file.

Here is an example:
key = "C:\\Users\\demouser\\Documents\\SecretKey.txt"

"""
key = ""


########################
# MODULE REQUIREMENT 3 #
########################
"""
Provide the required configuration settings to automate 
UCS server power control on Cisco Intersight. Remove the sample
values and replace them with your own, where applicable.
"""

####### Start Configuration Settings - Provide values for the variables listed below. #######

# General Settings
## NOTE - For the "Server Identifier" key below, the accepted values are the Server serial, name, model, PID (product ID), or user label. This information can be found in Intersight, if needed.
## If there are Server with duplicate names, models, PIDs, or user labels, please use the serial to ensure the correct Server is selected.
## Here is an example using the Server serial: "Server Identifier": " FCH37527777"
## Here is an example using the Server name: "Server Identifier": "UCS-IMM-Pod-1-1"
## Here is an example using the Server model: "Server Identifier": "UCSX-210C-M7"
## Here is an example using the Server PID: "Server Identifier": "UCSX-210C-M7"
## For the "Server Form Factor" key, the options are "Blade or "Rack". If the "Server Form Factor" key is not provided, the value will default to "Blade".
## For the "Server Connection Type" key, the options are "FI-Attached" or "Standalone". If the "Server Connection Type" key is not provided, the value will default to "FI-Attached".
## Here is an example: power_control_target_server_id_dictionary_list = [{"Server Identifier": "Demo-Blade-Server-1"}, {"Server Identifier": "Demo-Blade-Server-2"}, {"Server Identifier": "Demo-Blade-Server-3"},]
## To include additional target servers, add more dictionary entries to the power_control_target_server_id_dictionary_list variable below.
power_control_target_server_id_dictionary_list = [
    {"Server Identifier": "Demo-Blade-Server-1",
     "Server Form Factor": "Blade",
     "Server Connection Type": "FI-Attached"},
    {"Server Identifier": "Demo-Rack-Server-1",
     "Server Form Factor": "Rack",
     "Server Connection Type": "Standalone"},
    ]

power_control_state = "Reboot CIMC"      # Options: "Power On", "Power Off", "Power Cycle", "Hard Reset", "Shutdown", "Reboot CIMC". "Reboot CIMC" restarts the CIMC only, all other operations are directly on the server.

# Intersight Base URL Setting (Change only if using the Intersight Virtual Appliance)
intersight_base_url = "https://www.intersight.com/api/v1"
url_certificate_verification = True

####### Finish Configuration Settings - The required value entries are complete. #######


#############################################################################################################################
#############################################################################################################################


# Suppress InsecureRequestWarning error messages
urllib3.disable_warnings()

# Function to get Intersight API client as specified in the Intersight Python SDK documentation for OpenAPI 3.x
## Modified to align with overall formatting, try/except blocks added for additional error handling, certificate verification option added
def get_api_client(api_key_id,
                   api_secret_file,
                   endpoint="https://intersight.com",
                   url_certificate_verification=True
                   ):
    try:
        with open(api_secret_file, 'r') as f:
            api_key = f.read()
        
        if re.search('BEGIN RSA PRIVATE KEY', api_key):
            # API Key v2 format
            signing_algorithm = intersight.signing.ALGORITHM_RSASSA_PKCS1v15
            signing_scheme = intersight.signing.SCHEME_RSA_SHA256
            hash_algorithm = intersight.signing.HASH_SHA256

        elif re.search('BEGIN EC PRIVATE KEY', api_key):
            # API Key v3 format
            signing_algorithm = intersight.signing.ALGORITHM_ECDSA_MODE_DETERMINISTIC_RFC6979
            signing_scheme = intersight.signing.SCHEME_HS2019
            hash_algorithm = intersight.signing.HASH_SHA256

        configuration = intersight.Configuration(
            host=endpoint,
            signing_info=intersight.signing.HttpSigningConfiguration(
                key_id=api_key_id,
                private_key_path=api_secret_file,
                signing_scheme=signing_scheme,
                signing_algorithm=signing_algorithm,
                hash_algorithm=hash_algorithm,
                signed_headers=[
                    intersight.signing.HEADER_REQUEST_TARGET,
                    intersight.signing.HEADER_HOST,
                    intersight.signing.HEADER_DATE,
                    intersight.signing.HEADER_DIGEST,
                    ]
                )
            )

        if not url_certificate_verification:
            configuration.verify_ssl = False
    except Exception:
        print("\nA configuration error has occurred!\n")
        print("Unable to access the Intersight API Key.")
        print("Exiting due to the Intersight API Key being unavailable.\n")
        print("Please verify that the correct API Key ID and API Key have "
              "been entered, then re-attempt execution.\n")
        print("Exception Message: ")
        traceback.print_exc()
        sys.exit(0)
        
    return intersight.ApiClient(configuration)


# Establish function to test for the availability of the Intersight API and Intersight account
def test_intersight_api_service(intersight_api_key_id,
                                intersight_api_key,
                                intersight_base_url="https://www.intersight.com/api/v1",
                                preconfigured_api_client=None
                                ):
    """This is a function to test the availability of the Intersight API and
    Intersight account. The tested Intersight account contains the user who is
    the owner of the provided Intersight API Key and Key ID.

    Args:
        intersight_api_key_id (str):
            The ID of the Intersight API key.
        intersight_api_key (str):
            The system file path of the Intersight API key.
        intersight_base_url (str):
            Optional; The base URL for Intersight API paths. The default value
            is "https://www.intersight.com/api/v1". This value typically only
            needs to be changed if using the Intersight Virtual Appliance. The
            default value is "https://www.intersight.com/api/v1".
        preconfigured_api_client ("ApiClient"):
            Optional; An ApiClient class instance which handles
            Intersight client-server communication through the use of API keys.
            The default value is None. If a preconfigured_api_client argument
            is provided, empty strings ("") or None can be provided for the
            intersight_api_key_id, intersight_api_key, and intersight_base_url
            arguments.

    Returns:
        A string of the name for the Intersight account tested, verifying the
        Intersight API service is up and the Intersight account is accessible.
        
    Raises:
        Exception:
            An exception occurred due to an issue with the provided API Key
            and/or API Key ID.
    """
    # Define Intersight SDK ApiClient variable
    if preconfigured_api_client is None:
        api_client = get_api_client(api_key_id=intersight_api_key_id,
                                    api_secret_file=intersight_api_key,
                                    endpoint=intersight_base_url
                                    )
    else:
        api_client = preconfigured_api_client
    try:
        # Check that Intersight Account is accessible
        print("Testing access to the Intersight API by verifying the "
              "Intersight account information...")
        api_client.call_api(resource_path="/iam/Accounts",
                            method="GET",
                            auth_settings=['cookieAuth', 'http_signature', 'oAuth2', 'oAuth2']
                            )
        response = api_client.last_response.data
        iam_account = json.loads(response)
        if api_client.last_response.status != 200:
            print("\nThe Intersight API and Account Availability Test did not "
                  "pass.")
            print("The Intersight account information could not be verified.")
            print("Exiting due to the Intersight account being unavailable.\n")
            print("Please verify that the correct API Key ID and API Key have "
                  "been entered, then re-attempt execution.\n")
            sys.exit(0)
        else:
            intersight_account_name = iam_account["Results"][0]["Name"]
            print("The Intersight API and Account Availability Test has "
                  "passed.\n")
            print(f"The Intersight account named '{intersight_account_name}' "
                  "has been found.")
            return intersight_account_name
    except Exception:
        print("\nA configuration error has occurred!\n")
        print("Unable to access the Intersight API.")
        print("Exiting due to the Intersight API being unavailable.\n")
        print("Please verify that the correct API Key ID and API Key have "
              "been entered, then re-attempt execution.\n")
        print("Exception Message: ")
        traceback.print_exc()
        sys.exit(0)


# Establish function to retrieve the MOID of a specific Intersight API object by name
def intersight_object_moid_retriever(intersight_api_key_id,
                                     intersight_api_key,
                                     object_name,
                                     intersight_api_path,
                                     object_type="object",
                                     organization="default",
                                     intersight_base_url="https://www.intersight.com/api/v1",
                                     preconfigured_api_client=None
                                     ):
    """This is a function to retrieve the MOID of Intersight objects
    using the Intersight API.

    Args:
        intersight_api_key_id (str):
            The ID of the Intersight API key.
        intersight_api_key (str):
            The system file path of the Intersight API key.
        object_name (str):
            The name of the Intersight object.
        intersight_api_path (str):
            The Intersight API path of the Intersight object.
        object_type (str):
            Optional; The type of Intersight object. The default value is
            "object".
        organization (str):
            Optional; The Intersight organization of the Intersight object.
            The default value is "default".
        intersight_base_url (str):
            Optional; The base URL for Intersight API paths. The default value
            is "https://www.intersight.com/api/v1". This value typically only
            needs to be changed if using the Intersight Virtual Appliance.
        preconfigured_api_client ("ApiClient"):
            Optional; An ApiClient class instance which handles
            Intersight client-server communication through the use of API keys.
            The default value is None. If a preconfigured_api_client argument
            is provided, empty strings ("") or None can be provided for the
            intersight_api_key_id, intersight_api_key, and intersight_base_url
            arguments.

    Returns:
        A string of the MOID for the provided Intersight object.
        
    Raises:
        Exception:
            An exception occurred due to an issue accessing the Intersight API
            path. The status code or error message will be specified.
    """
    # Define Intersight SDK ApiClient variable
    if preconfigured_api_client is None:
        api_client = get_api_client(api_key_id=intersight_api_key_id,
                                    api_secret_file=intersight_api_key,
                                    endpoint=intersight_base_url
                                    )
    else:
        api_client = preconfigured_api_client
    try:
        # Retrieve the Intersight Account name
        api_client.call_api(resource_path="/iam/Accounts",
                            method="GET",
                            auth_settings=['cookieAuth', 'http_signature', 'oAuth2', 'oAuth2']
                            )
        response = api_client.last_response.data
        iam_account = json.loads(response)
        if api_client.last_response.status != 200:
            print("The provided Intersight account information could not be "
                  "accessed.")
            print("Exiting due to the Intersight account being unavailable.\n")
            print("Please verify that the correct API Key ID and API Key have "
                  "been entered, then re-attempt execution.\n")
            sys.exit(0)
        else:
            intersight_account_name = iam_account["Results"][0]["Name"]
    except Exception:
        print("\nA configuration error has occurred!\n")
        print("Unable to access the Intersight API.")
        print("Exiting due to the Intersight API being unavailable.\n")
        print("Please verify that the correct API Key ID and API Key have "
              "been entered, then re-attempt execution.\n")
        sys.exit(0)
    # Retrieving the provided object from Intersight...
    full_intersight_api_path = f"/{intersight_api_path}"
    try:
        api_client.call_api(resource_path=full_intersight_api_path,
                            method="GET",
                            auth_settings=['cookieAuth', 'http_signature', 'oAuth2', 'oAuth2']
                            )
        response = api_client.last_response.data
        intersight_objects = json.loads(response)
        # The Intersight API resource path has been accessed successfully.
    except Exception:
        print("\nA configuration error has occurred!\n")
        print("There was an issue retrieving the "
              f"{object_type} from Intersight.")
        print("Unable to access the provided Intersight API resource path "
              f"'{intersight_api_path}'.")
        print("Please review and resolve any error messages, then re-attempt "
              "execution.\n")
        print("Exception Message: ")
        traceback.print_exc()
        sys.exit(0)

    if intersight_objects.get("Results"):
        for intersight_object in intersight_objects.get("Results"):
            if intersight_object.get("Organization"):
                provided_organization_moid = intersight_object_moid_retriever(intersight_api_key_id=None,
                                                                              intersight_api_key=None,
                                                                              object_name=organization,
                                                                              intersight_api_path="organization/Organizations?$top=1000",
                                                                              object_type="Organization",
                                                                              preconfigured_api_client=api_client
                                                                              )
                if intersight_object.get("Organization", {}).get("Moid") == provided_organization_moid:
                    if intersight_object.get("Name") == object_name:
                        intersight_object_moid = intersight_object.get("Moid")
                        # The provided object and MOID has been identified and retrieved.
                        return intersight_object_moid
            else:
                if intersight_object.get("Name") == object_name:
                    intersight_object_moid = intersight_object.get("Moid")
                    # The provided object and MOID has been identified and retrieved.
                    return intersight_object_moid
        else:
            print("\nA configuration error has occurred!\n")
            print(f"The provided {object_type} named '{object_name}' was not "
                  "found.")
            print("Please check the Intersight Account named "
                  f"{intersight_account_name}.")
            print("Verify through the API or GUI that the needed "
                  f"{object_type} is present.")
            print(f"If the needed {object_type} is missing, please create it.")
            print("Once the issue has been resolved, re-attempt execution.\n")
            sys.exit(0)
    else:
        print("\nA configuration error has occurred!\n")
        print(f"The provided {object_type} named '{object_name}' was not "
              "found.")
        print(f"No requested {object_type} instance is currently available in "
              f"the Intersight account named {intersight_account_name}.")
        print("Please check the Intersight Account named "
              f"{intersight_account_name}.")
        print(f"Verify through the API or GUI that the needed {object_type} "
              "is present.")
        print(f"If the needed {object_type} is missing, please create it.")
        print("Once the issue has been resolved, re-attempt execution.\n")
        sys.exit(0)


# Establish function to retrieve all instances of a particular Intersight API object type
def get_intersight_objects(intersight_api_key_id,
                           intersight_api_key,
                           intersight_api_path,
                           object_type="object",
                           intersight_base_url="https://www.intersight.com/api/v1",
                           preconfigured_api_client=None
                           ):
    """This is a function to perform an HTTP GET on all objects under an
    available Intersight API type.

    Args:
        intersight_api_key_id (str):
            The ID of the Intersight API key.
        intersight_api_key (str):
            The system file path of the Intersight API key.
        intersight_api_path (str):
            The path to the targeted Intersight API object type. For example,
            to specify the Intersight API type for adapter configuration
            policies, enter "adapter/ConfigPolicies". More API types can be
            found in the Intersight API reference library at
            https://intersight.com/apidocs/introduction/overview/.
        object_type (str):
            Optional; The type of Intersight object. The default value is
            "object".
        intersight_base_url (str):
            Optional; The base URL for Intersight API paths. The default value
            is "https://www.intersight.com/api/v1". This value typically only
            needs to be changed if using the Intersight Virtual Appliance.
        preconfigured_api_client ("ApiClient"):
            Optional; An ApiClient class instance which handles
            Intersight client-server communication through the use of API keys.
            The default value is None. If a preconfigured_api_client argument
            is provided, empty strings ("") or None can be provided for the
            intersight_api_key_id, intersight_api_key, and intersight_base_url
            arguments.

    Returns:
        A dictionary containing all objects of the specified API type. If the
        API type is inaccessible, an implicit value of None will be returned.
        
    Raises:
        Exception:
            An exception occurred due to an issue accessing the Intersight API
            path. The status code or error message will be specified.
    """
    # Define Intersight SDK ApiClient variable
    if preconfigured_api_client is None:
        api_client = get_api_client(api_key_id=intersight_api_key_id,
                                    api_secret_file=intersight_api_key,
                                    endpoint=intersight_base_url
                                    )
    else:
        api_client = preconfigured_api_client
    # Retrieving the provided object from Intersight...
    full_intersight_api_path = f"/{intersight_api_path}"
    try:
        api_client.call_api(resource_path=full_intersight_api_path,
                            method="GET",
                            auth_settings=['cookieAuth', 'http_signature', 'oAuth2', 'oAuth2']
                            )
        response = api_client.last_response.data
        intersight_objects = json.loads(response)
        # The Intersight API resource path has been accessed successfully.
        return intersight_objects
    except Exception:
        print("\nA configuration error has occurred!\n")
        print(f"There was an issue retrieving the requested {object_type} "
              "instances from Intersight.")
        print("Unable to access the provided Intersight API resource path "
              f"'{intersight_api_path}'.")
        print("Please review and resolve any error messages, then re-attempt "
              "execution.\n")
        print("Exception Message: ")
        traceback.print_exc()
        sys.exit(0)


# Establish advanced function to retrieve Intersight API objects
def advanced_intersight_object_moid_retriever(intersight_api_key_id,
                                              intersight_api_key,
                                              object_attributes,
                                              intersight_api_path,
                                              object_type="object",
                                              organization="default",
                                              intersight_base_url="https://www.intersight.com/api/v1",
                                              preconfigured_api_client=None
                                              ):
    """This is a function to retrieve the MOID of Intersight objects based on
    various provided attributes using the Intersight API.

    Args:
        intersight_api_key_id (str):
            The ID of the Intersight API key.
        intersight_api_key (str):
            The system file path of the Intersight API key.
        object_attributes (dict):
            A dictionary containing the identifying attribute keys and values
            of the Intersight object to be found.
        intersight_api_path (str):
            The Intersight API path of the Intersight object.
        object_type (str):
            Optional; The type of Intersight object. The default value is
            "object".
        organization (str):
            Optional; The Intersight organization of the Intersight object.
            The default value is "default".
        intersight_base_url (str):
            Optional; The base URL for Intersight API paths. The default value
            is "https://www.intersight.com/api/v1". This value typically only
            needs to be changed if using the Intersight Virtual Appliance.
        preconfigured_api_client ("ApiClient"):
            Optional; An ApiClient class instance which handles
            Intersight client-server communication through the use of API keys.
            The default value is None. If a preconfigured_api_client argument
            is provided, empty strings ("") or None can be provided for the
            intersight_api_key_id, intersight_api_key, and intersight_base_url
            arguments.

    Returns:
        A string of the MOID for the provided Intersight object.
        
    Raises:
        Exception:
            An exception occurred due to an issue accessing the Intersight API
            path. The status code or error message will be specified.
    """
    # Define Intersight SDK ApiClient variable
    if preconfigured_api_client is None:
        api_client = get_api_client(api_key_id=intersight_api_key_id,
                                    api_secret_file=intersight_api_key,
                                    endpoint=intersight_base_url
                                    )
    else:
        api_client = preconfigured_api_client
    try:
        # Retrieve the Intersight Account name
        api_client.call_api(resource_path="/iam/Accounts",
                            method="GET",
                            auth_settings=['cookieAuth', 'http_signature', 'oAuth2', 'oAuth2']
                            )
        response = api_client.last_response.data
        iam_account = json.loads(response)
        if api_client.last_response.status != 200:
            print("The provided Intersight account information could not be "
                  "accessed.")
            print("Exiting due to the Intersight account being unavailable.\n")
            print("Please verify that the correct API Key ID and API Key have "
                  "been entered, then re-attempt execution.\n")
            sys.exit(0)
        else:
            intersight_account_name = iam_account["Results"][0]["Name"]
    except Exception:
        print("\nA configuration error has occurred!\n")
        print("Unable to access the Intersight API.")
        print("Exiting due to the Intersight API being unavailable.\n")
        print("Please verify that the correct API Key ID and API Key have "
              "been entered, then re-attempt execution.\n")
        sys.exit(0)
    # Retrieving the provided object from Intersight...
    full_intersight_api_path = f"/{intersight_api_path}"
    try:
        api_client.call_api(resource_path=full_intersight_api_path,
                            method="GET",
                            auth_settings=['cookieAuth', 'http_signature', 'oAuth2', 'oAuth2']
                            )
        response = api_client.last_response.data
        intersight_objects = json.loads(response)
        # The Intersight API resource path has been accessed successfully.
    except Exception:
        print("\nA configuration error has occurred!\n")
        print("There was an issue retrieving the "
              f"{object_type} from Intersight.")
        print("Unable to access the provided Intersight API resource path "
              f"'{intersight_api_path}'.")
        print("Please review and resolve any error messages, then re-attempt "
              "execution.\n")
        print("Exception Message: ")
        traceback.print_exc()
        sys.exit(0)

    if intersight_objects.get("Results"):
        for intersight_object in intersight_objects.get("Results"):
            if intersight_object.get("Organization"):
                provided_organization_moid = intersight_object_moid_retriever(intersight_api_key_id=None,
                                                                              intersight_api_key=None,
                                                                              object_name=organization,
                                                                              intersight_api_path="organization/Organizations?$top=1000",
                                                                              object_type="Organization",
                                                                              preconfigured_api_client=api_client
                                                                              )
                if intersight_object.get("Organization", {}).get("Moid") == provided_organization_moid:
                    for object_attribute in object_attributes:
                        try:
                            intersight_object[object_attribute]
                        except KeyError:
                            break
                        if intersight_object.get(object_attribute) != object_attributes.get(object_attribute):
                            break
                    else:
                        intersight_object_moid = intersight_object.get("Moid")
                        # The provided object and MOID has been identified and retrieved.
                        return intersight_object_moid
            else:
                for object_attribute in object_attributes:
                    try:
                        intersight_object[object_attribute]
                    except KeyError:
                        break
                    if intersight_object.get(object_attribute) != object_attributes.get(object_attribute):
                        break
                else:
                    intersight_object_moid = intersight_object.get("Moid")
                    # The provided object and MOID has been identified and retrieved.
                    return intersight_object_moid
        else:
            print("\nA configuration error has occurred!\n")
            print(f"The provided {object_type} was not found.")
            print("Please check the Intersight Account named "
                  f"{intersight_account_name}.")
            print("Verify through the API or GUI that the needed "
                  f"{object_type} is present.")
            print(f"If the needed {object_type} is missing, please create it.")
            print("Once the issue has been resolved, re-attempt execution.\n")
            sys.exit(0)
    else:
        print("\nA configuration error has occurred!\n")
        print(f"The provided {object_type} was not found.")
        print(f"No requested {object_type} instance is currently available in "
              f"the Intersight account named {intersight_account_name}.")
        print("Please check the Intersight Account named "
              f"{intersight_account_name}.")
        print(f"Verify through the API or GUI that the needed {object_type} "
              "is present.")
        print(f"If the needed {object_type} is missing, please create it.")
        print(f"Once the issue has been resolved, re-attempt execution.\n")
        sys.exit(0)


# Establish function to convert a list of strings in string type format to list type format.
def string_to_list_maker(string_list,
                         remove_duplicate_elements_in_list=True
                         ):
    """This function converts a list of strings in string type format to list
    type format. The provided string should contain commas, semicolons, or
    spaces as the separator between strings. For each string in the list,
    leading and rear spaces will be removed. Duplicate strings in the list are
    removed by default.

    Args:
        string_list (str):
            A string containing an element or range of elements.

        remove_duplicate_elements_in_list (bool):
            Optional; A setting to determine whether duplicate elements are
            removed from the provided string list. The default value is True.

    Returns:
        A list of elements.   
    """
    def string_to_list_separator(string_list,
                                 separator
                                 ):
        """This function converts a list of elements in string type format to
        list type format using the provided separator. For each element in the
        list, leading and rear spaces are removed.

        Args:
            string_list (str):
                A string containing an element or range of elements.

            separator (str):
                The character to identify where elements in the
                list should be separated (e.g., a comma, semicolon,
                hyphen, etc.).

        Returns:
            A list of separated elements that have been stripped of any spaces.   
        """
        fully_stripped_list = []
        # Split string by provided separator and create list of separated elements.
        split_list = string_list.split(separator)
        for element in split_list:
            if element:
                # Remove leading spaces from elements in list.
                lstripped_element = element.lstrip()
                # Remove rear spaces from elements in list.
                rstripped_element = lstripped_element.rstrip()
                # Populate new list with fully stripped elements.
                fully_stripped_list.append(rstripped_element)
        return fully_stripped_list

    def list_to_list_separator(provided_list,
                               separator
                               ):
        """This function converts a list of elements in list type format to
        list type format using the provided separator. For each element in the
        list, leading and rear spaces are removed.

        Args:
            provided_list (list): A list of elements to be separated.

            separator (str): The character to identify where elements in the
                list should be separated (e.g., a comma, semicolon,
                hyphen, etc.).

        Returns:
            A list of separated elements that have been stripped of any spaces.        
        """
        new_list = []
        # Split list by provided separator and create new list of separated elements.
        for element in provided_list:
            if separator in element:
                split_provided_list = string_to_list_separator(element, separator)
                new_list.extend(split_provided_list)
            else:
                new_list.append(element)
        return new_list
    
    staged_list = []
    # Split provided list by spaces.
    space_split_list = string_to_list_separator(string_list, " ")
    # Split provided list by commas.
    post_comma_split_list = list_to_list_separator(space_split_list, ",")
    # Split provided list by semicolons.
    post_semicolon_split_list = list_to_list_separator(post_comma_split_list, ";")
    # Split provided list by hyphens.
    for post_semicolon_split_string_set in post_semicolon_split_list:
        staged_list.append(post_semicolon_split_string_set)
    # Remove duplicates from list if enabled.
    if remove_duplicate_elements_in_list:
        final_list = list(set(staged_list))
    return final_list


# Establish function to retrieve target server data
def retrieve_target_server_data(
    intersight_api_key_id,
    intersight_api_key,
    server_identifier,
    server_form_factor="Blade",
    server_connection_type="FI-Attached",
    intersight_base_url="https://www.intersight.com/api/v1",
    preconfigured_api_client=None
    ):
    """
    This is a function to retrieve data for a target server on Cisco Intersight.

    Args:
        intersight_api_key_id (str):
            The ID of the Intersight API key.
        intersight_api_key (str):
            The system file path of the Intersight API key.
        server_identifier (str):
            The identifier of the target server.
        server_form_factor (str):
            Optional; The form factor of the target server. The accepted values
            are "Blade" or "Rack". The default value is "Blade".
        server_connection_type (str):
            Optional; The connection type of the target server. The accepted
            values are "FI-Attached" or "Standalone". IMM (Intersight Managed
            Mode) environments should use "FI-Attached". The default value is
            "FI-Attached".
        intersight_base_url (str):
            Optional; The base URL for Intersight API paths. The default value
            is "https://www.intersight.com/api/v1". This value typically only
            needs to be changed if using the Intersight Virtual Appliance.
        preconfigured_api_client ("ApiClient"):
            Optional; An ApiClient class instance which handles
            Intersight client-server communication through the use of API keys.
            The default value is None. If a preconfigured_api_client argument
            is provided, empty strings ("") or None can be provided for the
            intersight_api_key_id, intersight_api_key, and intersight_base_url
            arguments.

    Returns:
        A dictionary with the data for a target server on Cisco Intersight.
    """
    # Define Intersight SDK ApiClient variable
    if preconfigured_api_client is None:
        api_client = get_api_client(api_key_id=intersight_api_key_id,
                                    api_secret_file=intersight_api_key,
                                    endpoint=intersight_base_url
                                    )
    else:
        api_client = preconfigured_api_client
    try:
        # Retrieve the Intersight Account name
        api_client.call_api(resource_path="/iam/Accounts",
                            method="GET",
                            auth_settings=['cookieAuth', 'http_signature', 'oAuth2', 'oAuth2']
                            )
        response = api_client.last_response.data
        iam_account = json.loads(response)
        if api_client.last_response.status != 200:
            print("The provided Intersight account information could not be "
                  "accessed.")
            print("Exiting due to the Intersight account being unavailable.\n")
            print("Please verify that the correct API Key ID and API Key have "
                  "been entered, then re-attempt execution.\n")
            sys.exit(0)
        else:
            intersight_account_name = iam_account["Results"][0]["Name"]
    except Exception:
        print("\nA configuration error has occurred!\n")
        print("Unable to access the Intersight API.")
        print("Exiting due to the Intersight API being unavailable.\n")
        print("Please verify that the correct API Key ID and API Key have "
              "been entered, then re-attempt execution.\n")
        sys.exit(0)
    # If a Server Identifier has been provided, retrieve the targeted Server data
    if server_identifier:
        print("The provided server identifier for retrieval is "
              f"'{server_identifier}'.")
        provided_server_identifiers = string_to_list_maker(server_identifier)
        # Determine Server Form Factor
        if server_form_factor == "Blade":
            provided_server_form_factor = "Blades"
            provided_server_object_type = "Blade Server"
        elif server_form_factor == "Rack":
            provided_server_form_factor = "RackUnits"
            provided_server_object_type = "Rack Server"
        else:
            print("\nA configuration error has occurred!\n")
            print(f"During the retrieval of the data for the server "
                  f"identifier '{server_identifier}', there was an issue "
                  "with the value provided for the server form factor "
                  "setting.")
            print(f"The value provided was {server_form_factor}.")
            print("To proceed, the value provided for the server form "
                  "factor setting should be updated to an accepted string "
                  "format.")
            print("The accepted values are 'Blade' or 'Rack'.")
            print("Please update the configuration, then re-attempt "
                  "execution.\n")
            sys.exit(0)
        # Determine the Server Type (Target Platform or Management Mode)
        if server_connection_type == "FI-Attached":
            provided_server_connection_type = "FI-Attached"
            provided_server_management_mode = "Intersight"
        elif server_connection_type == "Standalone":
            provided_server_connection_type = "Standalone"
            provided_server_management_mode = "IntersightStandalone"
        else:
            print("\nA configuration error has occurred!\n")
            print(f"During the retrieval of the data for the server "
                  f"identifier '{server_identifier}', there was an issue "
                  "with the value provided for the server type setting.")
            print(f"The value provided was {server_connection_type}.")
            print("To proceed, the value provided for the server type "
                  "setting should be updated to an accepted string format.")
            print("The accepted values are 'FI-Attached' or 'Standalone'.")
            print("Please update the configuration, then re-attempt "
                  "execution.\n")
            sys.exit(0)
        # Find provided Server
        retrieved_intersight_servers = get_intersight_objects(
            intersight_api_key_id=None,
            intersight_api_key=None,
            intersight_api_path=f"compute/{provided_server_form_factor}?$top=1000&$filter=ManagementMode%20eq%20%27{provided_server_management_mode}%27",
            object_type=f"{provided_server_object_type}",
            preconfigured_api_client=api_client
            )
        if retrieved_intersight_servers.get("Results"):
            matching_intersight_server = None
            for intersight_server in retrieved_intersight_servers.get("Results"):
                server_serial = intersight_server.get("Serial", "")
                server_name = intersight_server.get("Name", "")
                server_model = intersight_server.get("Model", "")
                server_user_label = intersight_server.get("UserLabel", "")
                for server_identifier in provided_server_identifiers:
                    if server_identifier in [server_serial,
                                             server_name,
                                             server_model,
                                             server_user_label
                                             ]:
                        matching_intersight_server = intersight_server
                        break
                if matching_intersight_server:
                    break
            else:
                print("\nA configuration error has occurred!\n")
                print("There was an issue retrieving the server data "
                      "in Intersight.")
                print(f"A {provided_server_object_type} with the provided "
                      f"identifier of '{server_identifier}' was "
                      "not found.")
                print("Please check the Intersight Account named "
                      f"{intersight_account_name}.")
                print("Verify through the API or GUI that the needed "
                      f"{provided_server_object_type} and matching "
                      "identifier are present.")
                print("If any associated Intersight Target is missing, such as "
                      "an Intersight Managed Domain through an attached Fabric "
                      "Interconnect pair, claiming it first may be required.")
                print(f"Once the issue has been resolved, re-attempt "
                      "execution.\n")
                sys.exit(0)
        else:
            print("\nA configuration error has occurred!\n")
            print("There was an issue retrieving the server data "
                  "in Intersight.")
            print(f"The {provided_server_object_type} with the provided "
                  f"identifier of '{server_identifier}' was not "
                  "found.")
            print(f"No {provided_server_object_type}s could be found in "
                  "the Intersight account named "
                  f"{intersight_account_name}.")
            print(f"Compatible {provided_server_object_type}s need to be "
                  f"{provided_server_connection_type}.")
            print("Please check the Intersight Account named "
                  f"{intersight_account_name}.")
            print("Verify through the API or GUI that the needed "
                  f"{provided_server_object_type} and matching "
                  "identifier are present.")
            print("If any associated Intersight Target is missing, such as an "
                  "Intersight Managed Domain through an attached Fabric "
                  "Interconnect pair, claiming it first may be required.")
            print("Once the issue has been resolved, re-attempt execution.\n")
            sys.exit(0)
        # Log name of found matching Server
        matching_intersight_server_name = matching_intersight_server.get("Name")
        print(f"A matching {provided_server_object_type} named "
              f"{matching_intersight_server_name} has been found.")
        # Create the dictionary for the provided Server Identifier
        matching_intersight_server_moid = matching_intersight_server.get("Moid")
        matching_intersight_server_object_type = matching_intersight_server.get("ObjectType")
        matching_intersight_server_dictionary = {
            "ClassId": "mo.MoRef",
            "Moid": matching_intersight_server_moid,
            "ObjectType": matching_intersight_server_object_type,
            "link": f"{intersight_base_url}/compute/{provided_server_form_factor}/{matching_intersight_server_moid}"
            }
        return matching_intersight_server_dictionary           
    # Display error message if no Server Identifier is provided
    else:
        print("\nA configuration error has occurred!\n")
        print("There was an issue retrieving the server data in "
              "Intersight.")
        print("In order to retrieve the server data, a "
              "server identifier must also be provided.")
        print("Please check the value provided for the "
              "server identifier.")
        print("Once the issue has been resolved, re-attempt execution.\n")
        sys.exit(0)            
    

# Establish classes and functions to control the power state of UCS servers
class ServerSettingsPowerState:
    """This class is used to control the power state of UCS servers in Intersight.
    """
    object_type = "Server Settings (Power State Only)"
    intersight_api_path = "compute/ServerSettings"
    object_variable_value_maps = [
        {"VariableName": "power_control_state",
         "Description": "Power Control State",
         "AttributeName": "AdminPowerState",
         "Values": [
             {"FrontEndValue": "Power On",
              "BackEndValue": "PowerOn"
              },
             {"FrontEndValue": "Power Off",
              "BackEndValue": "PowerOff"
              },
             {"FrontEndValue": "Power Cycle",
              "BackEndValue": "PowerCycle"
              },
             {"FrontEndValue": "Hard Reset",
              "BackEndValue": "HardReset"
              },
             {"FrontEndValue": "Shutdown",
              "BackEndValue": "Shutdown"
              },
             {"FrontEndValue": "Reboot CIMC",
              "BackEndValue": "Reboot"
              }
             ]
         }
        ]
    
    def __init__(
        self,
        intersight_api_key_id,
        intersight_api_key,
        power_control_target_server_id_dictionary,
        power_control_state,
        intersight_base_url="https://www.intersight.com/api/v1",
        preconfigured_api_client=None
        ):
        self.intersight_api_key_id = intersight_api_key_id
        self.intersight_api_key = intersight_api_key
        self.power_control_target_server_id_dictionary = power_control_target_server_id_dictionary
        self.power_control_state = power_control_state
        self.intersight_base_url = intersight_base_url
        if preconfigured_api_client is None:
            self.api_client = get_api_client(api_key_id=intersight_api_key_id,
                                             api_secret_file=intersight_api_key,
                                             endpoint=intersight_base_url
                                             )
        else:
            self.api_client = preconfigured_api_client
        self.intersight_api_body = {}

    def __repr__(self):
        return (
            f"{self.__class__.__name__}"
            f"('{self.intersight_api_key_id}', "
            f"'{self.intersight_api_key}', "
            f"'{self.power_control_target_server_id_dictionary}', "
            f"'{self.power_control_state}', "
            f"'{self.intersight_base_url}', "
            f"{self.api_client})"
            )

    def __str__(self):
        return f"{self.__class__.__name__} class object for '{self.power_control_target_server_id_dictionary}'"

    def _post_intersight_object(self):
        """This is a function to configure an Intersight object by
        performing a POST through the Intersight API.

        Returns:
            A string with a statement indicating whether the POST method
            was successful or failed.
            
        Raises:
            Exception:
                An exception occurred while performing the API call.
                The status code or error message will be specified.
        """
        # Capture Target Server ID info
        power_control_target_server_id = self.power_control_target_server_id_dictionary.get("Server Identifier")
        power_control_target_server_form_factor = self.power_control_target_server_id_dictionary.get("Server Form Factor", "Blade")
        power_control_target_server_connection_type = self.power_control_target_server_id_dictionary.get("Server Connection Type", "FI-Attached")
        print(f"\nConfiguring the {self.object_type} for the target server ID: "
              f"{power_control_target_server_id}...")
        # Retrieve the provided Target Server MOID and data
        power_control_target_server_moid_and_data = retrieve_target_server_data(
            intersight_api_key_id=None,
            intersight_api_key=None,
            server_identifier=power_control_target_server_id,
            server_form_factor=power_control_target_server_form_factor,
            server_connection_type=power_control_target_server_connection_type,
            preconfigured_api_client=self.api_client
            )
        # Retrieve the provided Target Server underlying Server Settings MOID
        power_control_target_server_compute_server_settings_moid = advanced_intersight_object_moid_retriever(
            intersight_api_key_id=None,
            intersight_api_key=None,
            object_attributes={
                "Server": power_control_target_server_moid_and_data
                },
            intersight_api_path=f"{self.intersight_api_path}?$top=1000",
            object_type=self.object_type,
            preconfigured_api_client=self.api_client
            )
        
        full_intersight_api_path = f"/{self.intersight_api_path}/{power_control_target_server_compute_server_settings_moid}"
        try:
            self.api_client.call_api(resource_path=full_intersight_api_path,
                                     method="POST",
                                     body=self.intersight_api_body,
                                     auth_settings=['cookieAuth', 'http_signature', 'oAuth2', 'oAuth2']
                                     )
            print(f"The configuration of the base {self.object_type} "
                  "has completed.")
            return "The POST method was successful."
        except Exception:
            print("\nA configuration error has occurred!\n")
            print(f"Unable to configure the {self.object_type} under the "
                  "Intersight API resource path "
                  f"'{full_intersight_api_path}'.\n")
            print("Exception Message: ")
            traceback.print_exc()
            return "The POST method failed."

    def _update_api_body_mapped_object_attributes(self):
        """This function updates the Intersight API body with individual
        attributes that require mapping frontend to backend values for
        compatibility with the Intersight API.

        Raises:
            Exception:
                An exception occurred while reformatting a provided value for
                an attribute. The issue will likely be due to the provided
                value not being in string format. Changing the value to string
                format should resolve the exception.
        """
        # Check for object variables with value maps that need configuration
        if self.object_variable_value_maps:
            for object_variable in self.object_variable_value_maps:
                # Create list of all known and accepted frontend values
                all_known_and_accepted_frontend_values = (object_variable_value["FrontEndValue"]
                                                          for
                                                          object_variable_value
                                                          in
                                                          object_variable["Values"]
                                                          )
                # Retrieve the user provided object variable value
                provided_object_variable_value = getattr(self,
                                                         object_variable["VariableName"]
                                                         )
                # Reformat the user provided object variable value to lowercase and remove spaces to prevent potential format issues
                try:
                    reformatted_object_variable_value = "".join(provided_object_variable_value.lower().split())
                except Exception:
                    print("\nA configuration error has occurred!\n")
                    print(f"During the configuration of the {self.object_type} named "
                          f"{self.policy_name}, there was an issue with the value "
                          f"provided for the {object_variable['Description']} setting.")
                    print(f"The value provided was {provided_object_variable_value}.")
                    print("To proceed, the value provided for the "
                          f"{object_variable['Description']} setting should be updated to "
                          "an accepted string format.")
                    print("The recommended values are the following:\n")
                    # Print list of all known and accepted frontend values for user
                    print(*all_known_and_accepted_frontend_values,
                          sep=", "
                          )
                    print("\nPlease update the configuration, then re-attempt "
                          "execution.\n")
                    sys.exit(0)
                # Cycle through known values and match provided object variable value to backend value
                for object_variable_value in object_variable["Values"]:
                    # Create list of all known and accepted frontend and backend values
                    current_known_frontend_and_backend_value_options = (object_variable_value.values())
                    # Retrieve the current known backend value
                    current_known_backend_value = object_variable_value["BackEndValue"]
                    if (
                        reformatted_object_variable_value
                        in
                        ("".join(current_known_frontend_or_backend_value.lower().split())
                         for
                         current_known_frontend_or_backend_value
                         in
                         current_known_frontend_and_backend_value_options
                         )
                        ):
                        backend_object_variable_value = current_known_backend_value
                        break
                else:
                    # If no backend match is found with the user provided object variable value, pass on the user provided object variable value to Intersight to decide
                    print(f"\nWARNING: An unknown {self.object_type} value of "
                          f"'{provided_object_variable_value}' has been "
                          f"provided for the {object_variable['Description']} "
                          "settings!")
                    print("An attempt will be made to configure the unknown "
                          f"{object_variable['Description']} value.")
                    print("If there is an error, please use one of the "
                          "following known values for the "
                          f"{object_variable['Description']} settings, then "
                          "re-attempt execution:\n")
                    print(*all_known_and_accepted_frontend_values,
                          sep=", "
                          )
                    backend_object_variable_value = provided_object_variable_value
                # Update Intersight API body with the converted object variable value
                self.intersight_api_body[object_variable["AttributeName"]] = backend_object_variable_value
                
    def object_maker(self):
        """This function makes the targeted object.
        """
        # Update the API body with individual mapped object attributes
        self._update_api_body_mapped_object_attributes()
        # POST the API body to Intersight
        self._post_intersight_object()


def update_power_state(
    intersight_api_key_id,
    intersight_api_key,
    power_control_target_server_id_dictionary,
    power_control_state,
    intersight_base_url="https://www.intersight.com/api/v1",
    preconfigured_api_client=None
    ):
    """This is a function used to update the power state of a UCS server on
    Cisco Intersight.

    Args:
        intersight_api_key_id (str):
            The ID of the Intersight API key.
        intersight_api_key (str):
            The system file path of the Intersight API key.
        power_control_target_server_id_dictionary (dict):
            A dictionary containing the target server data. Required keys
            include "Server Identifier", "Server Form Factor", and
            "Server Connection Type". For the "Server Identifier" key, the
            accepted values are the Server serial, name, model, or PID
            (product ID). This information can be found in Intersight, if
            needed. For the "Server Form Factor" key, the options are "Blade or
            "Rack". For the "Server Connection Type" key, the options are
            "FI-Attached" or "Standalone".
        power_control_state (str):
            The desired power state of the target UCS server. The accepted 
            values include "Power On", "Power Off", "Power Cycle",
            "Hard Reset", "Shutdown", and "Reboot CIMC". The "Reboot CIMC"
            operation restarts the CIMC only, all other operations are directly
            on the server.
        intersight_base_url (str):
            Optional; The base URL for Intersight API paths. The default value
            is "https://www.intersight.com/api/v1". This value typically only
            needs to be changed if using the Intersight Virtual Appliance.
        preconfigured_api_client ("ApiClient"):
            Optional; An ApiClient class instance which handles
            Intersight client-server communication through the use of API keys.
            The default value is None. If a preconfigured_api_client argument
            is provided, empty strings ("") or None can be provided for the
            intersight_api_key_id, intersight_api_key, and intersight_base_url
            arguments.
    """
    def builder(target_object):
        """This is a function used to build the objects that are components of
        an overarching pool, policy, profile, template or related object on
        Cisco Intersight.

        Args:
            target_object (class):
                The class representing the object to be built on Intersight.

        Raises:
            Exception:
                An exception occurred due to an issue accessing the Intersight
                API path. The status code or error message will be specified.
        """
        try:
            target_object.object_maker()
        except Exception:
            print("\nA configuration error has occurred!\n")
            print("The builder function failed to configure the "
                  f"{target_object.object_type} settings.")
            print("Please check the provided arguments for the "
                  f"{target_object.object_type} settings.\n")
            print("Exception Message: ")
            traceback.print_exc()

    # Define and create the Server Settings object in Intersight
    builder(
        ServerSettingsPowerState(
            intersight_api_key_id=intersight_api_key_id,
            intersight_api_key=intersight_api_key,
            power_control_target_server_id_dictionary=power_control_target_server_id_dictionary,
            power_control_state=power_control_state,
            intersight_base_url=intersight_base_url,
            preconfigured_api_client=preconfigured_api_client
            ))


def main():
    # Establish Automated Server Power Control Tool specific variables
    deployment_type = "Automated Server Power Control Tool"
    
    # Establish Intersight SDK for Python API client instance
    main_intersight_api_client = get_api_client(api_key_id=key_id,
                                                api_secret_file=key,
                                                endpoint=intersight_base_url,
                                                url_certificate_verification=url_certificate_verification
                                                )
    
    # Starting the Automated Server Power Control Tool for Cisco Intersight
    print(f"\nStarting the {deployment_type} for Cisco Intersight.\n")

    # Run the Intersight API and Account Availability Test
    print("Running the Intersight API and Account Availability Test.")
    test_intersight_api_service(
        intersight_api_key_id=None,
        intersight_api_key=None,
        preconfigured_api_client=main_intersight_api_client
        )

    # Update the power state of the provided UCS servers
    for power_control_target_server_id_dictionary in power_control_target_server_id_dictionary_list:
        update_power_state(
            intersight_api_key_id=None,
            intersight_api_key=None,
            power_control_target_server_id_dictionary=power_control_target_server_id_dictionary,
            power_control_state=power_control_state,
            intersight_base_url=intersight_base_url,
            preconfigured_api_client=main_intersight_api_client
            )

    # Automated Server Power Control Tool completion
    print(f"\nThe {deployment_type} has completed.\n")


if __name__ == "__main__":
    main()

# Exiting the Automated Server Power Control Tool for Cisco Intersight
sys.exit(0)
