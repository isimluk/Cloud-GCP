"""Discover for GCP"""
#########################################################################
# gcp_discover_accounts - 2021.03.31                                    #
#                                                                       #
# Leverages the FalconPy uber class to perform check, update & register #
# operations within a customer Falcon Discover (GCP) environment.       #
#                                                                       #
# PLEASE NOTE: This solution requires the falconpy SDK. This project    #
# can be accessed here: https://github.com/CrowdStrike/falconpy         #
#########################################################################
import argparse
import json
import sys
import subprocess       # nosec
# Falcon SDK - All in one uber-class
from falconpy import api_complete as FalconSDK  # pylint: disable=E0401


# ============== FORMAT API PAYLOAD
def format_api_payload():
    """Formats the API payload"""
    # Generates a properly formatted JSON payload for POST and PATCH requests
    data = {
        "resources": [
            {
                "parent_id": parent_id
            }
        ]
    }
    return data


# ============== CHECK ACCOUNTS
def check_account():
    """Checks the status of registered accounts"""
    # Retrieve the account list
    account_list = falcon.command(action="GetCSPMCGPAccount", parameters={"scan_type": "{}".format(str(SCAN_TYPE))})
    # Log the results of the account query to a file if logging is enabled
    if log_enabled:
        with open('falcon-discover-accounts.json', 'w+') as file_handle:
            json.dump(account_list, file_handle)
    print(account_list)
    return True


# ============== REGISTER ACCOUNT
def register_account():
    """Registers the GCP account"""
    # Call the API to update the requested account.
    register_response = falcon.command(action="CreateCSPMGCPAccount", parameters={}, body=format_api_payload())
    if register_response["status_code"] == 201:
        member = "serviceAccount:cspm-nlcgo9d9x1ag578qjpaffhwo@cs-cspm-prod.iam.gserviceaccount.com"
        role = "roles/cloudasset.viewer"
        provisioned = subprocess.getoutput("gcloud projects add-iam-policy-binding {} --member {} --role {}".format(parent_id,
                                                                                                                    member,
                                                                                                                    role
                                                                                                                    ))
        if "Updated IAM policy for project" in provisioned:
            print("Successfully registered account.")
        else:
            print("Account registered. IAM role creation failed.")
    else:
        print("Registration failed with response: {} {}".format(register_response["status_code"],
                                                                register_response["body"]["errors"][0]["message"]
                                                                ))
    return True


# ============== DELETE ACCOUNT
def delete_account():
    """Deletes a GCP account"""
    # Call the API to delete the requested account, multiple IDs can be deleted by passing in a comma-delimited list
    # delete_response = falcon.command(action="DeleteAWSAccounts", parameters={}, ids=local_account)
    # if delete_response["status_code"] == 200:
    #     print("Successfully deleted account.")
    # else:
    #     print("Delete failed with response: {} {}".format(delete_response["status_code"],
    #                                                       delete_response["body"]["errors"][0]["message"]
    #                                                       ))
    print("Delete functionality not yet implemented.")
    return True


# ============== MAIN
if __name__ == "__main__":
    # Configure argument parsing
    parser = argparse.ArgumentParser(description="Get Params to send notification to CRWD topic")
    # Fully optional
    parser.add_argument('-t', '--scan_type', help='The type of scan, dry or full, to perform', required=False)
    parser.add_argument('-l', '--log_enabled', help='Save results to a file?', required=False, action="store_true")
    # Optionally required
    parser.add_argument('-i', '--parent_id', help='External ID used to assume role in account', required=False)
    # Always required
    parser.add_argument('-c', '--command', help='Troubleshooting action to perform', required=True)
    parser.add_argument("-f", "--falcon_client_id", help="Falcon Client ID", required=True)
    parser.add_argument("-s", "--falcon_client_secret", help="Falcon Client Secret", required=True)
    args = parser.parse_args()
    # ============== SET GLOBALS
    command = args.command
    # Only execute our defined commands
    if command.lower() in "check,register,delete":
        if command.lower() in "register,delete":
            # All fields required for update, register and delete
            if args.parent_id is None:
                parser.error("The {} command requires the parent_id (-i) argument to also be specified.".format(command))
            else:
                parent_id = args.parent_id
    else:
        parser.error("The {} command is not recognized.".format(command))
    # These globals exist for all requests
    falcon_client_id = args.falcon_client_id
    falcon_client_secret = args.falcon_client_secret
    log_enabled = args.log_enabled
    if args.scan_type is None:
        SCAN_TYPE = "dry"
    else:
        SCAN_TYPE = args.scan_type
    # ================= MAIN ROUTINE
    # Connect to the API using our provided falcon client_id and client_secret
    try:
        falcon = FalconSDK.APIHarness(creds={'client_id': falcon_client_id, 'client_secret': falcon_client_secret})
    except Exception:   # pylint: disable=W0703
        # We can't communicate with the endpoint
        print("Unable to communicate with API")
    # Authenticate
    if falcon.authenticate():
        try:
            # Execute the command by calling the named function
            exec("{}_account()".format(command.lower()))    # nosec     pylint: disable=W0122
        except Exception as err:       # pylint: disable=W0703
            # Handle any previously unhandled errors
            print("Command failed with error: {}.".format(str(err)))
        # Discard our token before we exit
        falcon.deauthenticate()
    else:
        # Report that authentication failed and stop processing
        print("Authentication Failure.")
    # Force clean exit
    sys.exit(0)
