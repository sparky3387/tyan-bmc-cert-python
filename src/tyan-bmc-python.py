#!/opt/certbot/bin/python
import os
import requests
import json
from pathlib import Path
from tempfile import NamedTemporaryFile
from aia import AIASession

def load_config(config_path):
    """
    Load all arguments from the specified configuration file.
    """
    try:
        if os.path.isfile(config_path):
            with open(config_path, "r") as config_file:
                return json.load(config_file)
        else:
            script_dir = os.path.dirname(os.path.abspath(__file__))
            with open(os.path.join(script_dir, config_path), "r") as config_file:
                return json.load(config_file)

    except FileNotFoundError:
        print(f"Config file not found: {config_path}")
        return None
    except json.JSONDecodeError:
        print(f"Error decoding JSON from the config file: {config_path}")
        return None

def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="Command-line tool to install a cert and key in Tyan's BMC"
    )
    parser.add_argument(
        "--config",
        help="Path to the configuration file containing BMC details and credentials",
        default="config.json"
    )
    args = parser.parse_args()

    # Load configuration from the file
    config = load_config(args.config)
    if config is None:
        print("Invalid or missing configuration file. Please check the path and format.")
        return

    # Extract required arguments from the config
    bmc = config.get("bmc")
    username = config.get("username")
    password = config.get("password")
    cert_file = config.get("cert_file")
    key_file = config.get("key_file")
    insecure_startup = config.get("insecure_startup")
    aia_db = config.get("aia_db")

    aia_session = AIASession(url=f"https://{bmc}",cache_db="/tmp/cache.db")
    cadata = aia_session.cadata_from_url()  # Validated PEM certificate chain
    with NamedTemporaryFile("wb") as pem_file:
        pem_file.write(cadata)
        pem_file.flush()
        # Validate configuration fields
        if not all([bmc, username, password, cert_file, key_file]):
            print("Configuration file is missing required fields (bmc, username, password, cert_file, key_file).")
            return

        # Check if cert and key files exist
        try:
            cert_file_name = Path(cert_file).name
            key_file_name = Path(cert_file).name
            cert_file_pointer = open(cert_file, "rb")
            key_file_pointer = open(key_file, "rb")
        except FileNotFoundError:
            print(f"Certificate or key file not found")
            return 

        print(f"Connecting to BMC at {bmc}...")

        try:
            session = requests.Session()
            if (insecure_startup):
                session.verify = False  # WARNING: Skip verification (not secure)
                session.trust_env = False

            auth_url = f"https://{bmc}/api/session"
            auth_data = {
                "username": username,
                "password": password
            }

            # First request to get the CSRF token and cookies
            if (insecure_startup):
                print("Requesting insecure connection, only use this for initial runs")
                response = session.post(auth_url, data=auth_data)
            else: 
                response = session.post(auth_url, data=auth_data, verify=pem_file.name)
            response.raise_for_status()

            csrf_token = response.json().get("CSRFToken")
            if not csrf_token:
                print("Failed to retrieve CSRF token")
                return

            files = {
            "new_certificate": (cert_file_name, cert_file_pointer, "application/octet-stream"),
            "new_private_key": (key_file_name, key_file_pointer, "application/octet-stream"),
            }

            post_url = f"https://{bmc}/api/settings/ssl/certificate"
            update_headers = {
                "X-CSRFTOKEN": csrf_token,
            }

            # Send the prepared request
            if (insecure_startup):
                response = session.post(post_url, files=files, headers=update_headers)
            else: 
                response = session.post(post_url, files=files, headers=update_headers,verify=pem_file.name)

            response.raise_for_status()

            response_data = response.json()
            print(response_data)
            if response_data.get("cc") == 0:
                print("Certificate installation successful")
            else:
                print("Installation failed with unknown error")

        except requests.exceptions.RequestException as e:
            print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
