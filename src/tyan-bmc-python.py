import argparse
import requests
import json
from pathlib import Path

def main():
    parser = argparse.ArgumentParser(
        description="Command-line tool to install a cert and key in Tyan's BMC"
    )
    parser.add_argument("bmc", help="FQDN or address of BMC")
    parser.add_argument("username", help="BMC username with sufficient rights to update cert")
    parser.add_argument("password", help="Password of user with sufficient rights to update cert")
    parser.add_argument("filename", help="Filename of cert file in PEM format")
    parser.add_argument("keyfile", help="Filename of key file in PEM format")
    
    args = parser.parse_args()

    bmc = args.bmc
    print(f"Calling {bmc}...")

    session = requests.Session()
    session.verify = False  # Disable certificate verification (dangerous, avoid in production)

    auth_url = f"https://{bmc}/api/session"
    auth_data = {
        "username": args.username,
        "password": args.password
    }

    auth_headers = {
        "Connection": "keep-alive",
        "Accept": "application/json, text/javascript, */*; q=0.01",
        "Host": bmc,
        "Origin": f"https://{bmc}",
        "Referer": f"https://{bmc}",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"
    }

    # Authenticate and get CSRF token
    response = session.post(auth_url, data=auth_data, headers=auth_headers)
    if response.status_code != 200:
        print(f"Not authenticated: {response.status_code}")
        return
    
    csrf_token = response.json().get("CSRFToken")
    if not csrf_token:
        print("Failed to retrieve CSRF token")
        return

    # Prepare certificate and key files
    with open(args.filename, "r") as cert_file:
        cert_data = cert_file.read()
    with open(args.keyfile, "r") as key_file:
        key_data = key_file.read()

    cert_name = Path(args.filename).name
    key_name = Path(args.keyfile).name

    files = {
        "new_certificate": (cert_name, cert_data, "application/octet-stream"),
        "new_private_key": (key_name, key_data, "application/octet-stream")
    }

    post_url = f"https://{bmc}/api/settings/ssl/certificate"
    update_headers = {
        "X-CSRFTOKEN": csrf_token,
        "X-Requested-With": "XMLHttpRequest",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Host": bmc,
        "Origin": f"https://{bmc}",
        "Referer": f"https://{bmc}"
    }

    response = session.post(post_url, files=files, headers=update_headers)
    if response.status_code != 200:
        print(f"Failed to update certificate: {response.status_code}")
        return

    response_data = response.json()
    if response_data.get("cc") == "0":
        print("Success")
    else:
        print("Unknown failure")

if __name__ == "__main__":
    main()
