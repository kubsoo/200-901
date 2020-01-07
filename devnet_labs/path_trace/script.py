import requests
from requests.auth import HTTPBasicAuth
import argparse


host = 'https://sandboxdnac.cisco.com'
username = 'devnetuser'
password = 'Cisco123!'
api_version = 'v1'

def get_token(host,username,password):
    url = '{}/api/system/{}/auth/token'.format(host,api_version)
    response = requests.post(url,auth=HTTPBasicAuth(username,password),verify=False)
    token = response.json()['Token']

    return token

if __name__ == "__main__":
    token = get_token(host,username,password)
    print(token)
    parser = argparse.ArgumentParser()
    parser.add_argument("source_ip", help = "Source IP Address")
    parser.add_argument("destination_ip", help = "Destination IP Address")

    args = parser.parse_args()

    #Get Source and Destination IPs from Command Line

    source_ip = args.source_ip
    destination_ip = args.destination_ip

    print(source_ip,destination_ip)

