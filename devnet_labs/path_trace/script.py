import requests
from requests.auth import HTTPBasicAuth
import argparse


host = 'https://sandboxdnac.cisco.com'
username = 'devnetuser'
password = 'Cisco123!'
api_version = 'v1'

def get_token(host,username,password,api_version):
    url = '{}/api/system/{}/auth/token'.format(host,api_version)
    response = requests.post(url,auth=HTTPBasicAuth(username,password),verify=False)
    token = response.json()['Token']

    return token


def get_host(host,token,api_version):
    url = '{}/api/{}/host'.format(host,api_version)
    headers = {
        "x-auth-token":token
    }
    response = requests.get(url,headers=headers,verify=False)
    print(response.text)

    return response

if __name__ == "__main__":
    token = get_token(host,username,password,api_version)
    print(token)
    parser = argparse.ArgumentParser()
    parser.add_argument("source_ip", help = "Source IP Address")
    parser.add_argument("destination_ip", help = "Destination IP Address")

    args = parser.parse_args()

    #Get Source and Destination IPs from Command Line

    source_ip = args.source_ip
    destination_ip = args.destination_ip

    print(source_ip,destination_ip)


    get_host(host,token,api_version)