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


def get_host(host,token,api_version,ip=None,mac=None,name=None):
    url = '{}/api/{}/host'.format(host,api_version)
    headers = {
        "x-auth-token":token
    }
    
    params = {
        "hostIp" : ip,
        "hostMac" : mac,
        "hostName" : name
    }

    response = requests.get(url,headers=headers,verify=False,params=params)
    
    r = response.json()["response"][0]

    return r


def get_network_devices(host,token,api_version,ip=None):
    url = '{}/api/{}/network-device'.format(host,api_version)
    headers = {
        "x-auth-token":token
    }

    params = {
        "managementIpAddress" :ip
    }

    response = requests.get(url,headers=headers,params=params,verify=False)
    r = response.json()["response"][0]

    return r   


def get_interface(host,token,api_version,id):
    url = '{}/api/{}/interface/{}'.format(host,api_version,id)
    headers = {
        "x-auth-token":token
    }

    #params = {
    #    "managementIpAddress" :ip
    #}

    response = requests.get(url,headers=headers,verify=False)
    print(response.text)
    #r = response.json()["response"][0]

    return response  

def flow_analysis(host,token,api_version,source_ip,destination_ip):
    url = '{}/api/{}/flow-analysis'.format(host,api_version)
    headers = {
        "x-auth-token":token
    }
    
    params = {
        "sourceIP" : source_ip, 
        "destIP" : destination_ip
     }

    response = requests.post(url,headers=headers,params=params,verify=False)
    r = response.json()["response"][0]
    print(r)
    return r


def print_host_details(host):
    """
    Print to screen interesting details about a given host.
    Input Paramters are:
      host_desc: string to describe this host.  Example "Source"
      host: dictionary object of a host returned from APIC-EM
    Standard Output Details:
      Host Name (hostName) - If available
      Host IP (hostIp)
      Host MAC (hostMac)
      Network Type (hostType) - wired/wireless
      Host Sub Type (subType)
      VLAN (vlanId)
      Connected Network Device (connectedNetworkDeviceIpAddress)

    Wired Host Details:
      Connected Interface Name (connectedInterfaceName)

    Wireless Host Details:
      Connected AP Name (connectedAPName)
    """
    if "hostName" not in host.keys():
        print("Host Name: Unavailable")
    else:    
        print("Host Name: {}".format(host["hostName"]))
    print("Network Type: {}".format(host["hostType"]))
    print("Connected Network Device: {}".format(host["connectedNetworkDeviceIpAddress"]))

    if host["hostType"] == "wired":
        print("Connected Interface Name: {}".format(host["connectedInterfaceName"]))  # noqa: E501
    if host["hostType"] == "wireless":
        print("Connected AP Name: {}".format(host["connectedAPName"]))

    print("VLAN: {}".format(host["vlanId"]))
    print("Host IP: {}".format(host["hostIp"]))
    print("Host MAC: {}".format(host["hostMac"]))
    print("Host Sub Type: {}".format(host["subType"]))

def print_network_device_details(network_device):
    """
    Print to screen interesting details about a network device.
    Input Paramters are:
      network_device: dict object of a network device returned from APIC-EM
    Standard Output Details:
      Device Hostname (hostname)
      Management IP (managementIpAddress)
      Device Location (locationName)
      Device Type (type)
      Platform Id (platformId)
      Device Role (role)
      Serial Number (serialNumber)
      Software Version (softwareVersion)
      Up Time (upTime)
      Reachability Status (reachabilityStatus)
      Error Code (errorCode)
      Error Description (errorDescription)
    """

    # Print Standard Details
    print("Device Hostname: {}".format(network_device["hostname"]))
    print("Management IP: {}".format(network_device["managementIpAddress"]))
    print("Device Location: {}".format(network_device["locationName"]))
    print("Device Type: {}".format(network_device["type"]))
    print("Platform Id: {}".format(network_device["platformId"]))
    print("Device Role: {}".format(network_device["role"]))
    print("Serial Number: {}".format(network_device["serialNumber"]))
    print("Software Version: {}".format(network_device["softwareVersion"]))
    print("Up Time: {}".format(network_device["upTime"]))
    print("Reachability Status: {}".format(network_device["reachabilityStatus"]))  # noqa: E501
    print("Error Code: {}".format(network_device["errorCode"]))
    print("Error Description: {}".format(network_device["errorDescription"]))

def print_interface_details(interface):
    """
    Print to screen interesting details about an interface.
    Input Paramters are:
      interface: dictionary object of an interface returned from APIC-EM
    Standard Output Details:
      Port Name - (portName)
      Interface Type (interfaceType) - Physical/Virtual
      Admin Status - (adminStatus)
      Operational Status (status)
      Media Type - (mediaType)
      Speed - (speed)
      Duplex Setting (duplex)
      Port Mode (portMode) - access/trunk/routed
      Interface VLAN - (vlanId)
      Voice VLAN - (voiceVlan)
    """

    # Print Standard Details
    print("Port Name: {}".format(interface["portName"]))
    print("Interface Type: {}".format(interface["interfaceType"]))
    print("Admin Status: {}".format(interface["adminStatus"]))
    print("Operational Status: {}".format(interface["status"]))
    print("Media Type: {}".format(interface["mediaType"]))
    print("Speed: {}".format(interface["speed"]))
    print("Duplex Setting: {}".format(interface["duplex"]))
    print("Port Mode: {}".format(interface["portMode"]))
    print("Interface VLAN: {}".format(interface["vlanId"]))
    print("Voice VLAN: {}".format(interface["voiceVlan"]))


if __name__ == "__main__":
    token = get_token(host,username,password,api_version)
    parser = argparse.ArgumentParser()
    parser.add_argument("source_ip", help = "Source IP Address")
    parser.add_argument("destination_ip", help = "Destination IP Address")

    args = parser.parse_args()

    #Get Source and Destination IPs from Command Line

    source_ip = args.source_ip
    destination_ip = args.destination_ip

  # print(source_ip,destination_ip)

   # mac = "00:1e:13:a5:b9:40"

    #list_host = get_host(host,token,api_version)

    #print(list_host)

    source_host = get_host(host,token,api_version,ip=source_ip)
    print("Source Host Details:\n-------------------------")
    print_host_details(source_host)
    print("\n\n")

    source_network_device_ip = source_host["connectedNetworkDeviceIpAddress"]
    source_interface_id = source_host["connectedInterfaceId"]
    destination_host = get_host(host,token,api_version,ip=destination_ip)
    print("Destination Host Details:\n-------------------------")
    print_host_details(destination_host)
    print("\n\n")

    destination_network_device_ip = destination_host["connectedNetworkDeviceIpAddress"]
    desination_interface_id = destination_host["connectedInterfaceId"]
    source_network_device=get_network_devices(host,token,api_version,ip=source_network_device_ip)
    print("Source Host Network Connection Details:\n---------------------------------------------")
    print_network_device_details(source_network_device)
    print("\n\n")    

    destination_network_device=get_network_devices(host,token,api_version,ip=destination_network_device_ip)
    print("Destination Host Network Connection Details:\n---------------------------------------------")
    print_network_device_details(destination_network_device)
    print("\n\n")    


    a = get_interface(host,token,api_version,desination_interface_id)
    print(a)
    #b = get_host(host,token,api_version,ip=source_ip)
    #print(b)

    #flow_analysis(host,token,api_version,source_ip,destination_ip)