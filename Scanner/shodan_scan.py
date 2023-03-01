#!/usr/bin/env python
import argparse
import ipaddress
import os.path
import socket
import sys
import time
from ipaddress import ip_address
from mimetypes import init
from os import environ as env

import shodan
from dotenv import load_dotenv

# Shodan API key
load_dotenv()
api = shodan.Shodan(env['API_KEY'])

def search_by_phrase(search_phrase):
    """
    Query by phrase, as a output return JSON with all data
    input: string
    output: shodan raw data (JSON)
    """
    try:
        results = api.search(search_phrase)
        return results
    except shodan.APIError as exception:
        print('Error msg in search_by_phrase: %s' % exception)
        return None

def search_by_host(search_host):
    """
    Query by Host IP, as a output return JSON with all data about specyfic IP
    input: host name/IP 
    output: shodan raw data (JSON) 
    """
    try:
        host_ip = socket.gethostbyname(search_host)
        results = api.host(host_ip)
        return results
    except shodan.APIError as exception:
        print('Error msg in search_by_host: %s, %s' % (exception, host_ip))
        return None

def json_to_ip_list(data):
    """
    Return IP list from the JSON data returned from search_by_phrase, only unique value
    input: Shodan raw data (JSON)
    output: list IPs
    """
    ip_list = []
    try:
        for ip in data['matches']:
            if ip['ip_str'] not in ip_list:
                ip_list.append(ip['ip_str']) 
        return ip_list
    except Exception as exception:
        print('Error msg in ip_list: %s' % exception)
        return None


def create_ip_data_dict(ip_list):
    """
    Return IP and ports list from the JSON data returned from search_by_host based on IP list
    input: ip list
    output: dictionary {IP: [ports]}
    """
    port_dict = {}
    raw_dict = {}
    try:
        for ip in ip_list:
            if (ipaddress.ip_address(ip).version != 4):
                port_dict.update({ip: 'None'})
                raw_dict.update({ip: 'None'})
            else:
                data = search_by_host(ip)
                if data:
                    port_dict.update({data['ip_str']: data['ports']})
                    raw_dict.update({ip: data})
                else:
                    port_dict.update({ip: 'None'})
                    raw_dict.update({ip: 'None'})
            time.sleep(1)
        return port_dict, raw_dict
    except Exception as exception:
        print('Error msg in port_list_creator: %s' % exception)
        return None, None

def str_to_ip_list(phrase_list):
    """
    Return IP list from the list(phrase)
    input: list(phrase)
    output: list IPs
    """
    try:
        output = []
        if type(phrase_list) == str: list_of_str = [phrase_list]
        else: list_of_str = phrase_list
        for phrase in list_of_str:
            ip_list = json_to_ip_list(search_by_phrase(phrase))
            output += ip_list
        return output
    except Exception as exception:
        print('Error msg in str_to_ip_list: %s' % exception)
        return None

def write_file(output, file_name = 'output.txt'):
    """
    Write data to txt file
    input_1: data to be writen to the file
    input_2: file name
    output: n/a
    """
    try:
        output_list = []
        if type(output) == dict:
            for key in output:
                output_list.append([key, output[key]])
        else:
            output_list = output
        with open(file_name, 'w+') as file:
            file.writelines('%s\n' % line for line in output_list)
    except Exception as exception:
        print('Error msg in write_file: %s' % exception)

def read_file(file_name = 'output.txt'):
    """
    Read file with phrases to query
    input: file name
    output: string from file
    """
    try:
        if os.path.exists(file_name):
            with open(file_name, "r") as file:
                return file.read()
    except Exception as exception:
        print('Error msg in read_file: %s' % exception)
        return None

def if_ip(address):
    """
    Checks if the given string is an IPv4 address
    input: string (ip)
    output: string (ip)
    """
    try:
        ip = ipaddress.ip_address(address)
        return address
    except:
        return None


def data_compare(new_data, old_data):
    """
    Compare two dictionaries with IP:ports data
    input: new and old dictionary with IP:ports
    output:
        added: List of new founded IPs 
        removed: List of removed IPs
        modified: Dict of changed ports - {'IP': [new ports, old ports]}
        same: List of the same IPs wit the same ports
    """
    try:
        new_keys = set(new_data.keys())
        old_keys = set(old_data.keys())
        shared_keys = new_keys.intersection(old_keys)
        added = new_keys - old_keys
        removed = old_keys - new_keys
        modified = {o: (new_data[o], old_data[o]) for o in shared_keys if new_data[o] != old_data[o]}
        same = set(o for o in shared_keys if new_data[o] == old_data[o])
        return added, removed, modified, same
    except Exception as exception:
        print('Error msg in data_compare: %s' % exception)
        return None, None, None, None


def print_ips_info(ip_dict):
    """
    Printout of ip addresses and ports in the console
    input: dict{ip:ports}
    """
    for ip in ip_dict:
        print(f'IP: {ip}')
        print(f'Ports: {ip_dict[ip]}')


parser = argparse.ArgumentParser(prog='shodan_scan',
                                description='Script to query data from Shodan based on host IP or typed phrase')

parser.add_argument('-iH', action='append', type=str, nargs='+', help='set the host IP ADDRESS (one or more) separating them with a space')
parser.add_argument('-iP', action='append', type=str, nargs='+', help='set the searched PHRASE (one or more) separating them with a space')
parser.add_argument('-iF', action='store', type=str, nargs=1, help='set the name of the FILE containing the phrases to be searched')
parser.add_argument('-oP', action='store_true', help='if selected, the IP addresses and ports found during the search will be listed on the screen')
parser.add_argument('-oR', action='store_true', help='if selected, the raw data found during the search will be printed on the screen')
parser.add_argument('-oF', action='store', type=str, nargs=1, default='output.txt', help='set the name of the file that will contain the output: IPs and ports')
parser.add_argument('-c', action='store_true', help='if selected, the data from the previous search will be compared with the new ones (requires an output file that also contains old data)')

args = parser.parse_args()

ip_list = []

if args.iH:
    ip_list += args.iH[0]
if args.iP:
    ip_list += str_to_ip_list(args.iP[0])
if args.iF:
    temp_file_list = read_file(args.iF[0]).split()
    for ip in temp_file_list:
        if if_ip(ip):
            ip_list += [ip]
        else:
            ip_list += str_to_ip_list(ip)


ip_dict, raw_dict = create_ip_data_dict(ip_list)
if args.oP:
    print_ips_info(ip_dict)
if args.oR:
    for key in raw_dict:
        print('IP: ', key)
        print(raw_dict[key])
if args.oF:
        write_file(ip_dict)
