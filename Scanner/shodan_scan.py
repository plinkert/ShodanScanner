#!/usr/bin/env python
import argparse
import socket
import sys
import time
import os.path
import shodan
import config

##
### SEARCH PART
##


api = shodan.Shodan(config.SHODAN_API_KEY)
"""Shodan API key"""


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
        print('Error msg in phrase: %s' % exception)
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
        print('Error msg: %s' % exception)
        return None

##
### Data transform
##
def ip_list_creator(data):
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
        print('Error msg in ipListCreator: %s' % exception)
        return None


def ports_list_creator(ip_list):
    """
    Return IP and ports list from the JSON data returned from search_by_host based on IP list
    input: ip list
    output: dictionary {IP: [ports]}
    """
    port_dict = {}
    try:
        for ip in ip_list:
            data = search_by_host(ip)
            port_dict.update({data['ip_str']: data['ports']})
            time.sleep(1)
        return port_dict
    except Exception as exception:
        print('Error msg in port_list_creator: %s' % exception)
        return None


##
### Files 
##

def write_file(output, file_name = 'output.txt'):
    """
    Write data to txt file
    input_1: data to be writen to the file
    input_2: file name
    output: n/a
    """
    try:
        with open(file_name, 'w+') as file:
            #file.writelines('%s\n' % line for line in output_list)
            file.write(output)
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

##
### Data
##

def data_collector(list_of_str):
    """
    Collect IPs makeing search based on phrases in list_of_str
    input: List - searched phrased
    output: dictionary {IP: ports}
    """
    try:
        output = {}
        if type(list_of_str) == str: list_of_str = [list_of_str]
        for phrase in list_of_str:
            ip_list = ip_list_creator(search_by_phrase(phrase))
            output.update(ports_list_creator(ip_list))
        return output
    except Exception as exception:
        print('Error msg in data_collector: %s' % exception)
        return None
