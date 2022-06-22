#!/usr/bin/env python
import argparse
from doctest import OutputChecker
import socket
import sys
import time
import shodan
import config
#from sympy import re

### SEARCH PART

# Shodan API key
api = shodan.Shodan(config.SHODAN_API_KEY)

# Query by phrase, as a output return JSON with all data
def search_by_phrase(search_phrase):
    try:
        results = api.search(search_phrase)
        return results
    except shodan.APIError as exception:
        print('Error msg in phrase: %s' % exception)
        return 'n/a'

# Query by Host IP, as a output return JSON with all data about specyfic IP
def search_by_host(search_host):
    try:
        host_ip = socket.gethostbyname(search_host)
        results = api.host(host_ip)
        return results
    except shodan.APIError as exception:
        print('Error msg: %s' % exception)
        return 'n/a'

# Print IPs list from the JSON data returned from "search_by_phrase"
def print_ip(data):
    #print(data)
    try:
        for ip in data['matches']:
            print(ip['ip_str'])
    except Exception as exception:
        print('Error msg in printIP: %s' % exception)

# Print IPs with open ports
def print_ports(ip_list):
    try:
        for ip in ip_list:
            data = search_by_host(ip)
            print('IP: ', data['ip_str'])
            print('Ports: ', data['ports'])
            time.sleep(1)
    except Exception as exception:
        print('Error msg in printPorts: %s' % exception)

# Return IP list from the JSON data returned from "search_by_phrase"
def ip_list_creator(data):
    ip_list = []
    try:
        for ip in data['matches']:
            ip_list.append(ip['ip_str'])
        return ip_list
    except Exception as exception:
        print('Error msg in ipListCreator: %s' % exception)
        return ip_list

# Return IP and ports list from the JSON data returned from "search_by_host" based on IP list
def ports_list_creator(ip_list):
    port_list = []
    try:
        for ip in ip_list:
            data = search_by_host(ip)
            port_list.append([data['ip_str'], data['ports']])
            time.sleep(1)
        return port_list
    except Exception as exception:
        print('Error msg in port_list_creator: %s' % exception)
        return port_list


### I/O file part

def read_file(file_name = 'phrases.txt'):
    with open(file_name) as file:
        for line in file:
            print(line)

def output_file(output_list, file_name = 'output.txt'):
    with open(file_name, 'w') as file:
        file.writelines('%s\n' % line for line in output_list)

### Parser part

argParser = argparse.ArgumentParser(description= "Shodan search")

argParser.add_argument("--phrase", dest = "phrase", help = "Search phrase", required = None)
argParser.add_argument("--host", dest = "host", help = "Host IP or address", required = None)
#test
argParser.add_argument("--file", dest = "file", help = "Input file name", required = None)

parsed_args = argParser.parse_args()

if len(sys.argv) > 1 and sys.argv[1] == '--phrase':
    #printIP(phrase(parsed_args.phrase))
    list = ip_list_creator(search_by_phrase(parsed_args.phrase))
    print_ports(list)
    output_file(ports_list_creator(list))
if len(sys.argv) > 1 and sys.argv[1] == '--host':
    print_ip(search_by_host(parsed_args.host))
    read_file()
if len(sys.argv) > 1 and sys.argv[1] == '--file':
    read_file(parsed_args.file)
'''
def printer(mode, results):
    if results == 'n/a':
        print('No data available!')
    else:
        if mode == 'phrase':
            print('Findings: %s' % results['total'])
            for result in results['matches']:
                print('IP: %s' % result['ip_str'])
                print(result['data'])
        elif mode == 'host':
            print("""
                IP: %s
                Org: %s
                OS: %s        
            """ % (results['ip_str'], results.get('org', 'n/a'), results.get('os', 'n/a')))
            for result in results['data']:
                print("""
                    Port: %s
                    Baner: %s""" 
                    % (result['port'], result['data']))


argParser = argparse.ArgumentParser(description= "Shodan search")

argParser.add_argument("--host", dest = "host", help = "Host IP or address", required = None)
argParser.add_argument("--phrase", dest = "phrase", help = "Search phrase", required = None)
argParser.add_argument("--multiple", dest = "multiple", help = "Search info about all IPs with phrase", required = None)
parsed_args = argParser.parse_args()

if len(sys.argv) > 1 and sys.argv[1] == '--phrase':
    printer('phrase', phrase(parsed_args.phrase))
if len(sys.argv) > 1 and sys.argv[1] == '--host':
    printer('host', host(parsed_args.host))
if len(sys.argv) > 1 and sys.argv[1] == '--multiple':
    results = phrase(parsed_args.multiple)
    reportData = []
    hostsIP = []
    if results != 'n/a':
        for result in results['matches']:
            if not (result['ip_str'] in hostsIP):
                hostsIP.append(result['ip_str'])
                hostData = host(result['ip_str'])
                parsedData = report.parser(hostData)
                reportData.append(parsedData)
                printer('host', hostData)
                time.sleep(1)
    print(reportData)
    report.createReport(reportData)


'''