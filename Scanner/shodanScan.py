#!/usr/bin/env python
import config
import shodan
import argparse
import socket
import sys

api = shodan.Shodan(config.SHODAN_API_KEY)

def phrase(searchPhrase):
    try:
        results = api.search(searchPhrase)
#        print('Findings: %s' % results['total'])
#        for result in results['matches']:
#            print('IP: %s' % result['ip_str'])
#            print(result['data'])
        return results
    except shodan.APIError as exception:
        print('Error msg: %s' % exception)
        return 'n/a'

def host(searchHost):
    try:
        hostIP = socket.gethostbyname(searchHost)
        results = api.host(hostIP)
 #       print("""
 #               IP: %s
 #               Org: %s
 #               OS: %s        
 #       """ % (results['ip_str'], results.get('org', 'n/a'), results.get('os', 'n/a')))
 #       for result in results['data']:
 #           print("""
 #               Port: %s
 #               Baner: %s""" 
 #               % (result['port'], result['data']))
        return results
    except shodan.APIError as exception:
        print('Error msg: %s' % exception)
        return 'n/a'

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
parsed_args = argParser.parse_args()

if len(sys.argv) > 1 and sys.argv[1] == '--phrase':
    printer('phrase', phrase(parsed_args.phrase))
if len(sys.argv) > 1 and sys.argv[1] == '--host':
    printer('host', host(parsed_args.host))