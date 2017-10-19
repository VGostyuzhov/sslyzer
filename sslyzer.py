#!/usr/bin/python2
# -*- coding: utf-8 -*-
import os
import sys
import argparse
import json
from pprint import pprint
from termcolor import colored

from modules import scan, report

BOLD = '\033[1m'
ENDBOLD = '\033[0m'

class ConnectionError(Exception):
    pass

def analyze_ciphers(server):
    weak_ciphers = {'rc4': [], 'DES': [], 'dh_export': [], 'weak_hash': [], 'anon': [], 'common_primes': []}
    with open('data/common_primes.json', 'rb') as cp_file:
        lines = [l.strip() for l in cp_file.readlines()]
        json_primes = [json.loads(j) for j in lines]
        common_primes = [p['prime'].lower() for p in json_primes]

    for protocol, ciphers in server['cipher_suites'].iteritems():
        for cipher in ciphers:
            if 'RC4' in cipher['name'] and cipher['name'] not in weak_ciphers['rc4']:
                weak_ciphers['rc4'].append(cipher['name'])
            if (('MD5' or 'SHA_') in cipher['name'] or cipher['name'].endswith('SHA')) and cipher['name'] not in weak_ciphers['weak_hash']:
                weak_ciphers['weak_hash'].append(cipher['name'])
            if 'DES' in cipher['name'] and cipher['name'] not in weak_ciphers['DES']:
                weak_ciphers['DES'].append(cipher['name'])
            if 'anon' in cipher['name'] and cipher['name'] not in weak_ciphers['anon']:
                weak_ciphers['anon'].append(cipher['name'])
            if 'dh_info' in cipher:
                if cipher['dh_info']['type'] == 'DH' and int(cipher['dh_info']['groupsize']) <= 1024:
                    if cipher['name'] not in weak_ciphers['dh_export']:
                        weak_ciphers['dh_export'].append(cipher['name'])
                if cipher['dh_info']['prime'] in common_primes and cipher['name'] not in weak_ciphers['common_primes']:
                    weak_ciphers['common_primes'].append(cipher['name'])
    return weak_ciphers

def check_Beast(server):
    protocols = {key: server['cipher_suites'][key] for key in ['sslv30', 'tlsv10']}
    for protocol, ciphers in protocols.iteritems():
        for cipher in ciphers:
            if 'CBC' in cipher['name']:
                return True
    return False

def check_Freak(server):
    export_rsa_ciphers = ['EXP1024-DES-CBC-SHA', 'EXP1024-RC2-CBC-MD5', 'EXP1024-RC4-SHA', 'EXP1024-RC4-MD5', 
    'EXP-EDH-RSA-DES-CBC-SHA', 'EXP-DH-RSA-DES-CBC-SHA', 'EXP-DES-CBC-SHA', 'EXP-RC2-CBC-MD5', 'EXP-RC4-MD5']
    for protocol, ciphers in server['cipher_suites'].iteritems():
        for cipher in ciphers:
            if cipher in export_rsa_ciphers:
                return True
    return False

def check_vulners(server):
    server['vulners']['poodle'] = server['sslv30']
    server['vulners']['drown'] = server['sslv20']
    server['vulners']['rc4'] = bool(len(server['weak_ciphers']['rc4']))
    server['vulners']['logjam'] = bool(len(server['weak_ciphers']['dh_export']))
    server['vulners']['beast'] = check_Beast(server)
    server['vulners']['freak'] = check_Freak(server)
    server['vulners']['crime'] = bool(server['compression'])
    server['vulners']['downgrade'] = server['fallback_scsv']
    server['vulners']['dh_common_primes'] = bool(len(server['weak_ciphers']['common_primes']))
    return server

def parseArguments():
    parser = argparse.ArgumentParser(description='Test multiple hosts for SSL vulnerabilities and misconfigurations using sslyze library')
    parser.add_argument('-f', '--file', dest='input_file', help='File containing input hostnames', metavar='FILENAME')
    parser.add_argument('-x', '--xlsx', dest='xlsx_file', help='Save report to .xlsx file', metavar='FILENAME')
    parser.add_argument('hostname', nargs='?', help='Single hostname to scan')
    return parser.parse_args()

if __name__ == '__main__':
    args = parseArguments()

    hostnames = []
    if args.input_file:
        with open(args.input_file, 'rb') as input_file:
            hostnames = [h.strip() for h in input_file.readlines()]
    elif args.hostname:
        hostnames.append(args.hostname)
    else:
        parser.print_help()
        sys.exit(0)

    servers = []
    error_servers = []
    i = 1
    for hostname in hostnames:
        print(colored('Host {3} of {4}: {0}{1}{2}'.format(BOLD, hostname, ENDBOLD, i, len(hostnames)), 'cyan'))
        i += 1
        server = scan.scan_server(hostname)
        server['weak_ciphers'] = analyze_ciphers(server)
        server = check_vulners(server)
        if 'error' in server:
            error_servers.append({'hostname': hostname, 'error': server['error']})
            continue
        else:
            servers.append(server)
            sys.stdout.write(colored(BOLD + 'OK!\n\n'.format(hostname) + ENDBOLD, 'green'))
    
    if args.xlsx_file:
        filename = 'reports/' + args.xlsx_file
        report.excel_report(servers, filename)
    else:
        pprint(servers)
        pprint(error_servers)