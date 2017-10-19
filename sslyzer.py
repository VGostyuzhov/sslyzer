#!/usr/bin/python2
# -*- coding: utf-8 -*-
#Import standard libraries
import os
import sys
import argparse
import json
from pprint import pprint

#Import Python packages
from termcolor import colored

from modules import scan, report

BOLD = '\033[1m'
ENDBOLD = '\033[0m'

class ConnectionError(Exception):
    pass

def get_weak_ciphers(server):
    rc4_ciphers = []
    des_ciphers = []
    anon_ciphers = []
    weak_hash_ciphers = []
    dh_export_ciphers = []
    common_primes_ciphers = []
    #with open('common_primes.json', 'rb') as cp_file:
    #    lines = [l.strip() for l in cp_file.readlines()]
    #    json_primes = [json.loads(j) for j in lines]
    #    common_primes = [p['prime'].lower() for p in json_primes]

    for protocol, ciphers in server['cipher_suites'].iteritems():
        for cipher in ciphers:
            cipher = cipher['cipher']
            if 'RC4' in cipher and cipher not in rc4_ciphers:
                rc4_ciphers.append(cipher)
            if (('MD5' or 'SHA-') in cipher or cipher.endswith('SHA')) and cipher not in weak_hash_ciphers:
                weak_hash_ciphers.append(cipher)
            if 'DES' in cipher and cipher not in des_ciphers:
                des_ciphers.append(cipher)
            if 'anon' in cipher and cipher not in anon_ciphers:
                anon_ciphers.append(cipher)
            if 'dh_info' in cipher:
                if cipher['dh_info']['Type'] == 'DH' and int(cipher['dh_info']['GroupSize']) <= 1024:
                    if cipher not in dh_export_ciphers:
                        dh_export_ciphers.append(cipher)
                print(cipher['dh_info']['prime'])
                #if prime in common_primes:
                #    common_primes_ciphers.appned(cipher)
    return {'rc4': rc4_ciphers, 'des': des_ciphers, 'dh_export': dh_export_ciphers, 'weak_hash': weak_hash_ciphers, 'anon_ciphers': anon_ciphers, 'common_primes_ciphers': common_primes_ciphers}

def check_Beast(server):
    protocols = {key: server['cipher_suites'][key] for key in ['sslv30', 'tlsv10']}
    for protocol, ciphers in protocols.iteritems():
        for cipher in ciphers:
            if 'CBC' in cipher['cipher']:
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
        server['weak_ciphers'] = get_weak_ciphers(server)
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