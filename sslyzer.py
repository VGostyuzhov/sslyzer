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
COMMON_PRIMES_FILE = 'data/common_primes.txt'
PFS_CIPHERS_FILE = 'data/pfs_ciphers.txt'

class ConnectionError(Exception):
    pass

def analyze_ciphers(server, common_primes, pfs_ciphers):  
    """ """
    for protocol, ciphers in server['cipher_suites'].iteritems():
        for cipher in ciphers:
            cipher['RC4']  = bool('RC4' in cipher['name'])
            cipher['DES']  = bool('DES' in cipher['name'])
            cipher['anon'] = bool('anon' in cipher['name'])
            cipher['MD5']  = bool('MD5' in cipher['name'])
            cipher['SHA1'] = bool('SHA_' in cipher['name'] or cipher['name'].endswith('SHA'))
            cipher['DH'] = {'dh_export': False, 'common_prime': False, 'groupsize' : '--'}
            cipher['PFS'] = bool('DHE' in cipher['name'])
            if 'dh_info' in cipher:                
                cipher['DH']['dh_export'] = bool(cipher['dh_info']['type'] == 'DH' and int(cipher['dh_info']['groupsize']) <= 1024)
                cipher['DH']['common_prime'] = bool(cipher['dh_info']['prime'] in common_primes)
                cipher['DH']['groupsize'] = cipher['dh_info']['groupsize']

def check_Beast(server):
    protocols = {key: server['cipher_suites'][key] for key in ['SSLv3.0', 'TLSv1.0']}
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

def ServerConsoleOutput(server):
    #print('Heartbleed: ' + colored((server['vulners']['heartbleed']), 'green'))
    yes_no = {False: 'No', True: 'Yes'}    
    for protocol, ciphers in server['cipher_suites'].iteritems():
        if len(ciphers):
            print(protocol)
            print(colored(BOLD + '{0:<36}{1:<5}{2:<5}{3:<6}{4:<6}{5:<5}{6:<5}{7:<10}{8:<14}{9:<5}{10:<11}'.format(
                'Cipher', 'RC4', 'MD5', 'SHA1', 'DES', 'Anon', 'PFS', 'Key Size', 'DH Group Size', 'DHE', 'Common Prime') + ENDBOLD, 'white'))
            for cipher in ciphers:
                print('{0:<36}{1:<5}{2:<5}{3:<6}{4:<6}{5:<5}{6:<5}{7:<10}{8:<14}{9:<5}{10:<11}'.format(
                    cipher['name'], yes_no[cipher['RC4']], yes_no[cipher['MD5']], yes_no[cipher['SHA1']], yes_no[cipher['DES']], yes_no[cipher['anon']],
                    yes_no[cipher['PFS']], cipher['key_size'], cipher['DH']['groupsize'], yes_no[cipher['DH']['dh_export']], yes_no[cipher['DH']['common_prime']]))
            print('------------------------------------------------------------------------------------------------------------')
    
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
    
    with open(PFS_CIPHERS_FILE, 'rb') as pfs_file:
        pfs_ciphers = [l.strip() for l in pfs_file.readlines()]
    with open(COMMON_PRIMES_FILE, 'rb') as cp_file:
        common_primes = [p.strip().lower() for p in cp_file.readlines()]

    servers = []
    error_servers = []
    i = 1
    for hostname in hostnames:
        print(colored('Host {3} of {4}: {0}{1}{2}'.format(BOLD, hostname, ENDBOLD, i, len(hostnames)), 'cyan'))
        i += 1
        server = scan.scan_server(hostname)       
        if 'error' in server:
            error_servers.append({'hostname': hostname, 'error': server['error']})
            continue
        else:
            analyze_ciphers(server, common_primes, pfs_ciphers)
            #server = check_vulners(server)
            servers.append(server)
            sys.stdout.write(colored(BOLD + 'OK!\n\n'.format(hostname) + ENDBOLD, 'green'))
            ServerConsoleOutput(server)
    if args.xlsx_file:
        filename = 'reports/' + args.xlsx_file
        report.excel_report(servers, filename)
    else:
        #pprint(servers)
        pprint(error_servers)