#!/usr/bin/python2
# -*- coding: utf-8 -*-

# Standard modules
import argparse
import json
import os
import sys
# Third-party modules
from pprint import pprint
from termcolor import colored
# Custom modules
from modules.report import server_console_output, excel_report
from modules.scan import scan_server
from modules.styles import Colors

COMMON_PRIMES_FILE = 'data/common_primes.txt'

def enrich_ciphers(server, common_primes):
    """ """
    for protocol, ciphers in server['cipher_suites'].iteritems():
        if 'Error' in ciphers:
            continue
        for cipher in ciphers:
            ci_name = cipher['name']
            cipher['RC4'] = bool('RC4' in ci_name)
            cipher['DES'] = bool('DES' in ci_name)
            cipher['anon'] = bool('anon' in ci_name)
            cipher['MD5'] = bool('MD5' in ci_name)
            # SHA1
            check_sha1 = 'SHA_' in ci_name or ci_name.endswith('SHA')
            cipher['SHA1'] = bool(check_sha1)
            cipher['PFS'] = bool('DHE' in ci_name)
            # Set default 'False' or '--' for DH params, as not every cipher 'DH'.
            # It will be overriden in case if cipher has 'dh_info' block.
            cipher.update({'DH_export': False, 'DH_common_prime': False, 'DH_GroupSize': '--', 'DH_weak': False, 'DH_insecure': False})
            # If cipher has 'DH' algorithm in cipher suite, let's analyze it's params.
            if 'dh_info' in cipher:
                if cipher['dh_info']['Type'] == 'DH':
                    cipher['DH_GroupSize'] = cipher['dh_info']['GroupSize']
                    cipher['DH_export'] = bool(int(cipher['DH_GroupSize']) <= 1024)
                    cipher['DH_common_prime'] = bool(cipher['dh_info']['prime'] in common_primes)
                    cipher['DH_weak'] = bool(int(cipher['DH_GroupSize']) == 1024)
                    cipher['DH_insecure'] = bool(int(cipher['DH_GroupSize']) < 1024)
    return server


def check_beast(server):
    """"""
    protocols = {key: server['cipher_suites'][key] for key in ['SSLv3.0', 'TLSv1.0']}
    for protocol, ciphers in protocols.iteritems():
        if 'Error' in ciphers:
            continue
        for cipher in ciphers:
            if 'CBC' in cipher['name']:
                return True
    return False


def check_freak(server):
    """"""
    export_rsa_ciphers = ['EXP1024-DES-CBC-SHA', 'EXP1024-RC2-CBC-MD5', 'EXP1024-RC4-SHA',
                          'EXP1024-RC4-MD5', 'EXP-EDH-RSA-DES-CBC-SHA', 'EXP-DH-RSA-DES-CBC-SHA',
                          'EXP-DES-CBC-SHA', 'EXP-RC2-CBC-MD5', 'EXP-RC4-MD5']
    for protocol, ciphers in server['cipher_suites'].iteritems():
        if 'Error' in ciphers:
            continue
        for cipher in ciphers:
            if cipher in export_rsa_ciphers:
                return True
    return False


def get_ciphers_param(protocols, key):
    """"""
    for protocol, ciphers in protocols.iteritems():
        if 'Error' in ciphers:
            continue
        key_list = [cipher[key] for cipher in ciphers]
        if True in key_list:
            return True
    return False


def check_vulners(server):
    """ """
    if server['SSLv3.0'] == 'Error':
        server['vulners']['poodle'] = 'Error'
    else:
        server['vulners']['poodle'] = server['SSLv3.0']

    if server['SSLv2.0'] == 'Error':
        server['vulners']['drown'] = server['SSLv2.0']
    else:
        server['vulners']['drown'] = server['SSLv2.0']

    server['vulners']['beast'] = check_beast(server)
    server['vulners']['freak'] = check_freak(server)

    if server['compression'] == 'Error':
        server['vulners']['crime'] = 'Error'
    else:
        server['vulners']['crime'] = bool(server['compression'])

    if server['fallback_scsv'] == 'Error':
        server['vulners']['downgrade'] = 'Error'
    else:
        server['vulners']['downgrade'] = not server['fallback_scsv']

    server['vulners']['RC4'] = get_ciphers_param(server['cipher_suites'], 'RC4')
    server['vulners']['logjam'] = get_ciphers_param(server['cipher_suites'], 'DH_export')
    server['DH_params'] = {}
    server['DH_params']['DH_common_prime'] = get_ciphers_param(server['cipher_suites'], 'DH_common_prime')
    server['DH_params']['DH_weak'] = get_ciphers_param(server['cipher_suites'], 'DH_weak')
    server['DH_params']['DH_insecure'] = get_ciphers_param(server['cipher_suites'], 'DH_insecure')
    server['PFS'] = get_ciphers_param(server['cipher_suites'], 'PFS')
    md5 = get_ciphers_param(server['cipher_suites'], 'MD5')
    des = get_ciphers_param(server['cipher_suites'], 'DES')
    dh_export = get_ciphers_param(server['cipher_suites'], 'DH_export')
    if md5 or des or dh_export:
        server['weak_ciphers'] = True
    else:
        server['weak_ciphers'] = False
    server['insecure_ciphers'] = get_ciphers_param(server['cipher_suites'], 'anon')
    return server


def sslyzer(hostnames, timeout=5):
    # Load list of common primes from file
    with open(COMMON_PRIMES_FILE, 'rb') as cp_file:
        common_primes = [p.strip().lower() for p in cp_file.readlines()]
    # Initialize lists for results and servers with errors
    servers = []
    error_servers = []
    for index, hostname in enumerate(hostnames, 1):
        print(colored('Host {3} of {4}: {0}{1}{2}'.format(Colors.BOLD, hostname, Colors.ENDBOLD, index, len(hostnames)), 'cyan'))
        # Run sslyze scan commands, get server dict
        server = scan_server(hostname, timeout)
        if 'error' in server:
            error_servers.append({'hostname': hostname, 'error': server['error']})
            # continue
        else:
            # Enrich server's cipher suites with 
            enriched_server = enrich_ciphers(server, common_primes)
            vulners_server = check_vulners(enriched_server)
            servers.append(vulners_server)
            sys.stdout.write(colored(Colors.BOLD + 'OK!\n\n'.format(hostname) + Colors.ENDBOLD, 'green'))
            if args.wide:
                server_console_output(server)
    return servers, error_servers


def parse_arguments():
    parser = argparse.ArgumentParser(description='Test multiple hosts for SSL vulnerabilities and misconfigurations using sslyze library')
    parser.add_argument('-f', '--file', dest='input_file', help='File containing input hostnames', metavar='FILENAME')
    parser.add_argument('-x', '--xlsx', dest='xlsx_file', help='Save report to .xlsx file', metavar='FILENAME')
    parser.add_argument('-w', '--wide', action='store_true', help='Wide output for each server')
    parser.add_argument('hostname', nargs='?', help='Single hostname to scan')
    return parser.parse_args()


if __name__ == '__main__':
    args = parse_arguments()
    # Load list of hostnames from file or positional argument
    hostnames = []
    if args.input_file:
        with open(args.input_file, 'rb') as input_file:
            hostnames = [h.strip() for h in input_file.readlines()]
    elif args.hostname:
        hostnames.append(args.hostname)
    else:
        parser.print_help()
        sys.exit(0)
    # Run all tests
    servers, error_servers = sslyzer(hostnames, timeout=5)

    #if len(error_servers):
        #hostnames_error = [s['hostname'] for s in error_servers]
        #servers, error_servers = sslyzer(hostnames_error, timeout=15)
    # Save report to XLSX file
    if args.xlsx_file:
        filename = 'reports/' + args.xlsx_file
        excel_report(servers, filename)
    # Print unprocessed hostnames
    if len(error_servers):
        pprint(error_servers)