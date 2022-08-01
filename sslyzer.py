#!/usr/bin/python2
# -*- coding: utf-8 -*-

# Standard modules
import argparse
import json
import os
import sys
# Third-party modules
from pprint import pprint
from sslyze.server_connectivity import ServerConnectivityError
from termcolor import colored
# Custom modules
from modules.report import server_console_output, save_report, build_report
from modules.scan import Server
from modules.styles import Colors


def print_single_line(string):
    sys.stdout.write(string)
    sys.stdout.flush()


def sslyzer(hostnames, timeout=5):
    """"""
    # Initialize lists for results and servers with errors
    servers = []
    error_servers = []
    for index, hostname in enumerate(hostnames, 1):
        print(colored('Host {3} of {4}: {0}{1}{2}'.format(Colors.BOLD, hostname, Colors.ENDBOLD, index, len(hostnames)), 'cyan'))
        # Run sslyze scan commands, get server dict
        server = Server(hostname)
        print_single_line('Testing connectivity: ')
        try:
            server.test_connectivity()
            sys.stdout.write(colored(Colors.BOLD + 'OK!\n' + Colors.ENDBOLD, 'green'))
        except ServerConnectivityError as e:
            error = Colors.BOLD + 'Error when connecting to {}: {}\n\n'.format(hostname, e.error_msg) + Colors.ENDBOLD
            sys.stdout.write(colored(error, 'red'))
        else:
            print_single_line('Getting scan results: ')
            server.scan(timeout)
            server.check_vulners()
            servers.append(server)
            if args.wide:
                server_console_output(server)
            sys.stdout.write(colored(Colors.BOLD + 'OK!\n\n'.format(hostname) + Colors.ENDBOLD, 'green'))
    return servers, error_servers


def parse_arguments():
    """Parse command-line arguments and return it's values"""
    parser = argparse.ArgumentParser(description='Test multiple hosts for SSL vulnerabilities and misconfigurations using sslyze library')
    parser.add_argument('-f', '--file', dest='input_file', help='File containing input hostnames', metavar='FILENAME')
    parser.add_argument('-x', '--xlsx', dest='xlsx_file', help='Save report to .xlsx file', metavar='FILENAME')
    parser.add_argument('-w', '--wide', action='store_true', help='Wide output for each server')
    parser.add_argument('hostname', nargs='?', help='Single hostname to scan')
    return parser.parse_args()


if __name__ == '__main__':
    args = parse_arguments()
    # Load list of hostnames from file or positional argument
    if args.input_file:
        with open(args.input_file, 'rb') as input_file:
            hostnames = [h.strip() for h in input_file.readlines()]
    elif args.hostname:
        hostnames =[args.hostname]
    else:
        parser.print_help()
        sys.exit(0)

    # Run all tests against hostnames
    servers, error_servers = sslyzer(hostnames, timeout=5)

    # Save report to XLSX file
    if args.xlsx_file:
        filename = 'reports/' + args.xlsx_file
        report = {}
        report = build_report(servers)
        save_report(servers, filename, report)

    # Print unprocessed hostnames
    if len(error_servers):
        pprint(error_servers)