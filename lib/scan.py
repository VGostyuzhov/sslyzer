#!/usr/bin/python2
# -*- coding: utf-8 -*-
#Import standard libraries
import sys

#Import sslyze Classes
from sslyze.server_connectivity                         import ServerConnectivityInfo, ServerConnectivityError
from sslyze.synchronous_scanner                         import SynchronousScanner
from sslyze.concurrent_scanner                          import ConcurrentScanner, PluginRaisedExceptionScanResult
from sslyze.plugins.openssl_cipher_suites_plugin        import Sslv20ScanCommand, Sslv30ScanCommand, Tlsv10ScanCommand, Tlsv11ScanCommand, Tlsv12ScanCommand
from sslyze.plugins.heartbleed_plugin                   import HeartbleedScanCommand
from sslyze.plugins.compression_plugin                  import CompressionScanCommand
from sslyze.plugins.fallback_scsv_plugin                import FallbackScsvScanCommand
from sslyze.plugins.openssl_ccs_injection_plugin        import OpenSslCcsInjectionScanCommand
from sslyze.plugins.session_renegotiation_plugin        import SessionRenegotiationScanCommand
from sslyze.plugins.http_headers_plugin                 import HttpHeadersScanCommand
from sslyze.plugins.certificate_info_plugin             import CertificateInfoScanCommand
from sslyze.plugins.utils.certificate_utils             import CertificateUtils

from termcolor import colored
BOLD = '\033[1m'
ENDBOLD = '\033[0m'

def scan_server(hostname):
    """Scan server for supported SSL cipher suites and vulnerabilities and
    return dict object"""
    server = {'hostname': hostname, 'cipher_suites': {}, 'weak_ciphers': {}, 'cert': {}, 'vulners': {}}
    # Setup the server to scan and ensure it is online/reachable
    sys.stdout.write('Testing connectivity: ')
    #Python buffer strings before printing to stdout. Let's fush it to screen before process next command.
    sys.stdout.flush()
    try:
        server_info = ServerConnectivityInfo(hostname)
        server_info.test_connectivity_to_server()
        sys.stdout.write(colored(BOLD + 'OK!\n' + ENDBOLD, 'green'))
    except ServerConnectivityError as e:
        sys.stdout.write(colored(BOLD + 'Error when connecting to {}: {}\n\n'.format(hostname, e.error_msg) + ENDBOLD, 'red'))
        return {'error': e.error_msg}
    sys.stdout.write('Getting test results: ')
    sys.stdout.flush()
    
    concurrent_scanner = ConcurrentScanner(network_retries=3, network_timeout=10)
    scan_commands = [Sslv20ScanCommand(), Sslv30ScanCommand(), Tlsv10ScanCommand(), Tlsv11ScanCommand(), Tlsv12ScanCommand(),
            Tlsv12ScanCommand(), HeartbleedScanCommand(), CompressionScanCommand(), FallbackScsvScanCommand(), OpenSslCcsInjectionScanCommand(),
            SessionRenegotiationScanCommand(), CertificateInfoScanCommand(), HttpHeadersScanCommand()]
    for scan_command in scan_commands:
        concurrent_scanner.queue_scan_command(server_info, scan_command)

    for scan_result in concurrent_scanner.get_results():
        #print('\nReceived scan result for {} on host {}'.format(scan_result.scan_command.__class__.__name__, scan_result.server_info.hostname))
        if isinstance(scan_result, PluginRaisedExceptionScanResult):
            sys.stdout.write(colored('{}Scan command failed: {}{}\n'.format(BOLD, scan_result.as_text(), ENDBOLD)))
            return {'error': scan_result.as_text()}

        commands = {'sslv20': Sslv20ScanCommand, 'sslv30': Sslv30ScanCommand, 'tlsv10': Tlsv10ScanCommand, 'tlsv11': Tlsv11ScanCommand, 'tlsv12': Tlsv12ScanCommand}
        for protocol, command in commands.iteritems():
            if isinstance(scan_result.scan_command, command):
                server['cipher_suites'][protocol] = []
                for cipher in scan_result.accepted_cipher_list:
                    c = {'cipher': cipher.name}
                    if cipher.dh_info is not None:
                        if cipher.dh_info['Type'] == 'DH':
                            c['dh_info'] = {key: cipher.dh_info[key] for key in ['Type', 'GroupSize', 'prime']}
                        elif cipher.dh_info['Type'] == 'ECDH':
                            c['dh_info'] = {key: cipher.dh_info[key] for key in ['Type', 'GroupSize', 'Prime']}
                    server['cipher_suites'][protocol].append(c)
                server[protocol] = bool(len(server['cipher_suites'][protocol]))

        if isinstance(scan_result.scan_command, HeartbleedScanCommand):
            server['vulners']['heartbleed'] = scan_result.is_vulnerable_to_heartbleed

        if isinstance(scan_result.scan_command, CompressionScanCommand):
            server['compression'] = scan_result.compression_name
            
        if isinstance(scan_result.scan_command, FallbackScsvScanCommand):
            server['fallback_scsv'] = scan_result.supports_fallback_scsv
            
        if isinstance(scan_result.scan_command, OpenSslCcsInjectionScanCommand):
            server['vulners']['ccs_injection'] = scan_result.is_vulnerable_to_ccs_injection

        if isinstance(scan_result.scan_command, SessionRenegotiationScanCommand):
            server['client_reneg'] = scan_result.accepts_client_renegotiation
            server['secure_reneg'] = scan_result.supports_secure_renegotiation

        if isinstance(scan_result.scan_command, HttpHeadersScanCommand):
            server['hsts_header'] = bool(scan_result.hsts_header)
            server['hpkp_header'] = bool(scan_result.hpkp_header)

        if isinstance(scan_result.scan_command, CertificateInfoScanCommand):
            server['cert']['matches_hostname'] = scan_result.certificate_matches_hostname
            cert = scan_result.certificate_chain[0]
            server['cert']['not_valid_after'] = cert.not_valid_after.strftime('%d.%m.%Y')
            subject = CertificateUtils.get_name_as_short_text(cert.subject)
            issuer = CertificateUtils.get_name_as_short_text(cert.issuer)
            if issuer == subject:
                server['cert']['self_signed'] = True
            else:
                server['cert']['self_signed'] = False
            server['cert']['trusted'] = scan_result.path_validation_result_list[0].is_certificate_trusted
            server['cert']['sign_hash_algorithm'] = cert.signature_hash_algorithm.name
            server['cert']['weak_hash_algorithm'] = bool(server['cert']['sign_hash_algorithm'] == 'sha1')     
    return server