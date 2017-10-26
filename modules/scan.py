#!/usr/bin/python2
# -*- coding: utf-8 -*-
import sys
from termcolor import colored
from sslyze.server_connectivity import ServerConnectivityInfo, ServerConnectivityError
from sslyze.synchronous_scanner import SynchronousScanner
from sslyze.concurrent_scanner import ConcurrentScanner, PluginRaisedExceptionScanResult
from sslyze.plugins.openssl_cipher_suites_plugin import Sslv20ScanCommand, Sslv30ScanCommand, Tlsv10ScanCommand, Tlsv11ScanCommand, Tlsv12ScanCommand
from sslyze.plugins.heartbleed_plugin import HeartbleedScanCommand
from sslyze.plugins.compression_plugin import CompressionScanCommand
from sslyze.plugins.fallback_scsv_plugin import FallbackScsvScanCommand
from sslyze.plugins.openssl_ccs_injection_plugin import OpenSslCcsInjectionScanCommand
from sslyze.plugins.session_renegotiation_plugin import SessionRenegotiationScanCommand
from sslyze.plugins.http_headers_plugin import HttpHeadersScanCommand
from sslyze.plugins.certificate_info_plugin import CertificateInfoScanCommand
from sslyze.plugins.utils.certificate_utils import CertificateUtils

BOLD = '\033[1m'
ENDBOLD = '\033[0m'


def scanServer(hostname, timeout):
    """Scan server for supported SSL cipher suites and vulnerabilities and return dict object"""
    # Test connectivity
    sys.stdout.write('Testing connectivity: ')
    sys.stdout.flush()
    try:
        server_info = ServerConnectivityInfo(hostname)
        server_info.test_connectivity_to_server()
        sys.stdout.write(colored(BOLD + 'OK!\n' + ENDBOLD, 'green'))
    except ServerConnectivityError as e:
        sys.stdout.write(colored(BOLD + 'Error when connecting to {}: {}\n\n'.format(hostname, e.error_msg) + ENDBOLD, 'red'))
        return {'error': e.error_msg}
    # Run scan commands
    sys.stdout.write('Getting test results: ')
    sys.stdout.flush()
    concurrent_scanner = ConcurrentScanner(network_retries=3, network_timeout=timeout)
    scan_commands = [Sslv20ScanCommand(), Sslv30ScanCommand(), Tlsv10ScanCommand(), Tlsv11ScanCommand(), Tlsv12ScanCommand(),
                     HeartbleedScanCommand(), CompressionScanCommand(), FallbackScsvScanCommand(),
                     OpenSslCcsInjectionScanCommand(), CertificateInfoScanCommand(),
                     SessionRenegotiationScanCommand(), HttpHeadersScanCommand()]
    for scan_command in scan_commands:
        concurrent_scanner.queue_scan_command(server_info, scan_command)
    # Process scan results
    server = {'hostname': server_info.hostname, 'ip_address': server_info.ip_address, 'port': str(server_info.port),
              'cipher_suites': {'SSLv2.0': [], 'SSLv3.0': [], 'TLSv1.0': [], 'TLSv1.1': [], 'TLSv1.2': []},
              'weak_ciphers': None, 'insecure_ciphers': None,
              'compression': None,
              'cert': {'trusted': None, 'matches_hostname': None, 'not_valid_after': None,
                       'self_signed': None, 'sign_hash_algorithm': None, 'weak_hash_algorithm': None},
              'vulners': {'poodle': None, 'crime': None, 'drown': None, 'beast': None, 'logjam': None, 'freak': None, 'downgrade': None},
              'DH_params': {'DH_common_prime': None, 'DH_weak': None, 'DH_insecure': None}
              }
    for scan_result in concurrent_scanner.get_results():
        if isinstance(scan_result, PluginRaisedExceptionScanResult):
            error_message = ''.join(scan_result.as_text())
            sys.stdout.write(colored('{0}Scan command {1} failed:, {2}{3}\n\n'.format(BOLD, scan_result.scan_command.__class__.__name__, error_message, ENDBOLD), 'red'))
            # return {'error': scan_result.as_text()}
            # continue

        # Get supported by server cipher suites
        commands = {'SSLv2.0': Sslv20ScanCommand, 'SSLv3.0': Sslv30ScanCommand, 'TLSv1.0': Tlsv10ScanCommand, 'TLSv1.1': Tlsv11ScanCommand, 'TLSv1.2': Tlsv12ScanCommand}
        for protocol, command in commands.iteritems():
            if isinstance(scan_result.scan_command, command):
                if isinstance(scan_result, PluginRaisedExceptionScanResult):
                    server['cipher_suites'][protocol] = ['Error']
                else:
                    server['cipher_suites'][protocol] = []
                    for cipher in scan_result.accepted_cipher_list:
                        cipher_name = cipher.name.replace('TLS_', '')
                        cipher_name = cipher_name.replace('WITH_', '')
                        c = {'name': cipher_name, 'key_size': cipher.key_size, 'dh_info': {'Type': None, 'prime': None, 'GroupSize': None}}
                        if cipher.dh_info is not None:
                            c['dh_info'] = {key: cipher.dh_info[key] for key in ['Type', 'GroupSize']}
                            if cipher.dh_info['Type'] == 'DH':
                                c['dh_info']['prime'] = cipher.dh_info['prime'][4:]
                        server['cipher_suites'][protocol].append(c)
                    server[protocol] = bool(len(server['cipher_suites'][protocol]))

        # Heartbleed
        if isinstance(scan_result.scan_command, HeartbleedScanCommand):
            if isinstance(scan_result, PluginRaisedExceptionScanResult):
                server['vulners']['heartbleed'] = 'Error'
            else:
                server['vulners']['heartbleed'] = scan_result.is_vulnerable_to_heartbleed

        # Data compression
        if isinstance(scan_result.scan_command, CompressionScanCommand):
            if isinstance(scan_result, PluginRaisedExceptionScanResult):
                server['compression'] = 'Error'
            else:
                server['compression'] = scan_result.compression_name

        # Fallback SCSV
        if isinstance(scan_result.scan_command, FallbackScsvScanCommand):
            if isinstance(scan_result, PluginRaisedExceptionScanResult):
                server['fallback_scsv'] = 'Error'
            else:
                server['fallback_scsv'] = scan_result.supports_fallback_scsv

        #CCS Injection
        if isinstance(scan_result.scan_command, OpenSslCcsInjectionScanCommand):
            if isinstance(scan_result, PluginRaisedExceptionScanResult):
                server['vulners']['ccs_injection'] = 'Error'
            else:
                server['vulners']['ccs_injection'] = scan_result.is_vulnerable_to_ccs_injection

        # Get renegotiation parameters
        if isinstance(scan_result.scan_command, SessionRenegotiationScanCommand):
            if isinstance(scan_result, PluginRaisedExceptionScanResult):
                server['client_reneg'] = 'Error'
                server['secure_reneg'] = 'Error'
            else:
                server['client_reneg'] = scan_result.accepts_client_renegotiation
                server['secure_reneg'] = scan_result.supports_secure_renegotiation

        # HSTS and HPKP headers
        if isinstance(scan_result.scan_command, HttpHeadersScanCommand):
            if isinstance(scan_result, PluginRaisedExceptionScanResult):
                server['hsts_header'] = 'Error'
                server['hsts_header'] = 'Error'
            else:
                server['hsts_header'] = bool(scan_result.hsts_header)
                server['hpkp_header'] = bool(scan_result.hpkp_header)

        # Get certificate parameters
        if isinstance(scan_result.scan_command, CertificateInfoScanCommand):
            if isinstance(scan_result, PluginRaisedExceptionScanResult):
                server['cert']['matches_hostname'] = 'Error'
                server['cert']['not_valid_after'] = 'Error'
                server['cert']['self_signed'] = 'Error'
                server['cert']['trusted'] = 'Error'
                server['cert']['sign_hash_algorithm'] = 'Error'
                server['cert']['weak_hash_algorithm'] = 'Error'
            else:
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