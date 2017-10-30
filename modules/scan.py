#!/usr/bin/python2
# -*- coding: utf-8 -*-

# Standard modules
import sys
# Third-party modules
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
from sslyze.server_connectivity import ServerConnectivityInfo, ServerConnectivityError
from termcolor import colored

BOLD = '\033[1m'
ENDBOLD = '\033[0m'

# Load list of common primes from file
with open('data/common_primes.txt', 'rb') as cp_file:
    common_primes = [p.strip().lower() for p in cp_file.readlines()]

class Certificate(object):
    """ """
    def __init__(self):
        self.subject = ''
        self.issuer = ''
        self.valid_to = ''
        self.trusted = None
        self.self_signed = None
        self.matches_hostname = None
        self.sign_hash_algo = ''
        self.weak_hash_algo = None

    def check_self_signed(self):
        """"""
        if self.issuer == self.subject:
           self.self_signed = True
        else:
           self.self_signed = False

    def check_sign_hash_algo(self):
        """"""
        self.weak_hash_algo = bool(self.sign_hash_algo == 'sha1')

class Protocol(object):
    """ """
    def __init__(self, name):
        self.name = name
        self.cipher_suites = []
        self.is_supported = False
        self.status = None

    def get_ciphers(self, scan_result):
        """ """
        if isinstance(scan_result, PluginRaisedExceptionScanResult):
            self.status = 'Error'
            raise ValueError('Error while scanning protocol')
        else:
            for scan_cipher in scan_result.accepted_cipher_list:
                cipher_suite = CipherSuite(cipher=scan_cipher)
                self.cipher_suites.append(cipher_suite)
        if len(self.cipher_suites):
            self.is_supported = True

class CipherSuite(object):
    """ """
    def __init__(self, cipher):
        self.name = cipher.name.replace('TLS_', '').replace('WITH_', '')
        self.key_size = cipher.key_size
        self.dh_info = {}
        self.rc4 = bool('RC4' in self.name)
        self.md5 = bool('MD5' in self.name)
        self.des = bool('DES' in self.name)
        self.anon = bool('anon' in self.name)
        self.sha1 = ('SHA_' in self.name) or (self.name.endswith('SHA'))
        self.pfs = bool('DHE' in self.name)
        if cipher.dh_info is not None:
            if cipher.dh_info['Type'] == 'DH':
                prime = cipher.dh_info['prime'][4:]
            else:
                prime = None
            self.dh_type =  cipher.dh_info['Type']
            self.dh_group_size = cipher.dh_info['GroupSize']
            self.dh_prime = prime
            self.dh_export = bool(int(self.dh_group_size) <= 1024)
            self.dh_common_prime = bool(self.dh_prime in common_primes)
            self.dh_weak = bool(int(self.dh_group_size) == 1024)
            self.dh_insecure = bool(int(self.dh_group_size) < 1024)
        else:
            self.dh_type =  None
            self.dh_group_size = None
            self.dh_export = None
            self.dh_common_prime = None
            self.dh_weak = None
            self.dh_insecure = None

class Server(object):
    """ """
    def __init__(self, hostname, ip, port):
        self.hostname = hostname
        self.ip = ip
        self.port = str(port)
        self.protocols = []
        self.compression = None
        self.fallback_scsv = None
        self.client_reneg = None
        self.server_reneg = None
        self.cert = Certificate()
        self.vulners = {}
        self.dh_params = {}
        self.weak_ciphers = None
        self.insec_ciphers = None

    def protocol_by_name(self, name):
        for protocol in self.protocols:
            if protocol.name == name:
                return protocol

    def check_freak(self):
        """"""
        export_rsa_ciphers = ['EXP1024-DES-CBC-SHA', 'EXP1024-RC2-CBC-MD5', 'EXP1024-RC4-SHA',
                              'EXP1024-RC4-MD5', 'EXP-EDH-RSA-DES-CBC-SHA', 'EXP-DH-RSA-DES-CBC-SHA',
                              'EXP-DES-CBC-SHA', 'EXP-RC2-CBC-MD5', 'EXP-RC4-MD5']
        self.vulners['Freak'] = False
        for protocol in self.protocols:
            if protocol.status == 'Error':
                continue
            for cipher in protocol.cipher_suites:
                if cipher.name in export_rsa_ciphers:
                    self.vulners['Freak'] = True

    def check_beast(self):
        """"""
        self.vulners['Beast'] = False
        sslv3 = self.protocol_by_name('SSLv3.0')
        tlsv1_0 = self.protocol_by_name('TLSv1.0')
        for protocol in [sslv3, tlsv1_0]:
            if protocol.status == 'Error':
                continue
            for cipher in protocol.cipher_suites:
                if 'CBC' in cipher.name:
                    self.vulners['Beast'] = True

    def __get_ciphers_param(self, key):
        """"""
        for protocol in self.protocols:
            if protocol.status == 'Error':
                continue
            for cipher in protocol.cipher_suites:
                if getattr(cipher, key):
                    return True
        return False

    def check_vulners(self):
        """ """
        sslv3 = self.protocol_by_name('SSLv3.0')
        if sslv3.status == 'Error':
            self.vulners['Poodle'] = 'Error'
        else:
            self.vulners['Poodle'] = sslv3.is_supported

        sslv2 = self.protocol_by_name('SSLv2.0')
        if sslv2.status == 'Error':
            self.vulners['Drown'] = 'Error'
        else:
            self.vulners['Drown'] = sslv2.is_supported

        self.check_freak()
        self.check_beast()

        if self.compression == 'Error':
            self.vulners['Crime'] = 'Error'
        else:
            self.vulners['Crime'] = bool(self.compression)

        if self.fallback_scsv == 'Error':
            self.vulners['Downgrade'] = 'Error'
        else:
            self.vulners['Downgrade'] = not bool(self.fallback_scsv)

        self.vulners['RC4'] = self.__get_ciphers_param('rc4')
        dhe = self.__get_ciphers_param('dh_export')
        self.vulners['Logjam'] = dhe
        
        md5 = self.__get_ciphers_param('md5')
        des = self.__get_ciphers_param('des')
        self.weak_ciphers = (dhe or md5 or des)

        self.insec_ciphers = self.__get_ciphers_param('anon')

        self.dh_params['Common prime'] = self.__get_ciphers_param('dh_common_prime')
        self.dh_params['Weak'] = self.__get_ciphers_param('dh_weak')
        self.dh_params['Insecure'] = self.__get_ciphers_param('dh_insecure')

        self.pfs = self.__get_ciphers_param('pfs')


def scan_server(hostname, timeout):
    """Scan server for supported SSL cipher suites and vulnerabilities and return dict object"""
    # Test connectivity
    sys.stdout.write('Testing connectivity: ')
    sys.stdout.flush()
    try:
        srv_info = ServerConnectivityInfo(hostname)
        srv_info.test_connectivity_to_server()
        sys.stdout.write(colored(BOLD + 'OK!\n' + ENDBOLD, 'green'))
    except ServerConnectivityError as e:
        sys.stdout.write(colored(BOLD + 'Error when connecting to {}: {}\n\n'.format(hostname, e.error_msg) + ENDBOLD, 'red'))
        return {'error': e.error_msg}

    # Run scan commands
    sys.stdout.write('Getting test results: ')
    sys.stdout.flush()
    scanner = ConcurrentScanner(network_retries=3, network_timeout=timeout)
    scan_commands = [Sslv20ScanCommand(), Sslv30ScanCommand(), Tlsv10ScanCommand(), Tlsv11ScanCommand(), Tlsv12ScanCommand(),
                     HeartbleedScanCommand(), CompressionScanCommand(), FallbackScsvScanCommand(),
                     OpenSslCcsInjectionScanCommand(), CertificateInfoScanCommand(),
                     SessionRenegotiationScanCommand(), HttpHeadersScanCommand()]
    for scan_command in scan_commands:
        scanner.queue_scan_command(srv_info, scan_command)
    
    # Process scan results
    server = Server(srv_info.hostname, srv_info.ip_address, srv_info.port)
    for scan_result in scanner.get_results():
        if isinstance(scan_result, PluginRaisedExceptionScanResult):
            error_message = ''.join(scan_result.as_text())
            sys.stdout.write(colored('{0}Scan command {1} failed:, {2}{3}\n\n'.format(BOLD, scan_result.scan_command.__class__.__name__, error_message, ENDBOLD), 'red'))
        # Get supported cipher suites
        commands = {'SSLv2.0': Sslv20ScanCommand, 'SSLv3.0': Sslv30ScanCommand, 'TLSv1.0': Tlsv10ScanCommand,
                    'TLSv1.1': Tlsv11ScanCommand, 'TLSv1.2': Tlsv12ScanCommand}
        for proto_name, command in commands.iteritems():
            if isinstance(scan_result.scan_command, command):
                protocol = Protocol(name=proto_name)
                protocol.get_ciphers(scan_result)
                server.protocols.append(protocol)

        # Heartbleed
        if isinstance(scan_result.scan_command, HeartbleedScanCommand):
            if isinstance(scan_result, PluginRaisedExceptionScanResult):
                server.vulners['Heartbleed'] = 'Error'
            else:
                server.vulners['Heartbleed'] = str(scan_result.is_vulnerable_to_heartbleed)

        # Data compression
        if isinstance(scan_result.scan_command, CompressionScanCommand):
            if isinstance(scan_result, PluginRaisedExceptionScanResult):
                server.compr = 'Error'
            else:
                server.compr = str(scan_result.compression_name)

        # Fallback SCSV
        if isinstance(scan_result.scan_command, FallbackScsvScanCommand):
            if isinstance(scan_result, PluginRaisedExceptionScanResult):
                server.fallback_scsv = 'Error'
            else:
                server.fallback_scsv = str(scan_result.supports_fallback_scsv)

        #CCS Injection
        if isinstance(scan_result.scan_command, OpenSslCcsInjectionScanCommand):
            if isinstance(scan_result, PluginRaisedExceptionScanResult):
                server.vulners['CCS injection'] = 'Error'
            else:
                server.vulners['CCS injection'] = str(scan_result.is_vulnerable_to_ccs_injection)

        # Get renegotiation parameters
        if isinstance(scan_result.scan_command, SessionRenegotiationScanCommand):
            if isinstance(scan_result, PluginRaisedExceptionScanResult):
                server.client_reneg = 'Error'
                server.secure_reneg = 'Error'
            else:
                server.client_reneg = str(scan_result.accepts_client_renegotiation)
                server.secure_reneg = str(scan_result.supports_secure_renegotiation)

        # HSTS and HPKP headers
        if isinstance(scan_result.scan_command, HttpHeadersScanCommand):
            if isinstance(scan_result, PluginRaisedExceptionScanResult):
                server.hsts_header = 'Error'
                server.hsts_header = 'Error'
            else:
                server.hsts_header = str(bool(scan_result.hsts_header))
                server.hpkp_header = str(bool(scan_result.hpkp_header))

        # Get certificate parameters
        if isinstance(scan_result.scan_command, CertificateInfoScanCommand):
            cert = Certificate()
            if isinstance(scan_result, PluginRaisedExceptionScanResult):
                cert.matches_hostname = 'Error'
                cert.not_valid_after = 'Error'
                cert.self_signed = 'Error'
                cert.trusted = 'Error'
                cert.sign_hash_algorithm = 'Error'
                cert.weak_hash_algorithm = 'Error'
            else:
                cert.matches_hostname = scan_result.certificate_matches_hostname
                cert_data = scan_result.certificate_chain[0]
                cert.valid_to = cert_data.not_valid_after.strftime('%d.%m.%Y')
                cert.subject = CertificateUtils.get_name_as_short_text(cert_data.subject)
                cert.issuer = CertificateUtils.get_name_as_short_text(cert_data.issuer)
                cert.check_self_signed()
                cert.trusted = scan_result.path_validation_result_list[0].is_certificate_trusted
                cert.sign_hash_algo = cert_data.signature_hash_algorithm.name
                cert.check_sign_hash_algo()
            server.cert = cert

    return server