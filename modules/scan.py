#!/usr/bin/python2
# -*- coding: utf-8 -*-

# Standard modules
import sys
from datetime import datetime
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

class ConnectivityTestException(Exception):
    pass

class Certificate(object):
    """ """
    def __init__(self):
        self.subject = None
        self.issuer = None
        self.valid_to = None
        self.expired = None
        self.trusted = None
        self.self_signed = None
        self.matches_hostname = None
        self.sign_hash_algo = ''
        self.weak_hash_algo = None

    def check_self_signed(self):
        """Cert is self-signed if issuer and subject names are the same"""
        if self.issuer == self.subject:
           self.self_signed = True
        else:
           self.self_signed = False

    def check_sign_hash_algo(self):
        """Weak if sign algo is SHA1"""
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
        self.dh_type =  None
        self.dh_group_size = None
        self.dh_prime = None
        self.dh_export = None
        self.dh_common_prime = None
        self.dh_weak = None
        self.dh_insecure = None
        if cipher.dh_info is not None:
            self.dh_type =  cipher.dh_info['Type']
            self.dh_group_size = cipher.dh_info['GroupSize']
            if self.dh_type == 'DH':
                prime = cipher.dh_info['prime'][4:]
                self.dh_export = bool(int(self.dh_group_size) <= 1024)
                self.dh_prime = prime
                self.dh_common_prime = bool(self.dh_prime in common_primes)
                self.dh_weak = bool(int(self.dh_group_size) == 1024)
                self.dh_insecure = bool(int(self.dh_group_size) < 1024)


class Server(object):
    """ """
    def __init__(self, hostname):
        self.server_info = None
        self.hostname = hostname
        self.ip = ''
        self.port = ''
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
        self.pfs = None
        self.hsts_header = None
        self.hpkp_header = None

    def test_connectivity(self):
        """Test connectivity, get server_info object"""
        try:
            self.server_info = ServerConnectivityInfo(self.hostname)
            self.server_info.test_connectivity_to_server()
            self.port = str(self.server_info.port)
            self.ip = self.server_info.ip_address
        except ServerConnectivityError as e:
            raise ServerConnectivityError(e.error_msg)

    def scan(self, timeout):
        """Scan server for supported SSL cipher suites and vulnerabilities and return dict object"""
        if not self.server_info:
            raise ConnectivityTestException

        scanner = ConcurrentScanner(network_retries=3, network_timeout=timeout)
        scan_commands = [Sslv20ScanCommand(), Sslv30ScanCommand(), Tlsv10ScanCommand(), Tlsv11ScanCommand(), Tlsv12ScanCommand(),
                        HeartbleedScanCommand(), CompressionScanCommand(), FallbackScsvScanCommand(),
                        OpenSslCcsInjectionScanCommand(), CertificateInfoScanCommand(),
                        SessionRenegotiationScanCommand(), HttpHeadersScanCommand()]
        # Supported protocols and cipher suites
        tls_commands = {'SSLv2.0': Sslv20ScanCommand, 'SSLv3.0': Sslv30ScanCommand, 'TLSv1.0': Tlsv10ScanCommand,
                    'TLSv1.1': Tlsv11ScanCommand, 'TLSv1.2': Tlsv12ScanCommand}

        # Run all scan commands
        for scan_command in scan_commands:
            scanner.queue_scan_command(self.server_info, scan_command)
        # Process scan results
        for scan_result in scanner.get_results():
            # If some of the commands failed, assign 'Error' value to corresponding params
            if isinstance(scan_result, PluginRaisedExceptionScanResult):
                error_message = ''.join(scan_result.as_text())
                error = '{0}Scan command {1} failed:, {2}{3}\n\n'.format(BOLD, scan_result.scan_command.__class__.__name__, error_message, ENDBOLD)
                sys.stdout.write(colored(error, 'red'))
                for proto_name, command in tls_commands.iteritems():
                    if isinstance(scan_result.scan_command, command):
                        protocol = Protocol(name=proto_name)
                        protocol.status = 'Error'
                        self.protocols.append(protocol)
                if isinstance(scan_result.scan_command, Sslv20ScanCommand):
                    protocol
                if isinstance(scan_result.scan_command, CompressionScanCommand):
                    self.compr = 'Error'
                if isinstance(scan_result.scan_command, HeartbleedScanCommand):
                    self.vulners['Heartbleed'] = 'Error'
                if isinstance(scan_result.scan_command, FallbackScsvScanCommand):
                    self.fallback_scsv = 'Error'
                if isinstance(scan_result.scan_command, OpenSslCcsInjectionScanCommand):
                    self.vulners['CCS Injection'] = 'Error'
                if isinstance(scan_result.scan_command, SessionRenegotiationScanCommand):
                    self.client_reneg = 'Error'
                    self.secure_reneg = 'Error'
                if isinstance(scan_result.scan_command, HttpHeadersScanCommand):
                    self.hsts_header = 'Error'
                    self.hsts_header = 'Error'
                if isinstance(scan_result.scan_command, CertificateInfoScanCommand):
                    self.cert.matches_hostname = 'Error'
                    self.cert.not_valid_after = 'Error'
                    self.cert.self_signed = 'Error'
                    self.cert.trusted = 'Error'
                    self.cert.sign_hash_algorithm = 'Error'
                    self.cert.weak_hash_algorithm = 'Error'
                continue
            # Scan results for TLS protocols
            for proto_name, command in tls_commands.iteritems():
                if isinstance(scan_result.scan_command, command):
                    protocol = Protocol(name=proto_name)
                    protocol.get_ciphers(scan_result)
                    self.protocols.append(protocol)
            # Heartbleed
            if isinstance(scan_result.scan_command, HeartbleedScanCommand):
                self.vulners['Heartbleed'] = str(scan_result.is_vulnerable_to_heartbleed)
            # Data compression
            if isinstance(scan_result.scan_command, CompressionScanCommand):
                self.compr = str(scan_result.compression_name)
            # Fallback SCSV
            if isinstance(scan_result.scan_command, FallbackScsvScanCommand):
                self.fallback_scsv = str(scan_result.supports_fallback_scsv)
            # CCS Injection
            if isinstance(scan_result.scan_command, OpenSslCcsInjectionScanCommand):
                self.vulners['CCS Injection'] = str(scan_result.is_vulnerable_to_ccs_injection)
            # Renegotiation parameters
            if isinstance(scan_result.scan_command, SessionRenegotiationScanCommand):
                self.client_reneg = str(scan_result.accepts_client_renegotiation)
                self.secure_reneg = str(scan_result.supports_secure_renegotiation)
            # HSTS and HPKP headers
            if isinstance(scan_result.scan_command, HttpHeadersScanCommand):
                self.hsts_header = str(bool(scan_result.hsts_header))
                self.hpkp_header = str(bool(scan_result.hpkp_header))
            # Get certificate parameters
            if isinstance(scan_result.scan_command, CertificateInfoScanCommand):
                cert = Certificate()
                cert_data = scan_result.certificate_chain[0]
                cert.matches_hostname = scan_result.certificate_matches_hostname

                cert.valid_to = cert_data.not_valid_after.strftime('%d.%m.%Y')                
                today = datetime.today()
                if cert_data.not_valid_after <= today:
                    cert.expired = True
                else:
                    cert.expired = False

                cert.subject = CertificateUtils.get_name_as_short_text(cert_data.subject)
                cert.issuer = CertificateUtils.get_name_as_short_text(cert_data.issuer)
                cert.check_self_signed()
                cert.trusted = scan_result.path_validation_result_list[0].is_certificate_trusted
                cert.sign_hash_algo = cert_data.signature_hash_algorithm.name
                cert.check_sign_hash_algo()
                self.cert = cert

    def protocol_by_name(self, name):
        """Returns Protocol object with certain name"""
        for protocol in self.protocols:
            if protocol.name == name:
                return protocol

    def __check_freak(self):
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

    def __check_beast(self):
        """"""
        self.vulners['Beast'] = False
        sslv3 = self.protocol_by_name('SSLv3.0')
        tlsv1_0 = self.protocol_by_name('TLSv1.0')
        for protocol in [sslv3, tlsv1_0]:
            if protocol.status == 'Error':
                self.vulners['Beast'] = 'Error'
            for cipher in protocol.cipher_suites:
                if 'CBC' in cipher.name:
                    self.vulners['Beast'] = True

    def __get_cipher_param(self, key):
        """"""
        #import pdb; pdb.set_trace()
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

        self.__check_freak()
        self.__check_beast()

        if self.compression == 'Error':
            self.vulners['Crime'] = 'Error'
        else:
            self.vulners['Crime'] = bool(self.compression)

        if self.fallback_scsv == 'Error':
            self.vulners['Downgrade'] = 'Error'
        else:
            self.vulners['Downgrade'] = not bool(self.fallback_scsv)

        self.vulners['RC4'] = self.__get_cipher_param('rc4')
        dhe = self.__get_cipher_param('dh_export')
        self.vulners['Logjam'] = dhe

        md5 = self.__get_cipher_param('md5')
        des = self.__get_cipher_param('des')
        self.weak_ciphers = (dhe or md5 or des)

        self.insec_ciphers = self.__get_cipher_param('anon')

        self.dh_params['Common prime'] = self.__get_cipher_param('dh_common_prime')
        self.dh_params['Weak'] = self.__get_cipher_param('dh_weak')
        self.dh_params['Insecure'] = self.__get_cipher_param('dh_insecure')

        self.pfs = self.__get_cipher_param('pfs')
