from openpyxl import Workbook
from openpyxl.styles import NamedStyle
from styles import styles, Colors, columnWidth
from termcolor import colored


def serverConsoleOutput(server):
    # print('Heartbleed: ' + colored((server['vulners']['heartbleed']), 'green'))
    yes_no = {False: 'No', True: 'Yes', 'Error': 'Error'}
    for protocol, ciphers in server['cipher_suites'].iteritems():
        if len(ciphers):
            print(colored(protocol, 'cyan'))
            a = 36
            print(colored(Colors.BOLD + Colors.UNDERLINE + '{:<36}|{:<5}|{:<5}|{:<6}|{:<6}|{:<5}|{:<5}|{:<9}|{:<9}|{:<4}|{:<13}|{:<8}|{:<9}'.format(
                'Cipher', 'RC4', 'MD5', 'SHA1', 'DES', 'Anon', 'PFS', 'Key Size', 'GroupSize', 'DHE', 'Common Prime', 'DH Weak', 'DH Insec') + Colors.ENDBOLD, 'white'))
            for cipher in ciphers:
                print('{:<36}|{:<5}|{:<5}|{:<6}|{:<6}|{:<5}|{:<5}|{:<9}|{:<9}|{:<4}|{:<13}|{:<8}|{:<9}'.format(
                    cipher['name'], yes_no[cipher['RC4']], yes_no[cipher['MD5']],
                    yes_no[cipher['SHA1']], yes_no[cipher['DES']], yes_no[cipher['anon']],
                    yes_no[cipher['PFS']], cipher['key_size'], cipher['DH_GroupSize'],
                    yes_no[cipher['DH_export']], yes_no[cipher['DH_common_prime']],
                    yes_no[cipher['DH_weak']], yes_no[cipher['DH_insecure']]))
            print('-----------------------------------------------------------------------------------------------------------------------------------')

    cert = server['cert']
    print(Colors.BOLD + 'Certificate' + Colors.ENDBOLD)
    print(Colors.BOLD + Colors.UNDERLINE + '{:<8}|{:<8}|{:<11}|{:<11}|{:<10}|{:<10}'.format('Matches', 'Trusted', 'Valid to', 'SelfSigned', 'Hash algo', 'Weak algo') + Colors.ENDBOLD)
    print('{:<8}|{:<8}|{:<11}|{:<11}|{:<10}|{:<10}'.format(
        yes_no[cert['matches_hostname']], yes_no[cert['trusted']], cert['not_valid_after'],
        yes_no[cert['self_signed']], cert['sign_hash_algorithm'].upper(), yes_no[cert['weak_hash_algorithm']]))
    print
    print(Colors.BOLD + 'Vulnerabilities' + Colors.ENDBOLD)
    for vulner, state in server['vulners'].iteritems():
        print('{0:<17}{1}'.format(vulner, state))

    print(Colors.BOLD + 'DH params' + Colors.ENDBOLD)
    for dh_param, state in server['DH_params'].iteritems():
        print('{0:<17}{1}'.format(dh_param, state))
    print
    print('{:<17}{}'.format('Forward Secrecy', str(server['PFS'])))
    print('{:<17}{}'.format('HSTS', server['hsts_header']))
    print('{:<17}{}'.format('Secure Reneg', str(server['secure_reneg'])))   
    print
    print('{:<17}{}'.format('Weak ciphers', str(server['weak_ciphers'])))
    print('{:<17}{}'.format('Insecure ciphers', str(server['insecure_ciphers'])))
    print


def excelReport(servers, filename):
    try:
        wb = Workbook()
    except Exception, error:
        raise error
    for key, value in styles.iteritems():
        wb.add_named_style(value)

    sheet = wb.create_sheet('SSL')
    headers = {'Server': 1, 'SSLv2': 2, 'SSLv3': 3, 'TLSv1.0': 4, 'TLSv1.1': 5, 'TLSv1.2': 6,
               'Heartbleed': 7, 'Crime': 8, 'Downgrade': 9, 'Poodle': 10 , 'RC4': 11, 'Beast': 12, 'CCS Injection': 13, 'Drown': 14, 'Freak': 15, 'Logjam': 16,
               'DH\nCommon Primes': 17, 'DH\nWeak': 18, 'DH\nInsecure': 19,
               'Forward\nSecrecy': 20, 'HSTS': 21, 'Secure\nRenegotiation': 22,
               'Weak\nCiphers': 23, 'Insecure\nCiphers': 24,
               'Trusted': 25, 'Self\nSigned': 26, 'Valid to': 27, 'Matches\nhostname': 28}
    for key, value in headers.iteritems():
        sheet.cell(column=value, row=1, value=key)
        sheet.cell(column=value, row=1).style = styles['Header']
    row = 2
    for server in servers:
        if 'hostname' in server:
            server_info = ':'.join([server['hostname'], server['ip_address'], server['port']])
            sheet.cell(column=1, row=row, value=server_info)
            sheet.cell(column=2, row=row, value=str(server['SSLv2.0']))
            sheet.cell(column=3, row=row, value=str(server['SSLv3.0']))
            sheet.cell(column=4, row=row, value=str(server['TLSv1.0']))
            sheet.cell(column=5, row=row, value=str(server['TLSv1.1']))
            sheet.cell(column=6, row=row, value=str(server['TLSv1.2']))
            sheet.cell(column=7, row=row, value=str(server['vulners']['heartbleed']))
            sheet.cell(column=8, row=row, value=str(server['vulners']['crime']))
            sheet.cell(column=9, row=row, value=str(server['vulners']['downgrade']))
            sheet.cell(column=10, row=row, value=str(server['vulners']['poodle']))
            sheet.cell(column=11, row=row, value=str(server['vulners']['RC4']))
            sheet.cell(column=12, row=row, value=str(server['vulners']['beast']))
            sheet.cell(column=13, row=row, value=str(server['vulners']['ccs_injection']))
            sheet.cell(column=14, row=row, value=str(server['vulners']['drown']))
            sheet.cell(column=15, row=row, value=str(server['vulners']['freak']))
            sheet.cell(column=16, row=row, value=str(server['vulners']['logjam']))
            sheet.cell(column=17, row=row, value=str(server['DH_params']['DH_common_prime']))
            sheet.cell(column=18, row=row, value=str(server['DH_params']['DH_weak']))
            sheet.cell(column=19, row=row, value=str(server['DH_params']['DH_insecure']))
            sheet.cell(column=20, row=row, value=str(server['PFS']))
            sheet.cell(column=21, row=row, value=str(server['hsts_header']))
            sheet.cell(column=22, row=row, value=str(server['secure_reneg']))
            sheet.cell(column=23, row=row, value=str(server['weak_ciphers']))
            sheet.cell(column=24, row=row, value=str(server['insecure_ciphers']))
            sheet.cell(column=25, row=row, value=str(server['cert']['trusted']))
            sheet.cell(column=26, row=row, value=str(server['cert']['self_signed']))
            sheet.cell(column=27, row=row, value=str(server['cert']['not_valid_after']))
            sheet.cell(column=28, row=row, value=str(server['cert']['matches_hostname']))
            row += 1

    for key, value in columnWidth.iteritems():
        sheet.column_dimensions[key].width = value

    try:
        wb.remove_sheet(wb.get_sheet_by_name('Sheet'))
        wb.save(filename)
    except Exception, error:
        raise error