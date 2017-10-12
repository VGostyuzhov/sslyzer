from openpyxl.styles import fills, PatternFill, Border, Side, Alignment, Font, NamedStyle
from copy import copy

styles = {}
styles['Header'] = NamedStyle(name='header')
styles['excel_Bad'] = NamedStyle(name='excel_Bad')
styles['excel_Good'] = NamedStyle(name='excel_Good')

styles['Header'].font = Font(name='Calibri', size=10, bold=True, color='00000000')
styles['Header'].fill = PatternFill(fill_type=fills.FILL_SOLID, start_color='DCE6F1')
styles['Header'].alignment = Alignment(horizontal='center', vertical='center')
styles['Header'].border = Border(left=Side(border_style='thin', color='000000'),
        right=Side(border_style='thin', color='000000'),
        top=Side(border_style='thin', color='000000'),
        bottom=Side(border_style='thin', color='000000'))


