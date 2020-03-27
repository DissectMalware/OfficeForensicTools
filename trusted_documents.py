import winreg
import utils
import struct


def parse_trustrecord_data(file_name, bin_data):
    bin_data = bytes(reversed(bin_data))
    res = {'file_name': file_name,
           'created_time': '',
           'created_time_zone': '',
           'added_time': '',
           'flag': ''}
    if len(bin_data) == 24:
        filetime_created = bin_data[16:]
        res['created_time'] = utils.convert_filetime_to_systemtime(filetime_created)
        time_zone = bin_data[8:16]
        res['created_time_zone'] = utils.get_time_zone(time_zone)
        filetime_enabled = bin_data[4:8]
        res['added_time'] = utils.estimate_access_time(filetime_enabled)
        flag = bin_data[:4]
        flag_int = struct.unpack('>I', flag)[0]
        if flag_int == 2147483647:
            res['flag'] = 'enabled_content'
        else:
            res['flag'] = 'trusted'

    else:
        raise Exception("Invalid format, size mismatch (must be 24 bytes)")

    return res


def format_result(doc):
    if doc['created_time_zone'].days < 0:
        doc['created_time_zone'] = '-' + str(-doc['created_time_zone'])
    else:
        doc['created_time_zone'] = str(doc['created_time_zone'])
    return [str(k) for i, k in result.items()]


if __name__ == '__main__':
    key_name = r"Software\Microsoft\Office\16.0\Excel\Security\Trusted Documents\TrustRecords"
    key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_name, 0, winreg.KEY_READ)

    for i in range(0, winreg.QueryInfoKey(key)[1]):
        try:
            value, data, type = winreg.EnumValue(key, i)
            result = parse_trustrecord_data(value, data)
            print(format_result(result))
        except Exception as exp:
            print(exp.message)
