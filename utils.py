from datetime import datetime
from datetime import timedelta
import struct


def convert_filetime_to_systemtime(filetime):
    EPOCH_AS_FILETIME = 116444736000000000;
    HUNDREDS_OF_NANOSECONDS = 10000000
    ft_dec = struct.unpack('>Q', filetime)[0]
    dt = datetime.utcfromtimestamp((ft_dec - EPOCH_AS_FILETIME) / HUNDREDS_OF_NANOSECONDS)
    return dt


def convert_filetime_str_to_systemtime(filetime_str):
    filetime_bytes = bytes.fromhex(filetime_str)
    return convert_filetime_to_systemtime(filetime_bytes)


def time_difference(filetime1, filetime2):
    filetime1_bytes = bytes.fromhex(filetime1)
    filetime2_bytes = bytes.fromhex(filetime2)
    time_limit = bytes.fromhex('FFFFFFFFFFFFFFFF')
    ft1_dec = struct.unpack('>Q', filetime1_bytes)[0]
    ft2_dec = struct.unpack('>Q', filetime2_bytes)[0]
    ft_limit_dec = struct.unpack('>Q', time_limit)[0]
    res = ft1_dec - ft2_dec
    # two's complement?
    res = ft_limit_dec - res + 1
    res = struct.pack('>Q', res)
    return res


def estimate_access_time(access_time):
    HUNDREDS_OF_NANOSECONDS = 10000000
    access_time = b'\x00\x00\x00\x00' + access_time
    multiplier = bytearray.fromhex('E5109EC205D7BEA7')
    access_time_dec = struct.unpack('>Q', access_time)[0]
    multiplier_dec = struct.unpack('>Q', multiplier)[0]
    access_time_dec = access_time_dec << (64 + 29)
    access_time_dec = access_time_dec // multiplier_dec
    access_time_dec /= HUNDREDS_OF_NANOSECONDS
    return datetime.utcfromtimestamp(access_time_dec)


def get_time_zone(timezone):
    HUNDREDS_OF_NANOSECONDS = 10000000
    ft_zone_dec = struct.unpack('>Q', timezone)[0]
    if timezone[0]== 255:
        time_limit = bytes.fromhex('FFFFFFFFFFFFFFFF')
        ft_limit_dec = struct.unpack('>Q', time_limit)[0]
        res = (ft_limit_dec - ft_zone_dec + 1)//HUNDREDS_OF_NANOSECONDS
        res = -res
    else:
        res = ft_zone_dec // HUNDREDS_OF_NANOSECONDS
    return timedelta(seconds=res)



