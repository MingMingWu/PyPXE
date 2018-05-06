# encoding:utf-8
'''

This file contains helper functions used throughout the PyPXE services

'''

import os.path
import logging
import platform

g_SysType = [SysUnknown, SysLinux, SysWindow, SysMac, SysOther] = range(5)
g_SysName = {
    SysUnknown: "Unknown",
    SysLinux: 'Linux',
    SysWindow: 'Windows',
    SysMac: 'Mac',
    SysOther: 'Other'
}


class PathTraversalException(Exception):
    pass


def normalize_path(base, filename):
    '''
        Join and normalize a base path and filename.

       `base` may be relative, in which case it's converted to absolute.

        Args:
            base (str): Base path
            filename (str): Filename (optionally including path relative to
                            base)

        Returns:
            str: The joined and normalized path

        Raises:
            PathTraversalException: if an attempt to escape the base path is
                                    detected
    '''
    abs_path = os.path.abspath(base)
    joined = os.path.join(abs_path, filename)
    normalized = os.path.normpath(joined)
    if normalized.startswith(os.path.join(abs_path, '')):
        return normalized
    raise PathTraversalException('Path Traversal detected')


def get_child_logger(logger, name):
    '''
        Get a descendant of an existing Logger.

        This only exists because logger.getChild isn't in Python 2.6.

        Args:
            logger (Logger): Parent logger to create descendant of
            name (str): Name to append to parent's name

        Returns:
            Logger: new Logger with `name` appended
    '''
    return logging.getLogger("{0}.{1}".format(logger.name, name))


def get_sys_type():
    global g_SysType
    global g_SysName
    for sys_type in g_SysType:
        if g_SysName[sys_type] in platform.system():
            return sys_type
    else:
        return SysUnknown

def get_sys_name(type):
    global g_SysName
    return g_SysName[type] if type < len(g_SysType) else "system type error"


#获取网卡名称和其ip地址，不包括回环
# TODO: 网卡名称转换问题
def get_netcard():
    import psutil
    netcard_info = []
    info = psutil.net_if_addrs()
    for k,v in info.items():
        for item in v:
            if item[0] == 2 and not item[1]=='127.0.0.1':
                netcard_info.append((k,item[1]))
    return netcard_info


if __name__ == "__main__":
    sys_type = get_sys_type()
    print sys_type, get_sys_name(sys_type)
    print get_netcard()
