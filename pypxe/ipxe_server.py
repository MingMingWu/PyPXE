# encoding: utf-8
# file name: ipxe_server.py


# import http
import dhcp
import tftp
# import nbd

import logging
import logging.handlers
import traceback
import helpers
import os
import signal
import sys

from time import sleep
from multiprocessing import Process, Value, Array

# for remote debug
# if helpers.SysLinux == helpers.get_sys_type():
#     import pydevd
#     pydevd.settrace('192.168.56.120', port=10001, stderrToServer=True, stdoutToServer=True)

g_win_exit_flag_tftp = Value('B', False) if helpers.SysWindow == helpers.get_sys_type() else None
g_win_exit_flag_dhcp = Value('B', False) if helpers.SysWindow == helpers.get_sys_type() else None
g_win_exit_flag_http = Value('B', False) if helpers.SysWindow == helpers.get_sys_type() else None

g_dhcp_leases = Array('c', 1024 * 1024 * ['\n']) if helpers.SysWindow == helpers.get_sys_type() else None


def read_leases():
    leases = []
    global g_dhcp_leases
    if g_dhcp_leases[0] != '\n':
        le_str = g_dhcp_leases[::].strip('\n').split('\n')
        for le in le_str:
            # print eval(le)
            leases.append(eval(le))
        return leases
    else:
        return None


def do_debug_verbose(cfg, service):
    return ((service.lower() in cfg.lower()
            or 'all' in cfg.lower())
            and '-{0}'.format(service.lower()) not in cfg.lower())


class IPXEServer(object):

    def __init__(self, **server_cfg):

        global g_win_exit_flag_tftp
        global g_win_exit_flag_dhcp
        global g_win_exit_flag_http

        self.servers = []
        # get cfg
        self.sys_cfg = server_cfg.get("sys_cfg", None)
        self.tftp_cfg = server_cfg.get("tftp_cfg", None)
        self.dhcp_cfg = server_cfg.get("dhcp_cfg", None)
        self.http_cfg = server_cfg.get("http_cfg", None)

        # system cfg
        if self.sys_cfg:
            self.syslog_name = self.sys_cfg.get("syslog_file", None)
            self.tftp_enable = self.sys_cfg.get("tftp_enable", False)
            self.dhcp_enable = self.sys_cfg.get("dhcp_enable", False)
            self.http_enable = self.sys_cfg.get("http_enable", False)

            # setup main logger
            self.sys_logger = logging.getLogger('PyPXE')
            if self.syslog_name is not None:
                handler = logging.FileHandler(self.syslog_name)
            else:
                handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(name)s\t%(message)s')
            handler.setFormatter(formatter)
            self.sys_logger.addHandler(handler)
            self.sys_logger.setLevel(logging.INFO)

            # set sys log level
            if do_debug_verbose(self.sys_cfg.get('mode_debug'), 'pypxe'):
                self.sys_logger.setLevel(logging.DEBUG)
            elif do_debug_verbose(self.sys_cfg.get('mode_verbose'), 'pypxe'):
                self.sys_logger.setLevel(logging.INFO)
            else:
                self.sys_logger.setLevel(logging.WARN)

            # log info
            self.sys_logger.info("PyPXE system config confirmed")
            self.sys_logger.info("system log: {}".format("StreamHandler" if self.syslog_name is None else self.syslog_name))
            self.sys_logger.info("system debug mode: {}".format(do_debug_verbose(self.sys_cfg.get('mode_debug'),
                                                                                 'pypxe')))
            self.sys_logger.info("system verbose mode: {}".format(do_debug_verbose(self.sys_cfg.get('mode_verbose'),
                                                                                   'pypxe')))
            self.sys_logger.info("tftp server enable: {}".format(self.tftp_enable))
            self.sys_logger.info("dhcp server enable: {}".format(self.dhcp_enable))
            self.sys_logger.info("http server enable: {}".format(self.http_enable))

        else:
            self.sys_logger = None

        # tftp cfg
        if self.sys_cfg.get("tftp_enable", False) and server_cfg.get("tftp_cfg", False):
            try:
                self.tftp_server = tftp.TFTPD(ip=self.tftp_cfg.get("ip", "192.168.56.120"),
                                              port=self.tftp_cfg.get("port", 69),
                                              netboot_directory=self.tftp_cfg.get("netboot_dir", "~"),
                                              mode_debug=do_debug_verbose(self.sys_cfg.get('mode_debug'), 'tftp'),
                                              mode_verbose=do_debug_verbose(self.sys_cfg.get('mode_verbose'), 'tftp'),
                                              logger=self.tftp_cfg.get("log_file", None),
                                              win_exit_flag=g_win_exit_flag_tftp)
                self.servers.append(self.tftp_server)
            except:
                self.tftp_server = None
                traceback.print_exc()

        # dhcp cfg

        if self.dhcp_enable and self.dhcp_cfg is not None:
            try:
                self.dhcp_server = dhcp.DHCPD(ip=self.dhcp_cfg.get("ip", "192.168.56.120"),
                                              port=self.dhcp_cfg.get("port", 67),
                                              offer_from=self.dhcp_cfg.get("offer_from", "192.168.56.150"),
                                              offer_to=self.dhcp_cfg.get("offer_to", "192.168.56.200"),
                                              subnet_mask=self.dhcp_cfg.get("subnet_mask", "255.255.255.0"),
                                              router=self.dhcp_cfg.get("router", "192.168.56.255"),
                                              dns_server=self.dhcp_cfg.get("dns_server", "8.8.8.8"),
                                              broadcast=self.dhcp_cfg.get("broadcast", "192.168.56.255"),
                                              file_server=self.dhcp_cfg.get("file_server", "192.168.56.120"),
                                              file_name=self.dhcp_cfg.get("file_name", None),
                                              file_option=self.dhcp_cfg.get("file_option",
                                                                                 {"option": 77,
                                                                                  "file_name":{"iPXE": "pxelinux.cfg"},
                                                                                  "default_file": "undionly.kpxe"}),
                                              use_ipxe=False,
                                              use_http=False,
                                              mode_proxy=self.dhcp_cfg.get("mode_proxy", False),
                                              mode_debug=do_debug_verbose(self.sys_cfg.get('mode_debug'), 'dhcp'),
                                              mode_verbose=do_debug_verbose(self.sys_cfg.get('mode_verbose'), 'dhcp'),
                                              whitelist=False,
                                              log_file=self.dhcp_cfg.get("log_file", None),
                                              saveleases=self.dhcp_cfg.get("leases_file", None),
                                              win_exit_flag=g_win_exit_flag_dhcp,
                                              leases_out=g_dhcp_leases)
                self.servers.append(self.dhcp_server)
            except :
                traceback.print_exc()

        # http
        # if self.sys_cfg.get("http_enable", False) and server_cfg.get("http_cfg", None):
        #     try:
        #         self.http_logger = helpers.get_child_logger(self.sys_logger, "http_log")
        #         self.http_cfg = server_cfg.get("http_cfg", None)
        #         self.http_cfg["logger"] = self.http_logger
        #         self.http_server = HTTPServer(**self.http_cfg)
        #         self.http_server.start()
        #
        #     except:
        #         self.http_server = None
        #         traceback.print_exc()

        # nbd
        # signal.signal(signal.SIGCHLD, self.read_leases)

        signal.signal(signal.SIGINT, self.stop)

    def start(self):
        for server in self.servers:
            server.start()

        sleep(0.5)

        for server in self.servers:
            self.sys_logger.info("{0} start {1}".format(server.name, "Success" if server.is_alive() else "Fail"))

    def stop(self, signum=None, frame=None):
        import platform
        if helpers.SysWindow == helpers.get_sys_type():
            # windows
            for server in self.servers:

                # signal包主要是针对UNIX平台(比如Linux, MAC
                # OS)，而Windows内核中由于对信号机制的支持不充分，所以在Windows上的Python不能发挥信号系统的功能。在windows上
                # terminate()不发送信号直接退出进程。这里使用共享内存设置标记，进程在循环时检查标记，保存数据后自己退出
                # os.popen("taskkill /pid {}".format(server.pid))
                global g_win_exit_flag_tftp
                global g_win_exit_flag_dhcp
                global g_win_exit_flag_http
                g_win_exit_flag_tftp.value = True
                g_win_exit_flag_dhcp.value = True
                g_win_exit_flag_http.value = True

        elif helpers.SysLinux == helpers.get_sys_type():
            for server in self.servers:
                server.terminate()
                sleep(0.5)
                os.kill(server.pid, signal.SIGTERM)
        else:
            for server in self.servers:
                server.terminate()
                # server.jion()

        sleep(0.5)

        for server in self.servers:
            self.sys_logger.info("{0} stop {1}".format(server.name, "Success" if not server.is_alive() else "Fail"))

        if signum == signal.SIGTERM:
            sys.exit()

    def get_dhcp_lease(self):
        if self.dhcp_server:
            pass

    def read_leases(self):
        print "test"


# test
if __name__ == "__main__":

    # print helpers.get_netcard()
    if helpers.SysWindow == helpers.get_sys_type():
        local_ip = '192.168.56.120'
        offer_from = "192.168.56.150"
        offer_to = "192.168.56.200"
        router = "192.168.56.1"
        broadcast = "192.168.56.255"
        file_server = "192.168.56.120"
        netboot_dir = r"E:\code\PyPXE\netboot"

    # elif helpers.SysLinux == helpers.get_sys_type():
    else:
        local_ip = "12.34.56.78"
        offer_from = "12.34.56.100"
        offer_to = "12.34.56.200"
        router = "12.34.56.1"
        broadcast = "12.34.56.255"
        file_server = "12.34.56.78"
        netboot_dir = r"~/netboot"

    ipx_cfg = {
        "sys_cfg": {
            # log
            # "syslog_file": "ipxe.log",

            # debug
            "mode_debug": "all",
            "mode_verbose": "all",

            # server enable
            "tftp_enable": True,
            "dhcp_enable": True,
            "http_enable": False,
            "nbd_enable": False,


        },

        "tftp_cfg": {
            "ip": local_ip,
            # "port": 69,   # should use default
            "netboot_dir": netboot_dir,

        },

        "dhcp_cfg": {
            "ip": local_ip,
            # "port": 67,
            "offer_from": offer_from,
            "offer_to": offer_to,
            "subnet_mask": "255.255.255.0",
            "router": "192.168.56.1",
            "broadcast": broadcast,
            # "dns_server": '8.8.8.8',
            "file_server": file_server,
            "file_option": {"option": 77,
                            "file_name": {"iPXE": "pxelinux.cfg"},
                            "default_file:": "undionly.kpxe"},
            "proxy": False,

            # "log_file": "dhcp.log",
            "leases_file": "leases.json",
        },
        "http_cfg": {

        },

        "nbd_cfg": {

        },
    }

    ipxe_server = IPXEServer(**ipx_cfg)
    ipxe_server.start()

    signal.signal(signal.SIGINT, ipxe_server.stop)
    # sleep(20)
    # ipxe_server.stop()
    # read_leases()
    while True:
        pass








