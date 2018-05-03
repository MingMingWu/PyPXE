# encoding: utf-8
# file name: ipxe_server.py


# import http
import dhcp
# import tftp
# import nbd

import logging
import logging.handlers
import traceback
# import helpers
import os
from time import sleep
import multiprocessing

g_dhcp_leases = multiprocessing.RawValue('B', 1024 * 1024)

def do_debug_verbose(cfg, service):
    return ((service.lower() in cfg.lower()
            or 'all' in cfg.lower())
            and '-{0}'.format(service.lower()) not in cfg.lower())


class IPXEServer(object):
    def __init__(self, **server_cfg):

        self.tftp_server = None
        self.dhcp_server = None
        self.http_server = None

        # get cfg
        self.sys_cfg = server_cfg.get("sys_cfg", None)
        self.tftp_cfg = server_cfg.get("tft_cfg", None)
        self.dhcp_cfg = server_cfg.get("dhcp_cfg", None)
        self.http_cfg = server_cfg.get("http_cfg", None)

        # system cfg
        if self.sys_cfg:
            self.syslog_name = self.sys_cfg.get("syslog_file", None)
            self.tftp_enable = self.sys_cfg.get("tft_enable", False)
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
            self.sys_logger.debug("PyPXE system config confirmed")
            self.sys_logger.debug("system log: {}".format("StreamHandler" if self.syslog_name is None else self.syslog_name))
            self.sys_logger.debug("system debug mode: {}".format(do_debug_verbose(self.sys_cfg.get('mode_debug'),
                                                                                 'pypxe')))
            self.sys_logger.debug("system verbose mode: {}".format(do_debug_verbose(self.sys_cfg.get('mode_verbose'),
                                                                                   'pypxe')))
            self.sys_logger.debug("tftp server enable: {}".format(self.tftp_enable))
            self.sys_logger.debug("dhcp server enable: {}".format(self.dhcp_enable))
            self.sys_logger.debug("http server enable: {}".format(self.http_enable))

        else:
            self.sys_logger = None

        # tftp cfg
        # if self.sys_cfg.get("tftp_enable", False) and server_cfg.get("tftp_cfg", False):
        #     try:
        #         self.tftp_logger = helpers.get_child_logger(self.sys_logger, "tftp_log")
        #         self.tftp_cfg = server_cfg.get("tftp_cfg", None)
        #         self.tftp_cfg["logger"] = self.tftp_logger
        #         self.tftp_cfg["mode_debug"] = self.sys_cfg.get("debug", False)
        #         self.tftp_cfg["mode_verbose"] = self.sys_cfg.get("verbose", False)
        #         self.tftp_server = tftp.TFTPD(
        #             ip=self.tftp_cfg.get("ip", "12.34.56.78"),
        #             port=self.tftp_cfg.get("port", 69),
        #             netboot_directory=self.tftp_cfg.get("netboot_directory", "~"),
        #             mode_debug=self.sys_cfg.get("mode_debug", False),
        #             mode_verbose=self.sys_cfg.get("mode_verbose", False),
        #             logger=self.tftp_logger)
        #         self.tftp_process = Process(target=self.tftp_server)
        #         self.tftp_process.daemon = True
        #         self.tftp_process.start()
        #         self.tftp_logger.info("tftp server isAlive:{0}".format(self.tftp_server.isAlive()))
        #     except:
        #         self.tft_server = None
        #         traceback.print_exc()

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
                                              file_name=self.dhcp_cfg.get("file_name", "undionly.kpxe"),
                                              file_option_name=self.dhcp_cfg.get("file_option_name",
                                                                                 {"pxe": "undionly.kpxe",
                                                                                  "ipxe": "ipxelinux.0"}),
                                              use_ipxe=False,
                                              use_http=False,
                                              mode_proxy=self.dhcp_cfg.get("mode_proxy", False),
                                              mode_debug=do_debug_verbose(self.sys_cfg.get('mode_debug'), 'dhcp'),
                                              mode_verbose=do_debug_verbose(self.sys_cfg.get('mode_verbose'), 'dhcp'),
                                              whitelist=False,
                                              log_file=self.dhcp_cfg.get("log_file", None),
                                              saveleases=self.dhcp_cfg.get("leases_file", None),
                                              )
            except :
                traceback.print_exc()

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

    def start(self):
        if self.tftp_server:
            self.tftp_server.start()
        if self.dhcp_server:
            self.dhcp_server.start()

    def stop(self):
        if self.tftp_server:
            self.tftp_server.terminal()
        if self.dhcp_server:
            self.dhcp_server.terminate()
            sleep(1)
            print self.dhcp_server

    def get_dhcp_lease(self):
        if self.dhcp_server:
            pass


# test
if __name__ == "__main__":

    ipx_cfg = {
        "sys_cfg": {
            # log
            # "syslog_file": "ipxe.log",

            # debug
            "mode_debug": "all",
            "mode_verbose": "",

            # server enable
            "tftp_enable": False,
            "dhcp_enable": True,
            "http_enable": False,
            "nbd_enable": False,


        },

        "tftp_cfg": {
            "ip": "12.34.56.78",
            # "port": 69,   # should use default
            "netboot_dir": "~"

        },

        "dhcp_cfg": {
            "ip": "192.168.56.120",
            # "port": 67,
            "offer_from": "192.168.56.150",
            "offer_to": "192.168.56.200",
            "subnet_mask": "255.255.255.0",
            "router": "192.168.56.1",
            "broadcast": "192.168.56.255",
            "dns_server": "8.8.8.8",
            "file_server": "192.168.56.120",
            "file_option_name":{
                "pxe": "undionly.kpxe",
                "ipxe": "pxelinux.0",
            },
            "proxy": False,

            # "log_file": "dhcp.log",
            "leases_file": "leases.json",
        },
        "http_cfg": {

        },

        "nbd_cfg": {

        },
    }

    import signal
    ipxe_server = IPXEServer(**ipx_cfg)
    ipxe_server.start()
    # sleep(2)
    # ipxe_server.stop()
    while True:
        pass







