# encoding: utf-8
'''

This file contains classes and functions that implement the PyPXE DHCP service

'''

import socket
import struct
import logging
import signal
import json
from collections import defaultdict
from time import time
from multiprocessing import Process, Value, Array
import sys
import helpers


# g_dhcp_leases = Array('b', 1024 * 1024 * [0]) if "Window" in platform.system() else None
# g_win_exit_flag_dhcp = Value('B', False) if "Window" in platform.system() else None

class OutOfLeasesError(Exception):
    pass


def default_dict():
    return {'ip': '', 'expire': 0, 'ipxe': False}


class DHCPD(Process):
    '''
        This class implements a DHCP Server, limited to PXE options.
        Implemented from RFC2131, RFC2132,
        https://en.wikipedia.org/wiki/Dynamic_Host_Configuration_Protocol,
        and http://www.pix.net/software/pxeboot/archive/pxespec.pdf.
    '''
    def __init__(self, **server_settings):
        Process.__init__(self, name='dhcp_server')

        self.ip = server_settings.get('ip', '192.168.2.2')
        self.port = int(server_settings.get('port', 67))
        self.offer_from = server_settings.get('offer_from', '192.168.2.100')
        self.offer_to = server_settings.get('offer_to', '192.168.2.150')
        self.subnet_mask = server_settings.get('subnet_mask', '255.255.255.0')
        self.router = server_settings.get('router', '192.168.2.1')
        self.dns_server = server_settings.get('dns_server', '8.8.8.8')

        self.broadcast = server_settings.get('broadcast', '')
        if not self.broadcast:
            # calculate the broadcast address from ip and subnet_mask
            nip = struct.unpack('!I', socket.inet_aton(self.ip))[0]
            nmask = struct.unpack('!I', socket.inet_aton(self.subnet_mask))[0]
            nbroadcast = (nip & nmask) | ((~ nmask) & 0xffffffff)
            derived_broadcast = socket.inet_ntoa(struct.pack('!I', nbroadcast))
            self.broadcast = derived_broadcast

        self.file_server = server_settings.get('file_server', '192.168.2.2')
        self.file_name = server_settings.get('file_name', '')
        self.file_option_name = server_settings.get("file_option_name", {"pxe": "undionly.kpxe",
                                                                         "ipxe": "ipxelinux.0"})
        if not self.file_name:
            self.force_file_name = False
            self.file_name = 'pxelinux.0'
        else:
            self.force_file_name = True
        self.ipxe = server_settings.get('use_ipxe', False)
        self.http = server_settings.get('use_http', False)
        self.mode_proxy = server_settings.get('mode_proxy', False)  # ProxyDHCP mode
        self.static_config = server_settings.get('static_config', dict())
        self.whitelist = server_settings.get('whitelist', False)
        self.mode_verbose = server_settings.get('mode_verbose', False)  # debug mode
        self.mode_debug = server_settings.get('mode_debug', False)  # debug mode
        self.log_file = server_settings.get('log_file', None)
        self.save_leases_file = server_settings.get('saveleases', '')

        self.magic = struct.pack('!I', 0x63825363)  # magic cookie
        self.options = dict()
        self.leases = defaultdict(default_dict)
        self.logger = logging.getLogger()
        # self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        signal.signal(signal.SIGTERM, self.export_leases)
        self.exit_flag = server_settings.get("win_exit_flag", None)
        self.leases_output_buffer = server_settings.get("leases_out", None)
        self.buffer_position = 0

    def before_listen(self):

        # setup logger
        self.logger = logging.getLogger('DHCP')
        handler = logging.StreamHandler() if self.log_file is None else logging.FileHandler(self.log_file)
        formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(name)s\t%(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

        if self.mode_debug:
            self.logger.setLevel(logging.DEBUG)
        elif self.mode_verbose:
            self.logger.setLevel(logging.INFO)
        else:
            self.logger.setLevel(logging.WARN)

        if self.http and not self.ipxe:
            self.logger.warning('HTTP selected but iPXE disabled. PXE ROM must support HTTP requests.')
        if self.ipxe and self.http:
            self.file_name = 'http://{0}/{1}'.format(self.file_server, self.file_name)
        if self.ipxe and not self.http:
            self.file_name = 'tftp://{0}/{1}'.format(self.file_server, self.file_name)

        self.logger.debug('NOTICE: DHCP server started in debug mode. DHCP server is using the following:')
        self.logger.debug('DHCP Server IP: {0}'.format(self.ip))
        self.logger.debug('DHCP Server Port: {0}'.format(self.port))

        # setup socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # socket.SO_BROADCAST 设置sock具有广播特性，下面绑定的时候不用指定具体网卡ip（指定ip时反而收不到），报文会从所有的网卡广播出去
        # 配置的ip会插入到报文中
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        return_code = self.sock.bind(('', self.port))
        self.logger.info("Bind return code: {}".format(return_code))
        self.sock.settimeout(1) if helpers.SysWindow == helpers.get_sys_type() else None

        # debug info for ProxyDHCP mode
        if not self.mode_proxy:
            self.logger.debug('Lease Range: {0} - {1}'.format(self.offer_from, self.offer_to))
            self.logger.debug('Subnet Mask: {0}'.format(self.subnet_mask))
            self.logger.debug('Router: {0}'.format(self.router))
            self.logger.debug('DNS Server: {0}'.format(self.dns_server))
            self.logger.debug('Broadcast Address: {0}'.format(self.broadcast))

        if self.static_config:
            self.logger.debug('Using Static Leasing')
            self.logger.debug('Using Static Leasing Whitelist: {0}'.format(self.whitelist))

        self.logger.debug('File Server IP: {0}'.format(self.file_server))
        self.logger.debug('File Name: {0}'.format(self.file_name))
        self.logger.debug('ProxyDHCP Mode: {0}'.format(self.mode_proxy))
        self.logger.debug('Using iPXE: {0}'.format(self.ipxe))
        self.logger.debug('Using HTTP Server: {0}'.format(self.http))

        # key is MAC
        # separate options dict so we don't have to clean up on export
        if self.save_leases_file:
            try:
                leases_file = open(self.save_leases_file, 'rb')
                imported = json.load(leases_file)
                import_safe = dict()
                self.logger.info('Loaded leases from {0}'.format(self.save_leases_file))
                for lease in imported:
                    packed_mac = struct.pack('BBBBBB', *map(lambda x:int(x, 16), lease.split(':')))
                    import_safe[packed_mac] = imported[lease]
                    self.output_leases(mac=lease,
                                       ip=imported[lease]['ip'],
                                       expire=imported[lease]['expire'])
                    self.logger.info("load lease: mac:{0} ip:{1}, expire:{2}".format(lease,
                                                                                     imported[lease]['ip'],
                                                                                     imported[lease]['expire']))
                self.leases.update(import_safe)
            except IOError, ValueError:
                pass

    def export_leases(self, signum=None, frame=None):
        if self.save_leases_file and len(self.leases):
            export_safe = dict()
            for lease in self.leases:
                # translate the key to json safe (and human readable) mac
                export_safe[self.get_mac(lease)] = self.leases[lease]
            leases_file = open(self.save_leases_file, 'wb')
            json.dump(export_safe, leases_file) if len(export_safe) else None
            self.logger.info('Exported leases to {0}'.format(self.save_leases_file))
        # if keyboard interrupt, propagate upwards
        if signum is not None:
            if signum == signal.SIGTERM:
                sys.exit()

    def output_leases(self, mac=None, ip=None, expire=None):
        if self.leases_output_buffer:
            lease = str({'mac': mac, 'ip': ip, 'expire': expire})
            for value in lease:
                self.leases_output_buffer[self.buffer_position] = value
                self.buffer_position += 1
            self.buffer_position += 1

    def get_namespaced_static(self, path, fallback={}):
        statics = self.static_config
        for child in path.split('.'):
            statics = statics.get(child, {})
        return statics if statics else fallback

    def next_ip(self):
        '''
            This method returns the next unleased IP from range;
            also does lease expiry by overwrite.
        '''

        # if we use ints, we don't have to deal with octet overflow
        # or nested loops (up to 3 with 10/8); convert both to 32-bit integers

        # e.g '192.168.1.1' to 3232235777
        encode = lambda x: struct.unpack('!I', socket.inet_aton(x))[0]

        # e.g 3232235777 to '192.168.1.1'
        decode = lambda x: socket.inet_ntoa(struct.pack('!I', x))
        from_host = encode(self.offer_from)
        to_host = encode(self.offer_to)

        # pull out already leased IPs
        leased = [self.leases[i]['ip'] for i in self.leases
                if self.leases[i]['expire'] > time()]

        # convert to 32-bit int
        leased = map(encode, leased)

        # loop through, make sure not already leased and not in form X.Y.Z.0
        for offset in xrange(to_host - from_host):
            if (from_host + offset) % 256 and from_host + offset not in leased:
                return decode(from_host + offset)
        raise OutOfLeasesError('Ran out of IP addresses to lease!')

    def tlv_encode(self, tag, value):
        '''Encode a TLV option.'''
        return struct.pack('BB', tag, len(value)) + value

    def tlv_parse(self, raw):
        '''Parse a string of TLV-encoded options.'''
        ret = {}
        while(raw):
            [tag] = struct.unpack('B', raw[0])
            if tag == 0: # padding
                raw = raw[1:]
                continue
            if tag == 255: # end marker
                break
            [length] = struct.unpack('B', raw[1])
            value = raw[2:2 + length]
            raw = raw[2 + length:]
            if tag in ret:
                ret[tag].append(value)
            else:
                ret[tag] = [value]
        return ret

    def get_mac(self, mac):
        '''
            This method converts the MAC Address from binary to
            human-readable format for logging.
        '''
        return ':'.join(map(lambda x: hex(x)[2:].zfill(2), struct.unpack('BBBBBB', mac))).upper()

    def craft_header(self, message):
        '''This method crafts the DHCP header using parts of the message.'''
        xid, flags, yiaddr, giaddr, chaddr = struct.unpack('!4x4s2x2s4x4s4x4s16s', message[:44])
        client_mac = chaddr[:6]

        # op, htype, hlen, hops, xid
        response =  struct.pack('!BBBB4s', 2, 1, 6, 0, xid)
        if not self.mode_proxy:
            response += struct.pack('!HHI', 0, 0, 0) # secs, flags, ciaddr
        else:
            response += struct.pack('!HHI', 0, 0x8000, 0)
        if not self.mode_proxy:
            if self.leases[client_mac]['ip'] and self.leases[client_mac]['expire'] > time(): # OFFER
                offer = self.leases[client_mac]['ip']
            else: # ACK
                offer = self.get_namespaced_static('dhcp.binding.{0}.ipaddr'.format(self.get_mac(client_mac)))
                offer = offer if offer else self.next_ip()
                self.leases[client_mac]['ip'] = offer
                self.leases[client_mac]['expire'] = time() + 86400

                # save leases
                self.output_leases(mac=self.get_mac(client_mac),
                                   ip=self.leases[client_mac]['ip'],
                                   expire=self.leases[client_mac]['expire'])
                self.logger.info('New Assignment - MAC: {0} -> IP: {1}'.format(self.get_mac(client_mac), self.leases[client_mac]['ip']))
            response += socket.inet_aton(offer) # yiaddr
        else:
            response += socket.inet_aton('0.0.0.0')
        response += socket.inet_aton(self.file_server) # siaddr
        response += socket.inet_aton('0.0.0.0') # giaddr
        response += chaddr # chaddr

        # BOOTP legacy pad
        response += chr(0) * 64 # server name
        if self.mode_proxy:
            response += self.file_name
            response += chr(0) * (128 - len(self.file_name))
        else:
            response += chr(0) * 128
        response += self.magic # magic section
        return (client_mac, response)

    def craft_options(self, opt53, client_mac):
        '''
            This method crafts the DHCP option fields
            opt53:
                2 - DHCPOFFER
                5 - DHCPACK
            See RFC2132 9.6 for details.
        '''
        response = self.tlv_encode(53, chr(opt53)) # message type, OFFER
        response += self.tlv_encode(54, socket.inet_aton(self.ip)) # DHCP Server
        if not self.mode_proxy:
            subnet_mask = self.get_namespaced_static('dhcp.binding.{0}.subnet'.format(self.get_mac(client_mac)), self.subnet_mask)
            response += self.tlv_encode(1, socket.inet_aton(subnet_mask)) # subnet mask
            router = self.get_namespaced_static('dhcp.binding.{0}.router'.format(self.get_mac(client_mac)), self.router)
            response += self.tlv_encode(3, socket.inet_aton(router)) # router
            dns_server = self.get_namespaced_static('dhcp.binding.{0}.dns'.format(self.get_mac(client_mac)), [self.dns_server])
            dns_server = ''.join([socket.inet_aton(i) for i in dns_server])
            response += self.tlv_encode(6, dns_server)
            response += self.tlv_encode(51, struct.pack('!I', 86400)) # lease time

        # TFTP Server OR HTTP Server; if iPXE, need both
        response += self.tlv_encode(66, self.file_server)

        # file_name null terminated
        filename = self.get_namespaced_static('dhcp.binding.{0}.rom'.format(self.get_mac(client_mac)))
        if not filename:
            # TODO: 支持文件可通过接口配置
            if not self.ipxe or not self.leases[client_mac]['ipxe']:
                # http://www.syslinux.org/wiki/index.php/PXELINUX#UEFI
                if 'options' in self.leases[client_mac] and 93 in self.leases[client_mac]['options'] and not self.force_file_name:
                    [arch] = struct.unpack("!H", self.leases[client_mac]['options'][93][0])
                    filename = {0: 'pxelinux.0', # BIOS/default
                                6: 'syslinux.efi32', # EFI IA32
                                7: 'syslinux.efi64', # EFI BC, x86-64
                                9: 'syslinux.efi64'  # EFI x86-64
                                }[arch]
                else:
                    filename = self.file_name
            else:
                filename = 'chainload.kpxe' # chainload iPXE
                if opt53 == 5: # ACK
                    self.leases[client_mac]['ipxe'] = False
        response += self.tlv_encode(67, filename.encode('ascii') + chr(0))

        if self.mode_proxy:
            response += self.tlv_encode(60, 'PXEClient')
            response += struct.pack('!BBBBBBB4sB', 43, 10, 6, 1, 0b1000, 10, 4, chr(0) + 'PXE', 0xff)
        response += '\xff'
        return response

    def dhcp_offer(self, message):
        '''This method responds to DHCP discovery with offer.'''
        client_mac, header_response = self.craft_header(message)
        options_response = self.craft_options(2, client_mac) # DHCPOFFER
        response = header_response + options_response
        self.logger.debug('DHCPOFFER - Sending the following')
        self.logger.debug('<--BEGIN HEADER-->')
        self.logger.debug('{0}'.format(repr(header_response)))
        self.logger.debug('<--END HEADER-->')
        self.logger.debug('<--BEGIN OPTIONS-->')
        self.logger.debug('{0}'.format(repr(options_response)))
        self.logger.debug('<--END OPTIONS-->')
        self.logger.debug('<--BEGIN RESPONSE-->')
        self.logger.debug('{0}'.format(repr(response)))
        self.logger.debug('<--END RESPONSE-->')
        self.sock.sendto(response, (self.broadcast, 68))

    def dhcp_ack(self, message):
        '''This method responds to DHCP request with acknowledge.'''
        client_mac, header_response = self.craft_header(message)
        options_response = self.craft_options(5, client_mac) # DHCPACK
        response = header_response + options_response
        self.logger.debug('DHCPACK - Sending the following')
        self.logger.debug('<--BEGIN HEADER-->')
        self.logger.debug('{0}'.format(repr(header_response)))
        self.logger.debug('<--END HEADER-->')
        self.logger.debug('<--BEGIN OPTIONS-->')
        self.logger.debug('{0}'.format(repr(options_response)))
        self.logger.debug('<--END OPTIONS-->')
        self.logger.debug('<--BEGIN RESPONSE-->')
        self.logger.debug('{0}'.format(repr(response)))
        self.logger.debug('<--END RESPONSE-->')
        self.sock.sendto(response, (self.broadcast, 68))

    def validate_req(self, client_mac):
        # client request is valid only if contains Vendor-Class = PXEClient
        if self.whitelist and self.get_mac(client_mac) not in self.get_namespaced_static('dhcp.binding'):
            self.logger.info('Non-whitelisted client request received from {0}'.format(self.get_mac(client_mac)))
            return False
        if 60 in self.options[client_mac] and 'PXEClient' in self.options[client_mac][60][0]:
            self.logger.info('PXE client request received from {0}'.format(self.get_mac(client_mac)))
            return True
        self.logger.info('Non-PXE client request received from {0}'.format(self.get_mac(client_mac)))
        return False

    def listen(self):
        '''Main listen loop.'''
        try:
            message, address = self.sock.recvfrom(1024)
            [client_mac] = struct.unpack('!28x6s', message[:34])
            self.logger.debug('Received message')
            self.logger.debug('<--BEGIN MESSAGE-->')
            self.logger.debug('{0}'.format(repr(message)))
            self.logger.debug('<--END MESSAGE-->')
            self.options[client_mac] = self.tlv_parse(message[240:])
            self.logger.debug('Parsed received options')
            self.logger.debug('<--BEGIN OPTIONS-->')
            self.logger.debug('{0}'.format(repr(self.options[client_mac])))
            self.logger.debug('<--END OPTIONS-->')
            if not self.validate_req(client_mac):
                return
            type = ord(self.options[client_mac][53][0]) # see RFC2131, page 10
            if type == 1:
                self.logger.debug('Sending DHCPOFFER to {0}'.format(self.get_mac(client_mac)))
                try:
                    self.dhcp_offer(message)
                except OutOfLeasesError:
                    self.logger.critical('Ran out of leases')
            elif type == 3 and address[0] == '0.0.0.0' and not self.mode_proxy:
                self.logger.debug('Sending DHCPACK to {0}'.format(self.get_mac(client_mac)))
                self.dhcp_ack(message)
            elif type == 3 and address[0] != '0.0.0.0' and self.mode_proxy:
                self.logger.debug('Sending DHCPACK to {0}'.format(self.get_mac(client_mac)))
                self.dhcp_ack(message)
        except socket.error:
            pass
    def run(self):
        self.before_listen()

        while True:
            self.listen()
            if self.exit_flag:
                if self.exit_flag.value:
                    self.export_leases()
                    sys.exit()


if __name__ == "__main__":
    exit_flag = Value('B', False)
    server = DHCPD(win_exit_flag=exit_flag)
    server.start()
    import time
    time.sleep(1)
    exit_flag.value = True
    time.sleep(3)
