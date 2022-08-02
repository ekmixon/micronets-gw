import re
import json
import netaddr
import logging

from pathlib import Path
from ipaddress import IPv4Network
from netaddr import EUI
from subprocess import call
from .utils import ip_addr_pattern, mac_addr_pattern, blank_line_re, comment_line_re

logger = logging.getLogger ('micronets-gw-service')

class IscDhcpdAdapter:
    block_start_re = re.compile ('^# %%MICRONET BLOCK START', re.ASCII)
    block_end_re = re.compile ('^# %%MICRONET BLOCK END', re.ASCII)

    micronet_block_prefix_re = re.compile ('^# %%MICRONET SUBNET (\w.[\w-]*)', re.ASCII)
    open_curly_line_re = re.compile ('^\s*{\s*(#.*)?$')
    closed_curly_line_re = re.compile ('^\s*}\s*(#.*)?$')

    # format: micronet <network address> netmask <network mask>
    micronet_start_re = re.compile ('^\s*micronet\s+(' + ip_addr_pattern + ')\s+netmask\s+('
                                  + ip_addr_pattern + ')\s*$', re.ASCII)

    # format: host <device/host name>
    host_start_re = re.compile ('^\s*host\s+([\w-]+)\s*$', re.ASCII)
    
    # format: hardware ethernet <host mac address> ; 
    hardware_ethernet_re = re.compile ('^\s*hardware\s+ethernet\s+(' + mac_addr_pattern + ')\s*;\s*$')
    
    # format: fixed-address <ip address> ; 
    fixed_address_re = re.compile ('^\s*fixed-address\s+(' + ip_addr_pattern + ')\s*;\s*$')

    # format: option routers <ip address> ;
    router_address_re = re.compile ('^\s*option\s+routers\s+(' + ip_addr_pattern + ')\s*;\s*$')

    # format: option broadcast-address <ip address> ;
    broadcast_address_re = re.compile ('^\s*option\s+broadcast-address\s+(' + ip_addr_pattern + ')\s*;\s*$')

    def __init__ (self, config):
        self.dhcpconf_path = Path (config ['ISC_DHCPD_CONF_FILE'])
        self.dhcpd_restart_command = config ['ISC_DHCPD_RESTART_COMMAND']
        logger.info (f"Instantiated IscDhcpdAdapter with {self.dhcpconf_path.absolute ()}")

    def read_from_conf (self):
        with self.dhcpconf_path.open ('r') as infile:
            infile.line_no = 0
            logger.info (f"IscDhcpdAdapter: Loading micronet data from {self.dhcpconf_path.absolute ()}")
            return self.parse_dhcp_conf (infile)

    def parse_dhcp_conf(self, infile):
        in_prefix = True
        self.prefix_lines = []
        self.postfix_lines = []
        for line in infile:
            infile.line_no += 1
            if in_prefix and self.block_start_re.match (line):
                self.micronet_block = self.parse_micronet_block (infile)
                in_prefix = False
            elif in_prefix:
                self.prefix_lines.append (line)
            else:
                self.postfix_lines.append (line)
        logger.info (f"Done reading {self.dhcpconf_path.absolute()}")
        return { 'prefix': self.prefix_lines, 
                 'micronets': self.micronet_block ['micronets'], 
                 'devices' : self.micronet_block ['devices'], 
                 'postfix': self.postfix_lines}

    def parse_micronet_block(self, infile):
        micronets = {}
        devices = {}
        for line in infile:
            infile.line_no += 1
            if self.block_end_re.match (line):
                break
            if (self.blank_line_re.match (line)):
                continue
            if micronet_prefix_match_result := self.micronet_block_prefix_re.match(
                line
            ):
                micronet_block_name = micronet_prefix_match_result.group (1)
                # logger.debug ("  Found micronet prefix: {}".format (micronet_block_name))
                micronet_block = self.parse_micronet_block (infile, micronet_block_name)
                micronets [micronet_block_name] = micronet_block ['micronet']
                devices [micronet_block_name] = micronet_block ['devices']
                continue
            if (self.comment_line_re.match (line)):
                continue
        return {'micronets' : micronets, 'devices': devices}

    def parse_micronet_block(self, infile, micronet_name):
        # The first line of a micronet block has to start with "micronet"
        line = infile.readline ()
        infile.line_no += 1
        micronet_match_result = self.micronet_start_re.match (line)
        if (not micronet_match_result):
            return None
        micronet = {
            'micronetId': micronet_name,
            'ipv4Network': {
                'network': micronet_match_result.group(1),
                'mask': micronet_match_result.group(2),
            },
        }

        devices = {}
        if (not self.open_curly_line_re.match (infile.readline ())):
            return None
        for line in infile:
            infile.line_no += 1
            if (self.closed_curly_line_re.match (line)):
                break
            if (self.blank_line_re.match (line)):
                continue
            if (self.comment_line_re.match (line)):
                continue
            if router_match_result := self.router_address_re.match(line):
                router_address = router_match_result.group (1)
                micronet ['gateway'] = router_address
                continue
            if broadcast_match_result := self.broadcast_address_re.match(line):
                broadcast_address = broadcast_match_result.group (1)
                # Not really anything to do here 
                continue
            if host_match_result := self.host_start_re.match(line):
                host_name = host_match_result.group (1)
                device_result = self.parse_device_block (infile, host_name)
                if (not isinstance (device_result, dict)): # There must have been an error
                    return device_result
                devices [device_result ['deviceId']] = device_result
                continue
            # If none of the REs match, bail out
            raise Exception(
                f"Unrecognized micronet entry on line {infile.line_no}: {line.rstrip()}"
            )

        return {'micronetId' : micronet_name, 'micronet': micronet, 'devices': devices}

    def parse_device_block(self, infile, device_name):
        infile.line_no += 1
        if (not self.open_curly_line_re.match (infile.readline ())):
            return None
        device = {'deviceId': device_name}
        for line in infile:
            infile.line_no += 1
            if (self.closed_curly_line_re.match (line)):
                break
            if (blank_line_re.match (line)):
                continue
            if (comment_line_re.match (line)):
                continue
            if hardware_ethernet_match_result := self.hardware_ethernet_re.match(
                line
            ):
                host_mac_address = hardware_ethernet_match_result.group (1)
                device ['macAddress'] = {'eui48': host_mac_address}
                continue
            if fixed_address_match_result := self.fixed_address_re.match(line):
                ipv4_address = fixed_address_match_result.group (1)
                device ['networkAddress'] = {'ipv4': ipv4_address}
                continue
            # If none of the REs match, bail out
            raise Exception(
                f"Unrecognized device entry on line {infile.line_no}: {line.rstrip()}"
            )

        if 'macAddress' not in device:
            return f'Error: Device {device_name} is missing a "hardware ethernet" entry'
        if 'networkAddress' not in device:
            return f'Error: Device {infile.fileno()} is missing a fixed-address entry'
        return device

    def save_to_conf (self, micronets, devices):
        with self.dhcpconf_path.open ('w') as outfile:
            logger.info ("IscDhcpdAdapter: Saving micronet data to {self.dhcpconf_path.absolute ()}")
            self.write_dhcp_conf (outfile)
        if self.dhcpd_restart_command:
            logger.info (f"Restarting ISC dhcp daemon ('{self.dhcpd_restart_command}')")
            call (self.dhcpd_restart_command)

    def write_dhcp_conf (self, outfile):
        for line in self.prefix_lines:
            outfile.write (line)
        self.write_micronets (outfile)
        for line in self.postfix_lines:
            outfile.write (line)

    def write_micronets(self, outfile):
        outfile.write ("# %%MICRONET BLOCK START\n")
        outfile.write ("# DO NOT modify anything between here and %%MICRONET BLOCK END\n")
        for micronet_id, micronet in self.micronet_block ['micronets'].items ():
            outfile.write(f"\n# %%MICRONET SUBNET {micronet_id}\n")
            ipv4_params = micronet ['ipv4Network']
            network_addr = ipv4_params['network']
            netmask = ipv4_params ['mask']
            outfile.write(f"micronet {network_addr} netmask {netmask}\n")
            outfile.write ("{\n")
            network = IPv4Network(f"{network_addr}/{netmask}")
            outfile.write(f"  option broadcast-address {network.broadcast_address};\n")
            if 'gateway' in ipv4_params:
                outfile.write(f"  option routers {ipv4_params['gateway']};\n")
            self.write_devices_for_micronet (outfile, micronet_id)
            outfile.write ("}\n")
        outfile.write ("# %%MICRONET BLOCK END\n")

    def write_devices_for_micronet(self, outfile, micronetId):
        device_list = self.micronet_block ['devices'] [micronetId].items ()
        for device_id, device in device_list:
            mac_addr = EUI (device ['macAddress']['eui48'])
            mac_addr.dialect = netaddr.mac_unix_expanded
            outfile.write(f"  host {device_id}\n")
            outfile.write ("  {\n")
            outfile.write(f"    hardware ethernet {mac_addr};\n")
            outfile.write(f"    fixed-address {device ['networkAddress']['ipv4']};\n")
            outfile.write ("  }\n")
        
if __name__ == '__main__':
    print ("Running ISC DHCPD conf parse/generation test smoke tests")
    dhcp_conf_path = "doc/dhcpd-sample.conf"
    dhcp_conf_parser = IscDhcpdAdapter (dhcp_conf_path)

    dhcp_conf = dhcp_conf_parser.read_from_conf ()
    print ("Done parsing. Found: ")
    print ("\nFound prefix:\n")
    for line in dhcp_conf ['prefix']:
        print (line.rstrip ())
    print ("Found micronets:")
    print (json.dumps (dhcp_conf ['micronets'], indent=2))
    print ("Found devices:")
    print (json.dumps (dhcp_conf ['devices'], indent=2))
    print ("\Found postfix:\n")
    for line in dhcp_conf ['postfix']:
        print (line.rstrip ())
