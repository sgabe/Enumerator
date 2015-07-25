#!/usr/bin/env python
"""
The SNMP module performs snmp-related
enumeration tasks.

@author: Gabor Seljan (gabor<at>seljan.hu)
@version: 1.0
"""
import sys
from .. import config
from ..process_manager import ProcessManager
from ..generic_service import GenericService


class SnmpEnumeration(GenericService, ProcessManager):
    SERVICE_DEFINITION = 'service:snmp'
    PROCESSES = [{
        'command': 'nmap -sU -Pn -p %(port)s %(scan_mode)s \
            --script=snmp-brute,snmp-interfaces,snmp-netstat,snmp-processes,snmp-sysdescr,snmp-win32-users,snmp-win32-services,snmp-win32-shares,snmp-win32-software \
            -oN %(output_dir)s/%(host)s-snmp-%(port)s-standard.txt %(host)s',
        'normal': '-T4',
        'stealth': '-T2',
    }, {
        'command': 'onesixtyone -o %(output_dir)s/%(host)s-snmp-%(port)s-onesixtyone.txt %(host)s',
        'normal': '',
        'stealth': '',
    }, {
        'command': 'snmpwalk -c public -v1 %(host)s 1 > %(output_dir)s/%(host)s-snmp-%(port)s-snmpwalk.txt',
        'normal': '',
        'stealth': '',
    }, {
        'command': 'snmpcheck -t %(host)s > %(output_dir)s/%(host)s-snmp-%(port)s-snmpcheck.txt',
        'normal': '',
        'stealth': '',
    }]

    def scan(self, directory, service_parameters):
        """Iterates over PROCESSES and builds
        the specific parameters required for
        command line execution of each process.

        @param directory: Directory path where
        final command output will go.

        @param service_parameters: Dictionary with
        key:value pairs of service-related data.
        """

        ip = service_parameters.get('ip')
        port = service_parameters.get('port')

        print '[+] enumerating SNMP service on host %s port %s' % (ip, port)
        for process in self.PROCESSES:
            self.start_processes(process.get('command'), params={
                'host': ip,
                'port': port,
                'output_dir': directory,
                'scan_mode': process.get(config.mode),
            }, display_exception=False)

if __name__ == '__main__':
    """For testing purposes, this
    module can be executed as a script.
    Use the following syntax from the root
    directory of enumerator:

    python -m lib.services.snmp <ip> <port> <output directory>
    """
    snmp = SnmpEnumeration()
    snmp.scan(sys.argv[3], dict(ip=sys.argv[1], port=sys.argv[2]))
