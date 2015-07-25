#!/usr/bin/env python
"""
The RDP module performs rdp-related
enumeration tasks.

@author: Gabor Seljan (gabor<at>seljan.hu)
@version: 1.0
"""
import sys
from ..config import Config
from ..process_manager import ProcessManager
from ..generic_service import GenericService


class RdpEnumeration(GenericService, ProcessManager):
    SERVICE_DEFINITION = 'service:ms-wbt-server'
    PROCESSES = [{
        'command': 'nmap -sV -Pn -p %(port)s %(scan_mode)s \
            --script=rdp-enum-encryption,rdp-vuln-ms12-020 \
            -oN %(output_dir)s/%(host)s-rdp-%(port)s-standard.txt %(host)s',
        'normal': '-T4',
        'stealth': '-T2',
    }, {
        'command': 'rdp-sec-check %(host)s:%(port)s --outfile %(output_dir)s/%(host)s-rdp-%(port)s-rdpseccheck.txt',
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
        config = Config().rdp

        print '[+] enumerating RDP service on host %s port %s' % (ip, port)
        for process in self.PROCESSES:
            self.start_processes(process.get('command'), params={
                'host': ip,
                'port': port,
                'output_dir': directory,
                'scan_mode': process.get(config['mode']),
            }, display_exception=False)

if __name__ == '__main__':
    """For testing purposes, this
    module can be executed as a script.
    Use the following syntax from the root
    directory of enumerator:

    python -m lib.services.rdp <ip> <port> <output directory>
    """
    rdp = RdpEnumeration()
    rdp.scan(sys.argv[3], dict(ip=sys.argv[1], port=sys.argv[2]))
