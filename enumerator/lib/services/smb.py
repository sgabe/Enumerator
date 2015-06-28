#!/usr/bin/env python
"""
The SMB module performs smb-related
enumeration tasks.

@author: Gabor Seljan (gabor<at>seljan.hu)
@version: 1.0
"""
import sys
from .. import config
from ..process_manager import ProcessManager
from ..generic_service import GenericService


class SmbEnumeration(GenericService, ProcessManager):
    SERVICE_DEFINITION = 'service:netbios-ssn,microsoft-ds or port:139,445'
    PROCESSES = [{
        'command': 'nmap -sV -Pn -p %(port)s %(scan_mode)s \
            --script=smb-os-discovery,smb-system-info,smb-check-vulns,smb-enum-users,smb-enum-shares,smb-enum-processes,smb-enum-sessions,smb-vuln-ms10-061 --script-args=unsafe=1 \
            -oN %(output_dir)s/%(host)s-smb-%(port)s-standard.txt %(host)s',
        'normal': '-T4',
        'stealth': '-T2',
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

        print '   [-] enumerating SMB service on host %s' % ip
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

    python -m lib.services.smb <ip> <port> <output directory>
    """
    smb = SmbEnumeration()
    smb.scan(sys.argv[3], dict(ip=sys.argv[1], port=sys.argv[2]))
