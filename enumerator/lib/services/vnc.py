#!/usr/bin/env python
"""
The VNC module performs vnc-related
enumeration tasks.

@author: Gabor Seljan (gabor<at>seljan.hu)
@version: 1.0
"""
import sys
from ..config import Config
from ..process_manager import ProcessManager
from ..generic_service import GenericService


class VncEnumeration(GenericService, ProcessManager):
    SERVICE_DEFINITION = 'service:vnc'
    PROCESSES = [{
        'command': 'nmap -sV -Pn -p %(port)s %(scan_mode)s \
            --script=vnc-brute,vnc-info \
            -oN %(output_dir)s/%(host)s-vnc-%(port)s-standard.txt %(host)s',
        'normal': '-T4',
        'stealth': '-T2'
    }, {
        'command': 'EyeWitness --single %(host)s:%(port)s --vnc --no-prompt --timeout 15 -d %(output_dir)s/eyewitness/%(port)s',
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
        config = Config().vnc

        print '[+] enumerating VNC service on host %s port %s' % (ip, port)
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

    python -m lib.services.vnc <ip> <port> <output directory>
    """
    vnc = VncEnumeration()
    vnc.scan(sys.argv[3], dict(ip=sys.argv[1], port=sys.argv[2]))
