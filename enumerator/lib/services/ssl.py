#!/usr/bin/env python
"""
The SSL module performs ssl-related
enumeration tasks.

@author: Gabor Seljan (gabor<at>seljan.hu)
@version: 1.0
"""
import sys
from .. import config
from ..process_manager import ProcessManager
from ..generic_service import GenericService


class SslEnumeration(GenericService, ProcessManager):
    SERVICE_DEFINITION = 'service:ssl/http,ssl/smtp,ssl/imap,ssl/pop3,https,smtps,imaps,pop3s'
    PROCESSES = [{
        'command': 'nmap -sV -Pn -p %(port)s %(scan_mode)s \
            --script=ssl-ccs-injection,ssl-cert,ssl-date,ssl-enum-ciphers,ssl-google-cert-catalog,ssl-heartbleed,ssl-known-key,ssl-poodle,sslv2 \
            -oN %(output_dir)s/%(host)s-ssl-%(port)s-standard.txt %(host)s',
        'normal': '-T4',
        'stealth': '-T2',
    }, {
        'command': 'testssl.sh %(host)s:%(port)s | aha > %(output_dir)s/%(host)s-ssl-%(port)s-testssl.html',
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

        print '   [-] enumerating SSL service on host %s' % ip
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

    python -m lib.services.ssl <ip> <port> <output directory>
    """
    ssl = SslEnumeration()
    ssl.scan(sys.argv[3], dict(ip=sys.argv[1], port=sys.argv[2]))
