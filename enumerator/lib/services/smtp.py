#!/usr/bin/env python
"""
The SMTP module performs smtp-related
enumeration tasks.

@author: Gabor Seljan (gabor<at>seljan.hu)
@version: 1.0
"""
import sys
from ..config import Config
from ..process_manager import ProcessManager
from ..generic_service import GenericService


class SmtpEnumeration(GenericService, ProcessManager):
    SERVICE_DEFINITION = 'service:smtp'
    PROCESSES = [{
        'command': 'nmap -Pn -p %(port)s %(scan_mode)s \
            --script=smtp-enum-users --script-args=smtp-enum-users.methods={VRFY} \
            -oN %(output_dir)s/%(host)s-smtp-%(port)s-standard.txt %(host)s',
        'normal': '-T4',
        'stealth': '-T2',
    }, {
        'command': 'smtp-user-enum -U %(static_path)s/user.txt -t %(host)s\
            > %(output_dir)s/%(host)s-smtp-%(port)s-smtpuserenum.txt',
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
        config = Config().smtp

        print '[+] enumerating SMTP service on host %s port %s' % (ip, port)
        for process in self.PROCESSES:
            self.start_processes(process.get('command'), params={
                'host': ip,
                'port': port,
                'output_dir': directory,
                'static_path': self.static_path,
                'scan_mode': process.get(config['mode']),
            }, display_exception=False)

if __name__ == '__main__':
    """For testing purposes, this
    module can be executed as a script.
    Use the following syntax from the root
    directory of enumerator:

    python -m lib.services.smtp <ip> <port> <output directory>
    """
    smtp = SmtpEnumeration()
    smtp.scan(sys.argv[3], dict(ip=sys.argv[1], port=sys.argv[2]))
