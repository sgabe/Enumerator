#!/usr/bin/env python
"""
The HTTP module performs http-related
enumeration tasks.

@author: Steve Coward (steve<at>sugarstack.io)
@version: 1.0
"""
import sys
from ..config import Config
from ..process_manager import ProcessManager
from ..generic_service import GenericService


class HttpEnumeration(GenericService, ProcessManager):
    SERVICE_DEFINITION = 'service:http,-proxy or port:8081'
    PROCESSES = [{
        'command': 'nmap -sV -Pn -p %(port)s %(scan_mode)s \
            --script=http-title,http-favicon,http-headers,http-methods,http-php-version,http-enum,http-robots.txt,http-shellshock \
            -oN %(output_dir)s/%(host)s-http-%(port)s-standard.txt %(host)s',
        'normal': '-T4',
        'stealth': '-T2',
    }, {
        'command': 'nikto -F txt %(scan_mode)s -o %(output_dir)s/%(host)s-http-%(port)s-nikto.txt -h %(host)s -p %(port)s',
        'normal': '',
        'stealth': '-Tuning 1 2',
    }, {
        'command': 'dirb %(url)s %(wordlist)s -o %(output_dir)s/%(host)s-http-%(port)s-dirb.txt -r -S -w %(scan_mode)s',
        'normal': '',
        'stealth': '-z 400',
    }, {
        'command': 'EyeWitness --single %(url)s:%(port)s --web --no-prompt --timeout 15 -d %(output_dir)s/eyewitness/%(port)s',
        'normal': '',
        'stealth': '',
    }]

    # TODO: Make these configurable either at runtime or via config file.
    # On the Kali distro, both of these files/paths exist.
    DIRB_WORDLISTS = '/usr/share/dirb/wordlists/common.txt,/usr/share/metasploit-framework/data/wmap/wmap_dirs.txt'

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
        config = Config().http

        print '[+] enumerating HTTP service on host %s port %s' % (ip, port)
        for process in self.PROCESSES:
            self.start_processes(process.get('command'), params={
                'host': ip,
                'port': port,
                'url': 'https://%s/' % ip if port == '443' else 'http://%s:%s/' % (ip, port),
                'output_dir': directory,
                'wordlist': self.DIRB_WORDLISTS,
                'scan_mode': process.get(config['mode']),
            }, display_exception=False)

if __name__ == '__main__':
    """For testing purposes, this
    module can be executed as a script.
    Use the following syntax from the root
    directory of enumerator:

    python -m lib.services.http <ip> <port> <output directory>
    """
    http = HttpEnumeration()
    http.scan(sys.argv[3], dict(ip=sys.argv[1], port=sys.argv[2]))
