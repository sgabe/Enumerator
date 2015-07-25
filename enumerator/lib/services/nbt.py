#!/usr/bin/env python
"""
The Netbios module performs netbios-related
enumeration tasks.

@author: Steve Coward (steve<at>sugarstack.io)
@author: Erik Dominguez (maleus<at>overflowsecurity.com)
@version: 1.0
"""
import sys
from .. import config
from ..process_manager import ProcessManager
from ..generic_service import GenericService


class NbtEnumeration(GenericService, ProcessManager):
    SERVICE_DEFINITION = 'port:139,445'
    PROCESSES = [{
        'command': 'enum4linux %(scan_mode)s %(host)s > %(output_dir)s/%(host)s-nbt-enum4linux.txt',
        'normal': '-a',
        'stealth': '-k -o',
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

        print '[+] enumerating NBT service on host %s' % ip
        for process in self.PROCESSES:
            self.start_processes(process.get('command'), params={
                'host': ip,
                'output_dir': directory,
                'scan_mode': process.get(config.mode),
            }, display_exception=False)

    def is_valid_service(self, attributes, services):
        """Returns True or False if the attributes
        of a service record match the definition of
        a service.

        @param attributes: Dict value of a scanned service
        (service,port,state).

        @param services: List of dict values of all scanned services
        (service,port,state).
        """
        service = attributes.get('service')
        port = attributes.get('port')
        state = attributes.get('state')

        if state != 'open':
            return False

        # Prevent duplicate execution
        if port == '445' and list((s for s in services if (s['port'] == '139') and (s['state'] == 'open'))):
            return False

        # The keys in rule will map to service, port and status set above.
        return eval(self.compiled_service_definition)

if __name__ == '__main__':
    """For testing purposes, this
    module can be executed as a script.
    Use the following syntax from the root
    directory of enumerator:

    python -m lib.services.nbt <ip> <output directory>
    """
    nbt = NbtEnumeration()
    nbt.scan(sys.argv[2], dict(ip=sys.argv[1]))
