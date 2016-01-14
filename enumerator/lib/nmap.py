#!/usr/bin/env python
"""This module is the first
step in gathering initial
service enumeration data from
a list of hosts. It initializes
the scanning commands and parses
the scan results. The scan results
are then passed to the delegator
module which determines what enumerator
should do next.

@author: Steve Coward (steve<at>sugarstack.io)
@version: 1.0
"""
import sys
import os
import re
import glob
import subprocess
from blinker import signal

from config import Config
import delegator
from .process_manager import ProcessManager

PROCESSES = [{
    'command': 'nmap -Pn %(scan_mode)s -sS -sV -oN %(output_dir)s/%(host)s-tcp-standard.txt -oG %(output_dir)s/%(host)s-tcp-greppable.txt -oX %(output_dir)s/%(host)s-tcp.xml %(host)s',
    'normal': '-T4 -p-',
    'stealth': '-T2',
}, {
    'command': 'nmap -Pn %(scan_mode)s -sU -sV --open -oN %(output_dir)s/%(host)s-udp-standard.txt -oG %(output_dir)s/%(host)s-udp-greppable.txt -oX %(output_dir)s/%(host)s-udp.xml %(host)s',
    'normal': '-T4 --top-ports 100',
    'stealth': '-T2 --top-ports 10',
}]

# Refined regex pattern for greppable nmap output.
SERVICE_PATTERN = re.compile(
    '\s(\d+)\/([^/]+)?\/([^/]+)?\/([^/]+)?\/([^/]+)?\/([^/]+)?\/([^/]+)?\/')

# Instantiate signal to delegate further service enumeration.
delegate_service_enumeration = signal('delegate_service_enumeration')
delegate_service_enumeration.connect(delegator.receive_service_data)


def parse_results(ip, directory):
    """Find greppable nmap scan output, extract service data.

    @param ip: IP Address

    @param directory: Directory to search for scan input
    """

    # Output structure to store results
    results = {
        ip: {
            'tcp': [],
            'udp': [],
        },
    }

    # Find greppable nmap output files
    scan_output = glob.glob('%s/*greppable*' % directory)
    for output_file in scan_output:
        contents = ''
        with open(output_file, 'r') as fh:
            contents = fh.read()

        # Locate service-related output from file contents
        services = SERVICE_PATTERN.findall(contents)
        for service_entry in services:
            try:
                port, state, protocol, owner, service, rpc_info, version = service_entry
                results[ip][protocol].append({
                    'port': port,
                    'state': state,
                    'owner': owner,
                    'service': service,
                    'version': version,
                })
            except Exception as exception:
                pass

        # Clean up scan files used for enumerator, standard nmap output files
        # can stay.
        os.remove(output_file)

    return results


def scan(args):
    """Build output folder structure and initiate multiprocessing threads

    @param args: tuple containing IP address and output directory
    """

    ip, directory = args
    config = Config().scan

    # Ensure output directory exists; if it doesn't, create it
    output_dir = '%s/%s' % (directory, ip)
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    print '[+] running TCP & UDP scans for host %s' % ip
    pm = ProcessManager()
    for process in PROCESSES:
        pm.start_processes(process.get('command'), params={
            'host': ip,
            'output_dir': output_dir,
            'scan_mode': process.get(config['mode']),
        })

    # nmap scans have completed at this point, send results to delegation
    # system.
    delegation_result = delegate_service_enumeration.send(
        'enumerator.lib.nmap', scan_results=parse_results(ip, output_dir), directory=output_dir)

if __name__ == '__main__':
    scan(sys.argv[1], sys.argv[2])
