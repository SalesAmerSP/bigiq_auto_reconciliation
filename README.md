# BIG-IQ Reconciliation Script
Python script to automatically re-discover and re-import BIG-IPs in BIG-IQ.

## Installation
Upload the script to the BIG-IQ's /shared/scripts folder.

## Usage
usage: reconcile.py [-h] --username USERNAME --password PASSWORD
               [--hostname HOSTNAME] [--target [TARGET [TARGET ...]]]
               [--targetfile [TARGETFILE]] [--debug]

optional arguments:
  -h, --help            show this help message and exit
  --username USERNAME   BIG-IQ user
  --password PASSWORD   password for BIG-IQ user
  --hostname HOSTNAME   BIG-IQ host (defaults to 'localhost')
  --target [TARGET [TARGET ...]]
                        BIG-IP(s) to re-import
  --targetfile [TARGETFILE]
                        plain text file with list of target BIG-IP hostnames,
                        one host per line
  --debug               Enable debug logging

## Execution on BIG-IQ
Instructions on how to execute the project directly on the BIG-IQ platform
- **Step 1**: Connect to the BIG-IQ platform
- **Step 2**: Upload the project files to `/shared/scripts`
- **Step 3**: Verify the execution and check the logs in the `/var/log` directory
