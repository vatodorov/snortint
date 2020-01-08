#!/usr/bin/env python
# --------------------------------------------------------------------------------------------------
#
# Developed by Valentin Todorov
#
# --------------------------------------------------------------------------------------------------

"""
PURPOSE: This script has multiple functions:
    1) Converts the timestamp from Snort logs to epoch
    2) Removes records with packet length greater than 1500. Those have a message "(ipv4) IPv4 datagram length > captured length"

"""


import json
import time


version = '1.6.0'

# Location of input and output files
input_loc = '/var/log/snort'
input_file = 'alert_json.txt'

output_loc = '/var/log/snort'
output_file = 'alert_json_reduced.txt'

# Exclude records that contain this record
exclude_recs = '"proto" : "eth", "pkt_gen" : "raw", "pkt_len" : 1500, "dir" : "UNK", "service" : "unknown", "rule" : "116:6:1", "priority" : 3, "class" : "none", "action" : "allow", "msg" : "(ipv4) IPv4 datagram length > captured length"'

snort_log_mod = []

# Ingest records
with open('{}/{}'.format(input_loc, input_file), 'r') as file:
    for cnt, dat in enumerate(file):
        if exclude_recs not in dat:
            data = json.loads(dat)

            # Convert date to epoch and create the modified snort log
            epoch_time = '20{}'.format(data['timestamp'])

            pattern = '%Y/%m/%d-%H:%M:%S.%f'
            epoch = int(time.mktime(time.strptime(epoch_time, pattern)))*1000

            # Overwrite the timestamp in the record
            data['timestamp'] = epoch
            snort_log_mod.append(json.dumps(data))

# Write out the data to a file
f = open('{}/{}'.format(output_loc, output_file), 'w+')

for i in snort_log_mod:
     f.write('{}\n'.format(i))

f.close()