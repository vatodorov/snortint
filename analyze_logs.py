#!/usr/bin/env python
# --------------------------------------------------------------------------------------------------
#
# Developed by Valentin Todorov
#
# --------------------------------------------------------------------------------------------------

"""
PURPOSE: Analysis of Snort logs
"""

import logging
import json
import argparse
import pandas as pd
import datetime


input_loc = '/Users/valentintodorov/Documents/GitRepos/snortint/'
input_file = 'alert_json_reduced_small.txt'

log_dir = '/var/log/'
log_name = 'snort_analysis.log'

# logger = logging.getLogger('Snort Logs Analysis')
# logger.setLevel(logging.DEBUG)
# logging.basicConfig(filename='{}{}'.format(log_dir, log_name),
#                     format='%(asctime)s %(levelname)-2s %(message)s',
#                     datefmt='%Y-%m-%d %H:%M:%S')
# handler = logging.StreamHandler()
# logger.addHandler(handler)

version = '0.0.1'


def read_data(input_loc, input_file):
    '''
    Reads the Snort logs data

    :param input_loc str: Location of the Snort log
    :param input_file str: Name of the Snort log
    :return dfSnort dataFrame: Data frame with Snort data
    '''

    data = []

    with open('{}{}'.format(input_loc, input_file), 'r') as f:
        for cnt, dat in enumerate(f):
            data.append(json.loads(dat))

    dfSnort = pd.DataFrame.from_records(data)
    dfSnort['date'] = pd.to_datetime(dfSnort['timestamp'], unit='ms')
    dfSnort['source'] = 'snort'

    return dfSnort


## Read the logs
data = read_data(input_loc, input_file)

## Get some stats
# Count valid values per field
data.count()

# Get valid values
data[['action']].count()

cols_keep = ['action', 'class', 'dir', 'icmp_code', 'msg', 'pkt_gen', 'pkt_len', 'priority', 'proto', 'rule', 'service', 'tcp_flags', 'date']
cols = [x for x in data.columns]
_cols = [x for x in cols if x in cols_keep]

# Frequency statistics
for i in _cols:
    #print (data[cols_keep].groupby(i).agg(['count'])
    print (data[cols_keep].groupby([i]).size().reset_index(name='counts'))

# Get the destination IP addresses for the ICMP traffic
print (data[data['proto'] == 'ICMP'].groupby(['dst_addr', 'icmp_code', 'date']).size().reset_index(name='counts'))

# Get stats for non-ICMP traffic
print (data[data['proto'] != 'ICMP'].groupby(['src_addr', 'msg', 'tcp_flags', 'date']).size().reset_index(name='counts'))


def ioc_data(df, addr, ioc):
    '''
    Returns data for a selected indicatorm either a source, or a destination address

    :param df dataFrame: A data frame with the Snort logs
    :param addr str: Name of the field that holds the indicator of interest - source (src_addr) or destination (dst_addr)
    :param ioc str: The IOC we are interested in
    :return dataFrame: Data frame for only a specific indicator
    '''

    return (df[df[addr] == ioc])

print (ioc_data(data, 'src_addr', '38.130.199.132').groupby(['src_addr', 'msg', 'tcp_flags', 'date']).size().reset_index(name='counts'))








# if __name__ == '__main__':
#     parser = argparse.ArgumentParser(
#         prog='Snort Logs Analysis',
#         description='Analyses logs from Snort'
#     )
#
#     parser.add_argument(
#         '-dl', '--data-location',
#         help='Location of the Snort log file to read',
#         required=True
#     )
#
#     parser.add_argument(
#         '-df', '--data-file',
#         help='Name of the Snort log file',
#         required=True
#     )

