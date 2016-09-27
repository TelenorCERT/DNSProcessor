#!/usr/bin/python
# -*- coding: utf-8 -*-

import os
import sys
path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..")
sys.path.append(path)
os.chdir(path)
import DNSProcessor
import argparse
import datetime

DEFAULT_PATH = u''

parser = argparse.ArgumentParser()

parser.add_argument('-o', '--output', dest='output',
        help='Name of output file. Can contain a path.')
parser.add_argument('-t', '--file_type', dest='type', choices=['json'],
        default='json', required=False, help='File output type.')

args = parser.parse_args()

if args.output == None:
    timestamp = unicode(datetime.datetime.utcnow().isoformat())
    default_file_name = timestamp + u'.json'
    args.output = DEFAULT_PATH + default_file_name

if os.path.isfile(args.output):
    OUTPUT_FILE = args.output
elif os.path.isdir(args.output):
    error_msg = u'Output file is a directory, needs filename.'
    raise ValueError(error_msg)
else:
    f = open(args.output, 'a')
    try:
        os.utime(args.output, None)
        OUTPUT_FILE = args.output
    finally:
        f.close()
        os.remove(args.output)

DNSParser = DNSProcessor.DNSParser()
dns_zones = DNSParser.transfer_zones()
DNSParser.build_json(dns_zones, OUTPUT_FILE)
