#!/usr/bin/python3
# Generate testssl.sh input file for GNU parallel from list of open ports in host:port format.
# Parallel invocation: parallel < output_of_this_script

import fileinput
import re
import argparse
import sys

argparser = argparse.ArgumentParser(description="Read host:port lines from text import file and create testssl.sh command lines")
argparser.add_argument("--command", "-c", default="testssl.sh", help="Invocation of testssl.sh")
argparser.add_argument("--arguments", "-a", default="--warnings=batch --openssl-timeout=60 --log --json --csv", help="Additional arguments for each testssl.sh invocation")
argparser.add_argument("files", nargs="*", help="List of input files. Each line must contain a host:port entry")
args = argparser.parse_args()

### Configuration of STARTTLS ports ###
starttlsPorts = {
        21: "ftp",
        25: "smtp",
        110: "pop3",
        }
#######################################

reInputLine = re.compile("^(.*):(\d+)$")

for line in fileinput.input(args.files):
    m = reInputLine.match(line)
    if not m:
        print("Ignoring %s:%s due to parse errors" % (fileinput.filename(), fileinput.filelineno()), file=sys.stderr)
    else:
        host = m.group(1)
        port = int(m.group(2))

        if port in starttlsPorts:
            print("%s %s --starttls %s %s:%d" % (args.command, args.arguments, starttlsPorts[port], host, port))
        else:
            print("%s %s %s:%d" % (args.command, args.arguments, host, port))
