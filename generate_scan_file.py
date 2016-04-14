#!/usr/bin/python3
# Generate testssl.sh input file for GNU parallel from list of open ports in host:port format.
# Parallel invocation: parallel < output_of_this_script

import fileinput
import re

### Configuration of STARTTLS ports ###
testsslPath = "testssl.sh/testssl.sh"
addParams = "--warnings=batch --openssl-timeout=60 --logfile=log --jsonfile=json --csvfile=csv"
starttlsPorts = {
        21: "ftp",
        25: "smtp",
        110: "pop3",
        }
#######################################

reInputLine = re.compile("^(.*):(\d+)$")

for line in fileinput.input():
    m = reInputLine.match(line)
    host = m.group(1)
    port = int(m.group(2))

    if port in starttlsPorts:
        print("%s %s --starttls %s %s:%d" % (testsslPath, addParams, starttlsPorts[port], host, port))
    else:
        print("%s %s %s:%d" % (testsslPath, addParams, host, port))
