#!/usr/bin/python3
# Generate testssl.sh mass scan input file from list of open ports in host:port format.

import fileinput
import re

### Configuration of STARTTLS ports ###
addParams = "--logfile=log --jsonfile=json --csvfile=csv"
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
        print("%s --starttls %s %s:%d" % (addParams, starttlsPorts[port], host, port))
    else:
        print("%s %s:%d" % (addParams, host, port))
