#!/usr/bin/python3
# Import testssl.sh CSV to ELasticSearch

from elasticsearch_dsl import DocType, Object, Date, String, Integer, Short, Boolean
from datetime import datetime
from tzlocal import get_localzone
import csv
import re
import pprint     # for debugging purposes only

pp = pprint.PrettyPrinter(indent=4)

tz = get_localzone()
reDefaultFilename = re.compile("(?:^|/)(?P<ip>\d+\.\d+\.\d+\.\d+)(:(?P<port>\d+))?-(?P<datetime>\d{8}-\d{4})\.csv$")
reProtocol = re.compile("^(?:sslv\\d|tls\\d(?:_\\d)?)$")
reCipherTests = re.compile("^std_(.*)$")
reIpHostColumn = re.compile("^(.*)/(.*)$")
reCipherColumnName = re.compile("^cipher_")
reCipherDetails = re.compile("^\\S+\\s+(\\S+)")
reCipherTests = re.compile("^std_(.*)$")
reDefaultProtocol = re.compile("^Default protocol (\\S+)")
reDefaultCipher = re.compile("^Default cipher: (.*?)(?:$|[,\\s])")
reKeySize = re.compile("Server Keys (\\d+) bits")
reSignAlgorithm = re.compile("Signature Algorithm: (.*)\\s\\(")
reFPMD5 = re.compile("MD5 (\\S+)")
reFPSHA1 = re.compile("SHA1 (\\S+)")
reFPSHA256 = re.compile("SHA256 (\\S+)")
reCN = re.compile("^(.*?)[\\s\\(]")
reSAN = re.compile(": (.*)$")
reIssuer = re.compile("'issuer= (.*?)' \\(")
reExpiration = re.compile("--> (.*)\\)")
reOCSPURI = re.compile(" : (?!--)(.*)")

reOffers = re.compile("(?<!not )offered")
reNotOffered = re.compile("not offered")
reOk = re.compile("\\(OK\\)")
reYes = re.compile("yes", re.IGNORECASE)
reVulnerable = re.compile("\\(NOT ok\\)", re.IGNORECASE)

class DocTestSSLResult(DocType):
    class Meta:
        doc_type = "TestSSLResult"

    source = String(fields={'raw': String(index='not_analyzed')})
    result = Boolean()
    timestamp = Date()
    ip = String(index='not_analyzed')
    hostname = String(index='not_analyzed')
    port = Integer()
    svcid = String(index='not_analyzed')
    protocols = String(index='not_analyzed', multi=True)
    ciphers = String(multi=True, fields={'raw': String(index='not_analyzed')})
    ciphertests = String(index='not_analyzed', multi=True)
    serverpref = Object(
            properties = {
                "cipher_order": Boolean(),
                "protocol": String(index='not_analyzed'),
                "cipher": String(fields={'raw': String(index='not_analyzed')})
                })
    cert = Object(
            properties = {
                "keysize": Short(),
                "signalgo": String(fields={'raw': String(index='not_analyzed')}),
                "md5_fingerprint": String(index='not_analyzed'),
                "sha1_fingerprint": String(index='not_analyzed'),
                "sha256_fingerprint": String(index='not_analyzed'),
                "cn": String(fields={'raw': String(index='not_analyzed')}),
                "san": String(multi=True, fields={'raw': String(index='not_analyzed')}),
                "issuer": String(fields={'raw': String(index='not_analyzed')}),
                "ev": Boolean(),
                "expiration": Date(),
                "ocsp_uri": String(fields={'raw': String(index='not_analyzed')}),
                "ocsp_stapling": Boolean(),
                })
    vulnerabilities = String(index='not_analyzed', multi=True)

    def parseCSVLine(self, line):
        if line['id'] == "id":
            return
        if not self.ip or not self.hostname or not self.port:   # host, ip and port
            m = reIpHostColumn.search(line['host'])
            if m:
                self.hostname, self.ip = m.groups()
            self.port = int(line['port'])

        if reProtocol.search(line['id']) and reOffers.search(line['finding']):     # protocols
            self.result = True
            m = reProtocol.search(line['id'])
            if m:
                self.protocols.append(line['id'].upper())
        elif reCipherColumnName.search(line['id']):                  # ciphers
            m = reCipherDetails.search(line['finding'])
            if m:
                self.ciphers.append(m.group(1))
        elif reCipherTests.search(line['id']) and reVulnerable.search(line['finding']):                       # cipher tests
            m = reCipherTests.search(line['id'])
            if m:
                self.ciphertests.append(m.group(1))
        elif line['id'] == "order":                                 # server prefers cipher
            self.serverpref.cipher_order = bool(reOk.search(line['finding']))
        elif line['id'] == "order_proto":                           # preferred protocol
            m = reDefaultProtocol.search(line['finding'])
            if m:
                self.serverpref.protocol = m.group(1)
        elif line['id'] == "order_cipher":                          # preferred cipher
            m = reDefaultCipher.search(line['finding'])
            if m:
                self.serverpref.cipher = m.group(1)
        elif line['id'] == "key_size":                              # certificate key size
            m = reKeySize.search(line['finding'])
            if m:
                self.cert.keysize = int(m.group(1))
        elif line['id'] == "algorithm":                             # certificate sign algorithm
            m = reSignAlgorithm.search(line['finding'])
            if m:
                self.cert.signalgo = m.group(1)
        elif line['id'] == "fingerprint":                           # certificate fingerprints
            m = reFPMD5.search(line['finding'])
            if m:
                self.cert.md5_fingerprint = m.group(1)
            m = reFPSHA1.search(line['finding'])
            if m:
                self.cert.sha1_fingerprint = m.group(1)
            m = reFPSHA256.search(line['finding'])
            if m:
                self.cert.sha256_fingerprint = m.group(1)
        elif line['id'] == "cn":                                    # certificate CN
            m = reCN.search(line['finding'])
            if m:
                self.cert.cn = m.group(1)
        elif line['id'] == "san":                                   # certificate SAN
            m = reSAN.search(line['finding'])
            if m:
                sans = m.group(1)
                for san in sans.split(" "):
                    if san != "--":
                        self.cert.san.append(san)
        elif line['id'] == "issuer":                                # certificate issuer
            m = reIssuer.search(line['finding'])
            if m:
                self.cert.issuer = m.group(1)
        elif line['id'] == "ev":                                    # certificate extended validation
            self.cert.ev = bool(reYes.search(line['finding']))
        elif line['id'] == "expiration":                            # certificate expiration
            m = reExpiration.search(line['finding'])
            if m:
                unparsedDate = m.group(1)
                self.cert.expiration = datetime.strptime(unparsedDate, "%Y-%m-%d %H:%M %z") 
        elif line['id'] == "ocsp_uri":                              # certificate OCSP URI
            m = reOCSPURI.search(line['finding'])
            if m:
                self.cert.ocsp_uri = m.group(1)
            else:
                self.cert.ocsp_uri = "-"
        elif line['id'] == "ocsp_stapling":                         # certificate OCSP stapling
            self.cert.ocsp_stapling = not bool(reNotOffered.search(line['finding']))
        elif line['id'] in ("heartbleed", "ccs", "secure_renego", "sec_client_renego", "crime", "breach", "poodle_ssl", "fallback_scsv", "freak", "DROWN", "logjam", "beast", "rc4") and reVulnerable.search(line['finding']):
            self.vulnerabilities.append(line['id'].upper())

    def parseCSV(self, csvfile):
        if self.source:
            m = reDefaultFilename.search(self.source)
            if m:
                self.ip = m.group('ip')
                self.port = int(m.group('port') or 0)
                self.timestamp = datetime.strptime(m.group('datetime'), "%Y%m%d-%H%M")
        csvReader = csv.DictReader(csvfile, fieldnames=("id", "host", "port", "severity", "finding"), delimiter=',', quotechar='"')
        for line in csvReader:
            self.parseCSVLine(line)

    def save(self, **kwargs):
        if not self.timestamp:
            self.timestamp = datetime.now(tz)
        self.svcid = "%s:%d" % (self.ip, int(self.port) or 0)
        if not self.result:
            self.result = False

        if 'debug' in kwargs and kwargs['debug']:
            pp.pprint(self.to_dict())
        return super().save()
