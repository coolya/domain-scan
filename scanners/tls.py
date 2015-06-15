import logging
from scanners import utils
import json
import os


###
# == tls ==
#
# Inspect a site's valid TLS configuration using ssllabs-scan.
#
# If data exists for a domain from `inspect`, will check results
# and only process domains with valid HTTPS, or broken chains.
###

command = os.environ.get("SSLLABS_PATH", "ssllabs-scan")

all_domains = None

def init(options, domains):
    global all_domains
    all_domains = domains
    return True

def get_data(data):
    domain = data['host']
    cache = utils.cache_path(domain, "tls")
    # if SSL Labs had an error hitting the site, cache this
    # as an invalid entry.
    if data["status"] == "ERROR":
        utils.write(utils.invalid(data), cache)
        return None

    utils.write(utils.json_for(data), cache)
    # can return multiple rows, one for each 'endpoint'
    for endpoint in data['endpoints']:

        # this meant it couldn't connect to the endpoint
        if not endpoint.get("grade"):
            continue

        sslv3 = False
        tlsv12 = False
        for protocol in endpoint['details']['protocols']:
            if ((protocol['name'] == "SSL") and
                    (protocol['version'] == '3.0')):
                sslv3 = True
            if ((protocol['name'] == "TLS") and
                    (protocol['version'] == '1.2')):
                tlsv12 = True

        spdy = False
        h2 = False
        npn = endpoint['details'].get('npnProtocols', None)
        if npn:
            spdy = ("spdy" in npn)
            h2 = ("h2-" in npn)

        return [
            domain,
            endpoint['grade'],
            endpoint['details']['cert']['sigAlg'],
            endpoint['details']['key']['alg'],
            endpoint['details']['key']['size'],
            endpoint['details']['forwardSecrecy'],
            endpoint['details']['ocspStapling'],
            endpoint['details'].get('fallbackScsv', "N/A"),
            endpoint['details']['supportsRc4'],
            sslv3,
            tlsv12,
            spdy,
            endpoint['details']['sniRequired'],
            h2
        ]

def scan(options):
    logging.debug("scanning tls")
    for domain in all_domains:
        cache = utils.cache_path(domain, "tls")
        force = options.get("force", False)

        if (force is False) and (os.path.exists(cache)):
            logging.debug("\tCached.")
            raw = open(cache).read()
            data = json.loads(raw)

            if data.get('invalid'):
                yield None
            else:
                yield get_data(data)
        else:
            logging.debug("\t %s %s" % (command, domain))
            utils.write(("%s \n" % domain), utils.temp_path('domains.txt'))

    usecache = str(not force).lower()

    logging.debug(open(utils.temp_path('domains.txt')).read())

    if options.get("debug"):
        cmd = [command, "--usecache=%s" % usecache,
               "--verbosity=debug", ("""--hostfile=%s""" % utils.temp_path('domains.txt'))]
    else:
        cmd = [command, "--usecache=%s" % usecache,
               "--quiet", ("""--hostfile=%s""" % utils.temp_path('domains.txt'))]
    raw = utils.scan(cmd)

    if raw:
        logging.debug("raw: %s" % raw)
        data = json.loads(raw)

        # We get an array of data from ssllabs-scan
        # They are not in the same order as we requested them
        for domain_data in data:
            yield get_data(domain_data)

    else:
        yield None
        # raise Exception("Invalid data from ssllabs-scan: %s" % raw)
            
headers = [
    "Domain", # order is no longer guaranteed due bulk scanning
    "Grade",  # unique to SSL Labs
    "Signature Algorithm", "Key Type", "Key Size",  # strength
    "Forward Secrecy", "OCSP Stapling",  # privacy
    "Fallback SCSV",  # good things
    "RC4", "SSLv3",  # old things
    "TLSv1.2", "SPDY", "Requires SNI",  # forward
    "HTTP/2"  # ever forward
]
