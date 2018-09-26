#! /usr/bin/python
# Written by Vinnie Vanhoecke
import dns.resolver
import sys, getopt
import re
import shodan
import nmap
import csv


import json,httplib
import time

from urllib2 import Request, urlopen
import urllib

## Global variables:
# Shodan api key
shodanKey = ""
# Domain name
domain = ""
# Name server
nameserver = "8.8.8.8"
# Save results
includedDomains = []
ips = []
ipRanges = []
loot = []
outputFileName = "output.csv"
# nmap
nm = nmap.PortScanner()
# Dependencies: shodan simplejson nmap


def help():
	print "##########################################"
	print "./spfenum.py -d <domain>"
	print " -d, --domain      : The domain to enumerate the SPF record on"
	print " -n, --nameserver  : Nameserver to use"
	print " -s, --shodan      : Shodan API key"
	print " -h, --help        : This helpmenu"
	print "##########################################"

# SPFenumerator
def spfenum(domain):
	global nameserver
	dnsResolver = dns.resolver.Resolver()
	dnsResolver.nameservers = [nameserver]
	answers = dnsResolver.query(domain, 'TXT')
	for record in answers:
		response = record.to_text().strip('"')
		# Only get the spf records
   		if re.search("^v=spf", response):
   			parseSpfRecord(domain,response)

# Parse an spf record of a domain
def parseSpfRecord(sdomain,spf):
	global domain, includedDomains, ips, loot
	for entry in spf.split(" "):
		# Clean up entry for iligal characters
		entry = entry.strip('"')
		# Check for ip entry
		if re.search("^ip4:", entry):
			ip = entry[4:]
			# Check if its an IP range
			ipRange = "false"
			if "/" in ip:
				ipRanges.append(ip)
				ipRange = "true"
			else:
				ips.append(ip)
			loot.append({"domain":sdomain,"ip":ip,"ipRange":ipRange})
		elif re.search("^include:", entry):
			include = entry[8:]
			# If new included domain check if its already scanned or not because it might get stuck in a loop when misconfigured
			if not (include in includedDomains or include == domain):
				spfenum(include)
			includedDomains.append(include)
	print "Parsed SPF record of " + sdomain


def shodanLookup():
	print "Starting Shodan lookup.."
	global shodanKey, loot
	api = shodan.Shodan(shodanKey)
	for ip in loot:
		if ip["ipRange"] == "true":
			continue
		try:
			# Because shodan is rate limitted :(
			time.sleep(1)
			# Search IP on Shodan
			host = api.host(ip["ip"])
			# Save the ports
			ports = []
			for item in host['data']:
				ports.append(item['port'])
			ip["ports"] = ports
		except shodan.APIError, e:
			if "No information available" in e.value:
				ip["ports"] = [0]
			else:
				print 'Error: %s' % e

def nmapScan():
	print "Starting nmap scans.."
	global domain
	for ip in loot:
		# Initiate openrelay array for result variable
		ip["openrelay"] = []
		# Don't check ip ranges
		if ip["ipRange"] == "true":
			continue
		print "NMAP scanning " + ip["ip"]
		# Perform SMTP relay scan
		nm.scan(hosts=ip["ip"], ports='25,465,587', arguments="--script smtp-open-relay.nse --script-args smtp-open-relay.domain=" + domain)
		# Check if results is not empty
		try:
			test = nm._scan_result['scan'][ip["ip"]]
		except:
			continue
		# Go over each port
		for port in nm._scan_result['scan'][ip["ip"]]["tcp"]:
			# Only if the port is open
			if nm._scan_result['scan'][ip["ip"]]["tcp"][port]["state"] == "open":
			 	relayResult = nm._scan_result['scan'][ip["ip"]]["tcp"][port]["script"]["smtp-open-relay"]
			 	# Check results of script
			 	if "isn't" in relayResult or "doesn't" in relayResult:
			 		print ip["ip"] + " is not an open relay on port " + str(port)
			 	else:
			 		ip["openrelay"].append(port)
			 		print "[JACKPOT] " + ip["ip"] + " is an open relay on port " + str(port)


# Get the parameters
def main(argv):
	global domain,outputFileName,nameserver,shodanKey
	if len(argv) == 0:
		help()
		sys.exit()
	try:
		opts, args = getopt.getopt(argv,"d:hn:s:",["domain","help","shodan","nameserver"])
	except getopt.GetoptError:
		sys.exit(2)
	for opt, arg in opts:
		if opt in ("-d", "--domain"):
			domain = arg
		elif opt in ("-s", "--shodan"):
			shodanKey = arg
		elif opt in ("-n", "--nameserver"):
			nameserver = arg
		elif opt in ("-h", "--help"):
			help()
			sys.exit()

if __name__ == "__main__":
    main(sys.argv[1:])


# Get all ip addresses defined in the SPF records (including resolving the domains)
spfenum(domain)
# Retrieve shodan information of the single IP's
shodanLookup()
# Perform nmap scans
nmapScan()

# Print results
print "##################################################################"
print "Found " + str(len(ips)) + " IP's linked to SPF of " + domain
for x in ips:
	print "IP: " + x
print "Found " + str(len(ipRanges)) + " IP ranges found linked to SPF of " + domain
for x in ipRanges:
	print "IPrange: " + x
	# Perhaps
print "Found " + str(len(includedDomains)) + " included domains linked to SPF of " + domain
print "Included domain that could be used to spoof emails"
for x in includedDomains:
    if "flexmail" in x:
        print "[VULNERABLE] Domain:" + x
    else:
        print "Domain: " + x
print "##################################################################"

