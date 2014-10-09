#!/usr/bin/perl  
# Author: Akos Daniel daniel.akos77ATgmail.com
#
# Filename: get_pa_global_counters.pl
# Current Version: 0.1 beta
# Created: 10th of Oct 2014
# Last Changed: 10th of Oct 2014
# -----------------------------------------------------------------------------------------------
# Description:
# -----------------------------------------------------------------------------------------------
# This script logs in the palo alto firewall issues a show command for global counters
# and gives back the output for cacti in the cacti syntax.
# Step 1.
# For the login you need a key. Open the following page on the firewall with a credential, example:
# https://10.13.13.1/api/?type=keygen&user=myusername&password=mypassword
# In the output is your key.
# Step 2.
# After that just test it like this example (change the IP the key and the interfacename for you!):
# $ ./get_pa_global_counters.pl 10.13.13.1 qeUcrTG9Cdjc0QnU
#
# Syntax:
# -------
# $ ./get_pa_global_counters.pl <IP> <Key>
#
# Mandatory arguments:
# --------------------
# <IP> : The IP of the cisco asa firewall.
# <Key> : Key for https login.
#
# Example:
# --------
# $ ./get_pa_global_counters.pl 10.13.13.1 qeUcrTG9Cdjc0QnU
# -----------------------------------------------------------------------------------------------
# Known issues:
#
# -----------------------------------------------------------------------------------------------
# [solved]
# -----------------------------------------------------------------------------------------------
# Change History
#
# -----------------------------------------------------------------------------------------------
# 0.1 beta: (10st of Oct 2014)

use strict;
use warnings;
use URI::Escape;
use LWP::UserAgent;  
use HTTP::Request;
use XML::LibXML;

my $hostname    =       $ARGV[0]; # IP of the firewall
my $httpskey    =       $ARGV[1]; # example 'vcxvert4rhhgfhf'
# command without URL encoding
my $command             =       "<show><counter><global><filter><delta>yes</delta></filter></global></counter></show>";
# command with URL encoding. See http://url-encoder.de/
my $urlcommand = uri_escape($command);
my $URL = 'https://'.$hostname.'/api/?type=op&key='.$httpskey.'&cmd='.$urlcommand;

# aspects
# awk '{print $5,$4,$1}' pa_counters_test.txt | sort -k3,3 -k2,2 | cut -d" " -f1,2 | sort | uniq -c | awk '{print $2,$3,$1}'
#  aa         HA Active/Active mode
#  arp        ARP procesing
#  dos        DoS protection
#  forward    Packet forwarding
#  ipfrag     IP fragment processing
#  ipsec      IPSec transport mode procesing
#  mgmt       Management-plane packet
#  mld        MLD procesing
#  nd         ND procesing
#  offload    Hardware offload
#  parse      Packet parsing
#  pktproc    Packet processing
#  qos        QoS enforcement
#  resource   Resource management
#  session    Session setup/teardown
#  system     System function
#  tunnel     Tunnel encryption/decryption
#
my @aspects     = ("aa","arp","dos","forward","ipfrag","ipsec","mgmt","mld","nd","offload","parse","pktproc","qos","resource","session","system","tunnel");

# categories
# awk '{print $6,$4,$1}' pa_counters_test.txt | sort -k3,3 -k2,2 | cut -d" " -f1,2 | sort | uniq -c | awk '{print $2,$3,$1}'
#  aho       AHO match engine
#  appid     Application-Identification
#  ctd       Content-Identification
#  dfa       DFA match engine
#  dlp       DLP
#  flow      Packet processing
#  fpga      FPGA
#  ha        High-Availability
#  log       Logging
#  nat       Network Address Translation
#  packet    Packet buffer
#  proxy     TCP proxy
#  session   Session management
#  ssh       SSH termination
#  ssl       SSL termination
#  tcp       TCP reordering
#  uid       User Indentification
#  url       URL filtering
#  zip       ZIP processing
#
my @categories  = ("aho","appid","ctd","dfa","dlp","flow","fpga","ha","log","nat","packet","proxy","session","ssh","ssl","tcp","uid","url","zip");

#severity
#  drop     Drop
#  error    Error
#  info     Informational
#  warn     Warning
#
my @severities  = ("drop","error","info","warn");
my $xml_string;

my $ua = LWP::UserAgent->new(ssl_opts => { verify_hostname => 0 });
my $header = HTTP::Request->new(GET => $URL);  
my $request = HTTP::Request->new('GET', $URL, $header);  
my $response = $ua->request($request);  

if ($response->is_success){  
        # input the xml content into var
        $xml_string = $response->content;
}
elsif ($response->is_error){  
        print "Error:$URL\n";  
        print $response->error_as_HTML;  
}

my $parser = XML::LibXML->new();
#load_xml function from XML::LibXML::Parser Package
my $xmlfile = XML::LibXML->load_xml(string => $xml_string);

foreach my $aspect (@aspects) {
		my $sum_err;
		my $sum_dr;
		foreach my $severity (@severities) {
                my $xpath  = "//entry[aspect/text() = '$aspect' and severity/text() = '$severity']/value/text()"; # xpath_expression (query)
                my $sum = 0;
				# findnodes function from XML::LibXML::Node Package
                my @nodes = $xmlfile->findnodes($xpath);
				#foreach my $value (@nodes) {
				#	$sum += $value;
				#}
				# did not work... :-(, have to use eval join.
				$sum = eval join '+', @nodes;
				$sum += 0;

				if ($severity eq "error")	{
					$sum_err = $sum;
				}
				elsif ($severity eq "drop")	{
					$sum_dr = $sum;
				}
				elsif ($severity eq "warn" or $severity eq "info") {
					print $aspect,"-",$severity,":",$sum," ";
				}
        }
		print $aspect,"-error-drop:",$sum_err+$sum_dr," ";
}
foreach my $category (@categories) {
		my $sum_err;
		my $sum_dr;
		foreach my $severity (@severities) {
                my $xpath  = "//entry[category/text() = '$category' and severity/text() = '$severity']/value/text()"; # xpath_expression (query)
                my $sum = 0;
				# findvalue function from XML::LibXML::Node Package
				my @nodes = $xmlfile->findnodes($xpath);
				$sum = eval join '+', @nodes;
				$sum += 0;

				if ($severity eq "error")	{
					$sum_err = $sum;
				}
				elsif ($severity eq "drop")	{
					$sum_dr = $sum;
				}
				elsif ($severity eq "warn" or $severity eq "info") {
					print $category,"-",$severity,":",$sum," ";
				}
        }
		print $category,"-error-drop:",$sum_err+$sum_dr," ";
}
print "\n";