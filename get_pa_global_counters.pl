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

my $hostname	=	$ARGV[0]; # IP of the firewall
my $httpskey	=	$ARGV[1]; # example 'vcxvert4rhhgfhf'
# command without URL encoding
my $command		=	"<show><counter><global><filter><value>non-zero</value></filter></global></counter></show>";
# command with URL encoding. See http://url-encoder.de/
my $urlcommand = uri_escape($command);
my $URL = 'https://'.$hostname.'/api/?type=op&key='.$httpskey.'&cmd='.$urlcommand;

#aspect
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
my @aspects	= ("aa","arp","dos","forward","ipfrag","ipsec","mgmt","mld","nd","offload","parse","pktproc","qos","resource","session","system","tunnel");
#category
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
my @categories	= ("aho","appid","ctd","dfa","dlp","flow","fpga","ha","log","nat","packet","proxy","session","ssh","ssl","tcp","uid","url","zip");
#severity
#  drop     Drop
#  error    Error
#  info     Informational
#  warn     Warning
#
my @severities	= ("drop","error","info","warn");

# aspect
# awk '{a=$1;b=$4;c=$5;d=$6;$1=$2=$3=$4=$5=$6="";print c,b,a}' pa_counters_test.txt | sort -k3,3 -k2,2 | cut -d" " -f1,2 | sort | uniq -c | awk '{print $2,$3,$1}'
# cat
# awk '{a=$1;b=$4;c=$5;d=$6;$1=$2=$3=$4=$5=$6="";print d,b,a}' pa_counters_test.txt | sort -k3,3 -k2,2 | cut -d" " -f1,2 | sort | uniq -c | awk '{print $2,$3,$1}'

my $ua = LWP::UserAgent->new(ssl_opts => { verify_hostname => 0 });

my $header = HTTP::Request->new(GET => $URL);  
my $request = HTTP::Request->new('GET', $URL, $header);  
my $response = $ua->request($request);  

my $xml_string;
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
	foreach my $severity (@severities) {
		my $xpath  = "//entry[name/text() = '$interface']/$if_counter/text()"; # xpath_expression (query)
		# findvalue function from XML::LibXML::Node Package
		print $interface,"-",$if_counter,": ",$xmlfile->findvalue($xpath)," ";
	}
}
foreach my $aspect (@aspects) {
	foreach my $severity (@severities) {
		my $xpath  = "//entry[name/text() = '$interface']/$if_counter/text()"; # xpath_expression (query)
		# findvalue function from XML::LibXML::Node Package
		print $interface,"-",$if_counter,": ",$xmlfile->findvalue($xpath)," ";
	}
}
print "\n";