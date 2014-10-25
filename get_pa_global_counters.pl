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
# $ ./get_pa_global_counters.pl 10.13.13.1 qeUcrTG9Cdjc0QnU category appid ctd flow fpga nat url
#
# Syntax:
# -------
# $ ./get_pa_global_counters.pl <IP> <Key> <Type> <type element1> <type entry2> <type entry3> <type entry4> <type entry5>
#
# Mandatory arguments:
# --------------------
# <IP> 				: The IP of the cisco asa firewall.
# <Key>				: Key for https login.
# <type>			: Type as category or aspect
# <element1>		: List of elements (max. 5)
#
# Example:
# --------
# $ ./get_pa_global_counters.pl 10.13.13.1 qeUcrTG9Cdjc0QnU category appid ctd flow fpga nat url
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

my $hostname    = $ARGV[0]; # IP of the firewall
my $httpskey    = $ARGV[1]; # example 'vcxvert4rhhgfhf'
my $type		= $ARGV[2]; # example 'category'
my @typeentries	= ($ARGV[3],$ARGV[4],$ARGV[5],$ARGV[6],$ARGV[7]);

# command without URL encoding
my $command		= "<show><counter><global><filter><delta>yes</delta></filter></global></counter></show>";
# command with URL encoding. See http://url-encoder.de/
my $urlcommand	= uri_escape($command);
my $URL			= 'https://'.$hostname.'/api/?type=op&key='.$httpskey.'&cmd='.$urlcommand;

# aspects
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
my $outid = 1;

foreach my $typeentry (@typeentries) {
	my $sum_err;
	my $sum_dr;
	foreach my $severity (@severities) {
		my $xpath  = "//entry[$type = '$typeentry' and severity = '$severity']/value/text()"; # xpath_expression (query)
		my $sum = 0;
		my @nodes;
		# findnodes function from XML::LibXML::Node Package
		# have to convert to string, since XML::Libxml version change....
		foreach my $node ($xmlfile->findnodes($xpath)) {
			push(@nodes,$node->toString);
		}
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
			print "typeentry".$outid.$severity.":".$sum." ";
		}
	}
	print "typeentry".$outid."error-drop:",$sum_err+$sum_dr," ";
	$outid += 1;
}
print "\n";