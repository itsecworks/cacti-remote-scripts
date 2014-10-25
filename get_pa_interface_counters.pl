#!/usr/bin/perl  
# Author: Akos Daniel daniel.akos77ATgmail.com
#
# Filename: get_pa_interface_bytes.pl
# Current Version: 0.1 beta
# Created: 1st of Sep 2014
# Last Changed: 1st of Oct 2014
# -----------------------------------------------------------------------------------------------
# Description:
# -----------------------------------------------------------------------------------------------
# This script logs in the palo alto firewall issues a show command for example for interface counters
# and gives back the output for cacti in the cacti syntax.
# Step 1.
# For the login you need a key. Open the following page on the firewall with a credential, example:
# https://10.13.13.1/api/?type=keygen&user=myusername&password=mypassword
# In the output is your key.
# Step 2.
# After that just test it like this example (change the IP the key and the interfacename for you!):
# $ ./get_pa_interface_bytes.pl 10.13.13.1 qeUcrTG9Cdjc0QnU ethernet1/4.13
#
# Syntax:
# -------
# $ ./get_pa_interface_bytes.pl <IP> <Key> <IFName1> <IFName2> <IFName3> <IFName4> <IFName5>
#
# Mandatory arguments:
# --------------------
# <IP> : The IP of the cisco asa firewall.
# <Key> : Key for https login.
# <IFName1-4> : Interface name, like GigabitEthernet0/0 or Fastethernet1. Max 4 Interface can you define!
#
# Example:
# --------
# $ ./get_pa_interface_bytes.pl 10.13.13.1 qeUcrTG9Cdjc0QnU ethernet1/4.13
# -----------------------------------------------------------------------------------------------
# Known issues:
# 
# -----------------------------------------------------------------------------------------------
# [solved]
# -----------------------------------------------------------------------------------------------
# Change History
#
# -----------------------------------------------------------------------------------------------
# 0.1 beta: (1st of Oct 2014)

use strict;
use warnings;
use URI::Escape;
use LWP::UserAgent;  
use HTTP::Request;
use XML::LibXML; 

my $hostname	=	$ARGV[0]; # IP of the firewall
my $httpskey	=	$ARGV[1]; # example 'vcxvert4rhhgfhf'
my $ifname1     =	$ARGV[2]; # example 'ethernet1/4.111'
my $ifname2     =	$ARGV[3]; # example 'ethernet1/4.112'
my $ifname3     =	$ARGV[4]; # example 'ethernet1/4.113'
my $ifname4     =	$ARGV[5]; # example 'ethernet1/4.114'
my $ifname5     =	$ARGV[6]; # example 'ethernet1/4.115'
# command without URL encoding
my $command		=	"<show><counter><interface>all</interface></counter></show>";
# command with URL encoding %3Cshow%3E%3Ccounter%3E%3Cinterface%3Eall%3C%2Finterface%3E%3C%2Fcounter%3E%3C%2Fshow%3E
# See http://url-encoder.de/
my $urlcommand = uri_escape($command);
my $URL = 'https://'.$hostname.'/api/?type=op&key='.$httpskey.'&cmd='.$urlcommand;
# counters used:
#
#ibytes		-	bytes received
#obytes		-	bytes transmitted
#ipackets	-	packets received
#opackets	-	packets transmitted
#
# Errors
#ierrors	-	receive errors
#ifwderrors	-	forwarding errors
#
# Drops
#idrops		-	packets dropped
#flowstate	-	packets dropped by flow state check
#
# Network Problems
#noroute	-	no route
#noarp		-	arp not found
#noneigh	-	neighbor not found
#neighpend	-	neighbor info pending
#nomac		-	mac not found
#
# Informational counters...I dont monitor it.
#zonechange	-	packets routed to different zone
#icmp_frag	-	ICMP fragment
#l2_encap	-	layer2 encapsulated packets
#l2_decap	-	layer2 decapsulated packets
#
# Basic Attacks
#land		-	land attacks
#pod		-	ping-of-death attacks
#teardrop	-	teardrop attacks
#ipspoof	-	ip spoof attacks
#macspoof	-	mac spoof attacks
#

my @if_counters	= ("ibytes","obytes","ipackets","opackets","ierrors","idrops","flowstate","ifwderrors","noroute","noarp","noneigh","neighpend","nomac","land","pod","teardrop","ipspoof","macspoof");
my @interfaces		= ($ifname1,$ifname2,$ifname3,$ifname4);

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
my $outid = 1;

foreach my $interface (@interfaces) {
	my $sum_err;
	my $sum_drp;
	my $sum_nonet;
	my $sum_att;
	
	foreach my $if_counter (@if_counters) {
		my $xpath  = "//entry[name = '$interface']/$if_counter/text()"; # xpath_expression (query)
		# findvalue function from XML::LibXML::Node Package
		my $val = $xmlfile->findvalue($xpath);
		
		if ($if_counter =~ m/bytes/ or $if_counter =~ m/packets/)	{
			print "if".$outid."-".$if_counter.": ".$val." ";
		}
		elsif ($if_counter eq "ierrors" or $if_counter eq "ifwderrors")	{
			$sum_err += $val;
		}
		elsif ($if_counter eq "idrops" or $if_counter eq "flowstate") {
			$sum_drp += $val;
		}
		elsif ($if_counter eq "noroute" or $if_counter eq "noarp" or $if_counter eq "noneigh" or $if_counter eq "neighpend" or $if_counter eq "nomac") {
			$sum_nonet += $val;
		}
		elsif ($if_counter eq "land" or $if_counter eq "pod" or $if_counter eq "teardrop" or $if_counter eq "ipspoof" or $if_counter eq "macspoof") {
			$sum_att += $val;
		}
	}
	print "if".$outid."-err: ".$sum_err." ";
	print "if".$outid."-drp: ".$sum_drp." ";
	print "if".$outid."-nonet: ".$sum_nonet." ";
	print "if".$outid."-att: ".$sum_att." ";
	$outid += 1;
}
print "\n";