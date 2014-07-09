#!/usr/bin/perl
# Author: Akos Daniel daniel.akos77ATgmail.com
#
# Filename: get_asa_inspect.pl
# Current Version: 0.1 beta
# Created: 4th of April 2014
# Last Changed: 4th of April 2014
# -----------------------------------------------------------------------------------------------
# Description:
# -----------------------------------------------------------------------------------------------
# This is a rather crude and quick hacked Perl-script to get multiple values from 'show service-policy' command.
# The drop reasons (max 5) should be defined in command.
#
# Currently supported inspections:
#mpf-policy-map-class mode commands/options:
#  ctiqbe           
#  dcerpc           
#  dns              
#  esmtp            
#  ftp              
#  gtp              
#  h323 h225
#  h323 ras      
#  http             
#  icmp             
#  ils              
#  im               
#  ip-options       
#  ipsec-pass-thru  
#  ipv6             
#  mgcp             
#  mmp              
#  netbios          
#  pptp             
#  rsh              
#  rtsp             
#  sip              
#  skinny           
#  snmp             
#  sqlnet           
#  sunrpc           
#  tftp             
#  waas             
#  xdmcp         
#
# Syntax:
# -------
# get_asa_inspect.pl <IP> <Username> <Password> <inspectedprotocol1> <inspectedprotocol2> <inspectedprotocol3> <inspectedprotocol4> <inspectedprotocol5>
#
# Mandatory arguments:
# -------------------
# <IP> : The IP of the cisco asa firewall.
# <Username> : Username for a readonly user.
# <Password> : Password of the user.
# <inspectedprotocol1> : in this script max 5 inspected protocol can be monitored. Just define the inspected protocol names.
#
# Example:
# --------
# ./get_asa_inspect.pl cisco cisco123 172.16.20.1 dns ftp sip icmp tftp
#
# This will give outputs of the required inspection counters.
# -----------------------------------------------------------------------------------------------
# Known issues:
# 
# -----------------------------------------------------------------------------------------------
# [solved]
# -----------------------------------------------------------------------------------------------
# Change History
#
# -----------------------------------------------------------------------------------------------
# 0.1 beta: (4th of April 2014)

# Example output:
#
#myfirewall# sh service-policy 
#
#Global policy: 
#  Service-policy: global_policy
#    Class-map: inspection_default
#      Inspect: dns preset_dns_map, packet 11936434, lock fail 0, drop 34090, reset-drop 0
#      Inspect: ftp, packet 1042, lock fail 0, drop 0, reset-drop 0
#      Inspect: sip , packet 458106, lock fail 0, drop 0, reset-drop 0
#               tcp-proxy: bytes in buffer 0, bytes dropped 0
#      Inspect: tftp, packet 6662070, lock fail 0, drop 0, reset-drop 0
#      Inspect: icmp, packet 135962897, lock fail 0, drop 1, reset-drop 0
#      Inspect: ip-options _default_ip_options_map, packet 0, lock fail 0, drop 0, reset-drop 0
#

use strict;

# Set variables based on input parameters
my $cisco_cmd 			= "show service-policy";
my $myfirewallip 		= $ARGV[0];
my $username	 		= $ARGV[1];
my $password	 		= $ARGV[2];
my $inspectedprotocol1	= $ARGV[3];
my $inspectedprotocol2 	= $ARGV[4];
my $inspectedprotocol3 	= $ARGV[5];
my $inspectedprotocol4 	= $ARGV[6];
my $inspectedprotocol5 	= $ARGV[7];

# Check variables to make sure data is there
if(!$myfirewallip||!$inspectedprotocol1||!$username||!$password){
	print "Not all requiredd parameters are filled.\n";
	print "Usage: get_asa_inspect.pl firewallip username password inspectedprotocol1 [... inspectedprotocol5] \n";
	exit;
}

my $output = `lynx -auth=$ARGV[1]:$ARGV[2] -width 100 -dump "https://$ARGV[0]:443/exec/$cisco_cmd"`;

foreach my $line (split /[\r\n]+/, $output) {
# source: http://stackoverflow.com/questions/10533/parsing-attributes-with-regex-in-perl
	if (defined $ARGV[3] && $line =~ /Inspect:\s$inspectedprotocol1.*,\spacket\s(\d+),\slock\sfail\s(\d+),\sdrop\s(\d+),\sreset-drop\s(\d+)/m) {
		print "inspectedproto1-pkts:",$1," inspectedproto1-drps:",$2+$3+$4," ";
	}
	elsif (defined $ARGV[4] && $line =~ /Inspect: $inspectedprotocol2.*,\spacket\s(\d+),\slock\sfail\s(\d+),\sdrop\s(\d+),\sreset-drop\s(\d+)/m) {
		print "inspectedproto2-pkts:",$1," inspectedproto2-drps:",$2+$3+$4," ";
	}
	elsif (defined $ARGV[5] && $line =~ /Inspect: $inspectedprotocol3.*,\spacket\s(\d+),\slock\sfail\s(\d+),\sdrop\s(\d+),\sreset-drop\s(\d+)/m) {
		print "inspectedproto3-pkts:",$1," inspectedproto3-drps:",$2+$3+$4," ";
	}
	elsif (defined $ARGV[6] && $line =~ /Inspect: $inspectedprotocol4.*,\spacket\s(\d+),\slock\sfail\s(\d+),\sdrop\s(\d+),\sreset-drop\s(\d+)/m) {
		print "inspectedproto4-pkts:",$1," inspectedproto4-drps:",$2+$3+$4," ";
	}
	elsif (defined $ARGV[7] && $line =~ /Inspect: $inspectedprotocol5.*,\spacket\s(\d+),\slock\sfail\s(\d+),\sdrop\s(\d+),\sreset-drop\s(\d+)/m) {
		print "inspectedproto5-pkts:",$1," inspectedproto1-drps:",$2+$3+$4," ";
	}
}