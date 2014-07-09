#!/usr/bin/perl
# Author: Akos Daniel daniel.akos77ATgmail.com
#
# Filename: get_asa_l2lipsectraffics.pl
# Current Version: 0.1 beta
# Created: 11th of April 2014
# Last Changed: 11th of April 2014
# -----------------------------------------------------------------------------------------------
# Description:
# -----------------------------------------------------------------------------------------------
# This is a rather crude and quick hacked Perl-script to get multiple values from 'show vpn-sessiondb l2l' command.
# The IPSec VPN Peer IPs (max 5) should be defined in command.
# Syntax:
# -------
# get_asa_l2lipsectraffics.pl <IP> <Username> <Password> <ipsecpeerip1> <ipsecpeerip2> <ipsecpeerip3> <ipsecpeerip4> <ipsecpeerip5>
#
# Mandatory arguments:
# -------------------
# <IP> : The IP of the cisco asa firewall.
# <Username> : Username for a readonly user.
# <Password> : Password of the user.
# <ipsecpeerip1> : in this script max 5 IPSec VPN Peer IP can be monitored. Just define the Peer IPs.
#
# Example:
# --------
# ./get_asa_l2lipsectraffics.pl 172.16.20.1 cisco cisco123 1.1.1.1 2.2.2.2 3.3.3.3
#
# This will give outputs of the required rx tx bytes
# -----------------------------------------------------------------------------------------------
# Known issues:
# 
# -----------------------------------------------------------------------------------------------
# [solved]
# -----------------------------------------------------------------------------------------------
# Change History
#
# -----------------------------------------------------------------------------------------------
# 0.1 beta: (11th of April 2014)

# Example output:
#
# asa-tg2-fr2k/pri/act# sh vpn-sessiondb l2l
#
#Session Type: LAN-to-LAN
#
#Connection   : 3.23.33.1
#Index        : 178                    IP Addr      : 3.23.33.1
#Protocol     : IKEv1 IPsec
#Encryption   : AES256                 Hashing      : SHA1
#Bytes Tx     : 1390560                Bytes Rx     : 1394220
#Login Time   : 23:32:17 CEDT Tue Apr 8 2014
#Duration     : 2d 16h:38m:29s
#Connection   : 4.36.73.2
#Index        : 216                    IP Addr      : 4.36.73.2
#Protocol     : IKEv1 IPsec
#Encryption   : AES256                 Hashing      : SHA1
#Bytes Tx     : 432599058              Bytes Rx     : 168772729
#Login Time   : 23:40:14 CEDT Tue Apr 8 2014
#Duration     : 2d 16h:30m:32s
#Connection   : 6.5.137.3
#Index        : 6440                   IP Addr      : 6.5.137.3
#Protocol     : IKEv1 IPsec
#Encryption   : AES256                 Hashing      : SHA1
#Bytes Tx     : 69737                  Bytes Rx     : 85711
#Login Time   : 19:45:28 CEDT Wed Apr 9 2014
#Duration     : 1d 20h:25m:18s

use strict;

# Set variables based on input parameters
my $cisco_cmd 		= "show vpn-sessiondb l2l";
my $myfirewallip 	= $ARGV[0];
my $username	 	= $ARGV[1];
my $password	 	= $ARGV[2];
my $ipsecpeerip1	= $ARGV[3];
my $ipsecpeerip2 	= $ARGV[4];
my $ipsecpeerip3 	= $ARGV[5];
my $ipsecpeerip4 	= $ARGV[6];
my $ipsecpeerip5 	= $ARGV[7];

# Check variables to make sure data is there
if(!$myfirewallip||!$ipsecpeerip1||!$username||!$password){
	print "Not all requiredd parameters are filled.\n";
	print "Usage: get_asa_l2lipsectraffics.pl firewallip username password ipsecpeerip1 [... ipsecpeerip5] \n";
	exit;
}

my $output = `lynx -auth=$username:$password -width 100 -dump "https://$myfirewallip:443/exec/$cisco_cmd"`;
my $connline;

foreach my $line (split /[\r\n]+/, $output) {
	
	if ($line =~ /^Connection\s+:\s+((\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3}))/m) {
		$connline = $1;
	}
	elsif ($line =~ /^Bytes\sTx\s+:\s(\d+)\s+Bytes\sRx\s+:\s(\d+)/m) {
		if ($connline eq $ipsecpeerip1) {
			print " ipsecpeer1-Tx:",$1," ipsecpeer1-Rx:",$2;
		}
		elsif ($connline eq $ipsecpeerip2) {
			print " ipsecpeer2-Tx:",$1," ipsecpeer2-Rx:",$2;
		}
		elsif ($connline eq $ipsecpeerip3) {
			print " ipsecpeer3-Tx:",$1," ipsecpeer3-Rx:",$2;
		}
		elsif ($connline eq $ipsecpeerip4) {
			print " ipsecpeer4-Tx:",$1," ipsecpeer4-Rx:",$2;
		}
		elsif ($connline eq $ipsecpeerip5) {
			print " ipsecpeer5-Tx:",$1," ipsecpeer5-Rx:",$2;
		}
	}
}