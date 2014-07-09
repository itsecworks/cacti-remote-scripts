#!/usr/bin/perl
# Author: Akos Daniel daniel.akos77ATgmail.com
#
# Filename: get_interface_drops.pl
# Current Version: 0.1 beta
# Created: 30th of May 2014
# Last Changed: 30th of May 2014
# -----------------------------------------------------------------------------------------------
# Description:
# -----------------------------------------------------------------------------------------------
# This is a rather crude and quick hacked Perl-script to get drop values from show interface command for the defined interface.
# The drop reasons are defined in the script.
# Cisco ASA does not support  OLD-CISCO-INTERFACES-MIB and that cause that detailed inerface errors cannot be monitored with snmp, but it can with script.
# ftp://ftp.cisco.com/pub/mibs/supportlists/asa/asa-supportlist.html
#
# Syntax:
# -------
# get_asa_interface_drops.pl <IP> <Username> <Password> <IFName>
#
# Mandatory arguments:
# --------------------
# <IP> : The IP of the cisco asa firewall.
# <Username> : Username for a readonly user.
# <Password> : Password of the user.
# <IFName> : Interface name, like GigabitEthernet0/0 or Fastethernet1, but no nameif accepted!
#
# Example:
# --------
# ./get_interface_drops.pl 172.16.20.1 cisco cisco123 GigabitEthernet0/0
#
# This will give outputs of the required drops reasons
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

# Example output of show interface command:
#
# Interface GigabitEthernet0/0 "", is up, line protocol is up
#  Hardware is i82546GB rev03, BW 1000 Mbps, DLY 10 usec
#        Auto-Duplex(Full-duplex), Auto-Speed(1000 Mbps)
#        Input flow control is unsupported, output flow control is off
#        Available but not configured via nameif
#        MAC address 0021.5537.9008, MTU not set
#        IP address unassigned
#        142690064811 packets input, 47721419285108 bytes, 0 no buffer
#        Received 1051470 broadcasts, 0 runts, 0 giants
#        3468812 input errors, 0 CRC, 0 frame, 3468812 overrun, 0 ignored, 0 abort
#        0 pause input, 0 resume input
#        0 L2 decode drops
#        158383627503 packets output, 97514266938349 bytes, 2462878 underruns
#        0 pause output, 0 resume output
#        0 output errors, 0 collisions, 2 interface resets
#        0 late collisions, 0 deferred
#        0 input reset drops, 0 output reset drops, 0 tx hangs
#        input queue (blocks free curr/low): hardware (255/230)
#        output queue (blocks free curr/low): hardware (226/0)
#Interface GigabitEthernet0/0.114 "fw-trans", is up, line protocol is up
#  Hardware is i82546GB rev03, BW 1000 Mbps, DLY 10 usec
#        VLAN identifier 114
#        MAC address 0021.5537.9008, MTU 1500
#        IP address 192.168.14.11, subnet mask 255.255.255.0
#  Traffic Statistics for "fw-trans":
#        142667518916 packets input, 44345923999682 bytes
#        158386091303 packets output, 93991992109018 bytes
#        39538536 packets dropped

use strict;

# Set variables based on input parameters
my $myfirewallip 	= $ARGV[0];
my $username	 	= $ARGV[1];
my $password	 	= $ARGV[2];
my $ifname			= $ARGV[3];

# Check variables to make sure data is there
if(!$myfirewallip||!$username||!$password||!$ifname){
	print "Not all requiredd parameters are filled.\n";
	print "Usage: get_asa_interface_drops.pl firewallip username password interfacename \n";
	exit;
}

#in html code the slash is used and have to change to HEX "%2F"
my $ifnamehex = $ifname;
$ifnamehex =~ s/\//%2F/g;
my $cisco_cmd = "show interface $ifnamehex";

# get the output
my $output = `lynx -auth=$username:$password -width 100 -dump "https://$myfirewallip:443/exec/$cisco_cmd"`;

my $interface_found;
#input values
my $input_packet;
my $input_byte;
my $input_nobuffer;
my $received_broadcast;
my $received_runt;
my $received_giant;
my $input_error;
my $input_crc;
my $input_frame;
my $input_overrun;
my $input_ignored;
my $input_abort;
my $input_pause;
my $input_resume;
my $input_l2decodedrop;
#output values
my $output_packet;
my $output_byte;
my $output_underrun;
my $output_pause;
my $output_resume;
my $output_error;
my $output_collision;
my $output_ifreset;
my $output_lcollision;
my $output_deferred;
#input / output reset drops
my $input_rdrop;
my $output_rdrop;
my $tx_hangs;

foreach my $line (split /[\r\n]+/, $output) {

	if ($line =~ /^Interface\s+$ifname\s.*/m) {
		$interface_found	= $ifname;
	}
	# Input values
	elsif ($line =~ /^\s+(\d+)\spackets\sinput,\s(\d+)\sbytes,\s(\d+)\sno\sbuffer$/m) {
		$input_packet		= $1;
		$input_byte			= $2;
		$input_nobuffer 	= $3;
	}
	elsif ($line =~ /^\s+Received\s(\d+)\sbroadcasts,\s(\d+)\srunts,\s(\d+)\sgiants$/m) {
		$received_broadcast	= $1;
		$received_runt		= $2;
		$received_giant		= $3;		
	}
	elsif ($line =~ /^\s+(\d+)\sinput\serrors,\s(\d+)\sCRC,\s(\d+)\sframe,\s(\d+)\soverrun,\s(\d+)\signored,\s(\d+)\sabort$/m) {
		$input_error		= $1;
		$input_crc			= $2;
		$input_frame		= $3;
		$input_overrun		= $4;
		$input_ignored		= $5;
		$input_abort		= $6;
	}
	elsif ($line =~ /^\s+(\d+)\spause\sinput,\s(\d+)\sresume\sinput$/m) {
		$input_pause		= $1;
		$input_resume		= $2;
	}
	elsif ($line =~ /^\s+(\d+)\sL2\sdecode\sdrops$/m) {
		$input_l2decodedrop	= $1;
	}
	# Output values
	elsif ($line =~ /^\s+(\d+)\spackets\soutput,\s(\d+)\sbytes,\s(\d+)\sunderruns$/m) {
		$output_packet		= $1;
		$output_byte		= $2;
		$output_underrun 	= $3;
	}
	elsif ($line =~ /^\s+(\d+)\spause\soutput,\s(\d+)\sresume\soutput$/m) {
		$output_pause		= $1;
		$output_resume		= $2;
	}
	elsif ($line =~ /^\s+(\d+)\soutput\serrors,\s(\d+)\scollisions,\s(\d+)\sinterface\sresets$/m) {
		$output_error		= $1;
		$output_collision	= $2;
		$output_ifreset		= $3;
	}
	elsif ($line =~ /^\s+(\d+)\slate\scollisions,\s(\d+)\sdeferred$/m) {
		$output_lcollision	= $1;
		$output_deferred	= $2;
	}
	elsif (($line =~ /^\s+(\d+)\sinput\sreset\sdrops,\s(\d+)\soutput\sreset\sdrops,\s(\d+)\stx\shangs$/m) || ($line =~ /^\s+(\d+)\sinput\sreset\sdrops,\s(\d+)\soutput\sreset\sdrops$/m)){
		$input_rdrop		= $1;
		$output_rdrop		= $2;
		$tx_hangs			= $3;
		if (not defined($tx_hangs)) {
			$tx_hangs = "0";
		}
		if ($interface_found eq $ifname) {
			print "input_packet:",$input_packet," input_byte:",$input_byte," input_nobuffer:",$input_nobuffer," received_broadcast:",$received_broadcast," received_runt:",$received_runt," received_giant:",$received_giant," input_error:",$input_error," input_crc:",$input_crc," input_frame:",$input_frame," input_overrun:",$input_overrun," output_packet:",$output_packet," output_byte:",$output_byte," output_underrun:",$output_underrun," output_pause:",$output_pause," output_resume:",$output_resume," output_error:",$output_error," output_collision:",$output_collision," output_ifreset:",$output_ifreset," output_lcollition:",$output_lcollision," output_deferred:",$output_deferred," input_rdrop:",$input_rdrop," output_rdrop:",$output_rdrop." tx_hangs:",$tx_hangs;
			$interface_found ='';
		}
	}
}