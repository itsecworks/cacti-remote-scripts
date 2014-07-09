#!/usr/bin/perl
# Modifier: Akos Daniel daniel.akos77ATgmail.com
#
# Filename: lan2lantraffic.pl
# Current Version: 0.1 beta
# Created: 4th of April 2014
# Last Changed: 4th of April 2014
# -----------------------------------------------------------------------------------------------
# Description:
# -----------------------------------------------------------------------------------------------
# LAN2LAN Traffic monitoring with snmp.
# This script will walk the LAN2LAN sessions on a Cisco ASA and return RX/TX Octets
# based on a session IP search criteria
# Original code from here: http://forums.cacti.net/about12873.html 
# Since the OID for IPSec VPN Peer IPs changes after they reconnect, this script is required to check
# continuously the OIDs.
#
# Syntax:
# -------
# Usage: lan2lantraffic.pl community host ipsecpeerip 
#
# Mandatory arguments:
# -------------------
# community : snmp community string
# host : ip of the firewall, that is monitored
# ipsecpeerip : ip of the ipsec peer
#
# Example:
# --------
# # perl ./lan2lantraffic.pl cisco1234 10.10.10.1 13.157.116.66
# ipsecrx:26924 ipsectx:8520 
# -----------------------------------------------------------------------------------------------
# Known issues:
# 
# -----------------------------------------------------------------------------------------------
# [solved]
# -----------------------------------------------------------------------------------------------
# Change History
# - OIDs updated for Cisco ASA.
# - Both snmp rx and tx will be presented.
# -----------------------------------------------------------------------------------------------
# 0.1 beta: (4th of April 2014)

use strict;
use Switch;
use Net::SNMP;

# Set variables based on input parameters
my $community 	= $ARGV[0];
my $host 		= $ARGV[1];
my $ipsecpeerip = $ARGV[2];

# Set OID variables
my $cikeTunRemoteValue 	= "1.3.6.1.4.1.9.9.171.1.2.3.1.7";
my $cikeTunInOctets 	= "1.3.6.1.4.1.9.9.171.1.2.3.1.19";
my $cikeTunOutOctets 	= "1.3.6.1.4.1.9.9.171.1.2.3.1.27";

# Check variables to make sure data is there
if(!$community||!$host||!$ipsecpeerip){
	print "Not all parameters filled.\n";
	print "Usage: lan2lantraffic.pl community host ipsecpeerip \n";
	exit;
}

# Create SNMP Session
my $snmpsession;
my $error;

($snmpsession, $error) = Net::SNMP->session(-hostname=>$host,-community=>$community,-port=>161);
die "session error: $error" unless ($snmpsession);

# Walk cikeTunRemoteValue (the ipsec peer ips) for list of active session OIDs
# Example return values:
# SNMPv2-SMI::enterprises.9.9.171.1.2.3.1.7.177811456 = STRING: "13.157.116.66"
# SNMPv2-SMI::enterprises.9.9.171.1.2.3.1.7.179879936 = STRING: "123.158.141.201"
my %result = $snmpsession->get_table($cikeTunRemoteValue);
die "request error: ".$snmpsession->error unless (defined %result);

# Grab the ipsec peer ip oids and stick it into an array (ghetto)
# result will be like:
# 1.3.6.1.4.1.9.9.171.1.2.3.1.7.177811456
my @indexoids = $snmpsession->var_bind_names;

# Loop through the oid array and make a seperate request to get the data (even more ghetto)
my %datatable;
foreach my $oid (@indexoids){
	# Split the full OID to get the index
	# result will be like:
	# $splits[1] = .177811456
	my @splits = split($cikeTunRemoteValue,$oid);

	# Set index var
	my $dataindex = $splits[1];

	# Grab a hash of the IPsec Peer IP address from the OID
	my $getdata = $snmpsession->get_request($oid);

	# Take the oid index and the returned value and create a hash
	# This is your datatable with index => ipaddress
	$datatable{$dataindex} = $getdata->{$oid};
}

# Search datatable for session ip parameter

my $outindex;
foreach my $key (sort keys (%datatable)){
	#print "$key => $datatable{$key}\n";
	if($datatable{$key} == $ipsecpeerip){

		# We have a match, set output index
		$outindex = $key;
	} else {
		# No match, no data
	}
}

# We now have an index of a matching session ip, lets grab the data

# Get session traffic octect based on index and flow (tx or rx)

# 'rx' {	# Set output to RX Octets (cikeTunInOctets)
my $outdata = $snmpsession->get_request($cikeTunInOctets.$outindex);
my $rxoutput = $outdata->{$cikeTunInOctets.$outindex};

# 'tx' {	# Set output to TX Octets (cikeTunOutOctets)
my $outdata = $snmpsession->get_request($cikeTunOutOctets.$outindex);
my $txoutput = $outdata->{$cikeTunOutOctets.$outindex};

# Close SNMP session
$snmpsession->close;

# Output data cleanly
chomp($rxoutput);
chomp($txoutput);
print "ipsecrx:",$rxoutput," ipsectx:",$txoutput;