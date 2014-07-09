#!/usr/bin/perl
# Author: Akos Daniel daniel.akos77ATgmail.com
#
# Filename: get_asa_asp_drop.pl
# Current Version: 0.1 beta
# Created: 4th of April 2014
# Last Changed: 4th of April 2014
# -----------------------------------------------------------------------------------------------
# Description:
# -----------------------------------------------------------------------------------------------
# This is a rather crude and quick hacked Perl-script to get multiple values from show asp drop command.
# The drop reasons (max 5) should be defined in command.
# Syntax:
# -------
# get_asa_asp_drop.pl <IP> <Username> <Password> <drop_reason1> <drop_reason2> <drop_reason3> <drop_reason4> <drop_reason5>
#
# Mandatory arguments:
# --------------------
# <IP> : The IP of the cisco asa firewall.
# <Username> : Username for a readonly user.
# <Password> : Password of the user.
# <drop_reason1> : in this script max 5 drop reasons can be monitored. Just define the drop reason name. The full ist can be seen in asp_drop_atts.txt
#
# Example:
# --------
# ./get_asa_asp_drop.pl 172.16.20.1 cisco cisco123 acl-drop tcp-not-syn tcp-rstfin-ooo
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

# Example output:
#
# Frame drop:
#  Flow is being freed (flow-being-freed)                                       3
#  Invalid IP header (invalid-ip-header)                                        1
#  Reverse-path verify failed (rpf-violated)                               260084
#  Flow is denied by configured rule (acl-drop)                          29307676
#  Flow denied due to resource limitation (unable-to-create-flow)               3
#  First TCP packet not SYN (tcp-not-syn)                                15606697
#  Bad TCP flags (bad-tcp-flags)                                             1804
#  TCP data send after FIN (tcp-data-past-fin)                                  1
#  TCP failed 3 way handshake (tcp-3whs-failed)                             52295
#  TCP RST/FIN out of order (tcp-rstfin-ooo)                              1265527

use strict;

my $cisco_cmd = "show asp drop";
my $output = `lynx -auth=$ARGV[1]:$ARGV[2] -width 100 -dump "https://$ARGV[0]:443/exec/$cisco_cmd"`;

foreach my $line (split /[\r\n]+/, $output) {
	if (defined $ARGV[3] && $line =~ /.*\s\($ARGV[3]\)\s+(\d+)/m) {
		print "dropr1:",$1," ";
	}
	elsif (defined $ARGV[4] &&  $line =~ /.*\s\($ARGV[4]\)\s+(\d+)/m ) {
		print "dropr2:",$1," ";
	}
	elsif (defined $ARGV[5] && $line =~ /.*\s\($ARGV[5]\)\s+(\d+)/m ) {
		print "dropr3:",$1," ";
	}
	elsif (defined $ARGV[6] && $line =~ /.*\s\($ARGV[6]\)\s+(\d+)/m ) {
		print "dropr4:",$1," ";
	}
	elsif (defined $ARGV[7] && $line =~ /.*\s\($ARGV[7]\)\s+(\d+)/m ) {
		print "dropr5:",$1," ";
	}
}