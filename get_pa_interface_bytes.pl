#!/usr/bin/perl  

use strict;
use warnings;
use LWP::UserAgent;  
use HTTP::Request;
use XML::LibXML; 

my $hostname	=	$ARGV[0]; # IP of the firewall
my $httpskey	=	$ARGV[1]; # example 'vcxvert4rhhgfhf'
my $ifname1     =	$ARGV[2]; # example 'ethernet1/4.112'
my $ifname2     =	$ARGV[3]; # example 'ethernet1/4.113'
my $ifname3     =	$ARGV[4]; # example 'ethernet1/4.114'
my $ifname4     =	$ARGV[5]; # example 'ethernet1/4.115'

my $URL = 'https://'.$hostname.'/api/?type=op&key='.$httpskey.'&cmd=%3Cshow%3E%3Ccounter%3E%3Cinterface%3Eall%3C%2Finterface%3E%3C%2Fcounter%3E%3C%2Fshow%3E';

my $ua = LWP::UserAgent->new(ssl_opts => { verify_hostname => 0 });

my $header = HTTP::Request->new(GET => $URL);  
my $request = HTTP::Request->new('GET', $URL, $header);  
my $response = $ua->request($request);  

my $xml_string;
if ($response->is_success){  
	$xml_string = $response->content;
}
elsif ($response->is_error){  
	print "Error:$URL\n";  
	print $response->error_as_HTML;  
}

my $parser = XML::LibXML->new();
#load_xml function from XML::LibXML::Parser Package
my $xmlfile = XML::LibXML->load_xml(string => $xml_string);

my $xpath  = "//entry[name/text() = '$ifname1']/ibytes/text()"; # xpath_expression (query)

# findnodes function from XML::LibXML::Node Package
foreach my $data (@{$xmlfile->findnodes($xpath)}) {
	print $data->data,"\n";
}