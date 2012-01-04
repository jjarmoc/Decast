#!/usr/bin/perl
#-------------
#- DeCast.pl -
#-------------
#
# Decodes and displays SQLi CAST statements
# Displays info about domains being inserted into script tags..
# 
# Jeff Jarmoc
# 10/6/09

sub domain_info ($) 
    {
 	my ($domain) = @_;
	my $dig = `dig $domain`;
	print "-- Dig output for $domain \n $dig \n--\n\n";
	
	my @components = split(/\./, $domain); # break domain name into components
	my $n_comp = ($components[-1] =~ /^uk/) ? 3 : 2; #take the last 3 components for .uk TLDs, otherwise take 2
	my $tld = lc(join '.', @components[-$n_comp .. -1]);
	$tld =~ s/^\.//; # remove leading . if one exists
	my $whois = `whois $tld`; # query whois
	print "-- Whois output for $tld \n $whois \n--\n\n";
    }

sub hex_to_ascii ($)
    {
    	## Convert each two-digit hex number to an ASCII character.
    	(my $str = shift) =~ s/([a-fA-F0-9]{2})/chr(hex $1)/eg;
    	return $str;
    }

sub decast ($)
   {
	my ($in) = @_;
	if ( $in =~ /Cast(\(|%28)0X(.*)as/i){
 	## extract the CAST hex, and return ascii.
		 	my $cast_hex = $2; 
		my $decode = hex_to_ascii($cast_hex);

		if ($decode =~ /Cast/i ) {
			## Decasted text has another cast..
			## Recursively continue until no more casts found.
			print "-- Decodes to\n" . $decode . "\n--\n\n";
			print "--- Embedded Cast found "; 
			decast($decode);
		} else {
		## No cast in embedded commands.
		print "-- Decodes to\n" . $decode . "\n--\n\n";
		}

		if ($decode =~ /\<script src=\"?http\:\/\/(.*)/){
		  ## decode has a script include
		  $domain = $1;
		  $domain =~ s/\/.*//;
		  print "-- Found embedded script tag for domain: " . $domain . "\n";
		  domain_info($domain);
		}
		return $decode;
 	} 
   }

foreach (@ARGV) {
  ## read in the argument file's text
  open(F,$_);
  $input=(<F>);
  close(F);
  print "-- Input\n" . $input . "\n--\n\n";
  }

if (!$input) {
  print "-- No Input file specified, reading from STDIN\n:";
  $input = <STDIN>;
  print "\n";
}

decast($input);
