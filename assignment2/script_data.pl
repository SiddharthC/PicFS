#!/usr/bin/perl

# script to process strace data

use strict;

my $fh;
my %syscallHash;
my $temp;
my $temp2;
my $line;
my $avg=0;
my $count=0;

open ($fh, "<", "datafile") or die "Can't open datafile\n";

while($line = <$fh>){
	chomp $line;
	if($line =~ m/(\w*)/){
		$temp = $1;
	}
	if($line =~ m/(?<=<)([\w\.]*)/){
		$temp2 = $1;
		print "$temp2\n";
	}
	push(@{$syscallHash{$temp}}, $temp2);
}

foreach my $key (sort keys(%syscallHash)){
	print "Systemcall: $key | Times: " ;
	foreach (@{$syscallHash{$key}}){
		$avg += $_;
		$count++;
	}
	$avg = $avg/$count;
	print "$avg\n";
	$avg = 0;
	$count = 0;
}
