use strict;
use warnings;
use 5.014;
use utf8;

use Test::More tests => 2;
use Test::Differences;

# This is needed to get rid of wide character print warnings
binmode STDOUT, ':utf8';

require_ok( 'PDT::TS::Whois::Util' );

subtest 'scrub_u_label' => sub {
    my %data = (
        'smörgås.购物.tube'  => ['xn--smrgs-pra0j.xn--g2xx48c.tube'],
        'smÖrgÅs.购物.tube'  => [],
        'smörgås．购物.tube' => [],
        'smörgås｡购物.tube'  => [],
        'SANDWICH.购物.tube'  => ['sandwich.xn--g2xx48c.tube'],
    );
    plan tests => scalar keys %data;

    for my $input ( sort keys %data ) {
        my $expected_output = $data{$input};
        my @actual_output   = PDT::TS::Whois::Util::scrub_u_label( $input );
        my $escaped_input   = $input =~ s/([^[:ascii:]])/sprintf "\\x{%04X}", ord $1/egr;
        eq_or_diff \@actual_output, $expected_output, "scrubbing of $escaped_input";
    }
};
