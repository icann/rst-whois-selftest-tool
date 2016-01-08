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
    );
    plan tests => scalar keys %data;

    while ( my ( $input, $expected_output ) = each( %data ) ) {
        my @actual_output = PDT::TS::Whois::Util::scrub_u_label( $input );
        eq_or_diff \@actual_output, $expected_output;
    }
};
