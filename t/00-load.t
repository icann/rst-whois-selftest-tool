#!perl -T

use Test::More tests => 1;

BEGIN {
    use_ok( 'PDT::TS::Whois' ) || print "Bail out!\n";
}

diag( "Testing PDT::TS::Whois $PDT::TS::Whois::VERSION, Perl $], $^X" );
