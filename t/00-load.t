#!perl -T

use Test::More tests => 1;

BEGIN {
    use_ok( 'Net::Whois::Spec' ) || print "Bail out!\n";
}

diag( "Testing Net::Whois::Spec $Net::Whois::Spec::VERSION, Perl $], $^X" );
