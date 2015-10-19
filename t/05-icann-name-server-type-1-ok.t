use strict;
use warnings;
use 5.014;

use Test::More tests => 1;
use Test::Differences;
use PDT::TS::Whois::Lexer;
use PDT::TS::Whois::Validator qw( validate );
use PDT::TS::Whois::Grammar qw( $grammar );
use PDT::TS::Whois::Types;

my $types = PDT::TS::Whois::Types->new;
$types->add_type( 'query name server' => sub { return ( lc( shift ) ne lc( 'NS1.EXAMPLE.TLD' ) ) ? ( 'expected exact name server' ) : () } );
$types->add_type( 'query name server ip' => sub { return ( $_[0] ne '192.0.2.123' && $_[0] ne '2001:0DB8::1' ) ? ( 'expected exact name server ip' ) : () } );

my $text = do { local $/; <DATA> };
$text =~ s/(?<!\r)\n/\r\n/g;
my $lexer = PDT::TS::Whois::Lexer->new($text);
my @errors = validate(rule => 'Name Server Object query', lexer => $lexer, grammar => $grammar, types => $types);
eq_or_diff \@errors, [], 'Should accept valid name server reply type 1';

__DATA__
Server Name: NS1.EXAMPLE.TLD
IP Address: 192.0.2.123
IP Address: 2001:0DB8::1
Registrar: Example Registrar, Inc.
WHOIS Server: whois.example-registrar.tld
Referral URL: http://www.example-registrar.tld
>>> Last update of WHOIS database: 2009-05-29T20:15:00Z <<<

For more information on Whois status codes, please visit https://icann.org/epp

Disclaimer: This is a legal disclaimer.
