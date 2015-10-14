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
$types->load_roid_suffix('t/roid-example.txt');
$types->add_type( 'query name server' => sub { } );

my $text = do { local $/; <DATA> };
$text =~ s/(?<!\r)\n/\r\n/g;
my $lexer = PDT::TS::Whois::Lexer->new($text);
my @errors = validate(rule => 'Name Server Object query', lexer => $lexer, grammar => $grammar, types => $types);
eq_or_diff \@errors, [], 'Should accept valid name server reply type 2';

__DATA__
Query matched more than one name server:
roid1abc-example (ns1.foo.example)
roid5jkl-example (ns2.example.com)
roid9mno-example (ns1.example.net)
>>> Last update of WHOIS database: 2009-05-29T20:15:00Z <<<

For more information on Whois status codes, please visit https://icann.org/epp

Disclaimer: This is a legal disclaimer.
