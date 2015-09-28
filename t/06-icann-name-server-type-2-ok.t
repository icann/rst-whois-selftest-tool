use strict;
use warnings;
use 5.014;

use Test::More tests => 1;
use Test::Differences;
use PDT::TS::Whois::Lexer;
use PDT::TS::Whois::Validator;
use PDT::TS::Whois::Grammar qw( $grammar );
use PDT::TS::Whois::Types;

my $types = PDT::TS::Whois::Types->new;
my $text = do { local $/; <DATA> };
$text =~ s/(?<!\r)\n/\r\n/g;
my $lexer = PDT::TS::Whois::Lexer->new($text);
my $validator = PDT::TS::Whois::Validator->new(lexer => $lexer, grammar => $grammar, types => $types);
my $result = $validator->validate('Name Server Object query');
eq_or_diff $result, [], 'Should accept valid name server reply type 2';

__DATA__
Query matched more than one name server:
roid1abc-example (ns1.foo.example)
roid5jkl-example (ns2.example.com)
roid9mno-example (ns1.example.net)
>>> Last update of Whois database: 2009-05-29T20:15:00Z <<<

For more information on Whois status codes, please visit https://icann.org/epp

Disclaimer: This is a legal disclaimer.
