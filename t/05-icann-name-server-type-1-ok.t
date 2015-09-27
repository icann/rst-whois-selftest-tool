use strict;
use warnings;
use 5.014;

use Test::More tests => 1;
use Test::Differences;
use Net::Whois::Spec::Lexer;
use Net::Whois::Spec::Validator;
use Net::Whois::Spec::Grammar qw( $grammar );
use Net::Whois::Spec::Types;

my $types = Net::Whois::Spec::Types->new;
my $text = do { local $/; <DATA> };
$text =~ s/(?<!\r)\n/\r\n/g;
my $lexer = Net::Whois::Spec::Lexer->new($text);
my $validator = Net::Whois::Spec::Validator->new(lexer => $lexer, grammar => $grammar, types => $types);
my $result = $validator->validate('Name Server Object query');
eq_or_diff $result, [], 'Should accept valid name server reply type 1';

__DATA__
Server Name: NS1.EXAMPLE.TLD
IP Address: 192.0.2.123
IP Address: 2001:0DB8::1
Registrar: Example Registrar, Inc.
WHOIS Server: whois.example-registrar.tld
Referral URL: http://www.example-registrar.tld
>>> Last update of Whois database: 2009-05-29T20:15:00Z <<<

For more information on Whois status codes, please visit https://icann.org/epp

Disclaimer: This is a legal disclaimer.
