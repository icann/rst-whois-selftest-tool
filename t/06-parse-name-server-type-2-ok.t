use strict;
use warnings;
use 5.014;

use Test::More tests => 1;
use Test::Differences;
use Net::Whois::Spec::Lexer;
use Net::Whois::Spec::Parser;
use YAML::Syck;
use File::ShareDir 'dist_file', 'dist_dir';

say dist_dir('Net-Whois-Spec');

my $types = {
    'hostname' => sub {},
    'key translation' => sub {},
    'time stamp' => sub {},
    'roid' => sub {},
};
my $text = do { local $/; <DATA> };
$text =~ s/(?<!\r)\n/\r\n/g;
my $lexer = Net::Whois::Spec::Lexer->new($text);
my $grammar = LoadFile(dist_file('Net-Whois-Spec', 'spec.yaml'));
my $parser = Net::Whois::Spec::Parser->new(lexer => $lexer, grammar => $grammar, types => $types);
my $result = $parser->parse_output('Name Server Object query');
eq_or_diff $result, [], 'Should accept valid name server reply type 2';

__DATA__
Query matched more than one name server:
roid1abc-example (ns1.foo.example)
roid5jkl-example (ns2.example.com)
roid9mno-example (ns1.example.net)
>>> Last update of Whois database: 2009-05-29T20:15:00Z <<<

For more information on Whois status codes, please visit https://icann.org/epp

Disclaimer: This is a legal disclaimer.
