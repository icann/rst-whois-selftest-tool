use strict;
use warnings;
use 5.014;

use Test::More tests => 1;
use Test::Differences;
use Net::Whois::Spec::Lexer;
use Net::Whois::Spec::Parser;
use YAML::Syck;
use File::ShareDir 'dist_file', 'dist_dir';
use IO::Handle;

say dist_dir('Net-Whois-Spec');

my $types = {
    'hostname' => sub {},
    'ip address' => sub {},
    'postal line' => sub {},
    'http url' => sub {},
    'key translation' => sub {},
    'time stamp' => sub {},
    'roid' => sub {},
};
my $io = IO::Handle->new_from_fd(*DATA, 'r');
my $lexer = Net::Whois::Spec::Lexer->new(io => $io);
$lexer->load();
my $grammar = LoadFile(dist_file('Net-Whois-Spec', 'spec.yaml'));
my $parser = Net::Whois::Spec::Parser->new(lexer => $lexer, grammar => $grammar, types => $types);
my $result = $parser->parse_output('Name Server Object query');
eq_or_diff $result, [], 'Should accept valid name server reply type 1';

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
