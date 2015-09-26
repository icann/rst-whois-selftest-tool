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
    'postal line' => sub {},
    'postal code' => sub {},
    'country code' => sub {},
    'phone number' => sub {},
    'token' => sub {},
    'email address' => sub {},
    'hostname' => sub {},
    'http url' => sub {},
    'key translation' => sub {},
    'time stamp' => sub {},
    'roid' => sub {},
};
my $text = do { local $/; <DATA> };
$text =~ s/(?<!\r)\n/\r\n/g;
my $lexer = Net::Whois::Spec::Lexer->new($text);
my $grammar = LoadFile(dist_file('Net-Whois-Spec', 'spec.yaml'));
my $parser = Net::Whois::Spec::Parser->new(lexer => $lexer, grammar => $grammar, types => $types);
my $result = $parser->parse_output('Registrar Object query');
eq_or_diff $result, [], 'Should accept valid registrar reply';

__DATA__
Registrar Name: Example Registrar, Inc.
Street: 1234 Admiralty Way
City: Marina del Rey
State/Province: CA
Postal Code: 90292
Country: US
Phone Number: +1.3105551212
Fax Number: +1.3105551213
Email: registrar@example.tld
WHOIS Server: whois.example-registrar.tld
Referral URL: http://www.example-registrar.tld
Admin Contact: Joe Registrar
Phone Number: +1.3105551213
Fax Number: +1.3105551213
Email: joeregistrar@example-registrar.tld
Admin Contact: Jane Registrar
Phone Number: +1.3105551214
Fax Number: +1.3105551213
Email: janeregistrar@example-registrar.tld
Technical Contact: John Geek
Phone Number: +1.3105551215
Fax Number: +1.3105551216
Email: johngeek@example-registrar.tld
>>> Last update of Whois database: 2009-05-29T20:15:00Z <<<

For more information on Whois status codes, please visit https://icann.org/epp

Disclaimer: This is a legal disclaimer.
