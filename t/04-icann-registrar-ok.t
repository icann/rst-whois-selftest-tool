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
$types->add_type( 'query registrar name' => sub { return (shift !~ /Example Registrar, Inc\./ ) ? ( 'expected matching registrar name' ) : () } );

my $text = do { local $/; <DATA> };
$text =~ s/(?<!\r)\n/\r\n/g;
my $lexer = PDT::TS::Whois::Lexer->new($text);
my @errors = validate(rule => 'Registrar Object query', lexer => $lexer, grammar => $grammar, types => $types);
eq_or_diff \@errors, [], 'Should accept valid registrar reply';

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
>>> Last update of WHOIS database: 2009-05-29T20:15:00Z <<<

For more information on Whois status codes, please visit https://icann.org/epp

Disclaimer: This is a legal disclaimer.
