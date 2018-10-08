use strict;
use warnings;
use 5.014;

use Test::More;
use Test::Differences;
use PDT::TS::Whois::Grammar qw( $grammar );
use PDT::TS::Whois::Lexer;
use PDT::TS::Whois::Remark qw( remark_string );
use PDT::TS::Whois::Types;
use PDT::TS::Whois::Validator qw( validate2 );

plan tests => 1;

my $types = PDT::TS::Whois::Types->new;
$types->load_roid_suffix('t/iana-epp-rep-id.txt');
$types->add_type( 'query domain name' => sub { return ( lc( shift ) ne lc( 'EXAMPLE.TLD' ) ) ? ( 'expected exact domain name' ) : () } );
$types->add_type( 'query name server' => sub { return ( lc( shift ) ne lc( 'NS1.EXAMPLE.TLD' ) ) ? ( 'expected exact name server' ) : () } );
$types->add_type( 'query name server ip' => sub { return ( $_[0] !~ /^192\.0\.[0-9]+\.123$/ && $_[0] ne '2001:0DB8::1' ) ? ( 'expected name server ip' ) : () } );
$types->add_type( 'query registrar name' => sub { return (shift !~ /Example Registrar, Inc\./ ) ? ( 'expected matching registrar name' ) : () } );

my $text = <<EOF;
Server Name: NS1.EXAMPLE.TLD
Registrar:
Registrar WHOIS Server:
Registrar URL:
Additional field 1:
Additional field 2: non-empty
EOF
$text =~ s/(?<!\r)\n/\r\n/g;
my $lexer = PDT::TS::Whois::Lexer->new($text);

my @remarks = validate2( rule => 'Name server details section', lexer => $lexer, grammar => $grammar, types => $types );
my @strings = map { remark_string( $_ ) } @remarks;
eq_or_diff \@strings, [
    'line 5: info: found an additional field: "Additional field 1"',
    'line 6: info: found an additional field: "Additional field 2"',
], 'Should report presence of additional fields';
