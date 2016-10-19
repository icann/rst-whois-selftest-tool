use strict;
use warnings;
use 5.014;

use Test::More tests => 7;
use Test::Differences;
use PDT::TS::Whois::Lexer;
use PDT::TS::Whois::Validator qw( validate );
use PDT::TS::Whois::Grammar qw( $grammar );
use PDT::TS::Whois::Types;

sub accept_registrar {
    my $test_name = shift;
    my $input     = shift =~ s/\r?\n/\r\n/gmr;

    my $types = PDT::TS::Whois::Types->new;
    $types->add_type( 'query registrar name' => sub { return (shift !~ /Example Registrar, Inc\./ ) ? ( 'expected matching registrar name' ) : () } );

    my $lexer     = PDT::TS::Whois::Lexer->new( $input );
    my @errors    = validate( rule => 'Registrar details section', lexer => $lexer, grammar => $grammar, types => $types );
    eq_or_diff \@errors, [], "Should accept $test_name";
}

sub reject_registrar {
    my $test_name  = shift;
    my $input      = shift =~ s/\r?\n/\r\n/gmr;

    my $types = PDT::TS::Whois::Types->new;
    $types->add_type( 'query registrar name' => sub { return (shift !~ /Example Registrar, Inc\./ ) ? ( 'expected matching registrar name' ) : () } );

    my $lexer     = PDT::TS::Whois::Lexer->new( $input );
    my @errors    = validate( rule => 'Registrar details section', lexer => $lexer, grammar => $grammar, types => $types );
    cmp_ok @errors, '>', 0, "Should reject $test_name";
}

accept_registrar 'Fax number section type A, empty' => <<EOF;
Registrar: Example Registrar, Inc.
Street: 1234 Admiralty Way
City: Marina del Rey
State/Province: CA
Postal Code:
Country: US
Phone Number: +1.3105551212
Fax Number: +1.3105551213
Fax Ext:
Fax Number: +1.3105551214
Email: registrar\@example.tld
Registrar WHOIS Server:
Registrar URL: http://www.example-registrar.tld
EOF

accept_registrar 'Fax number section type A, omitted' => <<EOF;
Registrar: Example Registrar, Inc.
Street: 1234 Admiralty Way
City: Marina del Rey
State/Province: CA
Country: US
Phone Number: +1.3105551212
Fax Number: +1.3105551213
Fax Ext:
Fax Number: +1.3105551214
Email: registrar\@example.tld
Registrar URL: http://www.example-registrar.tld
EOF

accept_registrar 'Fax number section type B, non-empty field' => <<EOF;
Registrar: Example Registrar, Inc.
Street: 1234 Admiralty Way
City: Marina del Rey
State/Province: CA
Postal Code:
Country: US
Phone Number: +1.3105551212
Fax Number:
Fax Ext: 567
Email: registrar\@example.tld
Registrar WHOIS Server:
Registrar URL: http://www.example-registrar.tld
EOF

accept_registrar 'Fax number section type B, empty field' => <<EOF;
Registrar: Example Registrar, Inc.
Street: 1234 Admiralty Way
City: Marina del Rey
State/Province: CA
Postal Code:
Country: US
Phone Number: +1.3105551212
Fax Number:
Fax Ext:
Email: registrar\@example.tld
Registrar WHOIS Server:
Registrar URL: http://www.example-registrar.tld
EOF

accept_registrar 'Fax number section type B, omitted field' => <<EOF;
Registrar: Example Registrar, Inc.
Street: 1234 Admiralty Way
City: Marina del Rey
State/Province: CA
Postal Code:
Country: US
Phone Number: +1.3105551212
Fax Number:
Email: registrar\@example.tld
Registrar WHOIS Server:
Registrar URL: http://www.example-registrar.tld
EOF

accept_registrar 'Fax number section type C' => <<EOF;
Registrar: Example Registrar, Inc.
Street: 1234 Admiralty Way
City: Marina del Rey
State/Province: CA
Country: US
Phone Number: +1.3105551212
Email: registrar\@example.tld
Registrar URL: http://www.example-registrar.tld
EOF

reject_registrar 'Empty fields but omitted Fax Number' => <<EOF;
Registrar: Example Registrar, Inc.
Street: 1234 Admiralty Way
City: Marina del Rey
State/Province:
Postal Code:
Country: US
Phone Number: +1.3105551212
Fax Number: +1.3105551213
Fax Ext:
Email: registrar\@example.tld
Registrar WHOIS Server:
Registrar URL: http://www.example-registrar.tld
Admin Contact: Joe Registrar
Phone Number: +1.3105551214
Email: joeregistrar\@example-registrar.tld
EOF
