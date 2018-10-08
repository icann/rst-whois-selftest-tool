use strict;
use warnings;
use 5.014;

use Test::More tests => 4;
use Test::Differences;
use PDT::TS::Whois::Grammar qw( $grammar );
use PDT::TS::Whois::Lexer;
use PDT::TS::Whois::Redaction qw( add_redaction_types );
use PDT::TS::Whois::Types;
use PDT::TS::Whois::Validator qw( validate );

sub accept_domain {
    my $test_name = shift;
    my $input     = shift =~ s/\r?\n/\r\n/gmr;

    my $types = PDT::TS::Whois::Types->new;
    $types->load_roid_suffix('t/iana-epp-rep-id.txt');
    add_redaction_types $types, {};
    $types->add_type( 'query domain name' => sub { return ( lc( shift ) ne lc( 'EXAMPLE.TLD' ) ) ? ( 'expected exact domain name' ) : () } );

    my $lexer = PDT::TS::Whois::Lexer->new($input);
    my @errors = validate(rule => 'Domain name details section', lexer => $lexer, grammar => $grammar, types => $types);
    eq_or_diff \@errors, [], $test_name;

}

accept_domain 'Should accept valid name server section type A with empty fields' => <<EOF;
Domain Name: EXAMPLE.TLD
Registry Domain ID: D1234567-IIS
Registrar WHOIS Server:
Registrar URL: http://www.example.tld
Updated Date:
Creation Date: 2000-10-08T00:45:00Z
Registry Expiry Date: 2010-10-08T00:44:59Z
Registrar Registration Expiration Date:
Registrar: EXAMPLE REGISTRAR LLC
Registrar IANA ID: 5555555
Registrar Abuse Contact Email: EMAIL\@EXAMPLE.TLD
Registrar Abuse Contact Phone: +1.5555551212
Reseller:
Domain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited
Registry Registrant ID: 5372808-IIS
Registrant Name: EXAMPLE REGISTRANT
Registrant Organization:
Registrant Street: 123 EXAMPLE STREET
Registrant City: ANYTOWN
Registrant State/Province:
Registrant Postal Code:
Registrant Country: EX
Registrant Phone: +1.5555551212
Registrant Phone Ext:
Registrant Fax:
Registrant Fax Ext:
Registrant Email: EMAIL\@EXAMPLE.TLD
Registry Admin ID: 5372809-IIS
Admin Name: EXAMPLE REGISTRANT ADMINISTRATIVE
Admin Organization:
Admin Street: 123 EXAMPLE STREET
Admin City: ANYTOWN
Admin State/Province:
Admin Postal Code:
Admin Country: EX
Admin Phone: +1.5555551212
Admin Phone Ext:
Admin Fax:
Admin Fax Ext:
Admin Email: EMAIL\@EXAMPLE.TLD
Registry Tech ID: 5372811-IIS
Tech Name: EXAMPLE REGISTRAR TECHNICAL
Tech Organization:
Tech Street: 123 EXAMPLE STREET
Tech City: ANYTOWN
Tech State/Province:
Tech Postal Code:
Tech Country: EX
Tech Phone: +1.1235551234
Tech Phone Ext:
Tech Fax:
Tech Fax Ext:
Tech Email: EMAIL\@EXAMPLE.TLD
Name Server: NS01.EXAMPLEREGISTRAR.TLD
IP Address: 192.0.2.1
IP Address: 192.0.2.2
Name Server: NS02.EXAMPLEREGISTRAR.TLD
DNSSEC: signedDelegation
URL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/
EOF

accept_domain 'Should accept valid name server section type A with omitted fields' => <<EOF;
Domain Name: EXAMPLE.TLD
Registry Domain ID: D1234567-IIS
Registrar URL: http://www.example.tld
Creation Date: 2000-10-08T00:45:00Z
Registry Expiry Date: 2010-10-08T00:44:59Z
Registrar: EXAMPLE REGISTRAR LLC
Registrar IANA ID: 5555555
Registrar Abuse Contact Email: EMAIL\@EXAMPLE.TLD
Registrar Abuse Contact Phone: +1.5555551212
Domain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited
Registry Registrant ID: 5372808-IIS
Registrant Name: EXAMPLE REGISTRANT
Registrant Street: 123 EXAMPLE STREET
Registrant City: ANYTOWN
Registrant Country: EX
Registrant Phone: +1.5555551212
Registrant Email: EMAIL\@EXAMPLE.TLD
Registry Admin ID: 5372809-IIS
Admin Name: EXAMPLE REGISTRANT ADMINISTRATIVE
Admin Street: 123 EXAMPLE STREET
Admin City: ANYTOWN
Admin Country: EX
Admin Phone: +1.5555551212
Admin Email: EMAIL\@EXAMPLE.TLD
Registry Tech ID: 5372811-IIS
Tech Name: EXAMPLE REGISTRAR TECHNICAL
Tech Street: 123 EXAMPLE STREET
Tech City: ANYTOWN
Tech Country: EX
Tech Phone: +1.1235551234
Tech Email: EMAIL\@EXAMPLE.TLD
Name Server: NS01.EXAMPLEREGISTRAR.TLD
IP Address: 192.0.2.1
IP Address: 192.0.2.2
Name Server: NS02.EXAMPLEREGISTRAR.TLD
DNSSEC: signedDelegation
URL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/
EOF

accept_domain 'Should accept valid name server section type B with empty fields' => <<EOF;
Domain Name: EXAMPLE.TLD
Registry Domain ID: D1234567-IIS
Registrar WHOIS Server:
Registrar URL: http://www.example.tld
Updated Date:
Creation Date: 2000-10-08T00:45:00Z
Registry Expiry Date: 2010-10-08T00:44:59Z
Registrar Registration Expiration Date:
Registrar: EXAMPLE REGISTRAR LLC
Registrar IANA ID: 5555555
Registrar Abuse Contact Email: EMAIL\@EXAMPLE.TLD
Registrar Abuse Contact Phone: +1.5555551212
Reseller:
Domain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited
Registry Registrant ID: 5372808-IIS
Registrant Name: EXAMPLE REGISTRANT
Registrant Organization:
Registrant Street: 123 EXAMPLE STREET
Registrant City: ANYTOWN
Registrant State/Province:
Registrant Postal Code:
Registrant Country: EX
Registrant Phone: +1.5555551212
Registrant Phone Ext:
Registrant Fax:
Registrant Fax Ext:
Registrant Email: EMAIL\@EXAMPLE.TLD
Registry Admin ID: 5372809-IIS
Admin Name: EXAMPLE REGISTRANT ADMINISTRATIVE
Admin Organization:
Admin Street: 123 EXAMPLE STREET
Admin City: ANYTOWN
Admin State/Province:
Admin Postal Code:
Admin Country: EX
Admin Phone: +1.5555551212
Admin Phone Ext:
Admin Fax:
Admin Fax Ext:
Admin Email: EMAIL\@EXAMPLE.TLD
Registry Tech ID: 5372811-IIS
Tech Name: EXAMPLE REGISTRAR TECHNICAL
Tech Organization:
Tech Street: 123 EXAMPLE STREET
Tech City: ANYTOWN
Tech State/Province:
Tech Postal Code:
Tech Country: EX
Tech Phone: +1.1235551234
Tech Phone Ext:
Tech Fax:
Tech Fax Ext:
Tech Email: EMAIL\@EXAMPLE.TLD
Name Server:
DNSSEC: signedDelegation
URL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/
EOF

accept_domain 'Should accept valid name server section type C with omitted fields' => <<EOF;
Domain Name: EXAMPLE.TLD
Registry Domain ID: D1234567-IIS
Registrar URL: http://www.example.tld
Creation Date: 2000-10-08T00:45:00Z
Registry Expiry Date: 2010-10-08T00:44:59Z
Registrar: EXAMPLE REGISTRAR LLC
Registrar IANA ID: 5555555
Registrar Abuse Contact Email: EMAIL\@EXAMPLE.TLD
Registrar Abuse Contact Phone: +1.5555551212
Domain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited
Registry Registrant ID: 5372808-IIS
Registrant Name: EXAMPLE REGISTRANT
Registrant Street: 123 EXAMPLE STREET
Registrant City: ANYTOWN
Registrant Country: EX
Registrant Phone: +1.5555551212
Registrant Email: EMAIL\@EXAMPLE.TLD
Registry Admin ID: 5372809-IIS
Admin Name: EXAMPLE REGISTRANT ADMINISTRATIVE
Admin Street: 123 EXAMPLE STREET
Admin City: ANYTOWN
Admin Country: EX
Admin Phone: +1.5555551212
Admin Email: EMAIL\@EXAMPLE.TLD
Registry Tech ID: 5372811-IIS
Tech Name: EXAMPLE REGISTRAR TECHNICAL
Tech Street: 123 EXAMPLE STREET
Tech City: ANYTOWN
Tech Country: EX
Tech Phone: +1.1235551234
Tech Email: EMAIL\@EXAMPLE.TLD
Name Server: NS01.EXAMPLEREGISTRAR.TLD
IP Address: 192.0.2.1
IP Address: 192.0.2.2
DNSSEC: signedDelegation
URL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/
EOF
