use strict;
use warnings;
use 5.014;

use Test::More;
use Test::Differences;
use PDT::TS::Whois::Lexer;
use PDT::TS::Whois::Validator qw( validate );
use PDT::TS::Whois::Grammar qw( $grammar );
use PDT::TS::Whois::Types;

my $nameserver_details_minimal_ok = <<EOF;
Server Name: NS1.EXAMPLE.TLD
EOF

my $nameserver_details_empty_ok = <<EOF;
Server Name: NS1.EXAMPLE.TLD
Registrar:
Registrar WHOIS Server:
Registrar URL:
Additional field:
EOF

my $nameserver_details_repeated_ok = <<EOF;
Server Name: NS1.EXAMPLE.TLD
IP Address: 192.0.1.123
IP Address: 192.0.2.123
EOF

my $domain_details_minimal_level_1_ok = <<EOF;
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
Domain Status: clientRenewProhibited https://icann.org/epp#clientRenewProhibited
Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
Domain Status: serverUpdateProhibited https://icann.org/epp#serverUpdateProhibited
Registry Registrant ID: abc123-IIS
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
DNSSEC: signedDelegation
URL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/
EOF

my $domain_details_minimal_level_2_ok = <<EOF;
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
Domain Status: clientRenewProhibited https://icann.org/epp#clientRenewProhibited
Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
Domain Status: serverUpdateProhibited https://icann.org/epp#serverUpdateProhibited
Registry Registrant ID: abc123-IIS
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
Registry Billing ID: 5372811-IIS
Billing Name: EXAMPLE REGISTRAR BILLING
Billing Street: 123 EXAMPLE STREET
Billing City: ANYTOWN
Billing Country: EX
Billing Phone: +1.1235551234
Billing Email: EMAIL\@EXAMPLE.TLD
Name Server: NS01.EXAMPLEREGISTRAR.TLD
DNSSEC: signedDelegation
URL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/
EOF

my $domain_details_free_ok = <<EOF;
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
Domain Status: clientRenewProhibited https://icann.org/epp#clientRenewProhibited
Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
Domain Status: serverUpdateProhibited https://icann.org/epp#serverUpdateProhibited
Registry Registrant ID: abc123-IIS
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
Registry Billing ID: 5372811-IIS
Billing Name: EXAMPLE REGISTRAR BILLING
Billing Organization:
Billing Street: 123 EXAMPLE STREET
Billing City: ANYTOWN
Billing State/Province:
Billing Postal Code:
Billing Country: EX
Billing Phone: +1.1235551234
Billing Phone Ext:
Billing Fax:
Billing Fax Ext:
Billing Email: EMAIL\@EXAMPLE.TLD
Name Server: NS01.EXAMPLEREGISTRAR.TLD
DNSSEC: signedDelegation
URL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/
EOF

my $domain_details_empty_level_1_ok = <<EOF;
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
Domain Status: clientRenewProhibited https://icann.org/epp#clientRenewProhibited
Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
Domain Status: serverUpdateProhibited https://icann.org/epp#serverUpdateProhibited
Registry Registrant ID: abc123-IIS
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
DNSSEC: signedDelegation
URL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/
EOF

my $domain_details_empty_level_2_ok = <<EOF;
Domain Name: EXAMPLE.TLD
Internationalized Domain Name:
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
Domain Status: clientRenewProhibited https://icann.org/epp#clientRenewProhibited
Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
Domain Status: serverUpdateProhibited https://icann.org/epp#serverUpdateProhibited
Registry Registrant ID: abc123-IIS
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
Registry Billing ID: 5372811-IIS
Billing Name: EXAMPLE REGISTRAR BILLING
Billing Street: 123 EXAMPLE STREET
Billing City: ANYTOWN
Billing Country: EX
Billing Phone: +1.1235551234
Billing Email: EMAIL\@EXAMPLE.TLD
Name Server: NS01.EXAMPLEREGISTRAR.TLD
DNSSEC: signedDelegation
Additional field:
URL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/
EOF

my $domain_details_nameserver_minimal_ok = <<EOF;
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
Domain Status: clientRenewProhibited https://icann.org/epp#clientRenewProhibited
Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
Domain Status: serverUpdateProhibited https://icann.org/epp#serverUpdateProhibited
Registry Registrant ID: abc123-IIS
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
DNSSEC: signedDelegation
URL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/
EOF

my $domain_details_repeated_ok = <<EOF;
Domain Name: EXAMPLE.TLD
Registry Domain ID: D1234567-IIS
Registrar URL: http://www.example.tld
Creation Date: 2000-10-08T00:45:00Z
Registry Expiry Date: 2010-10-08T00:44:59Z
Registrar: EXAMPLE REGISTRAR LLC
Registrar IANA ID: 5555555
Domain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited
Domain Status: clientRenewProhibited https://icann.org/epp#clientRenewProhibited
Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
Domain Status: serverUpdateProhibited https://icann.org/epp#serverUpdateProhibited
Registry Registrant ID: abc123-IIS
Registrant Name: EXAMPLE REGISTRANT
Registrant Street: 123
Registrant Street: EXAMPLE
Registrant Street: STREET
Registrant Street: That's right
Registrant City: ANYTOWN
Registrant Country: EX
Registrant Phone: +1.5555551212
Registrant Email: EMAIL\@EXAMPLE.TLD
Registry Admin ID: 5372809-IIS
Admin Name: EXAMPLE REGISTRANT ADMINISTRATIVE
Admin Street: 123
Admin Street: EXAMPLE
Admin Street: STREET
Admin Street: That's right
Admin City: ANYTOWN
Admin Country: EX
Admin Phone: +1.5555551212
Admin Email: EMAIL\@EXAMPLE.TLD
Registry Tech ID: 5372811-IIS
Tech Name: EXAMPLE REGISTRAR TECHNICAL
Tech Street: 123
Tech Street: EXAMPLE
Tech Street: STREET
Tech Street: That's right
Tech City: ANYTOWN
Tech Country: EX
Tech Phone: +1.1235551234
Tech Email: EMAIL\@EXAMPLE.TLD
Registry Billing ID: 5372811-IIS
Billing Name: EXAMPLE REGISTRAR BILLING
Billing Street: 123
Billing Street: EXAMPLE
Billing Street: STREET
Billing Street: That's right
Billing City: ANYTOWN
Billing Country: EX
Billing Phone: +1.1235551234
Billing Email: EMAIL\@EXAMPLE.TLD
Name Server: NS01.EXAMPLEREGISTRAR.TLD
DNSSEC: signedDelegation
URL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/
EOF

my $domain_details_nameserver_repeated_ok = <<EOF;
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
Domain Status: clientRenewProhibited https://icann.org/epp#clientRenewProhibited
Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
Domain Status: serverUpdateProhibited https://icann.org/epp#serverUpdateProhibited
Registry Registrant ID: abc123-IIS
Registrant Name: EXAMPLE REGISTRANT
Registrant Street: 123
Registrant Street: EXAMPLE
Registrant Street: STREET
Registrant Street: That's right
Registrant City: ANYTOWN
Registrant Country: EX
Registrant Phone: +1.5555551212
Registrant Email: EMAIL\@EXAMPLE.TLD
Registry Admin ID: 5372809-IIS
Admin Name: EXAMPLE REGISTRANT ADMINISTRATIVE
Admin Street: 123
Admin Street: EXAMPLE
Admin Street: STREET
Admin Street: That's right
Admin City: ANYTOWN
Admin Country: EX
Admin Phone: +1.5555551212
Admin Email: EMAIL\@EXAMPLE.TLD
Registry Tech ID: 5372811-IIS
Tech Name: EXAMPLE REGISTRAR TECHNICAL
Tech Street: 123
Tech Street: EXAMPLE
Tech Street: STREET
Tech Street: That's right
Tech City: ANYTOWN
Tech Country: EX
Tech Phone: +1.1235551234
Tech Email: EMAIL\@EXAMPLE.TLD
Name Server: NS01.EXAMPLEREGISTRAR.TLD
IP Address: 192.0.0.123
IP Address: 192.0.1.123
Name Server: NS02.EXAMPLEREGISTRAR.TLD
IP Address: 192.0.4.123
IP Address: 192.0.5.123
DNSSEC: signedDelegation
URL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/
EOF

my $technical_minimal_level_1_ok = <<EOF;
Technical Contact: EXAMPLE REGISTRAR TECHNICAL
Phone Number: +1.1235551234
Email: EMAIL\@EXAMPLE.TLD
EOF

my $technical_minimal_level_2_ok = <<EOF;
Technical Contact: EXAMPLE REGISTRAR TECHNICAL
Phone Number: +1.1235551234
Fax Number: +1.1235551234
Email: EMAIL\@EXAMPLE.TLD
EOF

my $technical_empty_ok = <<EOF;
Technical Contact: EXAMPLE REGISTRAR TECHNICAL
Phone Number: +1.1235551234
Phone Ext:
Fax Number: +1.1235551234
Fax Ext:
Email: EMAIL\@EXAMPLE.TLD
EOF

my $technical_repeated_ok = <<EOF;
Technical Contact: EXAMPLE REGISTRAR TECHNICAL
Phone Number: +1.1235551234
Phone Number: +1.1235551235
Fax Number: +1.1235551234
Fax Number: +1.1235551235
Email: EMAIL\@EXAMPLE.TLD
Email: EMAIL2\@EXAMPLE.TLD
EOF

my $admin_minimal_level_1_ok = <<EOF;
Admin Contact: EXAMPLE REGISTRAR ADMINISTRATIVE
Phone Number: +1.1235551234
Email: EMAIL\@EXAMPLE.TLD
EOF

my $admin_minimal_level_2_ok = <<EOF;
Admin Contact: EXAMPLE REGISTRAR ADMINISTRATIVE
Phone Number: +1.1235551234
Fax Number: +1.1235551234
Email: EMAIL\@EXAMPLE.TLD
EOF

my $admin_empty_ok = <<EOF;
Admin Contact: EXAMPLE REGISTRAR ADMINISTRATIVE
Phone Number: +1.1235551234
Phone Ext:
Fax Number: +1.1235551234
Fax Ext:
Email: EMAIL\@EXAMPLE.TLD
EOF

my $admin_repeated_ok = <<EOF;
Admin Contact: EXAMPLE REGISTRAR ADMINISTRATIVE
Phone Number: +1.1235551234
Phone Number: +1.1235551235
Fax Number: +1.1235551234
Fax Number: +1.1235551235
Email: EMAIL\@EXAMPLE.TLD
Email: EMAIL2\@EXAMPLE.TLD
EOF

my $registrar_details_minimal_level_1_ok = <<EOF;
Registrar: Example Registrar, Inc.
Street: 1234 Admiralty Way
City: Marina del Rey
Country: US
Phone Number: +1.3105551212
Email: registrar\@example.tld
Registrar URL: http://www.example-registrar.tld
EOF

my $registrar_details_minimal_level_2_ok = <<EOF;
Registrar: Example Registrar, Inc.
Street: 1234 Admiralty Way
City: Marina del Rey
Country: US
Phone Number: +1.3105551212
Email: registrar\@example.tld
Registrar URL: http://www.example-registrar.tld
Admin Contact: Joe Registrar
Phone Number: +1.3105551213
Email: joeregistrar\@example-registrar.tld
Technical Contact: John Geek
Phone Number: +1.3105551215
Email: johngeek\@example-registrar.tld
EOF

my $registrar_details_free_ok = <<EOF;
Registrar: Example Registrar, Inc.
Street: 1234 Admiralty Way
City: Marina del Rey
Country: US
Phone Number: +1.3105551212
Phone Ext:
Email: registrar\@example.tld
Registrar URL: http://www.example-registrar.tld
Admin Contact: Joe Registrar
Phone Number: +1.3105551212
Phone Ext:
Fax Number: +1.3105551213
Fax Ext:
Email: joeregistrar\@example-registrar.tld
Technical Contact: John Geek
Phone Number: +1.3105551214
Phone Ext:
Fax Number: +1.3105551215
Fax Ext:
Email: johngeek\@example-registrar.tld
EOF

my $registrar_details_empty_level_1_ok = <<EOF;
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
Fax Number:
Email: joeregistrar\@example-registrar.tld
Technical Contact: John Geek
Phone Number: +1.3105551216
Fax Number:
Email: johngeek\@example-registrar.tld
Additional field:
EOF

my $registrar_details_empty_level_2_ok = <<EOF;
Registrar: Example Registrar, Inc.
Street: 1234 Admiralty Way
City: Marina del Rey
State/Province:
Postal Code:
Country: US
Phone Number: +1.3105551212
Fax Number: +1.3105551213
Email: registrar\@example.tld
Registrar WHOIS Server:
Registrar URL: http://www.example-registrar.tld
Admin Contact: Joe Registrar
Phone Number: +1.3105551214
Fax Number: +1.3105551215
Email: joeregistrar\@example-registrar.tld
Technical Contact: John Geek
Phone Number: +1.3105551216
Fax Number: +1.3105551217
Email: johngeek\@example-registrar.tld
Additional field:
EOF

my $registrar_details_repeated_ok = <<EOF;
Registrar: Example Registrar, Inc.
Street: 1234
Street: Admiralty
Street: Way
Street: That's right
City: Marina del Rey
Country: US
Phone Number: +1.3105551212
Email: registrar\@example.tld
Registrar URL: http://www.example-registrar.tld
Admin Contact: Joe Registrar
Phone Number: +1.3105551213
Email: joeregistrar\@example-registrar.tld
Technical Contact: John Geek
Phone Number: +1.3105551215
Email: johngeek\@example-registrar.tld
EOF

my %data = (
    'Admin contact section/empty',                     => $admin_empty_ok,
    'Admin contact section/minimal level 1',           => $admin_minimal_level_1_ok,
    'Admin contact section/minimal level 2',           => $admin_minimal_level_2_ok,
    'Admin contact section/repeated',                  => $admin_repeated_ok,
    'Domain name details section/empty level 1',       => $domain_details_empty_level_1_ok,
    'Domain name details section/empty level 2',       => $domain_details_empty_level_2_ok,
    'Domain name details section/free',                => $domain_details_free_ok,
    'Domain name details section/minimal level 1',     => $domain_details_minimal_level_1_ok,
    'Domain name details section/minimal level 2',     => $domain_details_minimal_level_2_ok,
    'Domain name details section/nameserver minimal',  => $domain_details_nameserver_minimal_ok,
    'Domain name details section/nameserver repeated', => $domain_details_nameserver_repeated_ok,
    'Name server details section/empty',               => $nameserver_details_empty_ok,
    'Name server details section/minimal',             => $nameserver_details_minimal_ok,
    'Name server details section/repeated',            => $nameserver_details_repeated_ok,
    'Registrar details section/empty level 1',         => $registrar_details_empty_level_1_ok,
    'Registrar details section/empty level 2',         => $registrar_details_empty_level_2_ok,
    'Registrar details section/free',                  => $registrar_details_free_ok,
    'Registrar details section/minimal level 1',       => $registrar_details_minimal_level_1_ok,
    'Registrar details section/minimal level 2',       => $registrar_details_minimal_level_2_ok,
    'Registrar details section/repeated',              => $registrar_details_repeated_ok,
    'Technical contact section/empty',                 => $technical_empty_ok,
    'Technical contact section/minimal level 1',       => $technical_minimal_level_1_ok,
    'Technical contact section/minimal level 2',       => $technical_minimal_level_2_ok,
    'Technical contact section/repeated',              => $technical_repeated_ok,
);

plan tests => scalar keys %data;

my $types = PDT::TS::Whois::Types->new;
$types->load_roid_suffix('t/iana-epp-rep-id.txt');
$types->add_type( 'query domain name' => sub { return ( lc( shift ) ne lc( 'EXAMPLE.TLD' ) ) ? ( 'expected exact domain name' ) : () } );
$types->add_type( 'query name server' => sub { return ( lc( shift ) ne lc( 'NS1.EXAMPLE.TLD' ) ) ? ( 'expected exact name server' ) : () } );
$types->add_type( 'query name server ip' => sub { return ( $_[0] !~ /^192\.0\.[0-9]+\.123$/ && $_[0] ne '2001:0DB8::1' ) ? ( 'expected name server ip' ) : () } );
$types->add_type( 'query registrar name' => sub { return (shift !~ /Example Registrar, Inc\./ ) ? ( 'expected matching registrar name' ) : () } );

for my $test_name ( sort keys %data ) {
    $test_name =~ qr{(.*)/.*};
    my $rule = $1;

    my $text = $data{$test_name};
    $text =~ s/(?<!\r)\n/\r\n/g;

    my $lexer = PDT::TS::Whois::Lexer->new($text);

    my @errors = validate(rule => $rule, lexer => $lexer, grammar => $grammar, types => $types);
    @errors = grep { $_ !~ qr/^line \d+: found an additional field: "Additional field"$/ } @errors;
    eq_or_diff \@errors, [], $test_name;
}
