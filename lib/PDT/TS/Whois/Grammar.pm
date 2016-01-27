package PDT::TS::Whois::Grammar;
use utf8;
use strict;
use warnings;
use 5.014;

use YAML::Syck;

=head1 NAME

PDT::TS::Whois::Grammar - A data representation of the ICANN Whois specification

=cut

require Exporter;

our @ISA       = 'Exporter';
our @EXPORT_OK = qw( $grammar );

=head1 EXPORTS

=head2 $grammar

A set of rules represented by a HASHREF.  Each key-value-pair in the HASHREF
represents a rule.

Rules are represented by key-value-pairs where the key (string) is the rule
name.

There are two types of rule values:

=over 4

=item Sequence rule

Represented by an ARRAYREF.  Each element represents a subrule using a single-
key-value-pair HASHREF.

=item Choice rule

Represented by a HASHREF.  Each key-value-pair represents a subrule.

=back

Subrules are represented by key-value-pairs where the key (string) is the
subrule name and the value (HASHREF).

There are two types of subrules:

=over 4

=item Line rules

Represented by a HASHREF with a 'line' key.

=item Section rules

Represented by a HASHREF without a 'line' key.

=back

A subrule value HASHREF may have the following keys:

=over 4

=item quantifier

Values: 'required' | 'optional-free' | 'optional-not-empty' |
        'optional-constrained' | 'empty-constrained' | 'omitted-constrained' |
        /repeatable (max \d+)?/ | /optional-repeatable (max \d+)?/ (default:
        required)

=item line

Values: 'any line'|'awip line'|'empty line'|'field'|'last update line'|'multiple
name servers line'|'non-empty line'|'roid line'.

'any line' is a special wildcard value matching any one of the other line types.

=item type

Values: string

Specifies the type name that the field value must match. Only applicable if this
subrule contains line => 'field'.

=back

=cut

our $grammar = LoadFile( *DATA );

1;

__DATA__
---
Domain Name Object query:
  - Domain name reply: { }
Name Server Object query:
  Name server reply type 1: { }
  Name server reply type 2: { }
Registrar Object query:
  - Registrar reply: { }
Domain name reply:
  - Domain name details section: { }
  - Domain name subsection 1: { quantifier: optional-free }
  - Empty line: { quantifier: repeatable max 3, line: empty line }
  - AWIP footer: { }
  - Legal disclaimer: { }
Domain name subsection 1:
  Last updated footer: { }
  Domain name subsection 2: { }
Domain name subsection 2:
  - Empty line: { line: empty line }
  - Domain name subsection 3: { }
Domain name subsection 3:
  Domain name subsection 4: { }
  Last updated subsection 1: { }
Domain name subsection 4:
  - Domain name details section: { }
  - Domain name subsection 5: { }
Domain name subsection 5:
  Last updated footer: { }
  Domain name subsection 2: { }
Registrar reply:
  - Registrar details section: { }
  - Registrar subsection 1: { quantifier: optional-free }
  - Empty line: { quantifier: repeatable max 3, line: empty line }
  - AWIP footer: { quantifier: optional-free }
  - Legal disclaimer: { }
Registrar subsection 1:
  Last updated footer: { }
  Registrar subsection 2: { }
Registrar subsection 2:
  - Empty line: { line: empty line }
  - Registrar subsection 3: { }
Registrar subsection 3:
  Registrar subsection 4: { }
  Last updated subsection 1: { }
Registrar subsection 4:
  - Registrar details section: { }
  - Registrar subsection 5: { }
Registrar subsection 5:
  Last updated footer: { }
  Registrar subsection 2: { }
Name server reply type 1:
  - Name server details section: { }
  - Name server subsection 1: { quantifier: optional-free }
  - Empty line: { quantifier: repeatable max 3, line: empty line }
  - AWIP footer: { quantifier: optional-free }
  - Legal disclaimer: { }
Name server details section:
  - Server Name: { line: field, type: query name server }
  - IP Address: { quantifier: optional-repeatable, line: field, type: query name server ip }
  - Registrar: { quantifier: optional-constrained, line: field, type: postal line }
  - WHOIS Server: { quantifier: optional-constrained, line: field, type: hostname }
  - Referral URL: { quantifier: optional-constrained, line: field, type: http url }
  - Additional field: { quantifier: optional-repeatable, line: field, keytype: name server object additional field key }
Name server subsection 1:
  Last updated footer: { }
  Name server subsection 2: { }
Name server subsection 2:
  - Empty line: { line: empty line }
  - Name server subsection 3: { }
Name server subsection 3:
  Name server subsection 4: { }
  Last updated subsection 1: { }
Name server subsection 4:
  - Name server details section: { }
  - Name server subsection 5: { }
Name server subsection 5:
  Last updated footer: { }
  Name server subsection 2: { }
Name server reply type 2:
  - Multiple name servers section: { }
  - Empty line: { quantifier: optional-repeatable max 3, line: empty line }
  - Last updated footer: { }
  - Empty line: { quantifier: repeatable max 3, line: empty line }
  - AWIP footer: { quantifier: optional-free }
  - Legal disclaimer: { }
Registrar details section:
  - Registrar Name: { line: field, type: query registrar name }
  - Street: { line: field, type: postal line, quantifier: repeatable }
  - City: { line: field, type: postal line }
  - State/Province: { quantifier: optional-constrained, line: field, type: postal line }
  - Postal Code: { quantifier: optional-constrained, line: field, type: postal code }
  - Country: { line: field, type: country code }
  - Phone number section: { quantifier: repeatable }
  - Phone Ext: { quantifier: optional-free, line: field, type: token }
  - Fax number section: { quantifier: optional-free }
  - Email: { quantifier: repeatable, line: field, type: email address }
  - WHOIS Server: { quantifier: optional-constrained, line: field, type: hostname }
  - Referral URL: { line: field, type: http url }
  - Admin contact section: { quantifier: optional-repeatable }
  - Technical contact section: { quantifier: optional-repeatable }
  - Additional field: { quantifier: optional-repeatable, line: field, keytype: registrar object additional field key }
Admin contact section:
  - Admin Contact: { line: field, type: postal line }
  - Phone number section: { quantifier: repeatable }
  - Fax number section: { quantifier: optional-repeatable }
  - Email: { line: field, type: email address, quantifier: repeatable }
Technical contact section:
  - Technical Contact: { line: field, type: postal line }
  - Phone number section: { quantifier: repeatable }
  - Fax number section: { quantifier: optional-repeatable }
  - Email: { line: field, type: email address, quantifier: repeatable }
Phone number section:
  - Phone Number: { line: field, type: phone number }
  - Phone Ext: { quantifier: optional-free, line: field, type: token }
Fax number section:
  - Fax Number: { line: field, type: phone number }
  - Fax Ext: { quantifier: optional-free, line: field, type: token }
Domain name details section:
  - Domain Name: { line: field, type: query domain name }
  - Internationalized Domain Name: { quantifier: optional-free, line: field, type: u-label }
  - Domain ID: { line: field, type: epp repo id }
  - WHOIS Server: { quantifier: optional-constrained, line: field, type: hostname }
  - Referral URL: { line: field, type: http url }
  - Updated Date: { quantifier: optional-constrained, line: field, type: time stamp }
  - Creation Date: { line: field, type: time stamp }
  - Registry Expiry Date: { line: field, type: time stamp }
  - Sponsoring Registrar: { line: field, type: token }
  - Sponsoring Registrar IANA ID: { line: field, type: positive integer }
  - Domain Status: { quantifier: repeatable, line: field, type: domain status }
  - Registrant ID: { line: field, type: token }
  - Registrant Name: { line: field, type: postal line }
  - Registrant Organization: { quantifier: optional-constrained, line: field, type: postal line }
  - Registrant Street: { quantifier: repeatable, line: field, type: postal line }
  - Registrant City: { line: field, type: postal line }
  - Registrant State/Province: { quantifier: optional-constrained, line: field, type: postal line }
  - Registrant Postal Code: { quantifier: optional-constrained, line: field, type: postal code }
  - Registrant Country: { line: field, type: country code }
  - Registrant Phone: { line: field, type: phone number }
  - Registrant Phone Ext: { quantifier: optional-constrained, line: field, type: token }
  - Registrant Fax: { quantifier: optional-constrained, line: field, type: phone number }
  - Registrant Fax Ext: { quantifier: optional-constrained, line: field, type: token }
  - Registrant Email: { line: field, type: email address }
  - Admin ID: { line: field, type: token }
  - Admin Name: { line: field, type: postal line }
  - Admin Organization: { quantifier: optional-constrained, line: field, type: postal line }
  - Admin Street: { quantifier: repeatable, line: field, type: postal line }
  - Admin City: { line: field, type: postal line }
  - Admin State/Province: { quantifier: optional-constrained, line: field, type: postal line }
  - Admin Postal Code: { quantifier: optional-constrained, line: field, type: postal code }
  - Admin Country: { line: field, type: country code }
  - Admin Phone: { line: field, type: phone number }
  - Admin Phone Ext: { quantifier: optional-constrained, line: field, type: token }
  - Admin Fax: { quantifier: optional-constrained, line: field, type: phone number }
  - Admin Fax Ext: { quantifier: optional-constrained, line: field, type: token }
  - Admin Email: { line: field, type: email address }
  - Tech ID: { line: field, type: token }
  - Tech Name: { line: field, type: postal line }
  - Tech Organization: { quantifier: optional-constrained, line: field, type: postal line }
  - Tech Street: { quantifier: repeatable, line: field, type: postal line }
  - Tech City: { line: field, type: postal line }
  - Tech State/Province: { quantifier: optional-constrained, line: field, type: postal line }
  - Tech Postal Code: { quantifier: optional-constrained, line: field, type: postal code }
  - Tech Country: { line: field, type: country code }
  - Tech Phone: { line: field, type: phone number }
  - Tech Phone Ext: { quantifier: optional-constrained, line: field, type: token }
  - Tech Fax: { quantifier: optional-constrained, line: field, type: phone number }
  - Tech Fax Ext: { quantifier: optional-constrained, line: field, type: token }
  - Tech Email: { line: field, type: email address }
  - Billing contact section: { quantifier: optional-free }
  - Name server section: { quantifier: repeatable }
  - DNSSEC: { line: field, type: dnssec }
  - Additional field: { quantifier: optional-repeatable, line: field, keytype: domain name object additional field key }
Billing contact section:
  - Billing ID: { line: field, type: token }
  - Billing Name: { line: field, type: postal line }
  - Billing Organization: { quantifier: optional-free, line: field, type: postal line }
  - Billing Street: { quantifier: repeatable, line: field, type: postal line }
  - Billing City: { line: field, type: postal line }
  - Billing State/Province: { quantifier: optional-free, line: field, type: postal line }
  - Billing Postal Code: { quantifier: optional-free, line: field, type: postal code }
  - Billing Country: { line: field, type: country code }
  - Billing Phone: { line: field, type: phone number }
  - Billing Phone Ext: { quantifier: optional-free, line: field, type: token }
  - Billing Fax: { quantifier: optional-free, line: field, type: phone number }
  - Billing Fax Ext: { quantifier: optional-free, line: field, type: token }
  - Billing Email: { line: field, type: email address }
Name server section:
  - Name Server: { quantifier: optional-constrained, line: field, type: hostname }
  - IP Address: { quantifier: optional-repeatable, line: field, type: ip address }
Multiple name servers section:
  - Multiple name servers line: { line: multiple name servers line }
  - ROID line: { line: roid line }
  - ROID line: { line: roid line, quantifier: repeatable }
Last updated subsection 1:
  Last updated footer: { }
  Last updated subsection 2: { }
Last updated subsection 2:
  - Empty line: { quantifier: repeatable max 2, line: empty line }
  - Last updated footer: { }
Last updated footer:
  - Last update line: { line: last update line }
AWIP footer:
  - AWIP line: { line: awip line }
  - Empty line: { quantifier: repeatable max 3, line: empty line }
Legal disclaimer:
  - Non-empty line: { line: non-empty line }
  - Any line: { quantifier: optional-repeatable, line: any line }
