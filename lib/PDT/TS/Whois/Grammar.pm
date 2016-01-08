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

=item optional

Values: 'y'|'n' (default: n)

=item repeatable

Values: non-negative integer|'unbounded' (default: 1)

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
  - Domain name subsection 1: { optional: free }
  - Empty line: { repeatable: 3, line: empty line }
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
  - Registrar subsection 1: { optional: free }
  - Empty line: { repeatable: 3, line: empty line }
  - AWIP footer: { optional: free }
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
  - Name server subsection 1: { optional: free }
  - Empty line: { repeatable: 3, line: empty line }
  - AWIP footer: { optional: free }
  - Legal disclaimer: { }
Name server details section:
  - Server Name: { line: field, type: query name server }
  - IP Address: { optional: free, repeatable: unbounded, line: field, type: query name server ip }
  - Registrar: { optional: constrained, line: field, type: postal line }
  - WHOIS Server: { optional: constrained, line: field, type: hostname }
  - Referral URL: { optional: constrained, line: field, type: http url }
  - Additional fields section: { optional: free }
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
  - Empty line: { optional: free, repeatable: 3, line: empty line }
  - Last updated footer: { }
  - Empty line: { repeatable: 3, line: empty line }
  - AWIP footer: { optional: free }
  - Legal disclaimer: { }
Registrar details section:
  - Registrar Name: { line: field, type: query registrar name }
  - Street: { line: field, type: postal line, repeatable: unbounded }
  - City: { line: field, type: postal line }
  - State/Province: { optional: constrained, line: field, type: postal line }
  - Postal Code: { optional: constrained, line: field, type: postal code }
  - Country: { line: field, type: country code }
  - Phone Number: { line: field, type: phone number }
  - Phone Ext: { optional: free, line: field, type: token }
  - Fax number section: { optional: free }
  - Email: { line: field, type: email address }
  - WHOIS Server: { optional: constrained, line: field, type: hostname }
  - Referral URL: { line: field, type: http url }
  - Admin contact section: { optional: free, repeatable: unbounded }
  - Technical contact section: { optional: free, repeatable: unbounded }
  - Additional fields section: { optional: free }
Admin contact section:
  - Admin Contact: { line: field, type: postal line }
  - Phone number section: { repeatable: unbounded }
  - Fax number section: { optional: free, repeatable: unbounded }
  - Email: { line: field, type: email address, repeatable: unbounded }
Technical contact section:
  - Technical Contact: { line: field, type: postal line }
  - Phone number section: { repeatable: unbounded }
  - Fax number section: { optional: free, repeatable: unbounded }
  - Email: { line: field, type: email address, repeatable: unbounded }
Phone number section:
  - Phone Number: { line: field, type: phone number }
  - Phone Ext: { optional: free, line: field, type: token }
Fax number section:
  - Fax Number: { line: field, type: phone number }
  - Fax Ext: { optional: free, line: field, type: token }
Domain name details section:
  - Domain Name: { line: field, type: query domain name }
  - Internationalized Domain Name: { optional: free, line: field, type: u-label }
  - Domain ID: { line: field, type: epp repo id }
  - WHOIS Server: { optional: constrained, line: field, type: hostname }
  - Referral URL: { line: field, type: http url }
  - Updated Date: { optional: constrained, line: field, type: time stamp }
  - Creation Date: { line: field, type: time stamp }
  - Registry Expiry Date: { line: field, type: time stamp }
  - Sponsoring Registrar: { line: field, type: token }
  - Sponsoring Registrar IANA ID: { line: field, type: positive integer }
  - Domain Status: { repeatable: unbounded, line: field, type: domain status }
  - Registrant ID: { line: field, type: token }
  - Registrant Name: { line: field, type: postal line }
  - Registrant Organization: { optional: constrained, line: field, type: postal line }
  - Registrant Street: { repeatable: unbounded, line: field, type: postal line }
  - Registrant City: { line: field, type: postal line }
  - Registrant State/Province: { optional: constrained, line: field, type: postal line }
  - Registrant Postal Code: { optional: constrained, line: field, type: postal code }
  - Registrant Country: { line: field, type: country code }
  - Registrant Phone: { line: field, type: phone number }
  - Registrant Phone Ext: { optional: constrained, line: field, type: token }
  - Registrant Fax: { optional: constrained, line: field, type: phone number }
  - Registrant Fax Ext: { optional: constrained, line: field, type: token }
  - Registrant Email: { line: field, type: email address }
  - Admin ID: { line: field, type: token }
  - Admin Name: { line: field, type: postal line }
  - Admin Organization: { optional: constrained, line: field, type: postal line }
  - Admin Street: { repeatable: unbounded, line: field, type: postal line }
  - Admin City: { line: field, type: postal line }
  - Admin State/Province: { optional: constrained, line: field, type: postal line }
  - Admin Postal Code: { optional: constrained, line: field, type: postal code }
  - Admin Country: { line: field, type: country code }
  - Admin Phone: { line: field, type: phone number }
  - Admin Phone Ext: { optional: constrained, line: field, type: token }
  - Admin Fax: { optional: constrained, line: field, type: phone number }
  - Admin Fax Ext: { optional: constrained, line: field, type: token }
  - Admin Email: { line: field, type: email address }
  - Tech ID: { line: field, type: token }
  - Tech Name: { line: field, type: postal line }
  - Tech Organization: { optional: constrained, line: field, type: postal line }
  - Tech Street: { repeatable: unbounded, line: field, type: postal line }
  - Tech City: { line: field, type: postal line }
  - Tech State/Province: { optional: constrained, line: field, type: postal line }
  - Tech Postal Code: { optional: constrained, line: field, type: postal code }
  - Tech Country: { line: field, type: country code }
  - Tech Phone: { line: field, type: phone number }
  - Tech Phone Ext: { optional: constrained, line: field, type: token }
  - Tech Fax: { optional: constrained, line: field, type: phone number }
  - Tech Fax Ext: { optional: constrained, line: field, type: token }
  - Tech Email: { line: field, type: email address }
  - Billing contact section: { optional: free }
  - Name server section: { repeatable: unbounded }
  - DNSSEC: { line: field, type: dnssec }
  - Additional fields section: { optional: free }
Billing contact section:
  - Billing ID: { line: field, type: token }
  - Billing Name: { line: field, type: postal line }
  - Billing Organization: { optional: free, line: field, type: postal line }
  - Billing Street: { repeatable: unbounded, line: field, type: postal line }
  - Billing City: { line: field, type: postal line }
  - Billing State/Province: { optional: free, line: field, type: postal line }
  - Billing Postal Code: { optional: free, line: field, type: postal code }
  - Billing Country: { line: field, type: country code }
  - Billing Phone: { line: field, type: phone number }
  - Billing Phone Ext: { optional: free, line: field, type: token }
  - Billing Fax: { optional: free, line: field, type: phone number }
  - Billing Fax Ext: { optional: free, line: field, type: token }
  - Billing Email: { line: field, type: email address }
Name server section:
  - Name Server: { optional: constrained, line: field, type: hostname }
  - IP Address: { optional: free, repeatable: unbounded, line: field, type: ip address }
Multiple name servers section:
  - Multiple name servers line: { line: multiple name servers line }
  - ROID line: { line: roid line }
  - ROID line: { line: roid line, repeatable: unbounded }
Additional fields section:
  - Additional field: { repeatable: unbounded, line: field }
Last updated subsection 1:
  Last updated footer: { }
  Last updated subsection 2: { }
Last updated subsection 2:
  - Empty line: { repeatable: 2, line: empty line }
  - Last updated footer: { }
Last updated footer:
  - Last update line: { line: last update line }
AWIP footer:
  - AWIP line: { line: awip line }
  - Empty line: { repeatable: 3, line: empty line }
Legal disclaimer:
  - Non-empty line: { line: non-empty line }
  - Any line: { optional: free, repeatable: unbounded, line: any line }
