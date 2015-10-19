package PDT::TS::Whois::Grammar;

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

__DATA__
---
Domain Name Object query:
  - Domain name reply: { }
Name Server Object query:
  Name server reply type 1: { }
  Name server reply type 2: { }
Registrar Object query:
  - Registrar reply: { }
Registrar reply:
  - Registrar details section: { }
  - Subsequent registrar details section: { optional: y, repeatable: unbounded }
  - Last updated footer: { }
  - Empty line: { repeatable: 3, line: empty line }
  - AWIP footer: { optional: y }
  - Legal disclaimer: { }
  - EOF: { line: EOF }
Domain name reply:
  - Domain name details section: { }
  - Subsequent domain name details section: { optional: y, repeatable: unbounded }
  - Last updated footer: { }
  - Empty line: { repeatable: 3, line: empty line }
  - AWIP footer: { }
  - Legal disclaimer: { }
  - EOF: { line: EOF }
Name server reply type 1:
  - Name server details section: { }
  - Subsequent name server details section: { optional: y, repeatable: unbounded }
  - Last updated footer: { }
  - Empty line: { repeatable: 3, line: empty line }
  - AWIP footer: { optional: y }
  - Legal disclaimer: { }
  - EOF: { line: EOF }
Name server reply type 2:
  - Multiple name servers section: { }
  - Last updated footer: { }
  - Empty line: { repeatable: 3, line: empty line }
  - AWIP footer: { optional: y }
  - Legal disclaimer: { }
  - EOF: { line: EOF }
Subsequent registrar details section:
  - Empty line: { line: empty line }
  - Registrar details section: { }
Registrar details section:
  - Registrar Name: { line: field, type: query registrar name }
  - Street: { line: field, type: postal line }
  - City: { line: field, type: postal line }
  - State/Province: { optional: y, line: field, type: postal line }
  - Postal Code: { optional: y, line: field, type: postal code }
  - Country: { line: field, type: country code }
  - Phone Number: { line: field, type: phone number }
  - Phone Ext: { optional: y, line: field, type: token }
  - Fax number section: { optional: y }
  - Email: { line: field, type: email address }
  - WHOIS Server: { optional: y, line: field, type: hostname }
  - Referral URL: { line: field, type: http url }
  - Admin contact section: { optional: y, repeatable: unbounded }
  - Technical contact section: { optional: y, repeatable: unbounded }
Admin contact section:
  - Admin Contact: { line: field, type: postal line }
  - Phone Number: { line: field, type: phone number }
  - Phone Ext: { optional: y, line: field, type: token }
  - Fax number section: { optional: y }
  - Email: { line: field, type: email address }
Technical contact section:
  - Technical Contact: { line: field, type: postal line }
  - Phone Number: { line: field, type: phone number }
  - Phone Ext: { optional: y, line: field, type: token }
  - Fax number section: { optional: y }
  - Email: { line: field, type: email address }
Fax number section:
  - Fax Number: { line: field, type: phone number }
  - Fax Ext: { optional: y, line: field, type: token }
Subsequent domain name details section:
  - Empty line: { line: empty line }
  - Domain name details section: { }
Domain name details section:
  - Domain Name: { line: field, type: query domain name }
  - Internationalized Domain Name: { optional: y, line: field, type: u-label }
  - Domain ID: { line: field, type: epp repo id }
  - WHOIS Server: { optional: y, line: field, type: hostname }
  - Referral URL: { line: field, type: http url }
  - Updated Date: { optional: y, line: field, type: time stamp }
  - Creation Date: { line: field, type: time stamp }
  - Registry Expiry Date: { line: field, type: time stamp }
  - Sponsoring Registrar: { line: field, type: token }
  - Sponsoring Registrar IANA ID: { line: field, type: positive integer }
  - Domain Status: { repeatable: unbounded, line: field, type: domain status }
  - Registrant ID: { line: field, type: roid }
  - Registrant Name: { line: field, type: postal line }
  - Registrant Organization: { optional: y, line: field, type: postal line }
  - Registrant Street: { repeatable: 3, line: field, type: postal line }
  - Registrant City: { line: field, type: postal line }
  - Registrant State/Province: { optional: y, line: field, type: postal line }
  - Registrant Postal Code: { optional: y, line: field, type: postal code }
  - Registrant Country: { line: field, type: country code }
  - Registrant Phone: { line: field, type: phone number }
  - Registrant Phone Ext: { optional: y, line: field, type: token }
  - Registrant Fax: { optional: y, line: field, type: phone number }
  - Registrant Fax Ext: { optional: y, line: field, type: token }
  - Registrant Email: { line: field, type: email address }
  - Admin ID: { line: field, type: roid }
  - Admin Name: { line: field, type: postal line }
  - Admin Organization: { optional: y, line: field, type: postal line }
  - Admin Street: { repeatable: 3, line: field, type: postal line }
  - Admin City: { line: field, type: postal line }
  - Admin State/Province: { optional: y, line: field, type: postal line }
  - Admin Postal Code: { optional: y, line: field, type: postal code }
  - Admin Country: { line: field, type: country code }
  - Admin Phone: { line: field, type: phone number }
  - Admin Phone Ext: { optional: y, line: field, type: token }
  - Admin Fax: { optional: y, line: field, type: phone number }
  - Admin Fax Ext: { optional: y, line: field, type: token }
  - Admin Email: { line: field, type: email address }
  - Tech ID: { line: field, type: roid }
  - Tech Name: { line: field, type: postal line }
  - Tech Organization: { optional: y, line: field, type: postal line }
  - Tech Street: { repeatable: 3, line: field, type: postal line }
  - Tech City: { line: field, type: postal line }
  - Tech State/Province: { optional: y, line: field, type: postal line }
  - Tech Postal Code: { optional: y, line: field, type: postal code }
  - Tech Country: { line: field, type: country code }
  - Tech Phone: { line: field, type: phone number }
  - Tech Phone Ext: { optional: y, line: field, type: token }
  - Tech Fax: { optional: y, line: field, type: phone number }
  - Tech Fax Ext: { optional: y, line: field, type: token }
  - Tech Email: { line: field, type: email address }
  - Billing ID: { optional: y, line: field, type: roid }
  - Billing Name: { optional: y, line: field, type: postal line }
  - Billing Organization: { optional: y, line: field, type: postal line }
  - Billing Street: { optional: y, repeatable: 3, line: field, type: postal line }
  - Billing City: { optional: y, line: field, type: postal line }
  - Billing State/Province: { optional: y, line: field, type: postal line }
  - Billing Postal Code: { optional: y, line: field, type: postal code }
  - Billing Country: { optional: y, line: field, type: country code }
  - Billing Phone: { optional: y, line: field, type: phone number }
  - Billing Phone Ext: { optional: y, line: field, type: token }
  - Billing Fax: { optional: y, line: field, type: phone number }
  - Billing Fax Ext: { optional: y, line: field, type: token }
  - Billing Email: { optional: y, line: field, type: email address }
  - Name server section: { optional: y, repeatable: unbounded }
  - DNSSEC: { line: field, type: dnssec }
  - Additional fields section: { optional: y }
Name server section:
  - Name Server: { line: field, type: hostname }
  - IP Address: { optional: y, repeatable: unbounded, line: field, type: ip address }
Multiple name servers section:
  - Multiple name servers line: { line: multiple name servers line }
  - ROID line: { line: roid line }
  - ROID line: { line: roid line, repeatable: unbounded }
Subsequent name server details section:
  - Empty line: { line: empty line }
  - A name server details section: { }
Name server details section:
  - Server Name: { line: field, type: query name server }
  - IP Address: { repeatable: unbounded, line: field, type: query name server ip }
  - Registrar: { optional: y, line: field, type: postal line }
  - WHOIS Server: { optional: y, line: field, type: hostname }
  - Referral URL: { optional: y, line: field, type: http url }
Additional fields section:
  - Additional field: { repeatable: unbounded, line: field }
Last updated footer:
  - Empty line: { optional: y, repeatable: 3, line: empty line }
  - Last update line: { line: last update line }
AWIP footer:
  - AWIP line: { line: awip line }
  - Empty line: { repeatable: 3, line: empty line }
Legal disclaimer:
  - Non-empty line: { line: non-empty line }
  - Any line: { optional: y, repeatable: unbounded, line: any line }
