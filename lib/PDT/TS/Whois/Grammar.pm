package PDT::TS::Whois::Grammar;

use strict;
use warnings;
use 5.014;

use YAML::Syck;

require Exporter;

our @ISA       = 'Exporter';
our @EXPORT_OK = qw( $grammar );

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
  - Registrar Name: { type: postal line }
  - Street: { type: postal line }
  - City: { type: postal line }
  - State/Province: { optional: y, type: postal line }
  - Postal Code: { optional: y, type: postal code }
  - Country: { type: country code }
  - Phone Number: { type: phone number }
  - Phone Ext: { optional: y, type: token }
  - Fax number section: { optional: y }
  - Email: { type: email address }
  - WHOIS Server: { optional: y, type: hostname }
  - Referral URL: { type: http url }
  - Admin contact section: { optional: y, repeatable: unbounded }
  - Technical contact section: { optional: y, repeatable: unbounded }
Admin contact section:
  - Admin Contact: { type: postal line }
  - Phone Number: { type: phone number }
  - Phone Ext: { optional: y, type: token }
  - Fax number section: { optional: y }
  - Email: { type: email address }
Technical contact section:
  - Technical Contact: { type: postal line }
  - Phone Number: { type: phone number }
  - Phone Ext: { optional: y, type: token }
  - Fax number section: { optional: y }
  - Email: { type: email address }
Fax number section:
  - Fax Number: { type: phone number }
  - Fax Ext: { optional: y, type: token }
Subsequent domain name details section:
  - Empty line: { line: empty line }
  - Domain name details section: { }
Domain name details section:
  - Domain Name: { type: hostname }
  - Internationalized Domain Name: { optional: y, type: u-label }
  - Domain ID: { type: roid }
  - WHOIS Server: { optional: y, type: hostname }
  - Referral URL: { type: http url }
  - Updated Date: { optional: y, type: time stamp }
  - Creation Date: { type: time stamp }
  - Registry Expiry Date: { type: time stamp }
  - Sponsoring Registrar: { type: token }
  - Sponsoring Registrar IANA ID: { type: positive integer }
  - Domain Status: { repeatable: unbounded, type: domain status }
  - Registrant ID: { type: roid }
  - Registrant Name: { type: postal line }
  - Registrant Organization: { optional: y, type: postal line }
  - Registrant Street: { repeatable: 3, type: postal line }
  - Registrant City: { type: postal line }
  - Registrant State/Province: { optional: y, type: postal line }
  - Registrant Postal Code: { optional: y, type: postal code }
  - Registrant Country: { type: country code }
  - Registrant Phone: { type: phone number }
  - Registrant Phone Ext: { optional: y, type: token }
  - Registrant Fax: { optional: y, type: phone number }
  - Registrant Fax Ext: { optional: y, type: token }
  - Registrant Email: { type: email address }
  - Admin ID: { type: roid }
  - Admin Name: { type: postal line }
  - Admin Organization: { optional: y, type: postal line }
  - Admin Street: { repeatable: 3, type: postal line }
  - Admin City: { type: postal line }
  - Admin State/Province: { optional: y, type: postal line }
  - Admin Postal Code: { optional: y, type: postal code }
  - Admin Country: { type: country code }
  - Admin Phone: { type: phone number }
  - Admin Phone Ext: { optional: y, type: token }
  - Admin Fax: { optional: y, type: phone number }
  - Admin Fax Ext: { optional: y, type: token }
  - Admin Email: { type: email address }
  - Tech ID: { type: roid }
  - Tech Name: { type: postal line }
  - Tech Organization: { optional: y, type: postal line }
  - Tech Street: { repeatable: 3, type: postal line }
  - Tech City: { type: postal line }
  - Tech State/Province: { optional: y, type: postal line }
  - Tech Postal Code: { optional: y, type: postal code }
  - Tech Country: { type: country code }
  - Tech Phone: { type: phone number }
  - Tech Phone Ext: { optional: y, type: token }
  - Tech Fax: { optional: y, type: phone number }
  - Tech Fax Ext: { optional: y, type: token }
  - Tech Email: { type: email address }
  - Billing ID: { optional: y, type: roid }
  - Billing Name: { optional: y, type: postal line }
  - Billing Organization: { optional: y, type: postal line }
  - Billing Street: { optional: y, repeatable: 3, type: postal line }
  - Billing City: { optional: y, type: postal line }
  - Billing State/Province: { optional: y, type: postal line }
  - Billing Postal Code: { optional: y, type: postal code }
  - Billing Country: { optional: y, type: country code }
  - Billing Phone: { optional: y, type: phone number }
  - Billing Phone Ext: { optional: y, type: token }
  - Billing Fax: { optional: y, type: phone number }
  - Billing Fax Ext: { optional: y, type: token }
  - Billing Email: { optional: y, type: email address }
  - Name server section: { optional: y, repeatable: unbounded }
  - DNSSEC: { type: dnssec }
  - Additional fields section: { optional: y }
Name server section:
  - Name Server: { type: hostname }
  - IP Address: { optional: y, repeatable: unbounded, type: ip address }
Multiple name servers section:
  - Multiple name servers line: { line: multiple name servers line }
  - ROID line: { line: roid line }
  - ROID line: { line: roid line, repeatable: unbounded }
Subsequent name server details section:
  - Empty line: { line: empty line }
  - A name server details section: { }
Name server details section:
  - Server Name: { type: hostname }
  - IP Address: { repeatable: unbounded, type: ip address }
  - Registrar: { optional: y, type: postal line }
  - WHOIS Server: { optional: y, type: hostname }
  - Referral URL: { optional: y, type: http url }
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
