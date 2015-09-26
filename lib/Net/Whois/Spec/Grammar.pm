package Net::Whois::Spec::Grammar;

use strict;
use warnings;
use 5.014;

use YAML::Syck;

require Exporter;

our @ISA = 'Exporter';
our @EXPORT_OK = qw( $grammar );

our $grammar = LoadFile(*DATA);

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
  - Subsequent registrar details section: { min_occurs: 0, max_occurs: unbounded }
  - Last updated footer: { }
  - Empty line: { max_occurs: 3, line: empty line }
  - AWIP footer: { min_occurs: 0 }
  - Legal disclaimer: { }
  - EOF: { line: EOF }
Domain name reply:
  - Domain name details section: { }
  - Subsequent domain name details section: { min_occurs: 0, max_occurs: unbounded }
  - Last updated footer: { }
  - Empty line: { max_occurs: 3, line: empty line }
  - AWIP footer: { }
  - Legal disclaimer: { }
  - EOF: { line: EOF }
Name server reply type 1:
  - Name server details section: { }
  - Subsequent name server details section: { min_occurs: 0, max_occurs: unbounded }
  - Last updated footer: { }
  - Empty line: { max_occurs: 3, line: empty line }
  - AWIP footer: { min_occurs: 0 }
  - Legal disclaimer: { }
  - EOF: { line: EOF }
Name server reply type 2:
  - Multiple name servers section: { }
  - Last updated footer: { }
  - Empty line: { max_occurs: 3, line: empty line }
  - AWIP footer: { min_occurs: 0 }
  - Legal disclaimer: { }
  - EOF: { line: EOF }
Subsequent registrar details section:
  - Empty line: { line: empty line }
  - Registrar details section: { }
Registrar details section:
  - Registrar Name: { type: postal line }
  - Street: { type: postal line }
  - City: { type: postal line }
  - State/Province: { min_occurs: 0, type: postal line }
  - Postal Code: { min_occurs: 0, type: postal code }
  - Country: { type: country code }
  - Phone Number: { type: phone number }
  - Phone Ext: { min_occurs: 0, type: token }
  - Fax number section: { min_occurs: 0 }
  - Email: { type: email address }
  - WHOIS Server: { min_occurs: 0, type: hostname }
  - Referral URL: { type: http url }
  - Admin contact section: { min_occurs: 0, max_occurs: unbounded }
  - Technical contact section: { min_occurs: 0, max_occurs: unbounded }
Admin contact section:
  - Admin Contact: { type: postal line }
  - Phone Number: { type: phone number }
  - Phone Ext: { min_occurs: 0, type: token }
  - Fax number section: { min_occurs: 0 }
  - Email: { type: email address }
Technical contact section:
  - Technical Contact: { type: postal line }
  - Phone Number: { type: phone number }
  - Phone Ext: { min_occurs: 0, type: token }
  - Fax number section: { min_occurs: 0 }
  - Email: { type: email address }
Fax number section:
  - Fax Number: { type: phone number }
  - Fax Ext: { min_occurs: 0, type: token }
Subsequent domain name details section:
  - Empty line: { line: empty line }
  - Domain name details section: { }
Domain name details section:
  - Domain Name: { type: hostname }
  - Internationalized Domain Name: { min_occurs: 0, type: u-label }
  - Domain ID: { type: roid }
  - WHOIS Server: { min_occurs: 0, type: hostname }
  - Referral URL: { type: http url }
  - Updated Date: { min_occurs: 0, type: time stamp }
  - Creation Date: { type: time stamp }
  - Registry Expiry Date: { type: time stamp }
  - Sponsoring Registrar: { type: token }
  - Sponsoring Registrar IANA ID: { type: positive integer }
  - Domain Status: { max_occurs: unbounded, type: domain status }
  - Registrant ID: { type: roid }
  - Registrant Name: { type: postal line }
  - Registrant Organization: { min_occurs: 0, type: postal line }
  - Registrant Street: { max_occurs: 3, type: postal line }
  - Registrant City: { type: postal line }
  - Registrant State/Province: { min_occurs: 0, type: postal line }
  - Registrant Postal Code: { min_occurs: 0, type: postal code }
  - Registrant Country: { type: country code }
  - Registrant Phone: { type: phone number }
  - Registrant Phone Ext: { min_occurs: 0, type: token }
  - Registrant Fax: { min_occurs: 0, type: phone number }
  - Registrant Fax Ext: { min_occurs: 0, type: token }
  - Registrant Email: { type: email address }
  - Admin ID: { type: roid }
  - Admin Name: { type: postal line }
  - Admin Organization: { min_occurs: 0, type: postal line }
  - Admin Street: { max_occurs: 3, type: postal line }
  - Admin City: { type: postal line }
  - Admin State/Province: { min_occurs: 0, type: postal line }
  - Admin Postal Code: { min_occurs: 0, type: postal code }
  - Admin Country: { type: country code }
  - Admin Phone: { type: phone number }
  - Admin Phone Ext: { min_occurs: 0, type: token }
  - Admin Fax: { min_occurs: 0, type: phone number }
  - Admin Fax Ext: { min_occurs: 0, type: token }
  - Admin Email: { type: email address }
  - Tech ID: { type: roid }
  - Tech Name: { type: postal line }
  - Tech Organization: { min_occurs: 0, type: postal line }
  - Tech Street: { max_occurs: 3, type: postal line }
  - Tech City: { type: postal line }
  - Tech State/Province: { min_occurs: 0, type: postal line }
  - Tech Postal Code: { min_occurs: 0, type: postal code }
  - Tech Country: { type: country code }
  - Tech Phone: { type: phone number }
  - Tech Phone Ext: { min_occurs: 0, type: token }
  - Tech Fax: { min_occurs: 0, type: phone number }
  - Tech Fax Ext: { min_occurs: 0, type: token }
  - Tech Email: { type: email address }
  - Billing ID: { min_occurs: 0, type: roid }
  - Billing Name: { min_occurs: 0, type: postal line }
  - Billing Organization: { min_occurs: 0, type: postal line }
  - Billing Street: { min_occurs: 0, max_occurs: 3, type: postal line }
  - Billing City: { min_occurs: 0, type: postal line }
  - Billing State/Province: { min_occurs: 0, type: postal line }
  - Billing Postal Code: { min_occurs: 0, type: postal code }
  - Billing Country: { min_occurs: 0, type: country code }
  - Billing Phone: { min_occurs: 0, type: phone number }
  - Billing Phone Ext: { min_occurs: 0, type: token }
  - Billing Fax: { min_occurs: 0, type: phone number }
  - Billing Fax Ext: { min_occurs: 0, type: token }
  - Billing Email: { min_occurs: 0, type: email address }
  - Name server section: { min_occurs: 0, max_occurs: unbounded }
  - DNSSEC: { type: dnssec }
  - Additional fields section: { min_occurs: 0 }
Name server section:
  - Name Server: { type: hostname }
  - IP Address: { min_occurs: 0, max_occurs: unbounded, type: ip address }
Multiple name servers section:
  - Multiple name servers line: { line: multiple name servers line }
  - ROID line: { min_occurs: 2, max_occurs: unbounded, line: roid line }
Subsequent name server details section:
  - Empty line: { line: empty line }
  - A name server details section: { }
Name server details section:
  - Server Name: { type: hostname }
  - IP Address: { max_occurs: unbounded, type: ip address }
  - Registrar: { min_occurs: 0, type: postal line }
  - WHOIS Server: { min_occurs: 0, type: hostname }
  - Referral URL: { min_occurs: 0, type: http url }
Additional fields section:
  - Additional field: { max_occurs: unbounded, line: field }
Last updated footer:
  - Empty line: { min_occurs: 0, max_occurs: 3, line: empty line }
  - Last update line: { line: last update line }
AWIP footer:
  - AWIP line: { line: awip line }
  - Empty line: { max_occurs: 3, line: empty line }
Legal disclaimer:
  - Non-empty line: { line: non-empty line }
  - Any line: { min_occurs: 0, max_occurs: unbounded, line: any line }
