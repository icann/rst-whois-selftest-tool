use strict;
use warnings;
use 5.014;
use utf8;

use Test::More tests => 26;
use Test::Differences;

# This is needed to get rid of wide character print warnings
binmode STDOUT, ':utf8';

require_ok( 'PDT::TS::Whois::Types' );

my $types = PDT::TS::Whois::Types->new;
$types->load_roid_suffix('t/iana-epp-rep-id.txt');

sub accept_ok {
    my $test_name = shift;
    my $type_name = shift;
    my $input     = shift;

    subtest $test_name => sub {
        plan tests => 1;

        my @errors = $types->validate_type( $type_name, $input );
        eq_or_diff \@errors, [], 'Type '.$type_name.' should accept "'.(defined $input ? $input : '<undef>').'"';
    };
}

sub reject_ok {
    my $test_name   = shift;
    my $type_name   = shift;
    my $input       = shift;
    my $error_regex = shift || qr/$type_name/;

    subtest $test_name => sub {
        plan tests => 1;

        my @errors = $types->validate_type( $type_name, $input );

        if ( scalar @errors == 0 ) {
            fail 'Type ' . $type_name . ' should reject "' . ( defined $input ? $input : '<undef>' ) . '"';
        }
        else {
            like $errors[0], $error_regex, 'Type ' . $type_name . ' should reject "' . ( defined $input ? $input : '<undef>' ) . '" with complaint about type mismatch';
        }
    };
}

subtest 'Adding rules' => sub {
    plan tests => 3;

    ok !$types->has_type( 'my-type' ), "Should not have my-type by default";
    $types->add_type(
        'my-type',
        sub {
            my $value = shift;
            return ( "yeah, $value" );
        }
    );
    ok $types->has_type( 'my-type' ), "Should have my-type after adding it";
    my @errors = $types->validate_type( 'my-type', 'dude' );
    eq_or_diff( \@errors, ['yeah, dude'], "Should propagate errors from my-type sub" );
};

subtest 'roid' => sub {
    plan tests => 11;

    reject_ok 'undef' => 'roid';
    reject_ok 'empty' => 'roid', '';

    accept_ok 'roid-NAME'             => 'roid', 'roid-NAME';
    reject_ok 'wrong roid'            => 'roid', 'wrong roid';
    accept_ok 'abcdefg-IIS'           => 'roid', 'abcdefg-IIS';
    accept_ok 'non-ascii suffix'      => 'roid', 'abdcdd-ÅÄÖ';
    accept_ok 'non-latin prefix'      => 'roid', 'гцйнштд-ÅÄÖ';
    reject_ok 'suffix not registered' => 'roid', 'abcdee-iis';
    reject_ok 'illegal format'        => 'roid', 'abscdd';
    reject_ok 'too new codepoint'     => 'roid', "ro\x{0220}id-NAME";
    accept_ok 'han character'         => 'roid', "689a\x{3BD9}a8812833_DOMAIN-FRES";
};

subtest 'hostname' => sub {
    plan tests => 10;

    reject_ok 'undef' => 'hostname';
    reject_ok 'empty' => 'hostname', '';

    foreach (qw(ns1.example.example. ns1.xn--caf-dma.example abcdef.test xx-----xxx.zzz)) {
        accept_ok $_ => 'hostname', $_;
    }
    foreach (qw(-ns1.example.example. _ns1.xn--caf-dma.example abc_abc.com abcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghij.test)) {
        reject_ok $_ => 'hostname', $_;
    }
};

subtest 'time stamp' => sub {
    plan tests => 37;

    reject_ok 'undef' => 'time stamp';
    reject_ok 'empty' => 'time stamp', '';

    # Time zone Z
    accept_ok '1937-01-01T12:00:27.87Z'      => 'time stamp', '1937-01-01T12:00:27.87Z';
    reject_ok '1937-01-01T12:00:27.87+00:00' => 'time stamp', '1937-01-01T12:00:27.87+00:00';

    # Upper case Z
    accept_ok '1985-04-12T23:20:50.52Z' => 'time stamp', '1985-04-12T23:20:50.52Z';
    reject_ok '1985-04-12T23:20:50.52z' => 'time stamp', '1985-04-12T23:20:50.52z';

    # Upper case T
    accept_ok '1999-01-01T23:30:30Z' => 'time stamp', '1999-01-01T23:30:30Z';
    reject_ok '1999-01-01t23:30:30Z' => 'time stamp', '1999-01-01t23:30:30Z';
    reject_ok '1999-01-01 23:30:30Z' => 'time stamp', '1999-01-01 23:30:30Z';

    # Months of year
    accept_ok '2016-12-01T00:00:00Z' => 'time stamp', '2016-12-01T00:00:00Z';
    reject_ok '2016-00-01T00:00:00Z' => 'time stamp', '2016-00-01T00:00:00Z';
    reject_ok '2016-13-01T00:00:00Z' => 'time stamp', '2016-13-01T00:00:00Z';

    # Days of month
    accept_ok '2015-01-31T00:00:00Z' => 'time stamp', '2015-01-31T00:00:00Z';
    reject_ok '2015-01-32T00:00:00Z' => 'time stamp', '2015-01-32T00:00:00Z';

    accept_ok '2015-02-28T00:00:00Z' => 'time stamp', '2015-02-28T00:00:00Z';
    reject_ok '2015-02-29T00:00:00Z' => 'time stamp', '2015-02-29T00:00:00Z';

    accept_ok '2015-03-31T00:00:00Z' => 'time stamp', '2015-03-31T00:00:00Z';
    reject_ok '2015-03-32T00:00:00Z' => 'time stamp', '2015-03-32T00:00:00Z';

    accept_ok '2015-04-30T00:00:00Z' => 'time stamp', '2015-04-30T00:00:00Z';
    reject_ok '2015-04-31T00:00:00Z' => 'time stamp', '2015-04-31T00:00:00Z';

    # Leap days
    accept_ok '2016-02-29T00:00:00Z' => 'time stamp', '2016-02-29T00:00:00Z';
    reject_ok '2015-02-29T00:00:00Z' => 'time stamp', '2015-02-29T00:00:00Z';
    reject_ok '2000-02-29T00:00:00Z' => 'time stamp', '2000-02-29T00:00:00Z';

    # Hours of day
    accept_ok '2015-01-01T23:00:00Z' => 'time stamp', '2016-01-01T23:00:00Z';
    reject_ok '2015-01-01T24:00:00Z' => 'time stamp', '2016-01-01T24:00:00Z';

    # Minutes of hour
    accept_ok '2015-01-01T00:59:00Z' => 'time stamp', '2016-01-01T00:59:00Z';
    reject_ok '2015-01-01T00:60:00Z' => 'time stamp', '2016-01-01T00:60:00Z';

    # Seconds of minute
    accept_ok '2016-01-01T00:00:59Z' => 'time stamp', '2016-01-01T00:00:59Z';
    reject_ok '2016-01-01T00:00:60Z' => 'time stamp', '2016-01-01T00:00:60Z';

    # Allow positive leap seconds during first and second preference months
    accept_ok '2016-03-31T23:59:60Z' => 'time stamp', '2016-03-31T23:59:60Z';
    reject_ok '2016-03-31T23:59:61Z' => 'time stamp', '2016-03-31T23:59:61Z';

    accept_ok '2016-06-30T23:59:60Z' => 'time stamp', '2016-06-30T23:59:60Z';
    reject_ok '2016-06-30T23:59:61Z' => 'time stamp', '2016-06-30T23:59:61Z';

    accept_ok '2016-09-30T23:59:60Z' => 'time stamp', '2016-09-30T23:59:60Z';
    reject_ok '2016-09-30T23:59:61Z' => 'time stamp', '2016-09-30T23:59:61Z';

    accept_ok '2016-12-31T23:59:60Z' => 'time stamp', '2016-12-31T23:59:60Z';
    reject_ok '2016-12-31T23:59:61Z' => 'time stamp', '2016-12-31T23:59:61Z';
};

subtest 'u-label' => sub {
    plan tests => 4;

    reject_ok 'undef' => 'u-label';
    reject_ok 'empty' => 'u-label', '';

    accept_ok 'å.se' => 'u-label', 'å.se';
    reject_ok 'a.se' => 'u-label', 'a.se';
};

subtest 'http url' => sub {
    plan tests => 6;

    reject_ok 'undef' => 'http url';
    reject_ok 'empty' => 'http url', '';

    accept_ok 'http://example.com' => 'http url', 'http://example.com';
    accept_ok 'https://example.com' => 'http url', 'https://example.com';
    reject_ok 'ftp://example.com' => 'http url', 'ftp://example.com';
    reject_ok 'www.example.com' => 'http url', 'www.example.com';
};

subtest 'token' => sub {
    plan tests => 4;

    reject_ok 'undef' => 'token';
    reject_ok 'empty' => 'token', '';

    accept_ok 'token' => 'token', 'token';
    reject_ok 'to  ken' => 'token', 'to  ken';
};

subtest 'domain status' => sub {
    plan tests => 7;

    reject_ok 'undef' => 'domain status';
    reject_ok 'empty' => 'domain status', '';

    accept_ok 'ok https://icann.org/epp#ok'             => 'domain status', 'ok https://icann.org/epp#ok';
    accept_ok 'explicit exception for upper case OK'    => 'domain status', 'ok https://icann.org/epp#OK';
    accept_ok 'inactive https://icann.org/epp#inactive' => 'domain status', 'inactive https://icann.org/epp#inactive';
    reject_ok 'inactive https://icann.org/epp#INACTIVE' => 'domain status', 'inactive https://icann.org/epp#INACTIVE';
    reject_ok 'bad http://noticann.org/epp#bad'         => 'domain status', 'bad http://noticann.org/epp#bad';
};

subtest 'postal line' => sub {
    plan tests => 4;

    reject_ok 'undef' => 'postal line';
    reject_ok 'empty' => 'postal line', '';

    accept_ok 'Good street nr1' => 'postal line', 'Good street nr1';
    reject_ok "Bad\nStreet\rnr1" => 'postal line', "Bad\nStreet\rnr1";
};

subtest 'postal code' => sub {
    plan tests => 4;

    reject_ok 'undef' => 'postal code';
    reject_ok 'empty' => 'postal code', '';

    accept_ok 'good postal code' => 'postal code', '12345';
    reject_ok 'bad postal code' => 'postal code', ' 1 2  3';
};

subtest 'phone number' => sub {
    plan tests => 4;

    reject_ok 'undef' => 'phone number';
    reject_ok 'empty' => 'phone number', '';

    accept_ok 'good phone number' => 'phone number', '+1.800';
    reject_ok 'bad phone number' => 'phone number', '0800';
};

subtest 'email address' => sub {
    plan tests => 4;

    reject_ok 'undef' => 'email address';
    reject_ok 'empty' => 'email address', '';

    accept_ok 'test@example.com' => 'email address', 'test@example.com';
    reject_ok 'test@example.com.' => 'email address', 'test@example.com.';
};

subtest 'ip address' => sub {
    plan tests => 6;

    reject_ok 'undef' => 'ip address';
    reject_ok 'empty' => 'ip address', '';

    accept_ok 'good ipv4' => 'ip address', '1.2.3.4';
    reject_ok 'bad ipv4' => 'ip address', '256.333.666.3';
    accept_ok 'good ipv6' => 'ip address', '1::2';
    reject_ok 'bad ipv6' => 'ip address', '1:::2';
};

subtest 'epp repo id' => sub {
    plan tests => 6;

    reject_ok 'undef' => 'epp repo id';
    reject_ok 'empty' => 'epp repo id', '';

    accept_ok 'epp-NAME' => 'epp repo id', 'epp-NAME';
    reject_ok 'wrong epp' => 'epp repo id', 'wrong epp';
    reject_ok 'iis' => 'epp repo id', 'test-iis';
    accept_ok 'IIS' => 'epp repo id', 'test-IIS';
};

subtest 'translation clause' => sub {
    plan tests => 6;

    reject_ok 'undef' => 'translation clause';
    reject_ok 'empty' => 'translation clause', '';

    accept_ok 'Single translation'             => 'translation clause', ' (Domännamn)';
    accept_ok 'Multiple translations'          => 'translation clause', ' (Domännamn/Verkkotunnus/Nome de domínio)';
    reject_ok 'Parenthesis in key translation' => 'translation clause', ' (Domän(namn)', qr/key translation/;
    reject_ok 'Extraneous leading space'       => 'translation clause', '  (Domän(namn)';
};

subtest 'key translation' => sub {
    plan tests => 7;

    reject_ok 'undef' => 'key translation';
    reject_ok 'empty' => 'key translation', '';

    accept_ok 'Valid value'         => 'key translation', 'Domännamn';
    reject_ok 'Leading space'       => 'key translation', ' Domännamn';
    reject_ok 'Trailing space'      => 'key translation', 'Domännamn ';
    reject_ok 'Opening parenthesis' => 'key translation', '(Domännamn';
    reject_ok 'Closing parenthesis' => 'key translation', 'Domännamn)';
};

subtest 'positive integer' => sub {
    plan tests => 7;

    reject_ok 'undef' => 'positive integer';
    reject_ok 'empty' => 'positive integer', '';

    accept_ok 'Single digit'    => 'positive integer', '1';
    accept_ok 'Multiple digits' => 'positive integer', '1234567890';
    reject_ok 'Zero'            => 'positive integer', '0';
    reject_ok 'Leading zero'    => 'positive integer', '01';
    reject_ok 'Negative'		=> 'positive integer', '-1';
};

subtest 'country code' => sub {
    plan tests => 7;

    reject_ok 'undef' => 'country code';
    reject_ok 'empty' => 'country code', '';

    accept_ok 'Two letter country code'     => 'country code', 'SE';
    accept_ok 'Lower case country code'     => 'country code', 'se';
    accept_ok 'Two letter non-country code' => 'country code', 'XX';
    reject_ok 'Three letter country code'   => 'country code', 'SWE';
	reject_ok 'E.164 country code'			=> 'country code', '46';
};

subtest 'dnssec' => sub {
    my @ok     = qw( signedDelegation unsigned);
    my @not_ok = ( 'signed delegation' );
    plan tests => scalar @ok + scalar @not_ok + 2;

    reject_ok 'undef' => 'dnssec';
    reject_ok 'empty' => 'dnssec', '';

    for my $value ( @ok ) {
        accept_ok "Value $value", 'dnssec', $value;
    }
    for my $value ( @not_ok ) {
        reject_ok "Value $value", 'dnssec', $value;
    }
};

subtest 'domain status code' => sub {
    my @ok = qw(
      addPeriod autoRenewPeriod clientDeleteProhibited clientHold
      clientRenewProhibited clientTransferProhibited
      clientUpdateProhibited inactive ok pendingCreate pendingDelete
      pendingRenew pendingRestore pendingTransfer pendingUpdate
      redemptionPeriod renewPeriod serverDeleteProhibited serverHold
      serverRenewProhibited serverTransferProhibited
      serverUpdateProhibited transferPeriod
    );
    my @not_ok = ( 'OK' );
    plan tests => scalar @ok + scalar @not_ok + 2;

    reject_ok 'undef' => 'domain status code';
    reject_ok 'empty' => 'domain status code', '';

    for my $value ( @ok ) {
        accept_ok "Value $value", 'domain status code', $value;
    }
    for my $value ( @not_ok ) {
        reject_ok "Value $value", 'domain status code', $value;
    }
};

subtest 'domain name object additional field key errors' => sub {
    my @ok = (
        'Internationalized Domain Name',
        'Registry Billing ID',
        'Billing Name',
        'Billing Organization',
        'Billing Street',
        'Billing City',
        'Billing State/Province',
        'Billing Postal Code',
        'Billing Country',
        'Billing Phone',
        'Billing Phone Ext',
        'Billing Fax',
        'Billing Fax Ext',
        'Billing Email',
        'Billing ID',
    );
    my @not_ok = (
        'Registry Domain ID',
        'Registrar WHOIS Server',
        'Registrar URL',
        'Registrar Registration Expiration Date',
        'Registrar',
        'Registrar IANA ID',
        'Reseller',
        'Registry Registrant ID',
        'Registry Admin ID',
        'Registry Tech ID',
        'Domain ID',
        'WHOIS Server',
        'Referral URL',
        'Sponsoring Registrar',
        'Sponsoring Registrar IANA ID',
        'Registrant ID',
        'Admin ID',
        'Tech ID',
    );
    plan tests => scalar @ok + scalar @not_ok + 2;

    reject_ok 'undef' => 'domain name object additional field key';
    reject_ok 'empty' => 'domain name object additional field key', '';

    for my $value ( @ok ) {
        accept_ok "Value $value", 'domain name object additional field key', $value;
    }
    for my $value ( @not_ok ) {
        reject_ok "Value $value", 'domain name object additional field key', $value;
    }
};

subtest 'domain name object additional field key rejections' => sub {
    my @acceptable = (
        'Internationalized Domain Name',
        'Billing Name',
        'Billing Organization',
        'Billing Street',
        'Billing City',
        'Billing State/Province',
        'Billing Postal Code',
        'Billing Country',
        'Billing Phone',
        'Billing Phone Ext',
        'Billing Fax',
        'Billing Fax Ext',
        'Billing Email',
        'Registry Domain ID',
        'Registrar WHOIS Server',
        'Registrar URL',
        'Registrar Registration Expiration Date',
        'Registrar',
        'Registrar IANA ID',
        'Reseller',
        'Registry Registrant ID',
        'Registry Admin ID',
        'Registry Tech ID',
        'Registry Billing ID',
        'Domain ID',
        'WHOIS Server',
        'Referral URL',
        'Sponsoring Registrar',
        'Sponsoring Registrar IANA ID',
        'Registrant ID',
        'Admin ID',
        'Tech ID',
        'Billing ID',
    );
    my @rejectable = (
        'URL of the ICANN Whois Inaccuracy Complaint Form',
        'Registrar Abuse Contact Email',
        'Registrar Abuse Contact Phone',
    );

    plan tests => scalar @acceptable + scalar @rejectable;

    for my $field_key ( @acceptable ) {
        ok $types->is_acceptable_key( 'domain name object additional field key', $field_key ), "Field key should be acceptable: $field_key";
    }
    for my $field_key ( @rejectable ) {
        ok !$types->is_acceptable_key( 'domain name object additional field key', $field_key ), "Field key should be rejectable: $field_key";
    }
};

subtest 'registrar object additional field key' => sub {
    my @ok = (
        'Phone Ext',
        'Fax Ext',
    );
    my @not_ok = (
        'Registrar',
        'Registrar WHOIS Server',
        'Registrar URL',
        'Registrar Name',
        'WHOIS Server',
        'Referral URL',
    );
    plan tests => scalar @ok + scalar @not_ok + 2;

    reject_ok 'undef' => 'registrar object additional field key';
    reject_ok 'empty' => 'registrar object additional field key', '';

    for my $value ( @ok ) {
        accept_ok "Value $value", 'registrar object additional field key', $value;
    }
    for my $value ( @not_ok ) {
        reject_ok "Value $value", 'registrar object additional field key', $value;
    }
};

subtest 'name server object additional field key' => sub {
    my @ok = (
        'Nisse',
    );
    my @not_ok = (
        'Registrar WHOIS Server',
        'Registrar URL',
        'WHOIS Server',
        'Referral URL',
    );
    plan tests => scalar @ok + scalar @not_ok + 2;

    reject_ok 'undef' => 'registrar object additional field key';
    reject_ok 'empty' => 'registrar object additional field key', '';

    for my $value ( @ok ) {
        accept_ok "Value $value", 'registrar object additional field key', $value;
    }
    for my $value ( @not_ok ) {
        reject_ok "Value $value", 'registrar object additional field key', $value;
    }
};

subtest 'inaccuracy form url' => sub {
    my @ok = ( 'https://www.icann.org/wicf/', );
    my @not_ok = ( 'http://www.icann.org/wicf/', 'https://icann.org/wicf/', 'https://www.icann.org/wicf', 'HTTPS://WWW.ICANN.ORG/wicf/' );
    plan tests => scalar @ok + scalar @not_ok + 2;

    reject_ok 'undef' => 'inaccuracy form url';
    reject_ok 'empty' => 'inaccuracy form url', '';

    for my $value ( @ok ) {
        accept_ok "Value $value", 'inaccuracy form url', $value;
    }
    for my $value ( @not_ok ) {
        reject_ok "Value $value", 'inaccuracy form url', $value;
    }
};
