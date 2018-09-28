use strict;
use warnings;
use 5.014;
use utf8;

use Test::More;
use Test::Differences;
use Readonly;

# This is needed to get rid of wide character print warnings
binmode STDOUT, ':utf8';
binmode STDERR, ':utf8';

BEGIN {
    use_ok 'PDT::TS::Whois::Types';
    use_ok 'PDT::TS::Whois::Redaction', qw( add_redaction_types );
}

Readonly my %DEFAULT_PRIVACY => (
    "Upper case" => "REDACTED FOR PRIVACY",
    "Lower case" => "redacted for privacy",
    "Mixed case" => "ReDaCtEd FoR PrIvAcY",
);

Readonly my %ADDITIONAL_PRIVACY => (
    "Real world example" => "Personal data, can not be publicly disclosed according to applicable laws.",
    "Chinese characters" => "健康",
    "Mixed scripts"      => "域名forwhois.健康",
    "Arabic letters"     => "اتصالات",
);

Readonly my %DEFAULT_CONTACT => (
    "Mixed case" => "Please query the RDDS service of the Registrar of Record identified in this output for information on how to contact the Registrant, Admin, or Tech contact of the queried domain name.",
    "Lower case" => "please query the rdds service of the registrar of record identified in this output for information on how to contact the registrant, admin, or tech contact of the queried domain name.",
    "Upper case" => "PLEASE QUERY THE RDDS SERVICE OF THE REGISTRAR OF RECORD IDENTIFIED IN THIS OUTPUT FOR INFORMATION ON HOW TO CONTACT THE REGISTRANT, ADMIN, OR TECH CONTACT OF THE QUERIED DOMAIN NAME.",
);

Readonly my %ADDITIONAL_CONTACT => (
    "Real world example" => "Please check Registrar RDDS. Personal data, can not be publicly disclosed according to applicable laws.",
    "Chinese characters" => "健康",
    "Mixed scripts"      => "域名forwhois.健康",
    "Arabic letters"     => "اتصالات",
);

Readonly my $ROID_STRING          => 'AGRS-UR';
Readonly my $NON_TOKEN_STRING     => 'Double  space';
Readonly my $TOKEN_STRING         => '1234';
Readonly my $POSTAL_CODE_STRING   => '1111';
Readonly my $COUNTRY_CODE_STRING  => 'ZA';
Readonly my $PHONE_NUMBER_STRING  => '+27.113140077';
Readonly my $EMAIL_ADDRESS_STRING => 'public@dnservices.co.za';
Readonly my $WEB_ADDRESS_STRING   => 'https://iis.se/';

sub accept_ok {
    my $types     = shift;
    my $test_name = shift;
    my $type_name = shift;
    my $input     = shift;

    subtest $test_name => sub {
        plan tests => 1;

        my @errors = $types->validate_type( $type_name, $input );
        eq_or_diff \@errors, [], 'Type ' . $type_name . ' should accept "' . ( defined $input ? $input : '<undef>' ) . '"';
    };
}

sub reject_ok {
    my $types       = shift;
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

subtest 'Default Redact String values' => sub {
    my $types = PDT::TS::Whois::Types->new;
    $types->load_roid_suffix( 't/iana-epp-rep-id.txt' );
    add_redaction_types $types, {};

    for my $name ( sort keys %DEFAULT_PRIVACY ) {
        my $string = $DEFAULT_PRIVACY{$name};
        accept_ok $types, $name => 'redact string', $string;
    }

    for my $name ( sort keys %ADDITIONAL_PRIVACY ) {
        my $string = $ADDITIONAL_PRIVACY{$name};
        reject_ok $types, $name => 'redact string', $string, qr/Redact String/;
    }
};

subtest 'Additional Redact String values' => sub {
    my $types = PDT::TS::Whois::Types->new;
    $types->load_roid_suffix( 't/iana-epp-rep-id.txt' );
    add_redaction_types $types, { privacy => { map { $_ => 1 } values %ADDITIONAL_PRIVACY } };

    for my $name ( sort keys %DEFAULT_PRIVACY ) {
        my $string = $DEFAULT_PRIVACY{$name};
        accept_ok $types, $name => 'redact string', $string;
    }

    for my $name ( sort keys %ADDITIONAL_PRIVACY ) {
        my $string = $ADDITIONAL_PRIVACY{$name};
        accept_ok $types, $name => 'redact string', $string;
    }
};

subtest 'Default Email redact string values' => sub {
    my $types = PDT::TS::Whois::Types->new;
    $types->load_roid_suffix( 't/iana-epp-rep-id.txt' );
    add_redaction_types $types, {};

    for my $name ( sort keys %DEFAULT_CONTACT ) {
        my $string = $DEFAULT_CONTACT{$name};
        accept_ok $types, $name => 'email redact string', $string;
    }

    for my $name ( sort keys %ADDITIONAL_CONTACT ) {
        my $string = $ADDITIONAL_CONTACT{$name};
        reject_ok $types, $name => 'email redact string', $string, qr/Email redact string/;
    }
};

subtest 'Additional Email redact string values' => sub {
    my $types = PDT::TS::Whois::Types->new;
    $types->load_roid_suffix( 't/iana-epp-rep-id.txt' );
    add_redaction_types $types, { contact => { map { $_ => 1 } values %ADDITIONAL_CONTACT } };

    for my $name ( sort keys %DEFAULT_CONTACT ) {
        my $string = $DEFAULT_CONTACT{$name};
        accept_ok $types, $name => 'email redact string', $string;
    }

    for my $name ( sort keys %ADDITIONAL_CONTACT ) {
        my $string = $ADDITIONAL_CONTACT{$name};
        accept_ok $types, $name => 'email redact string', $string;
    }
};

subtest 'ROID or redacted' => sub {
    my $types = PDT::TS::Whois::Types->new;
    $types->load_roid_suffix( 't/iana-epp-rep-id.txt' );
    add_redaction_types $types, {};

    accept_ok $types, 'ROID'             => 'roid or redacted', $ROID_STRING;
    accept_ok $types, 'Privacy redacted' => 'roid or redacted', $DEFAULT_PRIVACY{"Upper case"};
    reject_ok $types, 'Contact redacted' => 'roid or redacted', $DEFAULT_CONTACT{"Mixed case"}, qr/(?=.*ROID)(?=.*Redact String)/;
};

subtest 'Token or redacted' => sub {
    my $types = PDT::TS::Whois::Types->new;
    $types->load_roid_suffix( 't/iana-epp-rep-id.txt' );
    add_redaction_types $types, {};

    accept_ok $types, 'Token' => 'token or redacted', $TOKEN_STRING;
    reject_ok $types, 'Disallowed' => 'token or redacted', $NON_TOKEN_STRING, qr/(?=.*Token)(?=.*Redact String)/;
};

subtest 'Postal code or redacted' => sub {
    my $types = PDT::TS::Whois::Types->new;
    $types->load_roid_suffix( 't/iana-epp-rep-id.txt' );
    add_redaction_types $types, {};

    accept_ok $types, 'Postal code'      => 'postal code or redacted', $POSTAL_CODE_STRING;
    accept_ok $types, 'Privacy redacted' => 'postal code or redacted', $DEFAULT_PRIVACY{"Upper case"};
    reject_ok $types, 'Contact redacted' => 'postal code or redacted', $DEFAULT_CONTACT{"Mixed case"}, qr/(?=.*Postal code)(?=.*Redact String)/;
};

subtest 'Country code or redacted' => sub {
    my $types = PDT::TS::Whois::Types->new;
    $types->load_roid_suffix( 't/iana-epp-rep-id.txt' );
    add_redaction_types $types, {};

    accept_ok $types, 'Country code'     => 'country code or redacted', $COUNTRY_CODE_STRING;
    accept_ok $types, 'Privacy redacted' => 'country code or redacted', $DEFAULT_PRIVACY{"Upper case"};
    reject_ok $types, 'Contact redacted' => 'country code or redacted', $DEFAULT_CONTACT{"Mixed case"}, qr/(?=.*Country code)(?=.*Redact String)/;
};

subtest 'Phone number or redacted' => sub {
    my $types = PDT::TS::Whois::Types->new;
    $types->load_roid_suffix( 't/iana-epp-rep-id.txt' );
    add_redaction_types $types, {};

    accept_ok $types, 'Phone number'     => 'phone number or redacted', $PHONE_NUMBER_STRING;
    accept_ok $types, 'Privacy redacted' => 'phone number or redacted', $DEFAULT_PRIVACY{"Upper case"};
    reject_ok $types, 'Contact redacted' => 'phone number or redacted', $DEFAULT_CONTACT{"Mixed case"}, qr/(?=.*Phone number)(?=.*Redact String)/;
};

subtest 'Email web or redacted' => sub {
    my $types = PDT::TS::Whois::Types->new;
    $types->load_roid_suffix( 't/iana-epp-rep-id.txt' );
    add_redaction_types $types, {};

    accept_ok $types, 'Email address'    => 'email web or redacted', $EMAIL_ADDRESS_STRING;
    accept_ok $types, 'Web address'      => 'email web or redacted', $WEB_ADDRESS_STRING;
    accept_ok $types, 'Contact redacted' => 'email web or redacted', $DEFAULT_CONTACT{"Mixed case"};
    reject_ok $types, 'Privacy redacted' => 'email web or redacted', $DEFAULT_PRIVACY{"Upper case"}, qr/(?=.*Email address)(?=.*HTTP URL)(?=.*Email redact string)/;
};

done_testing;
