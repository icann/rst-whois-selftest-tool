use strict;
use warnings;
use 5.014;

use Test::More tests => 23;

require_ok('Net::Whois::Spec::Types');
use Net::Whois::Spec::Types qw( $types );

subtest 'translation clause' => sub {
};

subtest 'key translation' => sub {
};

subtest 'field key' => sub {
};

subtest 'roid' => sub {
};

subtest 'roid suffix' => sub {
};

subtest 'hostname' => sub {
};

subtest 'time stamp' => sub {
};

subtest 'u-label' => sub {
};

subtest 'http url' => sub {
};

subtest 'token' => sub {
};

subtest 'domain status' => sub {
};

subtest 'domain status code' => sub {
};

subtest 'postal line' => sub {
};

subtest 'postal code' => sub {
};

subtest 'phone number' => sub {
};

subtest 'email address' => sub {
};

subtest 'dnssec' => sub {
};

subtest 'ip address' => sub {
};

subtest 'ipv4 address' => sub {
};

subtest 'ipv6 address' => sub {
};

subtest 'positive integer' => sub {
    plan tests => 5;

    my $type = $types->{'positive integer'};

    ok $type, 'Types should contain positive integer type';

    subtest 'Reject 0' => sub {
        plan tests => 2;
        my @errors = $type->('0');
        is scalar @errors, 1, 'Should report one error';
        like $errors[0], qr/positive integer/, 'Should complain about positive integers';
    };

    subtest 'Accept 1' => sub {
        plan tests => 1;
        my @errors = $type->('1');
        is scalar @errors, 0, 'Should report no errors';
    };

    subtest 'Accept 1234567890' => sub {
        plan tests => 1;
        my @errors = $type->('1234567890');
        is scalar @errors, 0, 'Should report no errors';
    };

    subtest 'Reject 01' => sub {
        plan tests => 2;
        my @errors = $type->('01');
        is scalar @errors, 1, 'Should report one error';
        like $errors[0], qr/positive integer/, 'Should complain about type mismatch';
    };
};

subtest 'country code' => sub {
    plan tests => 4;

    my $type = $types->{'country code'};

    ok $type, 'Types should contain country code type';

    subtest 'Accept se' => sub {
        plan tests => 1;
        my @errors = $type->('se');
        is scalar @errors, 0, 'Should report no errors';
    };

    subtest 'Accept xx' => sub {
        plan tests => 1;
        my @errors = $type->('xx');
        is scalar @errors, 0, 'Should report no errors';
    };

    subtest 'Reject swe' => sub {
        plan tests => 2;
        my @errors = $type->('swe');
        is scalar @errors, 1, 'Should report one error';
        like $errors[0], qr/country code/, 'Should complain about type mismatch';
    };
};

