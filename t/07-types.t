use strict;
use warnings;
use 5.014;

use Test::More tests => 24;
use Test::Differences;

require_ok('Net::Whois::Spec::Types');

my $types = Net::Whois::Spec::Types->new;

subtest 'Adding rules' => sub {
    plan tests => 3;
    ok !$types->has_type('my-type'), "Should not have my-type by default";
    $types->add_type('my-type', sub {
        my $value = shift;
        return ("yeah, $value");
    });
    ok $types->has_type('my-type'), "Should have my-type after adding it";
    my @errors = $types->validate_type('my-type', 'dude');
    eq_or_diff(\@errors, ['yeah, dude'], "Should propagate errors from my-type sub");
};

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
    plan tests => 4;

    subtest 'Reject 0' => sub {
        plan tests => 2;
        my @errors = $types->validate_type('positive integer', '0');
        is scalar @errors, 1, 'Should report one error';
        like $errors[0], qr/positive integer/, 'Should complain about positive integers';
    };

    subtest 'Accept 1' => sub {
        plan tests => 1;
        my @errors = $types->validate_type('positive integer', '1');
        is scalar @errors, 0, 'Should report no errors';
    };

    subtest 'Accept 1234567890' => sub {
        plan tests => 1;
        my @errors = $types->validate_type('positive integer', '1234567890');
        is scalar @errors, 0, 'Should report no errors';
    };

    subtest 'Reject 01' => sub {
        plan tests => 2;
        my @errors = $types->validate_type('positive integer', '01');
        is scalar @errors, 1, 'Should report one error';
        like $errors[0], qr/positive integer/, 'Should complain about type mismatch';
    };
};

subtest 'country code' => sub {
    plan tests => 3;

    subtest 'Accept SE' => sub {
        plan tests => 1;
        my @errors = $types->validate_type('country code', 'SE');
        is scalar @errors, 0, 'Should report no errors';
    };

    subtest 'Accept xx' => sub {
        plan tests => 1;
        my @errors = $types->validate_type('country code', 'XX');
        is scalar @errors, 0, 'Should report no errors';
    };

    subtest 'Reject swe' => sub {
        plan tests => 2;
        my @errors = $types->validate_type('country code', 'SWE');
        is scalar @errors, 1, 'Should report one error';
        like $errors[0], qr/country code/, 'Should complain about type mismatch';
    };
};

