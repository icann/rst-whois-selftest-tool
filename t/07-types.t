use strict;
use warnings;
use 5.014;

use Test::More tests => 23;
use Test::Differences;

require_ok('PDT::TS::Whois::Types');

my $types = PDT::TS::Whois::Types->new;

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

subtest 'postal line' => sub {
};

subtest 'postal code' => sub {
};

subtest 'phone number' => sub {
};

subtest 'email address' => sub {
};

subtest 'ip address' => sub {
};

subtest 'ipv4 address' => sub {
};

subtest 'ipv6 address' => sub {
};

subtest 'translation clause' => sub {
    plan tests => 4;

    subtest 'Accept single translation' => sub {
        plan tests => 1;

        my @errors = $types->validate_type('translation clause', ' (Domännamn)');
        is scalar @errors, 0, 'Should report no errors';
    };

    subtest 'Accept multiple translations' => sub {
        plan tests => 1;

        my @errors = $types->validate_type('translation clause', ' (Domännamn/Verkkotunnus/Nome de domínio)');
        is scalar @errors, 0, 'Should report no errors';
    };

    subtest 'Reject opening parenthesis in key translation' => sub {
        plan tests => 2;

        my @errors = $types->validate_type('translation clause', ' (Domän(namn)');
        is scalar @errors, 1, 'Should report no errors';
        like $errors[0], qr/key translation/, 'Should complain about type mismatch';
    };

    subtest 'Reject extra leading space' => sub {
        plan tests => 2;

        my @errors = $types->validate_type('translation clause', '  (Domän(namn)');
        is scalar @errors, 1, 'Should report no errors';
        like $errors[0], qr/translation clause/, 'Should complain about type mismatch';
    };
};

subtest 'key translation' => sub {
    plan tests => 5;

    subtest 'Should accept valid value' => sub {
        plan tests => 1;
        my @errors = $types->validate_type('key translation', 'Domännamn');
        is scalar @errors, 0, 'Should report no errors';
    };

    subtest 'Should reject leading space' => sub {
        plan tests => 2;
        my @errors = $types->validate_type('key translation', ' Domännamn');
        is scalar @errors, 1, 'Should report one error';
        like $errors[0], qr/key translation/, 'Should complain about type mismatch';
    };

    subtest 'Should reject trailing space' => sub {
        plan tests => 2;
        my @errors = $types->validate_type('key translation', 'Domännamn ');
        is scalar @errors, 1, 'Should report one error';
        like $errors[0], qr/key translation/, 'Should complain about type mismatch';
    };

    subtest 'Should reject opening parenthesis' => sub {
        plan tests => 2;
        my @errors = $types->validate_type('key translation', '(Domännamn');
        is scalar @errors, 1, 'Should report one error';
        like $errors[0], qr/key translation/, 'Should complain about type mismatch';
    };

    subtest 'Should reject closing parenthesis' => sub {
        plan tests => 2;
        my @errors = $types->validate_type('key translation', 'Domännamn)');
        is scalar @errors, 1, 'Should report one error';
        like $errors[0], qr/key translation/, 'Should complain about type mismatch';
    };

};

subtest 'positive integer' => sub {
    plan tests => 4;

    subtest 'Reject 0' => sub {
        plan tests => 2;
        my @errors = $types->validate_type('positive integer', '0');
        is scalar @errors, 1, 'Should report one error';
        like $errors[0], qr/positive integer/, 'Should complain about type mismatch';
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

subtest 'dnssec' => sub {
    plan tests => 3;

    subtest 'Accept signedDelegation' => sub {
        plan tests => 1;
        my @errors = $types->validate_type('dnssec', 'signedDelegation');
        is scalar @errors, 0, 'Should report no errors';
    };

    subtest 'Accept unsigned' => sub {
        plan tests => 1;
        my @errors = $types->validate_type('dnssec', 'unsigned');
        is scalar @errors, 0, 'Should report no errors';
    };

    subtest 'Reject signed delegation' => sub {
        plan tests => 2;
        my @errors = $types->validate_type('dnssec', 'signed delegation');
        is scalar @errors, 1, 'Should report one error';
        like $errors[0], qr/dnssec/, 'Should complain about type mismatch';
    };
};

subtest 'domain status code' => sub {
    my @ok_codes = qw(
            addPeriod autoRenewPeriod clientDeleteProhibited clientHold
            clientRenewProhibited clientTransferProhibited
            clientUpdateProhibited inactive ok pendingCreate pendingDelete
            pendingRenew pendingRestore pendingTransfer pendingUpdate
            redemptionPeriod renewPeriod serverDeleteProhibited serverHold
            serverRenewProhibited serverTransferProhibited
            serverUpdateProhibited transferPeriod
    );
    plan tests => (scalar(@ok_codes) + 2);

    for my $code (@ok_codes) {
        my @errors = $types->validate_type('domain status code', $code);
        is scalar @errors, 0, 'Should report no errors';
    }

    my @errors = $types->validate_type('domain status code', 'OK');
    is scalar @errors, 1, 'Should report one error';
    like $errors[0], qr/domain status code/, 'Should complain about positive integers';
};

