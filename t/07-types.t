use strict;
use warnings;
use 5.014;

use Test::More tests => 23;
use Test::Differences;

require_ok( 'PDT::TS::Whois::Types' );

my $types = PDT::TS::Whois::Types->new;

sub accept_ok {
    my $test_name = shift;
    my $type_name = shift;
    my $input     = shift;

    subtest $test_name => sub {
        plan tests => 1;

        my @errors = $types->validate_type( $type_name, $input );
        eq_or_diff \@errors, [], "Type $type_name should accept '$input'";
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
        like $errors[0], $error_regex, "Type $type_name should reject '$input' with complaint about type mismatch";
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

    accept_ok 'Single translation'             => 'translation clause', ' (Domännamn)';
    accept_ok 'Multiple translations'          => 'translation clause', ' (Domännamn/Verkkotunnus/Nome de domínio)';
    reject_ok 'Parenthesis in key translation' => 'translation clause', ' (Domän(namn)', qr/key translation/;
    reject_ok 'Extraneous leading space'       => 'translation clause', '  (Domän(namn)';
};

subtest 'key translation' => sub {
    plan tests => 5;

    accept_ok 'Valid value'         => 'key translation', 'Domännamn';
    reject_ok 'Leading space'       => 'key translation', ' Domännamn';
    reject_ok 'Trailing space'      => 'key translation', 'Domännamn ';
    reject_ok 'Opening parenthesis' => 'key translation', '(Domännamn';
    reject_ok 'Closing parenthesis' => 'key translation', 'Domännamn)';
};

subtest 'positive integer' => sub {
    plan tests => 4;

    accept_ok 'Single digit'    => 'positive integer', '1';
    accept_ok 'Multiple digits' => 'positive integer', '1234567890';
    reject_ok 'Zero'            => 'positive integer', '0';
    reject_ok 'Leading zero'    => 'positive integer', '01';
};

subtest 'country code' => sub {
    plan tests => 4;

    accept_ok 'Two letter country code'     => 'country code', 'SE';
    accept_ok 'Lower case country code'     => 'country code', 'se';
    accept_ok 'Two letter non-country code' => 'country code', 'XX';
    reject_ok 'Three letter country code'   => 'country code', 'SWE';
};

subtest 'dnssec' => sub {
    my @ok     = qw( signedDelegation unsigned);
    my @not_ok = ( 'signed delegation' );
    plan tests => @ok + @not_ok;

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
    plan tests => @ok + @not_ok;

    for my $value ( @ok ) {
        accept_ok "Value $value", 'domain status code', $value;
    }
    for my $value ( @not_ok ) {
        reject_ok "Value $value", 'domain status code', $value;
    }
};

