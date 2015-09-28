use strict;
use warnings;
use 5.014;

use Test::More tests => 6;
use Test::Differences;
use Test::MockObject;

use Data::Dumper;

require_ok('PDT::TS::Whois::Validator');

my $grammar = {
    'Simple field' => [
        { 'Domain Name' => { type => 'hostname', }, },
        { 'EOF' => { line => 'EOF', }, },
    ],
    'Optional field' => [
        { 'Domain Name' => { type => 'hostname', optional => 'y', }, },
        { 'Referral URL' => { type => 'http url', optional => 'y', }, },
        { 'EOF' => { line => 'EOF', }, },
    ],
    'Repeatable field' => [
        { 'Domain Name' => { type => 'hostname', repeatable => 'unbounded', }, },
        { 'EOF' => { line => 'EOF', }, },
    ],
    'Repeatable max 2 field' => [
        { 'Domain Name' => { type => 'hostname', repeatable => 2, }, },
        { 'EOF' => { line => 'EOF', }, },
    ],
    'Optional repeatable section' => [
        { 'A domain name' => { optional => 'y', repeatable => 'unbounded', }, },
        { 'EOF' => { line => 'EOF', }, },
    ],
    'A domain name' => [
        { 'Domain Name' => { type => 'hostname', }, },
    ],
};

my %type_subs = (
    'hostname' => sub {},
    'http url' => sub {},
    'roid' => sub {},
    'time stamp' => sub {},
    'key translation' => sub {},
);

my $types = Test::MockObject->new();
$types->mock('has_type', sub {
    my $self = shift;
    my $type_name = shift;
    return exists $type_subs{$type_name};
});
$types->mock('validate_type', sub {
    my $self = shift;
    my $type_name = shift;
    my $value = shift;
    return $type_subs{$type_name}($value);
});


sub make_mock_lexer {
    my @tokens = @_;
    my $line_no = 1;
    my $lexer = Test::MockObject->new();
    $lexer->mock('peek_line', sub {
            if (exists $tokens[$line_no - 1]) {
                return @{ $tokens[$line_no - 1] };
            }
            else {
                return;
            }
            });
    $lexer->mock('line_no', sub {
            return $line_no;
            });
    $lexer->mock('next_line', sub {
            $line_no++;
            return
            });
}

subtest 'Simple line' => sub {
    plan tests => 2;

    {
        my $lexer = make_mock_lexer (
            ['field', ['Domain Name', [], 'DOMAIN.EXAMPLE'], []],
            ['EOF', undef, []],
        );
        my $validator = PDT::TS::Whois::Validator->new(lexer => $lexer, grammar => $grammar, types => $types);
        my $result = $validator->validate( 'Simple field' );
        eq_or_diff $result, [], 'Should accept field line';
    }

    {
        my $lexer = make_mock_lexer (
            ['non-empty line', []],
            ['EOF', undef, []],
        );
        my $validator = PDT::TS::Whois::Validator->new(lexer => $lexer, grammar => $grammar, types => $types);
        my $result = $validator->validate( 'Simple field' );
        is scalar(@$result), 1, 'Should reject non-field line';
    }
};

subtest 'Optional subrule' => sub {
    plan tests => 3;

    {
        my $lexer = make_mock_lexer (
            ['field', ['Referral URL', [], 'http://domain.example/'], []],
            ['EOF', undef, []],
        );
        my $validator = PDT::TS::Whois::Validator->new(lexer => $lexer, grammar => $grammar, types => $types);
        my $result = $validator->validate( 'Optional field' );
        eq_or_diff $result, [], 'Should accept omitted field line';
    }

    {
        my $lexer = make_mock_lexer (
            ['field', ['Domain Name', [], undef], []],
            ['field', ['Referral URL', [], 'http://domain.example/'], []],
            ['EOF', undef, []],
        );
        my $validator = PDT::TS::Whois::Validator->new(lexer => $lexer, grammar => $grammar, types => $types);
        my $result = $validator->validate( 'Optional field' );
        eq_or_diff $result, [], 'Should accept empty field line';
    }

    {
        my $lexer = make_mock_lexer (
            ['field', ['Referral URL', [], undef], []],
            ['EOF', undef, []],
        );
        my $validator = PDT::TS::Whois::Validator->new(lexer => $lexer, grammar => $grammar, types => $types);
        my $result = $validator->validate( 'Optional field' );
        is scalar(@$result), 1, 'Should reject mixed empty field syntaxes';
    }
};

subtest 'Repeatable subrule' => sub {
    plan tests => 3;

    {
        my $lexer = make_mock_lexer (
            ['field', ['Domain Name', [], 'DOMAIN1.EXAMPLE'], []],
            ['field', ['Domain Name', [], 'DOMAIN2.EXAMPLE'], []],
            ['field', ['Domain Name', [], 'DOMAIN3.EXAMPLE'], []],
            ['EOF', undef, []],
        );
        my $validator = PDT::TS::Whois::Validator->new(lexer => $lexer, grammar => $grammar, types => $types);
        my $result = $validator->validate( 'Repeatable field' );
        eq_or_diff $result, [], 'Should accept repeated field lines';
    }

    {
        my $lexer = make_mock_lexer (
            ['field', ['Domain Name', [], 'DOMAIN1.EXAMPLE'], []],
            ['field', ['Domain Name', [], 'DOMAIN2.EXAMPLE'], []],
            ['EOF', undef, []],
        );
        my $validator = PDT::TS::Whois::Validator->new(lexer => $lexer, grammar => $grammar, types => $types);
        my $result = $validator->validate( 'Repeatable max 2 field' );
        eq_or_diff $result, [], 'Should accept repeated field lines';
    }

    {
        my $lexer = make_mock_lexer (
            ['field', ['Domain Name', [], 'DOMAIN1.EXAMPLE'], []],
            ['field', ['Domain Name', [], 'DOMAIN2.EXAMPLE'], []],
            ['field', ['Domain Name', [], 'DOMAIN3.EXAMPLE'], []],
            ['EOF', undef, []],
        );
        my $validator = PDT::TS::Whois::Validator->new(lexer => $lexer, grammar => $grammar, types => $types);
        my $result = $validator->validate( 'Repeatable max 2 field' );
        is scalar(@$result), 1, 'Should reject too many repetitions of field lines';
    }

};

subtest 'Error propagation' => sub {
    plan tests => 1;

    my $lexer = make_mock_lexer (
        ['field', ['Domain Name', [], 'DOMAIN.EXAMPLE'], ['BOOM!']],
        ['EOF', undef, []],
    );
    my $validator = PDT::TS::Whois::Validator->new(lexer => $lexer, grammar => $grammar, types => $types);
    my $result = $validator->validate( 'Simple field' );
    eq_or_diff $result, ['BOOM!'], 'Should propagate errors from lexer';
};

subtest 'Optional repeatable subrule' => sub {
    plan tests => 1;

    {
        my $lexer = make_mock_lexer (
            ['EOF', undef, []],
        );
        my $validator = PDT::TS::Whois::Validator->new(lexer => $lexer, grammar => $grammar, types => $types);
        my $result = $validator->validate( 'Optional repeatable section' );
        eq_or_diff $result, [], 'Should accept omitted lines';
    }

};
