use strict;
use warnings;
use 5.014;

use Test::More tests => 14;
use Test::Differences;
use Test::MockObject;

require_ok('PDT::TS::Whois::Validator');
use PDT::TS::Whois::Remark qw( remark_string );
use PDT::TS::Whois::Validator qw( validate validate2 );

my $grammar = {
    'Required field' => [
        { 'Domain Name' => { type => 'hostname', }, },
        { 'EOF' => { line => 'EOF', }, },
    ],
    'Required-strict field' => [
        { 'Domain Name' => { line => 'field', type => 'hostname', quantifier => 'required-strict' }, },
        { 'EOF' => { line => 'EOF', }, },
    ],
    'Optional-constrained field' => [
        { 'Domain Name' => { line => 'field', type => 'hostname', quantifier => 'optional-constrained', }, },
        { 'Referral URL' => { line => 'field', type => 'http url', quantifier => 'optional-constrained', }, },
        { 'EOF' => { line => 'EOF', }, },
    ],
    'Optional-free field' => [
        { 'Domain Name' => { line => 'field', type => 'hostname', quantifier => 'optional-constrained', }, },
        { 'Referral URL' => { line => 'field', type => 'http url', quantifier => 'optional-free', }, },
        { 'EOF' => { line => 'EOF', }, },
    ],
    'Optional-not-empty field' => [
        { 'Domain Name' => { line => 'field', type => 'hostname', quantifier => 'optional-not-empty', }, },
        { 'EOF' => { line => 'EOF', }, },
    ],
    'Lone empty-constrained field' => [
        { 'Domain Name' => { line => 'field', type => 'hostname', quantifier => 'empty-constrained', }, },
        { 'EOF' => { line => 'EOF', }, },
    ],
    'Empty-constrained field' => [
        { 'Domain Name' => { line => 'field', type => 'hostname', quantifier => 'optional-constrained', }, },
        { 'Referral URL' => { line => 'field', type => 'http url', quantifier => 'empty-constrained', }, },
        { 'EOF' => { line => 'EOF', }, },
    ],
    'Lone omitted-constrained field' => [
        { 'Domain Name' => { line => 'field', type => 'hostname', quantifier => 'omitted-constrained', }, },
        { 'EOF' => { line => 'EOF', }, },
    ],
    'Omitted-constrained field' => [
        { 'Domain Name' => { line => 'field', type => 'hostname', quantifier => 'optional-constrained', }, },
        { 'Referral URL' => { line => 'field', type => 'http url', quantifier => 'omitted-constrained', }, },
        { 'EOF' => { line => 'EOF', }, },
    ],
    'Repeatable field' => [
        { 'Domain Name' => { line => 'field', type => 'hostname', quantifier => 'repeatable', }, },
        { 'EOF' => { line => 'EOF', }, },
    ],
    'Repeatable max 2 field' => [
        { 'Domain Name' => { line => 'field', type => 'hostname', quantifier => 'repeatable max 2', }, },
        { 'EOF' => { line => 'EOF', }, },
    ],
    'Optional repeatable section' => [
        { 'A domain name' => { quantifier => 'optional-repeatable', }, },
        { 'EOF' => { line => 'EOF', }, },
    ],
    'Optional repeatable field' => [
        { 'Domain Name' => { line => 'field', type => 'hostname', quantifier => 'optional-repeatable', }, },
        { 'EOF' => { line => 'EOF', }, },
    ],
    'A domain name' => [
        { 'Domain Name' => { line => 'field', type => 'hostname', }, },
    ],
    'Field with keytype' => [
        { 'Special field' => { line => 'field', keytype => 'valid key', quantifier => 'repeatable', }, },
        { 'EOF' => { line => 'EOF', }, },
    ],
    'Repeated choice section' => [
        { 'Domain or referral' => {}, },
        { 'Domain or referral' => {}, },
        { 'EOF' => { line => 'EOF', }, },
    ],
    'Domain or referral' => {
        'Domain Name' => { line => 'field', type => 'hostname', },
        'Referral URL' => { line => 'field', type => 'http url', },
    },
    'Anything' => [
        { 'Any line' => { line => 'any line', quantifier => 'repeatable' }, },
    ],
};

sub mock_validate_type {
    my $value = shift;
    if ($value && $value eq 'INVALID!') {
        return 'validation error';
    }
    else {
        return ();
    }
}

my %type_subs = (
    'hostname' => \&mock_validate_type,
    'http url' => \&mock_validate_type,
    'roid' => \&mock_validate_type,
    'time stamp' => \&mock_validate_type,
    'key translation' => \&mock_validate_type,
    'query domain name' => \&mock_validate_type,
    'valid key' => \&mock_validate_type,
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
$types->mock('is_acceptable_key', sub {
    my $self = shift;
    my $keytype = shift;
    my $key = shift;
    return defined $keytype && !(defined $key && $key eq 'REJECT!');
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
            $line_no++ if $line_no < @tokens;
            return
            });
}

subtest 'Required field' => sub {
    plan tests => 6;

    {
        my $lexer = make_mock_lexer (
            ['field', ['Domain Name', [], 'DOMAIN.EXAMPLE'], []],
            ['EOF', undef, []],
        );
        my @errors = validate( rule => 'Required field', lexer => $lexer, grammar => $grammar, types => $types);
        eq_or_diff \@errors, [], 'Should accept field line';
        is $lexer->line_no(), 2, 'Should consume non-empty-field line';
    }

    {
        my $lexer = make_mock_lexer (
            ['non-empty line', 'gibberish', []],
            ['EOF', undef, []],
        );
        my @errors = validate(rule => 'Required field', lexer => $lexer, grammar => $grammar, types => $types);
        cmp_ok scalar(@errors), '>=', 1, 'Should reject non-field line';
        is $lexer->line_no(), 1, 'Should not consume non-field line';
    }

    {
        my $lexer = make_mock_lexer (
            ['field', ['Domain Name', [], undef], []],
            ['EOF', undef, []],
        );
        my @errors = validate( rule => 'Required field', lexer => $lexer, grammar => $grammar, types => $types);
        cmp_ok scalar(@errors), '>=', 1, 'Should reject empty-field line';
        is $lexer->line_no(), 2, 'Should consume empty-field line';
    }
};

subtest 'Required-strict field' => sub {
    plan tests => 7;

    {
        my $lexer = make_mock_lexer(
            [ 'field', [ 'Domain Name', [], 'DOMAIN.EXAMPLE' ], [] ],
            [ 'EOF', undef, [] ],
        );
        my @errors = validate( rule => 'Required-strict field', lexer => $lexer, grammar => $grammar, types => $types );
        eq_or_diff \@errors, [], 'Should accept non-empty field';
        is $lexer->line_no(), 2, 'Should consume non-empty field line';
    }

    {
        my $lexer = make_mock_lexer (
            ['non-empty line', 'gibberish', []],
            ['EOF', undef, []],
        );
        my @errors = validate(rule => 'Required-strict field', lexer => $lexer, grammar => $grammar, types => $types);
        cmp_ok scalar(@errors), '>=', 1, 'Should reject non-field line';
        is $lexer->line_no(), 1, 'Should not consume non-field line';
    }

    {
        my $lexer = make_mock_lexer(
            [ 'field', [ 'Domain Name', [], undef ], [] ],
            [ 'EOF', undef, [] ],
        );
        my @errors = validate( rule => 'Required-strict field', lexer => $lexer, grammar => $grammar, types => $types );
        cmp_ok scalar(@errors), '>=', 1, 'Should reject empty field';
        like $errors[0], qr/line 1/, 'Should refer to line number of the invalid field';
        is $lexer->line_no(), 1, 'Should not consume empty field line';
    }

};

subtest 'Optional-free subrule' => sub {
    plan tests => 3;

    {
        my $lexer = make_mock_lexer (
            ['field', ['Referral URL', [], 'http://domain.example/'], []],
            ['EOF', undef, []],
        );
        my @errors = validate( rule => 'Optional-free field', lexer => $lexer, grammar => $grammar, types => $types );
        eq_or_diff \@errors, [], 'Should accept omitted field line';
    }

    {
        my $lexer = make_mock_lexer (
            ['field', ['Domain Name', [], undef], []],
            ['field', ['Referral URL', [], 'http://domain.example/'], []],
            ['EOF', undef, []],
        );
        my @errors = validate( rule => 'Optional-free field', lexer => $lexer, grammar => $grammar, types => $types );
        eq_or_diff \@errors, [], 'Should accept empty field line';
    }

    {
        my $lexer = make_mock_lexer (
            ['field', ['Referral URL', [], undef], []],
            ['EOF', undef, []],
        );
        my @errors = validate( rule => 'Optional-free field', lexer => $lexer, grammar => $grammar, types => $types );
        eq_or_diff \@errors, [], 'Should accept mixed empty field syntaxes';
    }
};

subtest 'Optional-not-empty subrule' => sub {
    plan tests => 4;

    {
        my $lexer = make_mock_lexer (
            ['field', ['Domain Name', [], 'DOMAIN.EXAMPLE'], []],
            ['EOF', undef, []],
        );
        my @errors = validate( rule => 'Optional-not-empty field', lexer => $lexer, grammar => $grammar, types => $types );
        eq_or_diff \@errors, [], 'Should accept non-empty field line';
    }

    {
        my $lexer = make_mock_lexer (
            ['EOF', undef, []],
        );
        my @errors = validate( rule => 'Optional-not-empty field', lexer => $lexer, grammar => $grammar, types => $types );
        eq_or_diff \@errors, [], 'Should accept omitted field line';
    }

    {
        my $lexer = make_mock_lexer (
            ['field', ['Domain Name', [], undef], []],
            ['EOF', undef, []],
        );
        my @errors = validate( rule => 'Optional-not-empty field', lexer => $lexer, grammar => $grammar, types => $types );
        cmp_ok scalar(@errors), '>=', 1, 'Should reject empty field line';
        like $errors[0], qr/line 1/, 'Should refer to line number of the empty field';
    }
};

subtest 'Optional-constrained subrule' => sub {
    plan tests => 7;

    {
        my $lexer = make_mock_lexer (
            ['field', ['Referral URL', [], 'http://domain.example/'], []],
            ['EOF', undef, []],
        );
        my @errors = validate( rule => 'Optional-constrained field', lexer => $lexer, grammar => $grammar, types => $types );
        eq_or_diff \@errors, [], 'Should accept omitted field line';
    }

    {
        my $lexer = make_mock_lexer (
            ['field', ['Domain Name', [], undef], []],
            ['field', ['Referral URL', [], 'http://domain.example/'], []],
            ['EOF', undef, []],
        );
        my @errors = validate( rule => 'Optional-constrained field', lexer => $lexer, grammar => $grammar, types => $types );
        eq_or_diff \@errors, [], 'Should accept empty field line';
    }

    {
        my $lexer = make_mock_lexer (
            ['field', ['Referral URL', [], undef], []],
            ['EOF', undef, []],
        );
        my @errors = validate( rule => 'Optional-constrained field', lexer => $lexer, grammar => $grammar, types => $types );
        cmp_ok scalar(@errors), '>=', 1, 'Should reject mixed empty field syntaxes';
        like $errors[0], qr/line 1/, 'Should refer to line number of the empty field';
    }

    {
        my $lexer = make_mock_lexer (
            ['field', ['Domain Name', [], undef], []],
            ['EOF', undef, []],
        );
        my @errors = validate( rule => 'Optional-constrained field', lexer => $lexer, grammar => $grammar, types => $types );
        cmp_ok scalar(@errors), '>=', 2, 'Should reject mixed empty field syntaxes';
        like $errors[0], qr/line 1: .*Domain Name.*empty/, 'Should refer to line number of the empty field';
        like $errors[1], qr/line 2: .*Referral URL.*omitted/, 'Should refer to line number of the omitted field';
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
        my @errors = validate( rule => 'Repeatable field', lexer => $lexer, grammar => $grammar, types => $types );
        eq_or_diff \@errors, [], 'Should accept repeated field lines';
    }

    {
        my $lexer = make_mock_lexer (
            ['field', ['Domain Name', [], 'DOMAIN1.EXAMPLE'], []],
            ['field', ['Domain Name', [], 'DOMAIN2.EXAMPLE'], []],
            ['EOF', undef, []],
        );
        my @errors = validate( rule => 'Repeatable max 2 field', lexer => $lexer, grammar => $grammar, types => $types );
        eq_or_diff \@errors, [], 'Should accept repeated field lines';
    }

    {
        my $lexer = make_mock_lexer (
            ['field', ['Domain Name', [], 'DOMAIN1.EXAMPLE'], []],
            ['field', ['Domain Name', [], 'DOMAIN2.EXAMPLE'], []],
            ['field', ['Domain Name', [], 'DOMAIN3.EXAMPLE'], []],
            ['EOF', undef, []],
        );
        my @errors = validate( rule => 'Repeatable max 2 field', lexer => $lexer, grammar => $grammar, types => $types );
        ok scalar(@errors), 'Should reject too many repetitions of field lines';
    }

};

subtest 'Error propagation' => sub {
    plan tests => 1;

    my $lexer = make_mock_lexer (
        ['field', ['Domain Name', [], 'DOMAIN.EXAMPLE'], ['line 1: BOOM!']],
        ['EOF', undef, []],
    );
    my @remarks = validate2( rule => 'Required field', lexer => $lexer, grammar => $grammar, types => $types );
    my @strings = map { remark_string( $_ ) } @remarks;
    eq_or_diff \@strings, ['line 1: error: BOOM!'], 'Should propagate errors from lexer';
};

subtest 'Optional repeatable subrule' => sub {
    plan tests => 3;

    {
        my $lexer = make_mock_lexer (
            ['EOF', undef, []],
        );
        my @errors = validate( rule => 'Optional repeatable section', lexer => $lexer, grammar => $grammar, types => $types );
        eq_or_diff \@errors, [], 'Should accept omitted lines';
    }

    {
        my $lexer = make_mock_lexer (
            ['field', ['Domain Name', [], 'DOMAIN1.EXAMPLE'], []],
            ['field', ['Domain Name', [], undef], []],
            ['EOF', undef, []],
        );
        my @errors = validate( rule => 'Optional repeatable field', lexer => $lexer, grammar => $grammar, types => $types );
        cmp_ok scalar(@errors), '>=', 1, 'Should reject empty field in repetition';
    }

    {
        my $lexer = make_mock_lexer (
            ['field', ['Domain Name', [], undef], []],
            ['field', ['Domain Name', [], 'DOMAIN1.EXAMPLE'], []],
            ['EOF', undef, []],
        );
        my @errors = validate( rule => 'Optional repeatable field', lexer => $lexer, grammar => $grammar, types => $types );
        cmp_ok scalar(@errors), '>=', 1, 'Should reject empty field at start of repetition';
    }

};

subtest 'Repeated choice section' => sub {
    plan tests => 1;

    {
        my $lexer = make_mock_lexer (
            ['field', ['Domain Name', [], 'DOMAIN1.EXAMPLE'], []],
            ['field', ['Domain Name', [], 'DOMAIN2.EXAMPLE'], []],
            ['EOF', undef, []],
        );
        my @errors = validate( rule => 'Repeated choice section', lexer => $lexer, grammar => $grammar, types => $types );
        eq_or_diff \@errors, [], 'Should accept repeated choice section';
    }

};

subtest 'Anything' => sub {
    plan tests => 1;

    {
        my $lexer = make_mock_lexer (
            ['empty line', undef, []],
            ['non-empty line', 'gibberish', []],
            ['roid line', ['INVALID!', 'INVALID!'], []],
            ['EOF', undef, []],
        );
        my @errors = validate( rule => 'Anything', lexer => $lexer, grammar => $grammar, types => $types );
        eq_or_diff \@errors, [], 'Should accept anything';
    }

};

subtest 'Empty-constrained subrule' => sub {
    plan tests => 7;

    my $field_1_non_empty = [ 'field', [ 'Domain Name',  [], 'DOMAIN1.EXAMPLE' ],        [] ];
    my $field_1_empty     = [ 'field', [ 'Domain Name',  [], undef ],                    [] ];
    my $field_2_empty     = [ 'field', [ 'Referral URL', [], undef ],                    [] ];
    my $eof = [ 'EOF', undef, [] ];

    {
        my $lexer = make_mock_lexer(
            $field_1_non_empty,
            $eof,
        );
        my @errors = validate( rule => 'Lone empty-constrained field', lexer => $lexer, grammar => $grammar, types => $types );
        cmp_ok scalar(@errors), '>=', 1, 'Should reject non-empty field';
        like $errors[0], qr/line 1/, 'Should refer to line number of the omitted field';
    }

    {
        my $lexer = make_mock_lexer(
            $field_1_empty,
            $eof,
        );
        my @errors = validate( rule => 'Lone empty-constrained field', lexer => $lexer, grammar => $grammar, types => $types );
        eq_or_diff \@errors, [], 'Should accept empty field line';
    }

    {
        my $lexer = make_mock_lexer (
            $eof,
        );
        my @errors = validate( rule => 'Lone empty-constrained field', lexer => $lexer, grammar => $grammar, types => $types );
        cmp_ok scalar(@errors), '>=', 1, 'Should reject omitted field';
        like $errors[0], qr/line 1/, 'Should refer to line number of the omitted field';
    }

    {
        my $lexer = make_mock_lexer (
            $field_2_empty,
            $eof,
        );
        my @errors = validate( rule => 'Empty-constrained field', lexer => $lexer, grammar => $grammar, types => $types );
        cmp_ok scalar(@errors), '>=', 1, 'Should reject mixed empty field syntaxes';
        like $errors[0], qr/line 1/, 'Should refer to line number of the empty field';
    }
};

subtest 'Omitted-constrained subrule' => sub {
    plan tests => 8;

    my $field_1_non_empty = [ 'field', [ 'Domain Name',  [], 'DOMAIN1.EXAMPLE' ],        [] ];
    my $field_1_empty     = [ 'field', [ 'Domain Name',  [], undef ],                    [] ];
    my $field_2_empty     = [ 'field', [ 'Referral URL', [], undef ],                    [] ];
    my $eof = [ 'EOF', undef, [] ];

    {
        my $lexer = make_mock_lexer(
            $field_1_non_empty,
            $eof,
        );
        my @errors = validate( rule => 'Lone omitted-constrained field', lexer => $lexer, grammar => $grammar, types => $types );
        cmp_ok scalar(@errors), '>=', 1, 'Should reject non-empty field';
        like $errors[0], qr/line 1/, 'Should refer to line number of the omitted field';
    }

    {
        my $lexer = make_mock_lexer (
            $field_1_empty,
            $eof,
        );
        my @errors = validate( rule => 'Lone omitted-constrained field', lexer => $lexer, grammar => $grammar, types => $types );
        cmp_ok scalar(@errors), '>=', 1, 'Should reject empty field';
        like $errors[0], qr/line 1/, 'Should refer to line number of the empty field';
    }

    {
        my $lexer = make_mock_lexer(
            $eof,
        );
        my @errors = validate( rule => 'Lone omitted-constrained field', lexer => $lexer, grammar => $grammar, types => $types );
        eq_or_diff \@errors, [], 'Should accept omitted field';
    }

    {
        my $lexer = make_mock_lexer (
            $field_1_empty,
            $eof,
        );
        my @errors = validate( rule => 'Omitted-constrained field', lexer => $lexer, grammar => $grammar, types => $types );
        cmp_ok scalar(@errors), '>=', 2, 'Should reject mixed empty field syntaxes';
        like $errors[0], qr/line 1: .*Domain Name.*empty/, 'Should refer to line number of the empty field';
        like $errors[1], qr/line 2: .*Referral URL.*omitted/, 'Should refer to line number of the omitted field';
    }
};

subtest 'Keytype validation' => sub {
    plan tests => 1;

    {
        my $lexer = make_mock_lexer(
            [ 'field', [ 'Valid Field Key', [], undef ], [] ],
            [ 'field', [ 'INVALID!', [], undef ], [] ],
            [ 'EOF', undef, [] ],
        );
        my @errors = validate( rule => 'Field with keytype', lexer => $lexer, grammar => $grammar, types => $types );
        ok scalar(grep qr/line 2/, @errors), 'Should refer to line number of the invalid field';
    }
};

