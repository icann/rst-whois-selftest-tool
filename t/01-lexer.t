use 5.014;
use strict;
use warnings;

use Test::More tests => 8;
use Test::Differences;

require_ok('PDT::TS::Whois::Lexer');

subtest 'Line separators' => sub {
    plan tests => 15;

    my $lexer = PDT::TS::Whois::Lexer->new("line 1\r\nline 2\nline 3\rline 4");
    is($lexer->line_no(), 1, 'File should start out at line 1');

    {
        my ($token, $value, $errors) = $lexer->peek_line();
        eq_or_diff([$token, $value], ['non-empty line', 'line 1'], 'Should parse CRLF terminated line');
        eq_or_diff($errors, [], 'Should report no error');
        $lexer->next_line();
        is($lexer->line_no(), 2, 'CRLF should increment line number');
    }

    {
        my ($token, $value, $errors) = $lexer->peek_line();
        eq_or_diff([$token, $value], ['non-empty line', 'line 2'], 'Should parse LF terminated line');
        ok($errors && ref $errors eq 'ARRAY' && @$errors == 1, 'Should complain about line termination');
        $lexer->next_line();
        is($lexer->line_no(), 3, 'LF should increment line number');
    }

    {
        my ($token, $value, $errors) = $lexer->peek_line();
        eq_or_diff([$token, $value], ['non-empty line', 'line 3'], 'Should parse CR terminated line');
        ok($errors && ref $errors eq 'ARRAY' && @$errors == 1, 'Should complain about line termination');
        $lexer->next_line();
        is($lexer->line_no(), 4, 'CR should increment line number');
    }

    {
        my ($token, $value, $errors) = $lexer->peek_line();
        eq_or_diff([$token, $value], ['non-empty line', 'line 4'], 'Should parse EOF line');
        ok($errors && ref $errors eq 'ARRAY' && @$errors == 1, 'Should complain about line termination');
        $lexer->next_line();
        is($lexer->line_no(), 4, 'EOF should not increment line number');
    }

    {
        my ($token, $value, $errors) = $lexer->peek_line();
        is($token, 'EOF', 'EOF is indicated');
        eq_or_diff($errors, [], 'Should report no error');
    }
};

subtest 'Check_eol setting' => sub {
    plan tests => 13;
    {
        my $lexer = PDT::TS::Whois::Lexer->new('');
        is $lexer->check_eol, 1, 'Enabled by default';
        $lexer->check_eol( 0 );
        is $lexer->check_eol, 0, 'Disable setting';
        $lexer->check_eol( 1 );
        is $lexer->check_eol, 1, 'Enable setting';
        $lexer->check_eol( '' );
        is $lexer->check_eol, 0, 'Normalize false value';
        $lexer->check_eol( "I am a banana!" );
        is $lexer->check_eol, 1, 'Normalize true value';
        is $lexer->check_eol( 1 ), 1, 'Return old value when staying enabled';
        is $lexer->check_eol( 0 ), 1, 'Return old value when disabling';
        is $lexer->check_eol( 0 ), 0, 'Return old value when staying disabled';
        is $lexer->check_eol( 1 ), 0, 'Return old value when enabling';
    }
    {
        my $lexer = PDT::TS::Whois::Lexer->new("line 1\r\nline 2\nline 3\rline 4");
        $lexer->check_eol( 0 );
        {
            my (undef, undef, $errors) = $lexer->peek_line();
            eq_or_diff($errors, [], 'Should report no error for CRLF with check_eol disabled');
            $lexer->next_line();
        }
        {
            my (undef, undef, $errors) = $lexer->peek_line();
            eq_or_diff($errors, [], 'Should report no error for LF with check_eol disabled');
            $lexer->next_line();
        }
        {
            my (undef, undef, $errors) = $lexer->peek_line();
            eq_or_diff($errors, [], 'Should report no error for CR with check_eol disabled');
            $lexer->next_line();
        }
        {
            my (undef, undef, $errors) = $lexer->peek_line();
            eq_or_diff($errors, [], 'Should report no error for EOF with check_eol disabled');
            $lexer->next_line();
        }
    }
};

subtest 'Token types' => sub {
    plan tests => 20;

    my @lines = (
        '',
        'second line',
        'Domain Name: EXAMPLE.TLD',
        'Domain Name (Domännamn): EXAMPLE.TLD',
        'Name Server:',
        'Query matched more than one name server:',
        'roid1abc-example (ns1.foo.example)',
        '>>> Last update of WHOIS database: 2014-11-14T12:58:01Z <<<',
        '>>> Last update of Whois database: 2014-11-14T12:58:01Z <<<',
        'For more information on Whois status codes, please visit https://icann.org/epp',
    );
    my $lexer = PDT::TS::Whois::Lexer->new(join("\r\n", @lines, ''));

    {
        my ($token, $value, $errors) = $lexer->peek_line();
        eq_or_diff([$token, $value], ['empty line', undef], 'Should recognize empty lines');
        eq_or_diff($errors, [], 'Should report no error');
        $lexer->next_line();
    }

    {
        my ($token, $value, $errors) = $lexer->peek_line();
        eq_or_diff([$token, $value], ['non-empty line', 'second line'], 'Should recognize non-empty lines');
        eq_or_diff($errors, [], 'Should report no error');
        $lexer->next_line();
    }

    {
        my ($token, $value, $errors) = $lexer->peek_line();
        eq_or_diff([$token, $value], ['field', ['Domain Name', [], 'EXAMPLE.TLD']], 'Should recognize fields');
        eq_or_diff($errors, [], 'Should report no error');
        $lexer->next_line();
    }

    {
        my ($token, $value, $errors) = $lexer->peek_line();
        eq_or_diff([$token, $value], ['field', ['Domain Name', ['Domännamn'], 'EXAMPLE.TLD']], 'Should recognize fields with translations');
        eq_or_diff($errors, [], 'Should report no error');
        $lexer->next_line();
    }

    {
        my ($token, $value, $errors) = $lexer->peek_line();
        eq_or_diff([$token, $value], ['field', ['Name Server', [], undef]], 'Should recognize empty fields');
        eq_or_diff($errors, [], 'Should report no error');
        $lexer->next_line();
    }

    {
        my ($token, $value, $errors) = $lexer->peek_line();
        eq_or_diff([$token, $value], ['multiple name servers line', undef], 'Should recognize multiple name servers lines');
        eq_or_diff($errors, [], 'Should report no error');
        $lexer->next_line();
    }

    {
        my ($token, $value, $errors) = $lexer->peek_line();
        eq_or_diff([$token, $value], ['roid line', ['roid1abc-example', 'ns1.foo.example']], 'Should recognize ROID lines');
        eq_or_diff($errors, [], 'Should report no error');
        $lexer->next_line();
    }

    {
        my ($token, $value, $errors) = $lexer->peek_line();
        eq_or_diff([$token, $value], ['last update line', '2014-11-14T12:58:01Z'], 'Should recognize last update lines with all caps WHOIS');
        eq_or_diff($errors, [], 'Should report no error');
        $lexer->next_line();
    }

    {
        my ($token, $value, $errors) = $lexer->peek_line();
        eq_or_diff([$token, $value], ['last update line', '2014-11-14T12:58:01Z'], 'Should recognize last update lines with capitalized Whois');
        eq_or_diff($errors, [], 'Should report no error');
        $lexer->next_line();
    }

    {
        my ($token, $value, $errors) = $lexer->peek_line();
        eq_or_diff([$token, $value], ['awip line', undef], 'Should recognize AWIP lines');
        eq_or_diff($errors, [], 'Should report no error');
        $lexer->next_line();
    }
};

subtest 'Whitespace' => sub {
    plan tests => 3;

    my $lexer = PDT::TS::Whois::Lexer->new("	Key: Value\r\nKey:	Value\r\nKey: Tab	value\r\n");

    subtest 'Tab in leading space' => sub {
        plan tests => 4;

        my ($token, $value, $errors) = $lexer->peek_line();
        is($token, 'field', 'Should recognize field');
        eq_or_diff($value, ['Key', [], 'Value'], 'Should strip leading space');
        is(scalar @$errors, 1, 'Should detect an error');
        like($errors->[0], qr/whitespace/i, 'Should complain about whitespace');
        $lexer->next_line();
    };

    subtest 'Tab in field separator' => sub {
        plan tests => 4;

        my ($token, $value, $errors) = $lexer->peek_line();
        is($token, 'field', 'Should recognize field');
        eq_or_diff($value, ['Key', [], 'Value'], 'Should report token value normally');
        is(scalar @$errors, 1, 'Should detect an error');
        like($errors->[0], qr/whitespace/i, 'Should complain about whitespace');
        $lexer->next_line();
    };

    subtest 'Tab in field value' => sub {
        plan tests => 4;

        my ($token, $value, $errors) = $lexer->peek_line();
        is($token, 'field', 'Should recognize field');
        eq_or_diff($value, ['Key', [], 'Tab value'], 'Should homogenize whitespace to SPACE');
        is(scalar @$errors, 1, 'Should detect an error');
        like($errors->[0], qr/whitespace/i, 'Should complain about whitespace');
        $lexer->next_line();
    };

};

subtest 'Leading space' => sub {
    plan tests => 2;

    my $lexer = PDT::TS::Whois::Lexer->new("         Key: Good leading space\r\n          Key: Bad leading space\r\n");

    subtest 'Max allowed leading space' => sub {
        plan tests => 3;

        my ($token, $value, $errors) = $lexer->peek_line();
        is($token, 'field', 'Should recognize field');
        eq_or_diff($value, ['Key', [], 'Good leading space'], 'Should strip leading space from value');
        eq_or_diff($errors, [], 'Should report no error');
        $lexer->next_line();
    };

    subtest 'Too much leading space' => sub {
        plan tests => 4;

        my ($token, $value, $errors) = $lexer->peek_line();
        is($token, 'field', 'Should recognize field');
        eq_or_diff($value, ['Key', [], 'Bad leading space'], 'Should strip leading space from value');
        is(scalar @$errors, 1, 'Should detect an error');
        like($errors->[0], qr/leading space/i, 'Should complain about leading space');
        $lexer->next_line();
    };

};

subtest 'Trailing space' => sub {
    plan tests => 3;

    my $lexer = PDT::TS::Whois::Lexer->new("Key: Value with trailing space \r\nKey: \r\nKey:  \r\n");

    subtest 'Strip field value' => sub {
        plan tests => 4;
        my ($token, $value, $errors) = $lexer->peek_line();
        is($token, 'field', 'Should report correct token');
        eq_or_diff($value, ['Key', [], 'Value with trailing space'], 'Should report correct token value');
        is(scalar @$errors, 1, 'Should detect an error');
        like($errors->[0], qr/trailing space/i, 'Should complain about trailing space');
        $lexer->next_line();
    };

    subtest 'Empty field with single trailing space' => sub {
        plan tests => 3;
        my ($token, $value, $errors) = $lexer->peek_line();
        is($token, 'field', 'Should report correct token');
        eq_or_diff($value, ['Key', [], undef], 'Should report correct token value');
        eq_or_diff($errors, [], 'Should report no error');
        $lexer->next_line();
    };

    subtest 'Empty field with too much trailing space' => sub {
        plan tests => 4;
        my ($token, $value, $errors) = $lexer->peek_line();
        is($token, 'field', 'Should report correct token');
        eq_or_diff($value, ['Key', [], undef], 'Should report correct token value');
        is(scalar @$errors, 1, 'Should detect an error');
        like($errors->[0], qr/trailing space/i, 'Should complain about trailing space');
        $lexer->next_line();
    };
};

subtest 'Pattern matching' => sub {
    plan tests => 6;
    my $lexer = PDT::TS::Whois::Lexer->new("abcdef\r\n   surrounding space   \r\nthird line\r\n");
    my $line_no = $lexer->line_no();
    ok $lexer->matches(qr/bcde/), 'Should match substring';
    ok !$lexer->matches(qr/third/), 'Should not match next line';
    is $lexer->line_no(), $line_no, 'Should not advance line counter';
    $lexer->next_line();
    ok $lexer->matches(qr/^surrounding/), 'Should strip leading space before match';
    ok $lexer->matches(qr/space$/), 'Should strip trailing space before match';
    $lexer->next_line();
    $lexer->next_line();
    ok !$lexer->matches(qr/third/), 'Should not match last line after EOF is reached';
};
