use 5.014;
use strict;
use warnings;

use Test::More tests => 4;
use Test::Differences;
use IO::String;

require_ok('Net::Whois::Spec::Lexer');

subtest 'Line separators' => sub {
    plan tests => 15;

    my $lexer = Net::Whois::Spec::Lexer->new(io => IO::String->new("line 1\r\nline 2\nline 3\rline 4"));
    $lexer->load();
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

subtest 'Token types' => sub {
    plan tests => 16;

    my @lines = (
        '',
        'second line',
        'Domain Name: EXAMPLE.TLD',
        'Name Server:',
        'Query matched more than one name server:',
        'roid1abc-example (ns1.foo.example)',
        '>>> Last update of Whois database: 2014-11-14T12:58:01Z <<<',
        'For more information on Whois status codes, please visit https://icann.org/epp',
    );
    my $lexer = Net::Whois::Spec::Lexer->new(io => IO::String->new(join("\r\n", @lines, '')));
    $lexer->load();

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
        eq_or_diff([$token, $value], ['last update line', '2014-11-14T12:58:01Z'], 'Should recognize last update lines');
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

subtest 'Trailing space' => sub {
    plan tests => 3;

    my $lexer = Net::Whois::Spec::Lexer->new(io => IO::String->new("Key: Value with trailing space \r\n"));
    $lexer->load();

    my ($token, $value, $errors) = $lexer->peek_line();
    eq_or_diff([$token, $value], ['field', ['Key', [], 'Value with trailing space']], 'Should recognize field with stripped value');
    is(scalar @$errors, 1, 'Should detect an error');
    like($errors->[0], qr/trailing space/i, 'Should complain about trailing space');
    $lexer->next_line();
};
