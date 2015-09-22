use 5.014;
use strict;
use warnings;

use Test::More tests => 3;
use Test::Differences;
use IO::String;

require_ok('Net::Whois::Spec::Lexer');

subtest 'Line separators' => sub {
    plan tests => 15;
    my $lexer = Net::Whois::Spec::Lexer->new(io => IO::String->new("line 1\r\nline 2\nline 3\rline 4"));
    $lexer->load();
    is($lexer->line_no(), 1, 'File should start out at line 1');

    my ($token_crlf, $errors_crlf) = $lexer->peek_line();
    eq_or_diff($token_crlf, ['non-empty line', 'line 1'], 'Should parse CRLF terminated line');
    eq_or_diff($errors_crlf, [], 'Should report no error');
    $lexer->next_line();
    is($lexer->line_no(), 2, 'CRLF should increment line number');

    my ($token_lf, $errors_lf) = $lexer->peek_line();
    eq_or_diff($token_lf, ['non-empty line', 'line 2'], 'Should parse LF terminated line');
    ok($errors_lf && ref $errors_lf eq 'ARRAY' && @$errors_lf == 1, 'Should complain about line termination');
    $lexer->next_line();
    is($lexer->line_no(), 3, 'LF should increment line number');

    my ($token_cr, $errors_cr) = $lexer->peek_line();
    eq_or_diff($token_cr, ['non-empty line', 'line 3'], 'Should parse CR terminated line');
    ok($errors_cr && ref $errors_cr eq 'ARRAY' && @$errors_cr == 1, 'Should complain about line termination');
    $lexer->next_line();
    is($lexer->line_no(), 4, 'CR should increment line number');

    my ($token_none, $errors_none) = $lexer->peek_line();
    eq_or_diff($token_none, ['non-empty line', 'line 4'], 'Should parse EOF line');
    ok($errors_none && ref $errors_none eq 'ARRAY' && @$errors_none == 1, 'Should complain about line termination');
    $lexer->next_line();
    is($lexer->line_no(), 4, 'EOF should not increment line number');

    my ($token_eof, $errors_eof) = $lexer->peek_line();
    eq_or_diff($token_eof, undef, 'EOF is indicated');
    eq_or_diff($errors_eof, [], 'Should report no error');
};

subtest 'Token types' => sub {
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

    my ($empty_line, $errors_empty_line) = $lexer->peek_line();
    eq_or_diff($empty_line, ['empty line'], 'Should recognize empty lines');
    eq_or_diff($errors_empty_line, [], 'Should report no error');
    $lexer->next_line();

    my ($non_empty_line, $errors_non_empty_line) = $lexer->peek_line();
    eq_or_diff($non_empty_line, ['non-empty line', 'second line'], 'Should recognize non-empty lines');
    eq_or_diff($errors_non_empty_line, [], 'Should report no error');
    $lexer->next_line();

    my ($field, $errors_field) = $lexer->peek_line();
    eq_or_diff($field, ['field', 'Domain Name', [], 'EXAMPLE.TLD'], 'Should recognize fields');
    eq_or_diff($errors_field, [], 'Should report no error');
    $lexer->next_line();

    my ($empty_field, $errors_empty_field) = $lexer->peek_line();
    eq_or_diff($empty_field, ['empty field', 'Name Server', []], 'Should recognize empty fields');
    eq_or_diff($errors_empty_field, [], 'Should report no error');
    $lexer->next_line();

    my ($multi, $errors_multi) = $lexer->peek_line();
    eq_or_diff($multi, ['multiple name servers line'], 'Should recognize multiple name servers lines');
    eq_or_diff($errors_multi, [], 'Should report no error');
    $lexer->next_line();

    my ($roid, $errors_roid) = $lexer->peek_line();
    eq_or_diff($roid, ['roid line', 'roid1abc-example', 'ns1.foo.example'], 'Should recognize ROID lines');
    eq_or_diff($errors_roid, [], 'Should report no error');
    $lexer->next_line();

    my ($last_update, $errors_last_update) = $lexer->peek_line();
    eq_or_diff($last_update, ['last update line', '2014-11-14T12:58:01Z'], 'Should recognize last update lines');
    eq_or_diff($errors_last_update, [], 'Should report no error');
    $lexer->next_line();

    my ($awip, $errors_awip) = $lexer->peek_line();
    eq_or_diff($awip, ['awip line'], 'Should recognize AWIP lines');
    eq_or_diff($errors_awip, [], 'Should report no error');
    $lexer->next_line();
};
