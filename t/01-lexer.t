use Test::More tests => 2;
use Test::Differences;
use IO::String;

require_ok('Net::Whois::Spec::Lexer');

subtest 'Line separators' => sub {
    plan tests => 15;
    my $lexer = Net::Whois::Spec::Lexer->new(io => IO::String->new("line 1\r\nline 2\nline 3\rline 4"));
    $lexer->load();
    is($lexer->line_no(), 1, 'File should start out at line 1');

    my ($line_crlf, $errors_crlf) = $lexer->peek_line();
    is($line_crlf, "line 1", 'Should parse CRLF terminated line');
    eq_or_diff($errors_crlf, [], 'Should report no error');
    $lexer->next_line();
    is($lexer->line_no(), 2, 'CRLF should increment line number');

    my ($line_lf, $errors_lf) = $lexer->peek_line();
    is($line_lf, "line 2", 'Should parse LF terminated line');
    ok($errors_lf && ref $errors_lf eq 'ARRAY' && @$errors_lf == 1, 'Should complain about line termination');
    $lexer->next_line();
    is($lexer->line_no(), 3, 'LF should increment line number');

    my ($line_cr, $errors_cr) = $lexer->peek_line();
    is($line_cr, "line 3", 'Should parse CR terminated line');
    ok($errors_cr && ref $errors_cr eq 'ARRAY' && @$errors_cr == 1, 'Should complain about line termination');
    $lexer->next_line();
    is($lexer->line_no(), 4, 'CR should increment line number');

    my ($line_none, $errors_none) = $lexer->peek_line();
    is($line_none, "line 4", 'Should parse EOF line');
    ok($errors_none && ref $errors_none eq 'ARRAY' && @$errors_none == 1, 'Should complain about line termination');
    $lexer->next_line();
    is($lexer->line_no(), 4, 'EOF should not increment line number');

    my ($line_eof, $errors_eof) = $lexer->peek_line();
    is($line_eof, undef, 'EOF is indicated');
    eq_or_diff($errors_eof, [], 'Should report no error');
}
