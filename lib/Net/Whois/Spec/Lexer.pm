package Net::Whois::Spec::Lexer;

use 5.014;
use strict;
use warnings;

use Moo;
use Carp;
use File::Slurp;

=head1 NAME

Net::Whois::Spec::Lexer - Consumes a IO::Handle and produces a stream of line tokens.

=cut

=head1 SYNOPSIS

A class for consuming L<IO::Handle>s and producing streams of line tokens.

    use Net::Whois::Spec::Lexer;

    my $lexer = Net::Whois::Spec::Lexer->new(io => IO::String->new("    line 1\r\n    line 2\r\n"));
    while (my ($token, $value, $errors) = $lexer->peek_line() && defined $line) {
        printf("%d: [%s] [%s]", $lexer->line_no(), $token, join(", ", @$errors));

        $lexer->next_line();
        ($token, $value, $errors) = $lexer->peek_line();
    }

=head1 SUBROUTINES/METHODS

=head2 new(io => $io)

    my $lexer = Net::Whois::Spec::Lexer->new(io => IO::String->new("    line 1\r\n    line 2\r\n"));

=cut

has io => ( is => 'ro', );

has line_no => ( is => 'rw', );

has contents => ( is => 'rw', );

has lookahead => ( is => 'rw', );

sub load {
    my $self = shift;

    my $contents = read_file( $self->io, { binmode => ':encoding(UTF-8)' } ) or carp "Could not open file: $!";

    $self->line_no( 0 );
    $self->contents( $contents );
    $self->next_line();
}

sub peek_line {
    my $self = shift;

    if ( !defined $self->lookahead ) {
        confess 'must call load() before peek_line()';
    }
    return @{ $self->lookahead };
}

sub next_line {
    my $self = shift;

    if ( !defined $self->contents ) {
        confess 'must call load() before next_line()';
    }
    my $contents = $self->contents;
    my @errors;
    if ( !defined $self->line_no && $contents =~ /^\N{U+FEFF}/ ) {
        $contents =~ s/^\N{U+FEFF}//;
        push @errors, "line 1: found BOM";
    }

    if ( $self->contents eq '' ) {
        if ( !defined $self->line_no ) {
            $self->line_no( 1 );
        }
        $self->lookahead( [ undef, \@errors ] );
        return;
    }
    $self->line_no( ( $self->line_no || 0 ) + 1 );
    $contents =~ s/([^\r\n]*)(\r\n?|\n)//;
    my $line = $1;
    my $eol  = $2;
    if ( !defined $eol ) {
        $line     = $contents;
        $eol      = '';
        $contents = '';
    }
    $self->contents( $contents );

    # Strip CRLF
    if ( $eol ne "\r\n" ) {
        $eol =~ s/\r/CR/m;
        $eol =~ s/\n/LF/m;
        push @errors, sprintf( "line %d: expected CRLF, got '$eol'", $self->line_no );
    }

    # Homogenize whitespace
    my $space_count = () = $line =~ / /g;
    $line =~ s/\s/ /g;
    my $whitespace_count = () = $line =~ / /g;
    if ( $whitespace_count > $space_count ) {
        push @errors, sprintf( "line %d: whitespace other than SPACE (U+0020)", $self->line_no );
    }

    # Strip leading space
    $line =~ s/^( *)//;
    my $lead_space = $1;
    if ( length $lead_space > 9 ) {
        push @errors, sprintf( "line %d: too much leading space", $self->line_no );
    }

    # Strip trailing space
    $line =~ s/( *)$//;
    my $trail_space = $1;
    if ( length $trail_space > 0 ) {
        push @errors, sprintf( "line %d: trailing space", $self->line_no );
    }

    # Match token type
    my $token;
    my $token_value;
    if ( $line eq '' ) {
        $token       = 'empty line';
        $token_value = undef;
    }
    elsif ( $line eq 'Query matched more than one name server:' ) {
        $token       = 'multiple name servers line';
        $token_value = undef;
    }
    elsif ( $line =~ /^>>> Last update of Whois database: (.*) <<<$/ ) {
        my $timestamp = $1;

        # Note: validation is out of place here; move elsewhere if added complexity can be avoided
        if ( $timestamp !~ /^\d\d\d\d-\d\d-\d\d[Tt]\d\d:\d\d:\d\dZ$/ ) {
            push @errors, sprintf( 'line %d: invalid timestamp format' );
        }
        $token       = 'last update line';
        $token_value = $timestamp;
    }
    elsif ( $line =~ /^For more information on Whois status codes, please visit (.*)$/ ) {
        my $url = $1;

        # Note: validation is out of place here; move elsewhere if added complexity can be avoided
        if ( $url ne 'https://icann.org/epp' && $url ne 'https://www\.icann\.org/resources/pages/epp-status-codes-2014-06-16-en' ) {
            push @errors, sprintf( 'line %d: illegal url' );
        }

        $token       = 'awip line';
        $token_value = undef;
    }
    elsif ( $line =~ /^([^:]+)(?: \(([^()]+)\))?:(?: (.*))?$/ ) {
        my $key          = $1;
        my @translations = split '/', ( $2 || '' );
        my $value        = $3;

        $token = 'field';
        $token_value = [ $key, \@translations, $value ];
    }
    elsif ( $line =~ /^(.*) \((.*)\)$/ ) {
        my $roid     = $1;
        my $hostname = $2;
        $token = 'roid line';
        $token_value = [ $roid, $hostname ];
    }
    else {
        $token       = 'non-empty line';
        $token_value = $line;
    }

    $self->lookahead( [ $token, \@errors ] );
    return;
}

1;
