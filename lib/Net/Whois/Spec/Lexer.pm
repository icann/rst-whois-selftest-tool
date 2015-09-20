package Net::Whois::Spec::Lexer;
use 5.014;
use strict;
use warnings;

use Moo;
use Carp;
use File::Slurp;

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

    $self->lookahead( [ $line, \@errors ] );
    return;
}

1;
