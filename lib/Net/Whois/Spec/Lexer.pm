package Net::Whois::Spec::Lexer;

use 5.014;
use strict;
use warnings;

use Carp;

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

=head2 new($text)

    my $lexer = Net::Whois::Spec::Lexer->new("    line 1\r\n    line 2\r\n");

=cut

sub new {
    my $class = shift;
    my $text  = shift;

    croak "text: missing argument" unless defined $text;

    my $self = bless {
        _line_no   => undef,
        _lookahead => undef,
        _text      => $text,
    }, $class;

    return $self;
}

sub line_no {
    my $self = shift;
    if ( !defined $self->{_lookahead} ) {
        $self->next_line();
    }
    return $self->{_line_no};
}

sub peek_line {
    my $self = shift;

    if ( !defined $self->{_lookahead} ) {
        $self->next_line();
    }
    return @{ $self->{_lookahead} };
}

sub next_line {
    my $self = shift;

    my $text = $self->{_text};
    my @errors;
    if ( !defined $self->{_line_no} && $text =~ /^\N{U+FEFF}/ ) {
        $text =~ s/^\N{U+FEFF}//;
        push @errors, "line 1: found BOM";
    }

    if ( $self->{_text} eq '' ) {
        if ( !defined $self->{_line_no} ) {
            $self->{_line_no} = 1;
        }
        $self->{_lookahead} = [ 'EOF', undef, \@errors ];
        return;
    }
    $self->{_line_no} ||= 0;
    $self->{_line_no}++;
    $text =~ s/([^\r\n]*)(\r\n?|\n)//;
    my $line = $1;
    my $eol  = $2;
    if ( !defined $eol ) {
        $line = $text;
        $eol  = '';
        $text = '';
    }
    $self->{_text} = $text;

    # Strip CRLF
    if ( $eol ne "\r\n" ) {
        $eol =~ s/\r/CR/m;
        $eol =~ s/\n/LF/m;
        push @errors, sprintf( "line %d: expected CRLF, got '$eol'", $self->{_line_no} );
    }

    # Homogenize whitespace
    my $space_count = () = $line =~ / /g;
    $line =~ s/\s/ /g;
    my $whitespace_count = () = $line =~ / /g;
    if ( $whitespace_count > $space_count ) {
        push @errors, sprintf( "line %d: whitespace other than SPACE (U+0020)", $self->{_line_no} );
    }

    # Strip leading space
    $line =~ s/^( *)//;
    my $lead_space = $1;
    if ( length $lead_space > 9 ) {
        push @errors, sprintf( "line %d: too much leading space", $self->{_line_no} );
    }

    # Strip trailing space
    $line =~ s/( *)$//;
    my $trail_space = $1;
    if ( length $trail_space > 0 ) {
        push @errors, sprintf( "line %d: trailing space", $self->{_line_no} );
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

    $self->{_lookahead} = [ $token, $token_value, \@errors ];
    return;
}

1;
