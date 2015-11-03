package PDT::TS::Whois::Util;

use strict;
use warnings;
use 5.014;

use Carp;
use Exporter 'import';

use Net::IDN::Encode qw( domain_to_ascii );

our @EXPORT_OK = qw( extract_roid scrub_u_label );

=head2 extract_roid( text )

Extract the ROID of the first C<roid line> in the string B<text>.

    my $roid = extract_roid( read_file( 'queryoutput.txt' ) );

Possible return values:

=over 4

=item A ROID

A C<roid line> was found, and its ROID was returned.

=item An empty list

No C<roid line> was found.

=back

=cut

sub extract_roid {
    my $text = shift or croak 'Missing argument: $text';

    my $lexer = PDT::TS::Whois::Lexer->new( $text );
    my $types = PDT::TS::Whois::Types->new();
    while ( 1 ) {
        my ( $token, $value, $errors ) = $lexer->peek_line();
        if ( $token eq 'EOF' ) {
            return ();
        }
        elsif ( $token eq 'roid line' ) {
            ref $value eq 'ARRAY' or croak "'roid line' value expected to be arrayref";
            defined $value->[0] or croak "'roid line' value expected to have roid at position 0";
            defined $value->[1] or croak "'hostname' value expected to have roid at position 1";
            my ( $roid, $hostname ) = @{$value};
            my @errors;
            push @errors, $types->validate_type( 'roid', $roid );
            push @errors, $types->validate_type( 'hostname', $hostname );
            if ( !@errors ) {
                return $roid;
            }
        }
        $lexer->next_line();
    }
}

=head2 scrub_u_label( $u_label )

Convert a valid U-label to ASCII.

    my $a_label = scrub_u_label( $u_label );

Returns B<undef> if B<$u_label> is invalid or B<undef>.  The only allowed
label-separator is U+002E (FULL STOP).

When an A-label is returned, it is in lower case and without trailing dot.

=cut

sub scrub_u_label {
    my $value = shift;
    ref $value eq '' or croak 'Argument must be scalar: $value';

    if ( !defined $value || $value =~ /[\x{3002}\x{FF0E}\x{FF61}]/u ) {
        return ();
    }

    my $ascii = eval {
        domain_to_ascii(
            $value,
            AllowUnassigned        => 0,    # false
            TransitionalProcessing => 0,    # false
            UseSTD3ASCIIRules      => 0,    # false
        );
    };
    if ( my $error = $@ ) {
        # Whitelist of known exceptions resulting from invalid input
        return () if ref $error eq '' && $error =~ /^disallowed character /;

        # Rethrow with stack trace
        croak $error;
    }
    else {
        defined $ascii or croak 'unexpected return value';

        return lc( $ascii =~ s/\.?$//r );
    }
}

1;
