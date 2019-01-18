package PDT::TS::Whois::Remark;
use utf8;
use strict;
use warnings;
use 5.014;

use Carp;
use Exporter 'import';
use Readonly;

our @EXPORT_OK = qw(
  $ERROR_SEVERITY
  $INFO_SEVERITY
  is_remark
  is_severity
  new_remark
  remark_string
);

Readonly our $ERROR_SEVERITY => 'error';
Readonly our $INFO_SEVERITY  => 'info';

=head2 new_remark

Construct a remark hashref with error severity.

    use PDT::TS::Whois::Remark qw( new_remark $ERROR_SEVERITY );
    my $remark = new_remark( $ERROR_SEVERITY, 1, "BOOM!" );

Takes three arguments: a severity, a line number and a message.

Returns a hashref with keys C<severity>, C<lineno> and C<message>.

=cut

sub new_remark {
    my ( $severity, $lineno, $message ) = @_;

    ( is_severity( $severity ) ) or confess 'Invalid argument: $severity';
    ( defined $lineno  && ref $lineno eq '' )  or confess 'Invalid argument: $lineno';
    ( defined $message && ref $message eq '' ) or confess 'Invalid argument: $message';

    return {
        lineno   => $lineno,
        message  => $message,
        severity => $severity,
    };
}

=head2 is_severity

Test if a value is a valid severity.

    is_severity( $ERROR_SEVERITY ) or die;

=cut

sub is_severity {
    my ( $value ) = @_;

    return defined $value
      && ( $value eq $ERROR_SEVERITY
        || $value eq $INFO_SEVERITY );
}

=head2 is_remark

Test if a value is a valid remark hashref.

    my $value = new_remark( $ERROR_SEVERITY, 4, 'Boom!' );
    is_remark( $value ) or die;

=cut

sub is_remark {
    my ( $value ) = @_;

    return
         ref $value eq 'HASH'
      && is_severity( $value->{severity} )
      && defined $value->{lineno}
      && defined $value->{message};
}

=head2 remark_string

Format a remark hashref as a string.

    use PDT::TS::Whois::Remark qw( new_remark remark_string $ERROR_SEVERITY );
    my $remark = new_remark( $ERROR_SEVERITY, 1, "BOOM!" );
    my $string = remark_string( $remark );
    ( $string eq "line 1: error: BOOM!" ) or die;

=cut

sub remark_string {
    my ( $remark ) = @_;

    ( is_remark $remark ) or confess 'Invalid argument: $remark';

    return sprintf( "line %d: %s: %s", $remark->{lineno}, $remark->{severity}, $remark->{message} );
}

1;
