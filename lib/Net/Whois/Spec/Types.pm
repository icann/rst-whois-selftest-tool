package Net::Whois::Spec::Types;

use strict;
use warnings;
use 5.014;

my %default_types = (
    'positive integer' => sub {
        my $value = shift;
        if ( $value !~ /^[1-9][0-9]*$/ ) {
            return ( 'expected positive integer' );
        }
        else {
            return ();
        }
    },
    'country code' => sub {
        my $value = shift;
        if ( $value !~ /^[A-Z]{2}$/ ) {
            return ( 'expected country code' );
        }
        else {
            return ();
        }
    },
    'hostname'        => sub { },
    'u-label'         => sub { },
    'roid'            => sub { },
    'http url'        => sub { },
    'time stamp'      => sub { },
    'token'           => sub { },
    'domain status'   => sub { },
    'postal line'     => sub { },
    'postal code'     => sub { },
    'phone number'    => sub { },
    'email address'   => sub { },
    'dnssec'          => sub { },
    'ip address'      => sub { },
    'key translation' => sub { },
);

sub new {
    my $class = shift;
    my $self = bless { _types => { %default_types, }, }, $class;
    return $self;
}

sub add_type {
    my $self      = shift;
    my $type_name = shift;
    my $sub       = shift;
    $self->{_types}{$type_name} = $sub;
}

sub validate_type {
    my $self      = shift;
    my $type_name = shift;
    my $value     = shift;
    return $self->{_types}{$type_name}->( $value );
}

sub has_type {
    my $self      = shift;
    my $type_name = shift;
    return exists $self->{_types}{$type_name};
}

1;
