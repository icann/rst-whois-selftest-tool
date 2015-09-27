package Net::Whois::Spec::Types;

use strict;
use warnings;
use 5.014;

use Carp;

my %domain_status_codes = (
    addPeriod                => 1,
    autoRenewPeriod          => 1,
    clientDeleteProhibited   => 1,
    clientHold               => 1,
    clientRenewProhibited    => 1,
    clientTransferProhibited => 1,
    clientUpdateProhibited   => 1,
    inactive                 => 1,
    ok                       => 1,
    pendingCreate            => 1,
    pendingDelete            => 1,
    pendingRenew             => 1,
    pendingRestore           => 1,
    pendingTransfer          => 1,
    pendingUpdate            => 1,
    redemptionPeriod         => 1,
    renewPeriod              => 1,
    serverDeleteProhibited   => 1,
    serverHold               => 1,
    serverRenewProhibited    => 1,
    serverTransferProhibited => 1,
    serverUpdateProhibited   => 1,
    transferPeriod           => 1,
);

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
    'dnssec' => sub {
        my $value = shift;
        if ( $value !~ /^(?:signedDelegation|unsigned)$/ ) {
            return ( 'expected dnssec' );
        }
        else {
            return ();
        }
    },
    'domain status code' => sub {
        my $value = shift;
        if ( !exists $domain_status_codes{$value} ) {
            return ( 'expected domain status code' );
        }
        else {
            return ();
        }
    },
    'key translation' => sub {
        my $value = shift;
        if ( $value =~ /^ |[()]| $/ ) {
            return ( 'expected key translation' );
        }
        else {
            return ();
        }
    },
    'hostname'      => sub { },
    'u-label'       => sub { },
    'roid'          => sub { },
    'http url'      => sub { },
    'time stamp'    => sub { },
    'token'         => sub { },
    'domain status' => sub { },
    'postal line'   => sub { },
    'postal code'   => sub { },
    'phone number'  => sub { },
    'email address' => sub { },
    'ip address'    => sub { },
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
    croak "$type_name: unknown type" unless exists $self->{_types}{$type_name};
    return $self->{_types}{$type_name}->( $value );
}

sub has_type {
    my $self      = shift;
    my $type_name = shift;
    return exists $self->{_types}{$type_name};
}

1;
