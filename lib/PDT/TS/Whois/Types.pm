package PDT::TS::Whois::Types;

use strict;
use warnings;
use 5.014;

use Carp;

=head1 NAME

PDT::TS::Whois::Types - Simple type checker class

=head1 DESCRIPTION

This class provides a number of types out of the box and a mechanism for
extending the default set with specialized types.

A type consists of a name and a sub. The sub takes a string value and returns a
list of validation error strings.

The default types are:
 * country code
 * dnssec
 * domain status
 * domain status code
 * email address
 * hostname
 * http url
 * ip address
 * key translation
 * phone number
 * positive integer
 * postal code
 * postal line
 * roid
 * time stamp
 * token
 * translation clause
 * u-label

=cut

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

my %default_types;

%default_types = (
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
        if ( $value !~ /^[a-zA-Z]{2}$/ ) {
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
    'translation clause' => sub {
        my $value = shift;
        if ( $value =~ /^ \((.*)\)$/ ) {
            my @errors;
            for my $key_translation ( split qr{/}, $1 ) {
                push @errors, $default_types{'key translation'}->( $key_translation );
            }
            return @errors;
        }
        else {
            return ( 'expected translation clause' );
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

=head1 CONSTRUCTORS

=head2 new

Creates a new type checker object with the default set of types.

    my $types = PDT::TS::Whois::Types->new();

=cut

sub new {
    my $class = shift;
    my $self = bless { _types => { %default_types, }, }, $class;
    return $self;
}

=head2 add_type

Adds (or updates) a type to the set recognized by this type checker.

    $types->add_type('my-type', sub {
        my $value = shift;
        if ( $value =~ /^my-[a-z-]+/ ) {
            return ( 'expected my-type' );
        }
        else {
            return ();
        }
    });

=cut

sub add_type {
    my $self      = shift;
    my $type_name = shift;
    my $sub       = shift;
    $self->{_types}{$type_name} = $sub;
}

=head2 has_type

Test if a type is recognized by this type checker.

    if ($types->has_type('my-type')) {
        say "Type my-type recognized!";
    }
    else {
        say "Unknown type my-type!";
    }

=cut

sub has_type {
    my $self      = shift;
    my $type_name = shift;
    return exists $self->{_types}{$type_name};
}

=head2 validate_type

Validate a value against a type.

    my @errors = $types->validate_type('my-type', 'my-value')
    if (@errors) {
        for my $error (@errors) {
            say "type error: $error";
        }
    }
    else {
        say "ok";
    }

=cut

sub validate_type {
    my $self      = shift;
    my $type_name = shift;
    my $value     = shift;
    croak "$type_name: unknown type" unless exists $self->{_types}{$type_name};
    return $self->{_types}{$type_name}->( $value );
}

1;
