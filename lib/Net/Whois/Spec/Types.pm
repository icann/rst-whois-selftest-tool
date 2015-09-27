package Net::Whois::Spec::Types;

use strict;
use warnings;
use 5.014;

require Exporter;

our @ISA       = 'Exporter';
our @EXPORT_OK = qw( $types );

our $types = {
    'positive integer' => sub {
        my $value = shift;
        if ($value !~ /^[1-9][0-9]*$/) {
            return ('expected positive integer');
        }
        else {
            return ();
        }
    },
    'country code' => sub {
        my $value = shift;
        if ($value !~ /^[a-z]{2}$/) {
            return ('expected country code');
        }
        else {
            return ();
        }
    },
};

1;
