package PDT::TS::Whois::Validator;

use strict;
use warnings;
use 5.014;

use Carp;

require Exporter;

our @ISA       = 'Exporter';
our @EXPORT_OK = qw( validate );

=head1 NAME

PDT::TS::Whois::Validator - Consumes and validates Whois output, and produces
validation errors;

=cut

=head1 SYNOPSIS

This module exports a single function called L<validate>.

=head1 SUBROUTINES

=head2 validate

Reads line tokens from a lexer, matching them against grammar rules.  When a
line token is matched with a grammar rule, its token value is matched against a
type derived from the matched grammar rule.  The result of a validation is the
combined grammar and type mismatches and validation errors reported by the
lexer.

    use PDT::TS::Whois::Validator qw( validate );

    my @errors = validate(
        rule    => 'rule name',
        lexer   => $lexer,
        grammar => $grammar,
        types   => $types,
    );
    if (@errors) {
        for my $message (@errors) {
            say "error: $message";
        }
    }
    else {
        say "ok";
    }

=head3 Arguments

=head4 B<rule>

A string.  The grammar rule name to be used as starting point for validation.
The grammar argument must have a key with this name.

=head4 B<lexer>

A lexer.  The lexer producing input for the validation.  This is expected to be
an object with the interface of PDT::TS::Whois::Lexer;

=head4 B<grammar>

A HASHREF.  The grammar to be used for parsing.  The HASHREF is expected to
match the data structure described in PDT::TS::Whois::Grammar;

=head4 B<types>

A Types.  The types object to be used for type checking.  This is expected to
be an object with the interface of PDT::TS::Whois::Types.

=cut

sub validate {
    my %args = @_;

    croak "lexer: missing argument"       unless defined $args{lexer};
    croak "grammar: missing argument"     unless defined $args{grammar};
    croak "types: missing argument"       unless defined $args{types};
    croak "rule: missing argument"        unless defined $args{rule};
    croak "key translation: missing type" unless $args{types}->has_type( 'key translation' );
    croak "time stamp: missing type"      unless $args{types}->has_type( 'time stamp' );
    croak "roid: missing type"            unless $args{types}->has_type( 'roid' );
    croak "hostname: missing type"        unless $args{types}->has_type( 'hostname' );

    my $rule  = $args{rule};

    my $state = {
        lexer      => $args{lexer},
        grammar    => $args{grammar},
        types      => $args{types},
        empty_kind => undef,
    };

    my $result = _rule( $state, $rule );
    if ( defined $result ) {
        return @$result;
    }
    else {
        return ( sprintf( "line %d: unrecognized input", $state->{lexer}->line_no ) );
    }
}

sub _rule {
    my $state = shift or croak 'Missing argument: $state';
    my $rule  = shift or croak 'Missing argument: $rule';

    if ( my $section_rule = $state->{grammar}->{$rule} ) {
        if ( ref $section_rule eq 'ARRAY' ) {
            my $result = _sequence_section( $state, $section_rule );
            return $result;
        }
        elsif ( ref $section_rule eq 'HASH' ) {
            my $result = _choice_section( $state, $section_rule );
            return $result;
        }
        else {
            croak "invalid grammar rule: $rule";
        }
    }
    else {
        croak "unknown grammar rule: $rule";
    }
}

sub _sequence_section {
    my $state        = shift or croak 'Missing argument: $state';
    my $section_rule = shift or croak 'Missing argument: $section_rule';

    my @errors;
    my $total = 0;

    for my $elem ( @$section_rule ) {

        ref $elem eq 'HASH' or confess;

        my ( $key, $params ) = %$elem;

        ref $params eq 'HASH' or confess;

        my ( $count, $result ) = _occurances( $state, %$params, key => $key );
        if ( !defined $count ) {
            if ( $total == 0 ) {
                return;
            }
            else {
                push @errors, sprintf( "line %d: expected %s", $state->{lexer}->line_no, $key );
                last;
            }
        }
        ref $result eq 'ARRAY' or confess;
        push @errors, @$result;
        $total += $count;
    }

    return \@errors;
}

sub _choice_section {
    my $state        = shift or croak 'Missing argument: $state';
    my $section_rule = shift or croak 'Missing argument: $section_rule';
    ref $section_rule eq 'HASH' or croak 'Argument $section_rule must be hashref';

    for my $key ( keys $section_rule ) {
        my $params = $section_rule->{$key};

        ref $params eq 'HASH' or confess;
        my ( $count, $result ) = _occurances( $state, %$params, key => $key );
        if ( defined $count ) {
            return $result;
        }
    }

    return;
}

sub _occurances {
    my $state = shift;
    my %args  = @_;
    my $key   = $args{'key'} or croak 'Missing argument: key';
    my $line  = $args{'line'};
    my $type  = $args{'type'};

    my $min_occurs;
    if ( ( $args{'optional'} || 'n' ) eq 'y' ) {
        $min_occurs = 0;
    }
    else {
        $min_occurs = 1;
    }

    my $max_occurs;
    if ( !exists $args{'repeatable'} ) {
        $max_occurs = 1;
    }
    elsif ( $args{'repeatable'} ne 'unbounded' ) {
        $max_occurs = int $args{'repeatable'};
        $max_occurs >= 1 or croak 'Argument must not be zero or negative: repeatable';
    }

    my $count = 0;
    my @errors;
    while ( !defined $max_occurs || $count < $max_occurs ) {
        my ( $parsed, $parsed_errors ) = _subrule( $state, line => $line, key => $key, type => $type );
        if ( defined $parsed ) {
            ref $parsed_errors eq 'ARRAY' or confess;
            push @errors, @$parsed_errors;
            $count++;
            if ( $count == 1 && $parsed eq 'empty field' ) {
                last;
            }
        }
        else {
            if ( $count == 0 && defined $line && $line eq 'field' ) {
                push @errors, _set_empty_kind( $state, 'omitted field' );
            }
            last;
        }
    }

    if ( $count >= $min_occurs ) {
        return ( $count, \@errors );
    }
    else {
        return;
    }
}

sub _subrule {
    my $state = shift;
    my %args  = @_;
    my $line  = $args{'line'};
    my $key   = $args{'key'} or croak 'Missing argument: key';
    my $type  = $args{'type'};

    if ( defined $line || defined $type ) {
        my ( $subtype, $result ) = _line( $state, line => $line, key => $key, type => $type );
        return ( $subtype, $result );
    }
    else {
        my $result = _rule( $state, $key );
        my $subtype = ( defined $result ) && 'section' || undef;
        return ( $subtype, $result );
    }
}

sub _line {
    my $state = shift;
    my %args  = @_;
    my $key   = $args{'key'} or croak 'Missing argument: key';
    my $line  = $args{'line'};
    my $type  = $args{'type'};

    my $token;
    my $token_value;
    my $errors;
    my $subtype;

    if ( defined $type ) {
        if ( !$state->{types}->has_type( $type ) ) {
            croak "unknown type $type";
        }
        ( $token, $token_value, $errors ) = $state->{lexer}->peek_line();

        if ( !defined $token || $token ne 'field' ) {
            return;
        }

        ref $errors eq 'ARRAY' or confess;
        ref $token_value eq 'ARRAY' or confess;

        my ( $field_key, $field_translations, $field_value ) = @$token_value;
        if ( $field_key ne $key ) {
            return;
        }
        $subtype = ( defined $field_value ) && 'field' || 'empty field';
        if ($subtype eq 'empty field') {
            push @$errors, _set_empty_kind( $state, 'empty field' );
        }
    }
    else {
        ( $token, $token_value, $errors ) = $state->{lexer}->peek_line();

        if ( !defined $token ) {
            return;
        }
        elsif ( $line eq 'any line' && $token ne 'EOF' ) {
            $subtype = $line;
        }
        elsif ( $line eq 'non-empty line' && $token ne 'empty line' && $token ne 'EOF' ) {
            $subtype = $line;
        }
        elsif ( $token eq $line ) {
            $subtype = $token;
        }
        else {
            return;
        }

        ref $errors eq 'ARRAY' or confess;
    }

    if ( $token eq 'field' ) {

        ref $token_value eq 'ARRAY' or confess;

        my ( $key, $translations, $value ) = @$token_value;

        ref $translations eq 'ARRAY' or confess;

        for my $translation ( @$translations ) {
            push @$errors, _validate_type( $state, 'key translation', $translation );
        }

        if ( $type && $subtype eq 'field' ) {
            push @$errors, _validate_type( $state, $type, $value );
        }
    }
    elsif ( $token eq 'roid line' ) {

        ref $token_value eq 'ARRAY' or confess;

        my ( $roid, $hostname ) = @$token_value;

        push @$errors, _validate_type( $state, 'roid', $roid );

        push @$errors, _validate_type( $state, 'hostname', $hostname );
    }
    elsif ( $token eq 'last update line' ) {
        $token_value && ref $token_value eq '' or confess;
        my $timestamp = $token_value;

        push @$errors, _validate_type( $state, 'time stamp', $timestamp );
    }
    elsif ( $token ne 'any line' && $token ne 'empty line' && $token ne 'non-empty line' && $token ne 'multiple name servers line' && $token ne 'awip line' && $token ne 'EOF' ) {
        croak "unhandled line type: $token";
    }

    $state->{lexer}->next_line();

    return $subtype, $errors;
}

sub _set_empty_kind {
    my $state = shift or croak 'Missing argument: $state';
    my $kind  = shift or croak 'Missing argument: $kind';

    $state->{empty_kind} ||= $kind;
    if ( $state->{empty_kind} eq $kind ) {
        return ();
    }
    else {
        return ( sprintf( "line %d: mixed empty field markups", $state->{lexer}->line_no ) );
    }
}

sub _validate_type {
    my $state     = shift or croak 'Missing argument: $state';
    my $type_name = shift or croak 'Missing argument: $type_name';
    my $value     = shift or croak 'Missing argument: $value';

    my @errors;
    for my $error ( $state->{types}->validate_type( $type_name, $value ) ) {
        push @errors, sprintf("line %s: %s", $state->{lexer}->line_no, $error);
    }
    return @errors;
}

1;
