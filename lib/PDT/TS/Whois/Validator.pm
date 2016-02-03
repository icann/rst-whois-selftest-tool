package PDT::TS::Whois::Validator;
use utf8;
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

    my $rule = $args{rule};

    my $state = {
        lexer      => $args{lexer},
        grammar    => $args{grammar},
        types      => $args{types},
        empty_kind => undef,
    };

    # Validate rule
    my $result = _rule( $state, key => $rule, quantifier => 'required' );

    # Pick up validation warnings
    my @errors;
    if ( defined $result ) {
        ref $result eq 'ARRAY' or croak 'unexpected return value from _rule()';
        @errors = @{$result};
    }

    # Check status of parsed input
    my ( $token, $token_value ) = $state->{lexer}->peek_line();
    defined $token or confess 'unexpected return value from peek_line()';

    # Pick up fatal validation errors
    unless ( defined $result && $token eq 'EOF' ) {
        if ( !@errors ) {
            my $description = _describe_line( $token, $token_value );
            push @errors, sprintf( "line %d: %s not allowed here", $state->{lexer}->line_no, $description );
        }
        push @errors, sprintf 'line %d: validation aborted, no validation was perfomed beyond this line', $state->{lexer}->line_no();
    }

    return @errors;
}

sub _describe_line {
    my $token       = shift;
    my $token_value = shift;

    my $description;
    if ( $token eq 'field' ) {
        ref $token_value eq 'ARRAY' or croak 'unexpected token_value for field token';
        my ( $field_key, undef, undef ) = @{$token_value};
        defined $field_key or croak 'unexpected token_value for field token';

        return "field '" . $field_key . "'";
    }
    elsif ( $token eq 'non-empty line' ) {
        ( defined $token_value && ref $token_value eq '' ) or croak 'unexpected token_value for non-empty line token';
        my $contents = ( $token_value =~ s/\W+/ /gru );

        $contents = ( length $contents > 15 ) ? "'" . substr( $contents, 0, 15 ) . "'..." : "'" . $contents . "'";
        return "non-empty line " . $contents;
    }
    else {
        return $token;
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

        ref $params eq 'HASH' or confess "value of key '$key' must be a hashref";

        ## no critic (TestingAndDebugging::ProhibitNoWarnings)
        no warnings 'recursion';
        ## use critic
        my ( $count, $result ) = _occurances( $state, %$params, key => $key );

        if ( !defined $count ) {
            if ( $total == 0 ) {
                return;
            }
            else {
                my ( $token, $token_value, $token_errors ) = $state->{lexer}->peek_line();
                defined $token or croak 'unexpected return value';
                ref $token_errors eq 'ARRAY' or croak 'unexpected return value';

                push @errors, @{$token_errors};

                my $description = _describe_line( $token, $token_value );
                push @errors, sprintf( "line %d: %s not allowed here", $state->{lexer}->line_no, $description );
                last;
            }
        }
        ref $result eq 'ARRAY' or confess;
        push @errors, @$result;
        $total += $count;
    }

    return ( 'section', \@errors );
}

sub _choice_section {
    my $state        = shift or croak 'Missing argument: $state';
    my $section_rule = shift or croak 'Missing argument: $section_rule';
    ref $section_rule eq 'HASH' or croak 'Argument $section_rule must be hashref';

    for my $key ( sort keys %{$section_rule} ) {
        my $params = $section_rule->{$key};

        ref $params eq 'HASH' or confess "value of key '$key' must be a hashref";
        my ( $count, $result ) = _occurances( $state, %$params, key => $key );
        if ( defined $count ) {
            return ( 'section', $result );
        }
    }

    return;
}

sub _occurances {
    my ( $state, %args ) = @_;
    my $key        = $args{'key'} or croak 'Missing argument: key';
    my $line       = $args{'line'};
    my $type       = $args{'type'};
    my $quantifier = $args{'quantifier'} || 'required';
    my $keytype    = $args{'keytype'};

    my $min_occurs;
    my $max_occurs;
    for ( $quantifier ) {
        when ( 'required' ) {
            $min_occurs = 1;
            $max_occurs = 1;
        }
        when ( /^optional-free$|^optional-not-empty$|^optional-constrained$|^empty-constrained$|^omitted-constrained$/ ) {
            $min_occurs = 0;
            $max_occurs = 1;
        }
        when ( /^optional-repeatable(?: max ([1-9][0-9]*))?$/ ) {
            $min_occurs = 0;
            $max_occurs = $1;
        }
        when ( /^repeatable(?: max ([1-9][0-9]*))?$/ ) {
            $min_occurs = 1;
            $max_occurs = $1;
        }
        default {
            croak "internal error: unhandled quantifier '$_'";
        }
    }

    my $count               = 0;
    my @pending_empty_error = ();
    my @errors;
    while ( !defined $max_occurs || $count < $max_occurs ) {
        my $line_before = $state->{lexer}->line_no;
        my ( $parsed, $parsed_errors ) = _rule( $state, line => $line, key => $key, type => $type, quantifier => $quantifier, keytype => $keytype );
        if ( defined $parsed ) {
            ref $parsed_errors eq 'ARRAY' or confess;
            $count++;
            my $line_after = $state->{lexer}->line_no;
            if ( $line_before == $line_after ) {
                last;
            }
            push @errors, @$parsed_errors;
            if ( $parsed eq 'empty field' ) {
                push @pending_empty_error, sprintf( "line %d: empty field in repetition '%s'", $line_after - 1, $key );
                if ( $count != 1 ) {
                    push @errors, @pending_empty_error;
                    @pending_empty_error = ();
                }
                elsif ( $quantifier =~ /^required$|^repeatable|^omitted-constrained$|^optional-not-empty$/ ) {
                    push @errors, sprintf( "line %d: field '%s' is %s and must not be present as an empty field", $line_after - 1, $key, $quantifier );
                }
                elsif ( $quantifier =~ /^optional-constrained$|^empty-constrained$/ ) {
                    push @errors, _set_empty_kind( $state, kind => 'empty field', line_no => $line_after - 1, key => $key );
                }
            }
            else {
                push @errors, @pending_empty_error;
                @pending_empty_error = ();

                if ( $parsed eq 'field' && $quantifier =~ /^empty-constrained$|^omitted-constrained$/ ) {
                    push @errors, sprintf( "line %d: field '%s' is %s and must not be present as a non-empty field", $line_after - 1, $key, $quantifier );
                }
            }
        }
        else {
            if ( $count == 0 && defined $line && $line eq 'field' ) {
                if ( $quantifier eq 'empty-constrained' ) {
                    push @errors, sprintf( "line %d: field '%s' is empty-constrained and must not be omitted", $state->{lexer}->line_no, $key );
                }
                elsif ( $quantifier =~ /^optional-constrained$|^omitted-constrained$/ ) {
                    push @errors, _set_empty_kind( $state, kind => 'omitted field', line_no => $state->{lexer}->line_no, key => $key );
                }
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

## no critic (Subroutines::RequireArgUnpacking)
sub _rule {
    my ( $state, %args ) = @_;
    my $line       = $args{'line'};
    my $key        = $args{'key'} or croak 'Missing argument: key';
    my $type       = $args{'type'};
    my $quantifier = $args{'quantifier'} or croak 'Missing argument: quantifier';
    my $keytype    = $args{'keytype'};

    if ( defined $line || defined $type ) {
        my ( $subtype, $result ) = _line( $state, line => $line, key => $key, type => $type, quantifier => $quantifier, keytype => $keytype );
        return ( $subtype, $result );
    }
    else {
        if ( my $section_rule = $state->{grammar}->{$key} ) {
            if ( ref $section_rule eq 'ARRAY' ) {
                ## no critic (TestingAndDebugging::ProhibitNoWarnings)
                no warnings 'recursion';
                ## use critic
                @_ = ( $state, $section_rule );
                goto &_sequence_section;
            }
            elsif ( ref $section_rule eq 'HASH' ) {
                ## no critic (TestingAndDebugging::ProhibitNoWarnings)
                no warnings 'recursion';
                ## use critic
                @_ = ( $state, $section_rule );
                goto &_choice_section;
            }
            else {
                croak "invalid grammar rule: $key";
            }
        }
        else {
            croak "unknown grammar rule: $key";
        }
    }
}
## use critic

sub _line {
    my ( $state, %args ) = @_;
    my $key        = $args{'key'} or croak 'Missing argument: key';
    my $line       = $args{'line'};
    my $type       = $args{'type'};
    my $quantifier = $args{'quantifier'} or croak 'Missing argument: quantifier';
    my $keytype    = $args{'keytype'};
    ( $line || $type ) or croak 'Must give at least one of arguments: line, type';

    if ( defined $type ) {
        $state->{types}->has_type( $type ) or croak "unknown type '$type'";
        $line ||= 'field';
        $line eq 'field' or confess;
    }
    if ( defined $keytype ) {
        $state->{types}->has_type( $keytype ) or croak "unknown type '$keytype'";
    }

    my $token;
    my $token_value;
    my $errors;
    my $subtype;

    if ( defined $type ) {
        ( $token, $token_value, $errors ) = $state->{lexer}->peek_line();

        if ( !defined $token || $token ne 'field' ) {
            return;
        }

        ref $errors eq 'ARRAY'      or confess;
        ref $token_value eq 'ARRAY' or confess;

        my ( $field_key, $field_translations, $field_value ) = @$token_value;
        if ( $field_key ne $key ) {
            return;
        }

        if ( defined $field_value ) {
            if ( $quantifier =~ /^(?:omitted-constrained|empty-constrained)$/ ) {
                return;
            }
            $subtype = 'field';
        }
        else {
            if ( $quantifier =~ /^(?:omitted-constrained|required)$/ ) {
                return;
            }
            $subtype = 'empty field';
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

    if ( $line eq 'any line' || $line eq 'non-empty line' ) {

        # skip validations
    }
    elsif ( $token eq 'field' ) {

        ref $token_value eq 'ARRAY' or confess;

        my ( $key, $translations, $value ) = @$token_value;

        ref $translations eq 'ARRAY' or confess;

        if ( $keytype ) {
            push @$errors, _validate_type( $state, type_name => $keytype, value => $key, prefix => "invalid field key '$key', " );
        }

        for my $translation ( @$translations ) {
            push @$errors, _validate_type( $state, type_name => 'key translation', value => $translation, prefix => "invalid key translation for field '$key', " );
        }

        if ( $type && $subtype eq 'field' ) {
            push @$errors, _validate_type( $state, type_name => $type, value => $value, prefix => "invalid value for field '$key', " );
        }
    }
    elsif ( $token eq 'roid line' ) {

        ref $token_value eq 'ARRAY' or confess;

        my ( $roid, $hostname ) = @$token_value;

        push @$errors, _validate_type( $state, type_name => 'roid', value => $roid );

        push @$errors, _validate_type( $state, type_name => 'hostname', value => $hostname );
    }
    elsif ( $token eq 'last update line' ) {
        ( $token_value && ref $token_value eq '' ) or croak "assertion error";
        my $timestamp = $token_value;

        push @$errors, _validate_type( $state, type_name => 'time stamp', value => $timestamp );
    }
    elsif ( $token ne 'any line' && $token ne 'empty line' && $token ne 'non-empty line' && $token ne 'multiple name servers line' && $token ne 'awip line' && $token ne 'EOF' ) {
        croak "unhandled line type: $token";
    }

    $state->{lexer}->next_line();

    return $subtype, $errors;
}

sub _set_empty_kind {
    my ( $state, %args ) = @_;
    $state or croak 'Missing argument: $state';
    my $kind    = $args{kind}    or croak 'Missing argument: kind';
    my $key     = $args{key}     or croak 'Missing argument: key';
    my $line_no = $args{line_no} or croak 'Missing argument: line_no';

    $state->{empty_kind} ||= $kind;
    if ( $state->{empty_kind} eq $kind ) {
        return ();
    }
    else {
        return ( sprintf( "line %d: optional field '%s' (%s): either all empty optional fields must be present or no empty optional field may be present", $line_no, $key, $kind ) );
    }
}

sub _validate_type {
    my ( $state, %args ) = @_;
    $state or croak 'Missing argument: $state';
    my $type_name = $args{type_name} or croak 'Missing argument: type_name';
    my $value     = $args{value}     or croak 'Missing argument: value';
    my $prefix = $args{prefix} || '';

    my @errors;
    for my $error ( $state->{types}->validate_type( $type_name, $value ) ) {
        push @errors, sprintf( "line %s: %s%s", $state->{lexer}->line_no, $prefix, $error );
    }
    return @errors;
}

1;
