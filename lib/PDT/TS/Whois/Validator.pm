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
        lexer        => $args{lexer},
        grammar      => $args{grammar},
        types        => $args{types},
        empty_kind   => undef,
        empty_fields => [],
    };

    # Validate rule
    my ( $result, $rule_errors ) = _rule( $state, key => $rule, quantifier => 'required' );

    # Pick up validation warnings
    my @errors;
    if ( defined $result ) {
        ref $rule_errors eq 'ARRAY' or croak 'unexpected return value from _rule()';
        @errors = @{$rule_errors};
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

=head2 B<_occurances( $state, key, line, type, quantifier, keytype )>

Parse a quantified grammar rule or a line type with the given $key.

    my $result = _occurances( $state, key => 'field', type => 'hostname', quantifier => 'required' );

Returns:

=over 4

=item B<()>

No match. Input may have been consumed.

=item B<$result>

Match. Input may have been consumed.

B<$result> is an arrayref containing validation error strings.

=back

=cut

sub _occurances {
    my ( $state, %args ) = @_;
    my $key        = $args{'key'} or croak 'Missing argument: key';
    my $line       = $args{'line'};
    my $type       = $args{'type'};
    my $quantifier = $args{'quantifier'} || 'required';
    my $keytype    = $args{'keytype'};
    if ( $type ) {
        $line ||= 'field';
    }

    my $is_optional;
    my $max_occurs;
    for ( $quantifier ) {
        when ( /^required$|^required-strict$/ ) {
            $is_optional = '';
            $max_occurs  = 1;
        }
        when ( /^optional-free$|^optional-not-empty$|^optional-constrained$|^empty-constrained$|^omitted-constrained$/ ) {
            $is_optional = 1;
            $max_occurs  = 1;
        }
        when ( /^optional-repeatable(?: max ([1-9][0-9]*))?$/ ) {
            $is_optional = 1;
            $max_occurs  = $1;
        }
        when ( /^repeatable(?: max ([1-9][0-9]*))?$/ ) {
            $is_optional = '';
            $max_occurs  = $1;
        }
        default {
            croak "internal error: unhandled quantifier '$_'";
        }
    }

    my $first               = 1;
    my $element_count       = 0;
    my $found_empty_fields  = '';
    my @pending_empty_error = ();
    my @errors;
    while ( !defined $max_occurs || $element_count < $max_occurs ) {
        my $line_before = $state->{lexer}->line_no;
        my ( $parsed, $parsed_errors );
        {
            ## no critic (TestingAndDebugging::ProhibitNoWarnings)
            no warnings 'recursion';
            ## use critic
            ( $parsed, $parsed_errors ) = _rule( $state, line => $line, key => $key, type => $type, quantifier => $quantifier, keytype => $keytype );
        }

        if ( defined $parsed ) {
            ref $parsed_errors eq 'ARRAY' or croak 'unexpected return value from _rule()';
            my $line_after = $state->{lexer}->line_no;
            push @errors, @$parsed_errors;
            if ( $parsed eq 'empty field' ) {
                push @pending_empty_error, sprintf( "line %d: empty field in repetition '%s'", $line_after - 1, $key );
                if ( !$first ) {
                    push @errors, @pending_empty_error;
                    @pending_empty_error = ();
                }
                elsif ( $quantifier =~ /^required$|^repeatable|^optional-repeatable|^omitted-constrained$|^optional-not-empty$/ ) {
                    push @errors, sprintf( "line %d: field '%s' is %s and must not be present as an empty field", $line_after - 1, $key, $quantifier );
                }
                elsif ( $quantifier =~ /^optional-constrained$|^empty-constrained$/ ) {
                    push @errors,
                      _set_empty_kind(
                        $state,
                        kind       => 'empty field',
                        quantifier => $quantifier,
                        line_no    => $line_after - 1,
                        key        => $key
                      );
                }
                $found_empty_fields = 1;
            }
            else {
                push @errors, @pending_empty_error;
                @pending_empty_error = ();
                $element_count++;
                if ( $parsed eq 'field' && $quantifier =~ /^empty-constrained$|^omitted-constrained$/ ) {
                    return;    # mismatch: field must not be present as a non-empty field
                }
                elsif ( $line_before == $line_after ) {
                    last;      # successfully parsed zero lines - once is enough
                }
            }
        }
        else {
            if ( $first && defined $line && $line eq 'field' ) {
                if ( $quantifier eq 'empty-constrained' ) {
                    return;    # mismatch: field must not be omitted
                }
                elsif ( $quantifier =~ /^optional-constrained$|^omitted-constrained$/ ) {
                    push @errors,
                      _set_empty_kind(
                        $state,
                        kind       => 'omitted field',
                        quantifier => $quantifier,
                        line_no    => $state->{lexer}->line_no,
                        key        => $key
                      );
                }
            }
            last;
        }

        $first = '';
    }

    if ( $element_count > 0 || $is_optional || $found_empty_fields ) {
        return \@errors;
    }
    else {
        return;
    }
}

=head2 B<_rule( $state, key, line, type, quantifier, keytype )>

Parse a single occurance of a grammar rule or a line type with the given $key.

    my ( $token, $errors ) = _rule( $state, key => 'field', type => 'hostname', quantifier => 'required' );

Returns:

=over 4

=item B<( undef, [] )>

No match. Input may have been consumed.

=item B<( $token, $errors )>

Match. Input may have been consumed.

If a grammar rule was parsed, B<$token> is 'section'. If a line was parsed,
B<$token> is the one B<_line()> returned.

=back

=cut

sub _rule {
    my ( $state, %args ) = @_;
    my $line       = $args{'line'};
    my $key        = $args{'key'} or croak 'Missing argument: key';
    my $type       = $args{'type'};
    my $quantifier = $args{'quantifier'} or croak 'Missing argument: quantifier';
    my $keytype    = $args{'keytype'};

    if ( defined $line || defined $type ) {
        my ( $rule_token, $rule_errors ) = _line( $state, line => $line, key => $key, type => $type, quantifier => $quantifier, keytype => $keytype );
        ref $rule_token eq '' or croak 'unexpected return value from _line()';
        ( !defined $rule_errors || ref $rule_errors eq 'ARRAY' ) or croak 'unexpected return value from _line()';

        return ( $rule_token, $rule_errors || [] );
    }
    elsif ( my $section_rule = $state->{grammar}->{$key} ) {
        if ( ref $section_rule eq 'ARRAY' ) {
            my @errors;

            for my $elem ( @$section_rule ) {

                ref $elem eq 'HASH' or confess;

                my ( $key, $params ) = %$elem;

                ref $params eq 'HASH' or confess "value of key '$key' must be a hashref";

                my $result;
                {
                    ## no critic (TestingAndDebugging::ProhibitNoWarnings)
                    no warnings 'recursion';
                    ## use critic
                    $result = _occurances( $state, %$params, key => $key );
                }

                if ( defined $result ) {
                    ref $result eq 'ARRAY' or croak 'unexpected return value from _occurances()';
                    push @errors, @{$result};
                }
                else {
                    my ( $token, $token_value, $token_errors ) = $state->{lexer}->peek_line();
                    defined $token or croak 'unexpected return value';
                    ref $token_errors eq 'ARRAY' or croak 'unexpected return value';

                    push @errors, @{$token_errors};

                    my $description = _describe_line( $token, $token_value );
                    push @errors, sprintf( "line %d: %s not allowed here", $state->{lexer}->line_no, $description );
                    return ( undef, \@errors );
                }
            }

            return ( 'section', \@errors );
        }
        elsif ( ref $section_rule eq 'HASH' ) {
            for my $key ( sort keys %{$section_rule} ) {
                my $params = $section_rule->{$key};
                ref $params eq 'HASH' or confess "value of key '$key' must be a hashref";

                my $result;
                {
                    ## no critic (TestingAndDebugging::ProhibitNoWarnings)
                    no warnings 'recursion';
                    ## use critic
                    $result = _occurances( $state, %$params, key => $key );
                }
                if ( defined $result ) {
                    ref $result eq 'ARRAY' or croak 'unexpected return value from _occurances()';
                    return ( 'section', $result );
                }
            }

            return ( undef, [] );
        }
        else {
            croak "invalid grammar rule: $key";
        }
    }
    else {
        croak "unknown grammar rule: $key";
    }
}

=head2 B<_line( $state, key, line, type, quantifier, keytype )>

Parse a line of an expected type.

    my ( $token, $errors ) = _line( $state, key => 'field', type => 'hostname', quantifier => 'required' );

Returns one of the following:

=over 4

=item B<()>

No match. No input was consumed.

=item B<( $token, $errors )>

Match. One line of input was consumed.

B<$token> is one of the B<PDT::TS::Whoiw::Lexer> token types, 'empty field' or 'any line'.

=back

=cut

sub _line {
    my ( $state, %args ) = @_;
    my $key        = $args{'key'}        or croak 'Missing argument: key';
    my $line       = $args{'line'}       or croak 'Missing argument: line';
    my $type       = $args{'type'};
    my $quantifier = $args{'quantifier'} or croak 'Missing argument: quantifier';
    my $keytype    = $args{'keytype'};

    if ( defined $type ) {
        $state->{types}->has_type( $type ) or croak "unknown type '$type'";
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
            if ( $quantifier =~ /^(?:omitted-constrained|required-strict)$/ ) {
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
            if ( !_is_acceptable_key( $state, keytype => $keytype, key => $key, ) ) {
                return;
            }

            my @keytype_errors = _validate_type( $state, type_name => $keytype, value => $key, prefix => "invalid field key '$key', " );

            if ( @keytype_errors ) {
                push @$errors, @keytype_errors;
            }
            elsif ( !defined $type && $subtype eq 'field' ) {
                push @$errors, ( sprintf( 'line %s: found an additional field: "%s"', $state->{lexer}->line_no, $key ) );
            }
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

=head2 B<_set_empty_kind( $state, kind, quantifier, key, line_no )>

Validates the uniformity of an empty field in the context of a sequence of empty fields.

    my @errors = _set_empty_kind(
        $state,
        kind       => 'omitted field',
        quantifier => 'optional-constrained',
        key        => 'Fax Ext',
        line_no    => 20,
    );

The B<kind> is compared to those of previously validated fields. As long as all
fields have the same empty kind no validation errors are returned. Error
reporting is turned on as soon as a field with deviating empty kind is reported.
At this point validation errors are reported retroactively for all previous
empty fields, including the deviating field. After this point a validation error
is reported for every validated field.

=head3 Arguments

=over

=item B<$state>

=item B<kind>

C<'empty field'> or C<'omitted field'>. The field's manifestation in the parsed
input.

=item B<quantifier>

C<'optional-constrained'>, C<'empty-constrained'> or C<'omitted-constrained'>.
The field's manifestation in the grammar.

=item B<key>

A string. The field key.

=item B<line_no>

A number. For an empty field, the line number where it is present. For an
omitted field, the line number of the line after where it was omitted.

=back

Returns a list of error message strings.

=cut

sub _set_empty_kind {
    my ( $state, %args ) = @_;
    $state or croak 'Missing argument: $state';
    my $kind       = $args{kind}       or croak 'Missing argument: kind';
    my $quantifier = $args{quantifier} or croak 'Missing argument: quantifier';
    my $key        = $args{key}        or croak 'Missing argument: key';
    my $line_no    = $args{line_no}    or croak 'Missing argument: line_no';

    $state->{empty_kind} ||= $kind;
    if ( $state->{empty_kind} eq $kind ) {
        push @{ $state->{empty_fields} }, [ $line_no, $key, $quantifier ];
        return ();
    }
    else {
        my @errors;
        for my $old_field ( @{ $state->{empty_fields} } ) {
            my ( $old_line_no, $old_key, $old_quantifier ) = @{$old_field};
            push @errors,
              _get_empty_kind_error_message(
                line_no    => $old_line_no,
                key        => $old_key,
                quantifier => $old_quantifier,
                kind       => $state->{empty_kind},
              );
        }

        $state->{empty_fields} = [];
        $state->{empty_kind}   = 'mixed';
        push @errors,
          _get_empty_kind_error_message(
            line_no    => $line_no,
            key        => $key,
            quantifier => $quantifier,
            kind       => $kind,
          );
        return @errors;
    }
}

=head2 B<_get_empty_kind_error_message( $state, key, line_no, type, quantifier, kind )>

Construct an error message regarding an empty-kind violation.

    my $message = _get_empty_kind_error_message(
        $state,
        kind       => 'omitted field',
        quantifier => 'optional-constrained',
        key        => 'Fax Ext',
        line_no    => 20,
    );

=head3 Arguments

=over

=item B<kind>

C<'empty field'> or C<'omitted field'>. The field's manifestation in the parsed
input.

=item B<quantifier>

C<'optional-constrained'>, C<'empty-constrained'> or C<'omitted-constrained'>.
The field's manifestation in the grammar.

=item B<key>

A string. The field key.

=item B<line_no>

A number. For an empty field, the line number where it is present. For an
omitted field, the line number of the line after where it was omitted.

=back

Returns a string containing the error message.

=cut

sub _get_empty_kind_error_message {
    my %args       = @_;
    my $kind       = $args{kind} or croak 'Missing argument: kind';
    my $quantifier = $args{quantifier} or croak 'Missing argument: quantifier';
    my $key        = $args{key} or croak 'Missing argument: key';
    my $line_no    = $args{line_no} or croak 'Missing argument: line_no';

    my $explanation;
    if ( $kind eq 'empty field' && $quantifier eq 'optional-constrained' ) {
        $explanation = "if one such empty field is present then empty fields of type optional-constrained must be present and must not be combined with field of type omitted-constrained. [see Whois TP, ver K, sec 5.7.2 and 5.7.4 ]";
    }
    elsif ( $kind eq 'empty field' && $quantifier eq 'empty-constrained') {
        $explanation = "this must not be combined with an omitted field of type optional-constrained or with a field of type omitted-constrained. [see Whois TP, ver K, sec 5.7.2, 5.7.3 and 5.7.4 ]";
    }
    elsif ( $kind eq 'omitted field' && $quantifier eq 'optional-constrained' ) {
        $explanation = "if one such field is omitted then no empty fields of type optional-constrained may be present and must not be combined with field of type empty-constrained. [see Whois TP, ver K, sec 5.7.2 and 5.7.3 ]";
    }
    elsif ( $kind eq 'omitted field' && $quantifier eq 'omitted-constrained' ) {
        $explanation = "this must not be combined with an empty field of type optional-constrained or with a field of type empty-constrained. [see Whois TP, ver K, sec 5.7.2, 5.7.3 and 5.7.4 ]";
    }
    else {
        croak sprintf( "missing explanation for empty kind '%s' and quantifier '%s'", $kind, $quantifier );
    }

    return sprintf( "line %d: field of type %s '%s' (%s): %s", $line_no, $quantifier, $key, $kind, $explanation );
}

sub _is_acceptable_key {
    my ( $state, %args ) = @_;
    $state or croak 'Missing argument: $state';
    my $keytype = $args{keytype} or croak 'Missing argument: keytype';
    my $key     = $args{key}     or croak 'Missing argument: key';

    return $state->{types}->is_acceptable_key( $keytype, $key );
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
