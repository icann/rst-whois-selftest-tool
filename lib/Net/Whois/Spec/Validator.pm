package Net::Whois::Spec::Validator;

use strict;
use warnings;
use 5.014;

use Carp;

sub new {
    my $class = shift;
    my %args  = @_;

    croak "lexer: missing argument"       unless defined $args{lexer};
    croak "grammar: missing argument"     unless defined $args{grammar};
    croak "types: missing argument"       unless defined $args{types};
    croak "key translation: missing type" unless exists $args{types}->{'key translation'};
    croak "time stamp: missing type"      unless exists $args{types}->{'time stamp'};
    croak "roid: missing type"            unless exists $args{types}->{'roid'};
    croak "hostname: missing type"        unless exists $args{types}->{'hostname'};

    my $self = bless {
        _lexer      => $args{lexer},
        _grammar    => $args{grammar},
        _types      => $args{types},
        _empty_kind => undef,
    }, $class;

    return $self;
}

sub validate {
    my $self = shift;
    my $rule = shift;

    my $result = $self->_rule( $rule );
    if ( !defined $result ) {
        $result = [ sprintf( "line %d: unrecognized input", $self->{_lexer}->line_no ) ];
    }
    return $result;
}

sub _rule {
    my $self = shift;
    my $rule = shift;

    if ( my $section_rule = $self->{_grammar}->{$rule} ) {
        if ( ref $section_rule eq 'ARRAY' ) {
            my $result = $self->_sequence_section( $section_rule );
            return $result;
        }
        elsif ( ref $section_rule eq 'HASH' ) {
            my $result = $self->_choice_section( $section_rule );
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
    my $self         = shift;
    my $section_rule = shift;

    my @errors;
    my $total = 0;

    for my $elem ( @$section_rule ) {
        my ( $key, $params ) = %$elem;
        my ( $count, $result ) = $self->_occurances( %$params, key => $key );
        if ( !defined $count ) {
            if ( $total == 0 ) {
                return;
            }
            else {
                push @errors, sprintf( "line %d: expected $key", $self->{_lexer}->line_no );
                last;
            }
        }
        push @errors, @$result;
        $total += $count;
    }

    return \@errors;
}

sub _choice_section {
    my $self         = shift;
    my $section_rule = shift;

    while ( my ( $key, $params ) = each( %$section_rule ) ) {
        my ( $count, $result ) = $self->_occurances( %$params, key => $key );
        if ( defined $count ) {
            return $result;
        }
    }

    return;
}

sub _occurances {
    my $self = shift;
    my %args = @_;
    my $key  = $args{'key'};
    my $line = $args{'line'};
    my $type = $args{'type'};

    my $min_occurs;
    if ( !exists $args{'min_occurs'} ) {
        $min_occurs = 1;
    }
    else {
        $min_occurs = int $args{'min_occurs'};
    }

    my $max_occurs;
    if ( !exists $args{'max_occurs'} ) {
        $max_occurs = 1;
    }
    elsif ( $args{'max_occurs'} ne 'unbounded' ) {
        $max_occurs = int $args{'max_occurs'};
    }

    my $count = 0;
    my @errors;
    while ( !defined $max_occurs || $count < $max_occurs ) {
        my ( $parsed, $parsed_errors ) = $self->_subrule( line => $line, key => $key, type => $type );
        if ( defined $parsed ) {
            push @errors, @$parsed_errors;
            $count++;
            if ( $count == 1 && $parsed eq 'empty field' ) {
                push @errors, $self->_set_empty_kind( 'empty field' );
                last;
            }
        }
        else {
            if ( $count == 0 && defined $type || ( defined $line && $line eq 'field' ) ) {
                push @errors, $self->_set_empty_kind( 'omitted field' );
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
    my $self = shift;
    my %args = @_;
    my $line = $args{'line'};
    my $key  = $args{'key'};
    my $type = $args{'type'};

    if ( defined $type && !exists $self->{_types}->{$type} ) {
        croak "$type: unknown type";
    }

    if ( defined $line || defined $type ) {
        my ( $subtype, $result ) = $self->_line( line => $line, key => $key, type => $type );
        return ( $subtype, $result );
    }
    else {
        my $result = $self->_rule( $key );
        my $subtype = ( defined $result ) && 'section' || undef;
        return ( $subtype, $result );
    }
}

sub _line {
    my $self = shift;
    my %args = @_;
    my $key  = $args{'key'};
    my $line = $args{'line'};
    my $type = $args{'type'};

    my $token;
    my $token_value;
    my $errors;
    my $subtype;

    if ( defined $type ) {
        if ( !exists $self->{_types}->{$type} ) {
            croak "unknown type $type";
        }
        ( $token, $token_value, $errors ) = $self->{_lexer}->peek_line();
        if ( !defined $token || $token ne 'field' ) {
            return;
        }
        my ( $field_key, $field_translations, $field_value ) = @$token_value;
        if ( $field_key ne $key ) {
            return;
        }
        $subtype = ( defined $field_value ) && 'field' || 'empty field';
    }
    else {
        ( $token, $token_value, $errors ) = $self->{_lexer}->peek_line();
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
    }

    $self->{_lexer}->next_line();

    if ( $token eq 'field' ) {
        my ( $key, $translations, $value ) = @$token_value;

        for my $translation ( @$translations ) {
            push @$errors, $self->{_types}->{'key translation'}->( $translation );
        }

        if ( $type ) {
            push @$errors, $self->{_types}->{$type}->( $value );
        }
    }
    elsif ( $token eq 'roid line' ) {
        my ( $roid, $hostname ) = @$token_value;

        push @$errors, $self->{_types}->{'roid'}->( $roid );

        push @$errors, $self->{_types}->{'hostname'}->( $hostname );
    }
    elsif ( $token eq 'last update line' ) {
        my $timestamp = $token_value;

        push @$errors, $self->{_types}->{'time stamp'}->( $timestamp );
    }
    elsif ( $token ne 'any line' && $token ne 'empty line' && $token ne 'non-empty line' && $token ne 'multiple name servers line' && $token ne 'awip line' && $token ne 'EOF' ) {
        croak "unhandled line type: $token";
    }
    return $subtype, $errors;
}

sub _set_empty_kind {
    my $self = shift;
    my $kind = shift;

    $self->{_empty_kind} ||= $kind;
    if ( $self->{_empty_kind} eq $kind ) {
        return ();
    }
    else {
        return ( sprintf( "line %d: mixed empty field markups", $self->{_lexer}->line_no ) );
    }
}

1;
