package Net::Whois::Spec::Parser;

use strict;
use warnings;
use 5.014;

use Moo;
use Carp;

has grammar => ( is => 'ro', required => 1 );

has types => ( is => 'ro', required => 1 );

has lexer => ( is => 'ro', required => 1 );

has empty_kind => ( is => 'rw' );

sub parse_output {
    my $self = shift;
    my $rule = shift;

    my $result = $self->parse_rule( $rule );
    if ( defined $result ) {
        if ( $self->lexer->peek_line() ) {
            push @$result, sprintf( "line %d: expected EOF", $self->lexer->line_no );
        }
        return $result;
    }
    else {
        return [ sprintf( "line %d: unrecognized input", $self->lexer->line_no ) ];
    }
}

sub parse_rule {
    my $self = shift;
    my $rule = shift;

    if ( my $section_rule = $self->grammar->{$rule} ) {
        if ( ref $section_rule eq 'ARRAY' ) {
            return $self->_parse_sequence_section( $section_rule );
        }
        elsif ( ref $section_rule eq 'HASH' ) {
            return $self->_parse_choice_section( $section_rule );
        }
        else {
            carp "invalid grammar rule: $rule";
        }
    }
    else {
        carp "unknown grammar rule: $rule";
    }
}

sub _parse_sequence_section {
    my $self         = shift;
    my $section_rule = shift;

    my @errors;
    my $first = 1;

    for my $elem ( @$section_rule ) {
        my ( $key, $params ) = %$elem;
        my $result = $self->_parse_occurances( %$params, key => $key );
        if ( defined $result ) {
            push @errors, @$result;
        }
        elsif ( $first ) {
            return ( undef );
        }
        else {
            push @errors, sprintf( "line %d: expected section $key", $self->lexer->line_no );
        }
        $first = 0;
    }

    return \@errors;
}

sub _parse_choice_section {
    my $self         = shift;
    my $section_rule = shift;

    while ( my ( $key, $params ) = %$section_rule ) {
        my $result = $self->_parse_occurances( %$params, key => $key );
        if ( defined $result ) {
            return $result;
        }
    }

    return [ sprintf( "line %d: expected either: %s", $self->lexer->line_no, join( ', ', keys( %$section_rule ) ) ) ];
}

sub _parse_occurances {
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
    if ( !defined $line && defined $type ) {
        $line = 'field';
    }

    my @errors;
    my $count = 0;

    for ( 1 .. $min_occurs ) {
        my ( $subtype, @parsed_errors ) = $self->_parse_subrule( key => $key, line => $line, type => $type );
        if ( defined $subtype ) {
            push @errors, @parsed_errors;
            if ( $subtype eq 'empty field' ) {
                push @errors, $self->__set_empty_kind( 'empty field' );
                return \@errors;
            }
        }
        elsif ( $count == 0 ) {
            push @errors, $self->__set_empty_kind( 'omitted field' );
            return;
        }
        else {
            push @errors, sprintf( "line %d: expected at least $min_occurs $key(s)", $self->lexer->line_no );
            return \@errors;
        }
        $count++;
    }

    while ( !defined $max_occurs || $count < $max_occurs ) {
        my ( $subtype, @parsed_errors ) = $self->_parse_subrule( key => $key, line => $line, type => $type );
        if ( defined $subtype ) {
            push @errors, @parsed_errors;
            if ( $subtype eq 'empty field' ) {
                push @errors, $self->__set_empty_kind( 'empty field' );
                return \@errors;
            }
        }
        else {
            if ( $count == 0 ) {
                push @errors, $self->__set_empty_kind( 'omitted field' );
            }
            last;
        }
        $count++;
    }

    return \@errors;
}

sub _parse_subrule {
    my $self = shift;
    my %args = @_;
    my $key  = $args{'key'};
    my $line = $args{'line'};
    my $type = $args{'type'};

    if ( defined $type && !exists $self->types->{$type} ) {
        carp "unknown type $type";
    }

    if ( defined $line || defined $type ) {
        return $self->_parse_line( key => $key, line => $line, type => $type );
    }
    else {
        my $result = return $self->parse_rule( $key );
        my $subtype = ( defined $result ) && 'section' || undef;
        return ( $subtype, @$result );
    }
}

sub _parse_line {
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
        if ( !exists $self->types->{$type} ) {
            carp "unknown type $type";
        }
        ( $token, $token_value, $errors ) = $self->lexer->peek_line();
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
        ( $token, $token_value, $errors ) = $self->lexer->peek_line();
        if ( $token ne $line ) {
            return;
        }
        $subtype = $token;
    }

    $self->lexer->next_line();

    if ( $token eq 'field' ) {
        my ( $key, $translations, $value ) = @$token_value;

        for my $translation ( @$translations ) {
            push @$errors, $self->types->{'key translation'}->( $translation );
        }

        push @$errors, $self->types->{$type}->( $value );
    }
    elsif ( $token eq 'roid line' ) {
        my ( $roid, $hostname ) = @$token_value;

        push @$errors, $self->types->{'roid'}->( $roid );

        push @$errors, $self->types->{'hostname'}->( $hostname );
    }
    elsif ( $token eq 'last update line' ) {
        my $timestamp = $token_value;

        push @$errors, $self->types->{'timestamp'}->( $timestamp );
    }
    elsif ( $token ne 'empty line' && $token ne 'non-empty line' && $token ne 'multiple name servers line' && $token ne 'awip line' ) {
        carp "unhandled line type: $token";
    }
    return $subtype, @$errors;
}

sub __set_empty_kind {
    my $self = shift;
    my $kind = shift;

    $self->empty_kind( $self->empty_kind || $kind );
    if ( $self->empty_kind eq $kind ) {
        return ();
    }
    else {
        return ( sprintf( "line %d: mixed empty field markups", $self->lexer->line_no ) );
    }
}

1;
