package PDT::TS::Whois;
use strict;
use warnings;
use 5.014;

=head1 NAME

PDT::TS::Whois - Validates Whois output

=head1 DESCRIPTION

This module validates Whois output strings according to the ICANN specification.

It consists of the following sub-modules:

=over 4

=item L<PDT::TS::Whois::Lexer>

Takes a string and produces a token/value/errors triplet for each line.

=item L<PDT::TS::Whois::Grammar>

Exports a datastructure representing the ICANN specification.

=item L<PDT::TS::Whois::Types>

Type checker providing most rules required by the ICANN specification and a means for the user to go the last mile.

=item L<PDT::TS::Whois::Validator>

Validates the output of a lexer according to a grammar and types.

=back


=head1 VERSION

Version 1.01

=cut

our $VERSION = '1.01';

=head1 SYNOPSIS

    use PDT::TS::Whois::Grammar qw( $grammar );
    use PDT::TS::Whois::Lexer;
    use PDT::TS::Whois::Types;
    use PDT::TS::Whois::Validator qw( validate );

    my $types = PDT::TS::Whois::Types->new();
    $types->add_type( 'query domain name', sub { return ( lc( shift ) ne 'domain.example' )     && ( 'expected exact domain name' ) || () } );
    $types->add_type( 'query name server', sub { return ( lc( shift ) ne 'ns1.domain.example' ) && ( 'expected exact name server' ) || () } );
    $types->add_type( 'query registrar name', sub { return ( shift !~ /Example Registrar/ ) && ( 'expected exact registrar name' ) || () } );

    my $lexer = PDT::TS::Whois::Lexer->new( `whois domain.example` );
    my @errors = validate(
        rule    => 'Domain Name Object query',
        lexer   => $lexer,
        grammar => $grammar,
        types   => $types,
    );
    say join( "\n", @errors ) || "OK";

=head1 AUTHOR

Mattias Päivärinta, C<< <mattias.paivarinta at iis.se> >>

=head1 BUGS

Please report any bugs or feature requests to C<mats.dufberg at iis.se>, or through
the web interface at L<http://jira.iis.se/browse/PDTT>.

=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc PDT::TS::Whois


=head1 LICENSE AND COPYRIGHT

Copyright (C) 2015 IIS (The Internet Infrastructure Foundation).
All rights reserved.

This module is subject to the following licensing conditions.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

* Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright
notice, this list of conditions and the following disclaimer in the
documentation and/or other materials provided with the distribution.

THE SOFTWARE IS PROVIDED AS-IS AND MAKES NO REPRESENTATIONS OR
WARRANTIES OF ANY KIND CONCERNING THE WORK, EXPRESS, IMPLIED,
STATUTORY OR OTHERWISE, INCLUDING, WITHOUT LIMITATION, WARRANTIES OF
TITLE, MERCHANTIBILITY, FITNESS FOR A PARTICULAR PURPOSE,
NONINFRINGEMENT, OR THE ABSENCE OF LATENT OR OTHER DEFECTS, ACCURACY,
OR THE PRESENCE OF ABSENCE OF ERRORS, WHETHER OR NOT DISCOVERABLE.

IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
DAMAGE.

=cut

1;    # End of PDT::TS::Whois
