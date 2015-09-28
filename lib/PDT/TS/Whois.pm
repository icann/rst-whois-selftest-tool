package PDT::TS::Whois;
use strict;
use warnings;
use 5.014;

=head1 NAME

PDT::TS::Whois - Whois output validation according to the ICANN specification.

=head1 VERSION

Version 0.01

=cut

our $VERSION = '0.01';

=head1 SYNOPSIS

This module provides a library for parsing Whois output according to the ICANN specification.

The library is split up into the following modules:
 * PDT::TS::Whois::Lexer     - Takes a string and produces a token/value/errors triplet for each line.
 * PDT::TS::Whois::Grammar   - Exports a datastructure representing the ICANN specification.
 * PDT::TS::Whois::Types     - Type checker providing most rules required by the ICANN specification and a means for the user to go the last mile.
 * PDT::TS::Whois::Validator - Validates the output of a lexer according to a grammar and types.

Perhaps a little code snippet.

    use PDT::TS::Whois;

    my $foo = PDT::TS::Whois->new();
    ...

=head1 EXPORT

A list of functions that can be exported.  You can delete this section
if you don't export anything, such as for a purely object-oriented module.

=head1 SUBROUTINES/METHODS

=head2 function1

=cut

sub function1 {
}

=head2 function2

=cut

sub function2 {
}

=head1 AUTHOR

Mattias Päivärinta, C<< <mattias.paivarinta at iis.se> >>

=head1 BUGS

Please report any bugs or feature requests to C<bug-net-whois-spec at rt.cpan.org>, or through
the web interface at L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=PDT-TS-Whois>.  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.




=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc PDT::TS::Whois


You can also look for information at:

=over 4

=item * RT: CPAN's request tracker (report bugs here)

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=PDT-TS-Whois>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/PDT-TS-Whois>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/PDT-TS-Whois>

=item * Search CPAN

L<http://search.cpan.org/dist/PDT-TS-Whois/>

=back


=head1 ACKNOWLEDGEMENTS


=head1 LICENSE AND COPYRIGHT

Copyright 2015 Mattias Päivärinta.

This program is distributed under the (Revised) BSD License:
L<http://www.opensource.org/licenses/bsd-license.php>

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

* Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright
notice, this list of conditions and the following disclaimer in the
documentation and/or other materials provided with the distribution.

* Neither the name of Mattias Päivärinta's Organization
nor the names of its contributors may be used to endorse or promote
products derived from this software without specific prior written
permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


=cut

1;    # End of PDT::TS::Whois
