Purpose
=======
The purpose of the Whois Selftest Tool is to help gTLD applicants prepare for
[Pre-Delegation Testing]( http://newgtlds.icann.org/en/applicants/pdt) (PDT) by
providing pre-PDT Whois output validation.

Scope
=====
While Whois Selftest Tool _does_ validate Whois output and it _does_ strive to
reflect the state of PDT Whois output validation, it _is not_ authoritative on
the outcome of PDT and it _is_ subject to change.

Disclaimer
----------
The Whois Selftest Tool and the actual Whois testing under PDT are not equal.
We strive to make the two as equal as possible, but here is no guarantee that 
successfully running the Whois Selftest Tool means
that the same Whois system will pass the Whois testing under PDT. For example,
the parts of Whois tests under Whois that include DNS lookups and TCP
connections are not included in the Whois Selftest Tool. For a complete
reference of the Whois tests under PDT see the PDT Whois documents.

Version history
===============
* v1.0.0 - Initial public release (2015-12-03)
* v1.1.0 - Uppdated public release (2016-01-08)

The v1.1.0 release primarily matches the updates to the PDT Whois TP and TCs in the version 2.9 document release. It also handles the issue with IDN in the v1.0.0 release and corrects found bugs.

Specification compatibility matrix
----------------------------------
Refer to this compatibility matrix when deciding which version of Whois Selftest
Tool to use.

<table>
  <tr>
    <th>Whois Selftest Tool version</th>
    <th>PDT Test Specifications</th>
  </tr>
  <tr>
    <td>v1.0.0</td>
    <td>v.2.8</td>
  </tr>
  <tr>
    <td>v1.1.0</td>
    <td>v.2.9</td>
  </tr>
</table>

Roadmap
=======
The plan is to solve know issues and any bugs of importance. New versions will be released
when fixes are stable.

References
==========
The [Pre-Delegation Testing]( http://newgtlds.icann.org/en/applicants/pdt)
microsite hosts the following documents relevant to the Whois Selftest Tool:

* The PDT\_Whois\_TC\_CLI and PDT\_Whois\_TC\_Web documents, within the PDT Test
  Specifications zip, specifies the test cases that the Whois Selftest Tool
  partially implements.
* The PDT\_Whois\_TP document, within the PDT Test Specifications zip, specifies
  the format specification that the Whois Selftest Tool implements.

In the PDT\_Whois\_TP you can find references to other useful documents.

Licensing
=========
Whois Selftest Tool is distributed under the terms of [this license]( LICENSE).

Dependencies
============
 * Ubuntu Linux version 12.04
 * Perl, version 5.14 or higher
 * Standard Perl libraries found on CPAN.org
   * DateTime
   * File::Slurp
   * File::Which
   * Net::IDN::Encode
   * Net::IP
   * Readonly
   * Regexp::IPv6
   * Test::Differences
   * Test::MockObject
   * Text::CSV
   * Text::CSV\_XS
   * URI
   * YAML::Syck
 * wget

The Whois Selftest Tool has been developed on Unbuntu Linux, but we have tried to
avoid Linux specific coding. There is, however, no guarantee that it works on
other OSs.

Installation
============
Clone the project repository and choose version according to the specification
compatibility matrix.

    $> git clone https://github.com/dotse/Whois-Selftest-Tool.git <srcdir>
    $> cd <srcdir>
    $> git checkout <version>

Install Whois Selftest Tool scripts and libraries.

    $> perl Build.PL
    $> ./Build
    $> ./Build test
    $> ./Build install

To check the installation run the scripts with `--help`.

    $> whois-test --help
    $> whois-fetch-epp-repo-ids --help

After installing, you can find documentation for this module with the
perldoc command.

    perldoc PDT::TS::Whois

Before use
==========
Before you use the tool, make sure that you have read the documents listed
in the reference above. Some error messages may be difficult to understand
without referring to the PDT\_Whois\_TP document.

Usage
=====
The Whois Selftest Tool provides the two commands `whois-fetch-epp-repo-ids`
and `whois-test`. If you have followed the installation above, always go to
your `<programdir>` and run the commands from there or else the scripts will
not be able to find its libraries in the `PDT` directory. You probably have to
prepend the commands with `./` just as in the instructions above.

`whois-fetch-epp-repo-ids` fetches the EPP Repository Identifiers registered
with IANA and stores them in a text file inside the user's home directory.

`whois-test` validates the Whois responses according to the format specification
in the PDT\_Whois\_TP document.

The database of EPP Repository Identifiers is a prerequisite for running
`whois-test` command, so `whois-fetch-epp-repo-ids` must be run at least once
before `whois-test` is used for the first time.  After that, run
`whois-fetch-epp-repo-ids` again to update the database every time 
the Whois Selfttest Tool is to be used.

See the man pages for the respective commands for details on how to run them.
(You can use the `--man` option to view the man pages)

Known issues
============

* The description of the two types of replies on queries for nameserver objects is a bit unclear. For full understanding, please see the PDT Test Case WhoisCLI03 found in the PDT\_Whois\_TC\_CLI document listed in the references above.

Reporting bugs
--------------
If you think you've found a bug, please search both the list of known issues and
the [issue tracker](https://github.com/dotse/Whois-Selftest-Tool/issues) to see
if this is a known bug.  If you cannot find it, please report it to the issue
tracker.
