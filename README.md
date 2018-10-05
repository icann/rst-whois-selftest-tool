Purpose
=======
The purpose of the Whois Selftest Tool is to help gTLD Registry Operators 
prepare for [Registry System Testing] (RST) by providing pre-RST Whois 
output validation. (PDT is now part of RST.)

Scope
=====
While Whois Selftest Tool _does_ validate Whois output and it _does_ strive to
reflect the state of RST Whois output validation, it _is not_ authoritative on
the outcome of RST and it _is_ subject to change.

Disclaimer
----------
The Whois Selftest Tool and the actual Whois testing under RST are not equal.
We strive to make the two as equal as possible, but here is no guarantee that 
successfully running the Whois Selftest Tool means
that the same Whois system will pass the Whois testing under RST. For example,
the parts of Whois tests under Whois that include DNS lookups and TCP
connections are not included in the Whois Selftest Tool. For a complete
reference of the Whois tests under RST see the RST Whois document listed under
the references below.

Version history
===============

* v1.0.0 - Initial public release (2015-12-03)
* v1.1.0 - Updated public release (2016-01-08)
* v1.2.0 - Updated public release (2016-02-02)
* v1.3.0 - Updated public release (2016-02-26)
* v1.4.0 - Updated public release (2016-11-01)
* v1.4.1 - No public release
* v1.3.1 - No public release
* v1.4.2 - Updated public release (2017-03-23, on Github 2017-08-24)
* v1.4.3 - Updated public release (2018-10-09)

The v1.1.0 release primarily matches the updates to the PDT Whois TP and TCs 
in the version 2.9 document release. It also handles the issue with IDN in the 
v1.0.0 release and corrects found bugs.

The v1.2.0 release primarily matches the updates to the PDT Whois TP in the the 
version 2.10 document release. It also corrects found bugs.

The v1.3.0 release includes two updates of the PDT Whois TP that will be included 
in the next document release:

* If the Domain Status is "ok" then the fragment in the URL in the Domain Status 
field may be "ok" or "OK".
* If a field is empty (key is there, but no value) there may be one space character 
(U+0020) after the colon, i.e. trailing space is permitted.

The v1.4.0 release updates Whois Selftest Tool to match the new format requirements 
specified in "[Registry Registration Data Directory Services Consistent Labeling and Display Policy]".

The v1.4.1 release updates Whois Selftest Tool with two improvements:

* Better error message when fields of type "optional-constrained", "empty-constrained" 
or "omitted-constrained" are not following the specification.
* Improved error message when "Registrar Abuse Contact Phone" (or "... Email") is empty.

The v1.3.1 release only updates the debian/changelog for IIS internal package building.

The v1.4.2 release corrects a bug and a Perl warning only seen in Perl 5.18 or higher.

The v1.4.2 release now refer to the RST documents.

The v1.4.3 release adapts the requirements to GDPR and 
"[Temporary Specification for gTLD Registration Data]".


Specification compatibility matrix
----------------------------------
Refer to this compatibility matrix when deciding which version of Whois Selftest
Tool (WSTT) to use. TP = Test Plan (PDT). TC = Test Case (PDT). 
TA = Test Area (RST).

WSTT ver |PDT Doc Release |[PDT Whois TP] ver |[PDT Whois CLI TC doc] ver |[RST Whois TA Spec] ver
:--------|:---------------|:----------------|:------------------------|:--------------------
v1.0.0   |2.8             |                 |                         |
v1.1.0   |2.9             |                 |                         |
v1.2.0   |2.10            |                 |                         |
v1.3.0   |2.10 plus two updates described above|J  |H                 |-
v1.4.0   |2.11            |K                |I                        |-
v1.4.1   |2.11            |K                |I                        |-
v1.3.1   |2.10 plus two updates described above|J  |H                 |-
v1.4.2   |2.11            |K                |I                        |-
v1.4.2   |3.0             |-                |-                        |B
v1.4.3   |3.1             |-                |-                        |C

Roadmap
=======
The plan is to release new versions of the tool whenever the underlying
requirements on Whois testing as specified in 
_[RST Whois Test Area Specification]_ has been changed. The plan is also
to solve known issues and bugs of importance. New versions will be released
when such fixes are stable.

PDT References
==============
The old [Pre-Delegation Testing] microsite hosts the old PDT documents relevant 
to old versions of Whois Selftest Tool. 

* Find the _PDT Test Specifications_ zip file.
* The _PDT Whois CLI Test Cases_ document, within the zip file, specifies the 
  test cases that the Whois Selftest Tool partially implements.
* The _PDT Whois Test Plan_ document, within the zip file, specifies the format 
  specification that the Whois Selftest Tool implements.

In _PDT Whois Test Plan_ you can find references to other useful documents.

For the most current information, go to the the RST site instead.

RST References
==============
The [Registry System Testing]
site at ICANN hosts the RST documents relevant to the Whois Selftest Tool. 

* Find the _RST Test Specifications_ zip file.
* The _**RST Whois Test Area Specification**_, within the zip file, specifies the
  test cases the the Whois Selftest Tool partially implements. It also
  contains the format specification that the Whois Selftest Tool implements.

In _RST Whois Test Area Specification_ you can find references to other useful documents.

Licensing
=========
Whois Selftest Tool is distributed under the terms of [this license].

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
   * Test::Exception
 * wget

The Whois Selftest Tool has been developed on Unbuntu Linux, but we have tried to
avoid Linux specific coding. There is, however, no guarantee that it works on
other OSs.

Installation
============
Clone the project repository and choose version according to the specification
compatibility matrix. In the normal case, choose the latest version.

    $> git clone https://github.com/dotse/Whois-Selftest-Tool.git <srcdir>
    $> cd <srcdir>
    $> git checkout <version>

Install Whois Selftest Tool scripts and libraries.

    $> perl Build.PL
    $> ./Build
    $> ./Build test
    $> ./Build install

To check the installation run the scripts with `--help`. Before the whois-test
script can be run, the EPP database must be fetched.

    $> whois-fetch-epp-repo-ids --help
    $> whois-fetch-epp-repo-ids
    $> whois-test --help

After installing, you can find documentation for this module with the
perldoc command.

    perldoc PDT::TS::Whois

Before use
==========
Before you use the tool, make sure that you have read the documents listed
in the reference above. Some error messages may be difficult to understand
without referring to the _[RST Whois Test Area Specification]_ document.

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
in the _[RST Whois Test Area Specification]_ document.

The database of EPP Repository Identifiers is a prerequisite for running
`whois-test` command, so `whois-fetch-epp-repo-ids` must be run at least once
before `whois-test` is used for the first time.  After that, run
`whois-fetch-epp-repo-ids` again to update the database every time 
the Whois Selfttest Tool is to be used.

The tool accepts the default "redact strings" as specified in the 
_[RST Whois Test Area Specification]_ document. If an additional redact string
is used, and be accepted by the tool, it has to be added to the redaction string 
database. Use `--redaction-db` to point at the selected database. Run
`whois-test --man` to get full documentation.

See the man pages for the respective commands for details on how to run them.
Use the `--man` option to view the man pages.

Known issues
============

* The description of the two types of replies on queries for nameserver objects 
is a bit unclear. For full understanding, please see Test Case WhoisCLI03 found 
in the _[RST Whois Test Area Specification]_ document.

Reporting bugs
--------------
If you think you've found a bug, please search both the list of known issues and
the [issue tracker] to see if this is a known bug.  If you cannot find it, 
please report it to the issue tracker.


[Pre-Delegation Testing]: http://newgtlds.icann.org/en/applicants/pdt
[Registry System Testing]: https://www.icann.org/resources/registry-system-testing
[Registry Registration Data Directory Services Consistent Labeling and Display Policy]: https://www.icann.org/rdds-labeling-display 
[Temporary Specification for gTLD Registration Data]: https://www.icann.org/resources/pages/gtld-registration-data-specs-en
[RST Whois Test Area Specification]: #rst-references
[issue tracker]: https://github.com/dotse/Whois-Selftest-Tool/issues
[this license]: LICENSE
[PDT Whois TP]: #pdt-references
[PDT Whois CLI TC doc]: #pdt-references
[RST Whois TA Spec]: #rst-references