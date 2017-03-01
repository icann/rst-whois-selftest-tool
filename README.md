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
* v1.1.0 - Updated public release (2016-01-08)
* v1.2.0 - Updated public release (2016-02-02)
* v1.3.0 - Updated public release (2016-02-26)
* v1.4.0 - Updated public release (2016-11-01)
* v1.4.1 - No public release
* v1.3.1 - No public release
* v1.4.2 - Updated public release (2016-03-23)

The v1.1.0 release primarily matches the updates to the PDT Whois TP and TCs in the version 2.9 document release. It also handles the issue with IDN in the v1.0.0 release and corrects found bugs.

The v1.2.0 release primarily matches the updates to the PDT Whois TP in the the version 2.10 document release. It also corrects found bugs.

The v1.3.0 release includes two updates of the PDT Whois TP that will be included in the next document release:

* If the Domain Status is "ok" then the fragment in the URL in the Domain Status field may be "ok" or "OK".
* If a field is empty (key is there, but no value) there may be one space character (U+0020) after the colon, i.e. trailing space is permitted.

The v1.4.0 release updates Whois Selftest Tool to match the new format requirements specified in ["Registry Registration Data Directory Services Consistent Labeling and Display Policy"](https://www.icann.org/rdds-labeling-display). That specification is optional until 2017-08-01, and registries still using the current format should stick to v1.3.0 of Whois Selftest Tool.

The v1.4.1 release updates Whois Selftest Tool with two improvements:

* Better error message when fields of type "optional-constrained", "empty-constrained" or "omitted-constrained" are not following the specification.
* Improved error message when "Registrar Abuse Contact Phone" (or "... Email") is empty.

The v1.3.1 release only updates the debian/changelog for IIS internal package building.

The v1.4.2 release corrects a bug and a Perl warning only seen in Perl 5.18 or higher. 

Specification compatibility matrix
----------------------------------
Refer to this compatibility matrix when deciding which version of Whois Selftest
Tool to use.

<table>
  <tr>
    <th>Whois Selftest Tool version</th>
    <th>PDT Document Release</th>
    <th>PDT Whois Test Plan version</th>
    <th>PDT Whois CLI Test Case document version</th>
  </tr>
  <tr>
    <td>v1.0.0</td>
    <td>2.8</td>
    <td></td>
    <td></td>
  </tr>
  <tr>
    <td>v1.1.0</td>
    <td>2.9</td>
    <td></td>
    <td></td>
  </tr>
  <tr>
    <td>v1.2.0</td>
    <td>2.10</td>
    <td></td>
    <td></td>
  </tr>
  <tr>
    <td>v1.3.0</td>
    <td>2.10 plus two updates described above</td>
    <td>J</td>
    <td>H</td>
  </tr>
  <tr>
    <td>v1.4.0</td>
    <td>2.11</td>
    <td>K</td>
    <td>I</td>
  </tr>
  <tr>
    <td>v1.4.1</td>
    <td>2.11</td>
    <td>K</td>
    <td>I</td>
  </tr>
  <tr>
    <td>v1.3.1</td>
    <td>2.10 plus two updates described above</td>
    <td>J</td>
    <td>H</td>
  </tr>
  <tr>
    <td>v1.4.2</td>
    <td>2.11</td>
    <td>K</td>
    <td>I</td>
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
