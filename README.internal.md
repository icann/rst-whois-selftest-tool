Internal Process documentation
==============================

The intended audience of this document is the Whois-Selftest-Tool team itself.


Branch model
------------

### Repositories

* `upstream`: https://stash.iis.se/projects/PDT/repos/whois-selftest-tool
* `public`: https://github.com/dotse/whois-selftest-tool


### Branches

* `upstream/develop`: All development is merged here using reviewed pull
  requests.
* `upstream/master`: Latest release.
* `public/master`: Latest release.


Release procedure
-----------------

1. Verify that no unexpected commits are present in `upstream/master` and
   `public/master`.

2. Make sure the `$VERSION` number in `lib/PDT/TS/Whois.pm` has been updated in
   `upstream/develop`.

3. Make sure the `MANIFEST` file is up to date in `upstream/develop`.

   In order to have a complete installation from a package, the `MANIFEST` needs
   to be the complete set of files to be included.

4. Make sure that the `Build.PL` is up to date in `upstream/develop`.

   The `Build.PL` contains all the required modules, including version numbers.
   The remaining metadata in the file should also be checked.

5. Make sure the `META.json`, `META.yml` and `Makefile.PL` files are up to date
   in `upstream/develop`.

   ```
   git clean -dfx && perl Build.PL && ./Build distmeta && git status
   ```

6. Make sure a distribution file can be built in `upstream/develop`.

   Verify that the distribution file builds in a clean Perl installation.

   ```
   git clean -dfx && perl Build.PL && ./Build dist
   ```

7. Make sure that all tests pass in `upstream/develop`.

   Verify that the module builds and all tests pass with the latest point
   release for every supported major Perl version. This can be done quite easily
   with something like this:

   ```
   perlbrew exec --with 5.14.4,5.16.3,5.18.4,5.20.1 '( git clean -dfx && perl Build.PL && ./Build ) >& /dev/null && prove -bQ'
   ```

8. Make sure the `Version history` and `Specification compatibility matrix`
   sections in `README.md` have been updated in `upstream/develop`.

9. Make sure the `debian/changelog` has been updated in `upstream/develop`.

10. Merge `upstream/develop` into `upstream/master`.

11. Tag `upstream/master` with the new version number.

12. Push the `upstream/master` branch to `public/master`.

13. Add release notes to the version number tag on Github.
