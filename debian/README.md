# Whois Selftest Tool packaging

How to build and upload deb packages to packages1.


## Setup variables

This instruction uses two environment variables.

 * VERSION - Upstream version.
 * REV - Packaging revision. Reset to "iis1" for each new VERSION.


### VERSION value for a proper release

    git tag | tr -d v | sort -Vr | head -1


### VERSION value for a development version

    release="`git tag | tr -d v | sort -Vr | head -1`"
    count="`git log --oneline --no-merges "v$release".. | wc -l`"
    shortsha="`git rev-parse --short HEAD`"
    echo "$release-$count-$shortsha"


### REV

For example:

    export REV=iis1


## Download dist tarball

### Packaging a development version

    make all
    make distcheck
    make dist


## Create original tarball

    tar xzf Whois-Selftest-Tool-v${VERSION/%-*/}.tar.gz
    mv Whois-Selftest-Tool-v${VERSION/%-*/} libwhois-selftest-tool-perl-${VERSION}
    tar czf ../libwhois-selftest-tool-perl_${VERSION}.orig.tar.gz libwhois-selftest-tool-perl-${VERSION}
    rm -rf libwhois-selftest-tool-perl-${VERSION}
    rm -f Whois-Selftest-Tool-v${VERSION/%-*/}.tar.gz


## Extract original tarball

    tar xzf ../libwhois-selftest-tool-perl_${VERSION}.orig.tar.gz --strip-components 1 --exclude .gitignore


## Update changelog

    dch -v "${VERSION}-${REV}"


## Build source package

    dpkg-buildpackage -S -k92388F75


## Build binary packages


    sudo DIST=precise cowbuilder --build ../libwhois-selftest-tool-perl_${VERSION}-${REV}.dsc


## Upload packages

    sudo -ubuild dput packages1-pdt ~/packages/libwhois-selftest-tool-perl_${VERSION}-${REV}_amd64.changes


## Tag release

    git tag ${VERSION}-${REV}
    git push --tags
