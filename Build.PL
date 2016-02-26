use 5.006;
use strict;
use warnings;
use Module::Build;

my $builder = Module::Build->new(
    module_name         => 'Whois::Selftest::Tool',
    dist_author         => q{Mattias Päivärinta <mattias.paivarinta@doxwork.com>},
    dist_version_from   => 'lib/PDT/TS/Whois.pm',
    build_requires => {
        'Test::More' => 0,
        'Test::Differences' => 0,
        'Test::MockObject' => 0,
    },
    configure_requires => { 'Module::Build' => 0.38 },
    requires => {
        'perl' => 5.014,
        'DateTime' => 0,
        'File::Slurp' => 0,
        'File::Which' => 0,
        'Net::IDN::Encode' => 0,
        'Net::IP' => 0,
        'Readonly' => 0,
        'Regexp::IPv6' => 0.03,
        'Test::Differences' => 0,
        'Test::MockObject' => 0,
        'Text::CSV' => 0,
        'Text::CSV_XS' => 0,
        'URI' => 0,
        'YAML::Syck' => 0,
    },
    add_to_cleanup      => [ 'Whois-Selftest-Tool-*' ],
    create_makefile_pl => 'traditional',
    script_files => [
        'script/whois-fetch-epp-repo-ids',
        'script/whois-test',
    ],
);

$builder->create_build_script();
