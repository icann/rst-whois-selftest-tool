use 5.006;
use strict;
use warnings;
use Module::Build;

my $builder = Module::Build->new(
    module_name         => 'PDT::TS::Whois',
    license             => 'bsd',
    dist_author         => q{Mattias Päivärinta <mattias.paivarinta@iis.se>},
    dist_version_from   => 'lib/PDT/TS/Whois.pm',
    build_requires => {
        'Test::More' => 0,
        'Test::Differences' => 0,
        'Test::MockObject' => 0,
    },
    requires => {
        'perl' => 5.006,
        'YAML::Syck' => 0,
        'URI' => 0,
        'Regexp::IPv6' => 0.03,
    },
    add_to_cleanup      => [ 'PDT-TS-Whois-*' ],
    create_makefile_pl => 'traditional',
);

$builder->create_build_script();
