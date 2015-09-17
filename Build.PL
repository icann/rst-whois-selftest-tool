use 5.006;
use strict;
use warnings;
use Module::Build;

my $builder = Module::Build->new(
    module_name         => 'Net::Whois::Spec',
    license             => 'bsd',
    dist_author         => q{Mattias Päivärinta <mattias.paivarinta@iis.se>},
    dist_version_from   => 'lib/Net/Whois/Spec.pm',
    build_requires => {
        'Test::More' => 0,
    },
    requires => {
        'perl' => 5.006,
    },
    add_to_cleanup      => [ 'Net-Whois-Spec-*' ],
    create_makefile_pl => 'traditional',
);

$builder->create_build_script();
