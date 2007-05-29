use ExtUtils::MakeMaker;

WriteMakefile(
    'NAME'          => 'HTML::StripScripts',
    'VERSION_FROM'  => 'StripScripts.pm',
    'ABSTRACT_FROM' => 'StripScripts.pm',
    'PREREQ_PM'     => { 'Test::More' => 0, },
    'AUTHOR'        => 'Nick Cleaton <nick@cleaton.net>,'
        . ' Clinton Gormley <clint@traveljury.com>',
    $ExtUtils::MakeMaker::VERSION >= 6.31
    ? ( 'LICENSE' => 'perl' )
    : (),    
);

