use ExtUtils::MakeMaker;

WriteMakefile(
    'NAME'         => 'HTML::StripScripts',
    'VERSION_FROM' => 'StripScripts.pm',
    'PREREQ_PM'    => {
                        'Test::More' => 0,
                      },
);

