use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    'NAME'		=> 'Tree::Authz',
    'VERSION_FROM'	=> 'Authz.pm', # finds $VERSION
    'PREREQ_PM'		=> { Sub::Override => 0,
                         Lingua::EN::Inflect::Number => 0,
                         Class::Data::Inheritable => 0,
                         }, # e.g., Module::Name => 1.1
    ($] >= 5.005 ?    ## Add these new keywords supported since 5.005
      ( # ABSTRACT_FROM => 'Authz.pm', # retrieve abstract from module
       AUTHOR     => 'David R. Baird <cpan@riverside-cms.co.uk>') : ()),
);

