package Tree::Authz;
use strict;
use warnings;
use Carp;

use Lingua::EN::Inflect::Number ();

use base 'Class::Data::Inheritable';

__PACKAGE__->mk_classdata( 'AllGroups' );

__PACKAGE__->AllGroups( {} );

our $VERSION = '0.01';

=head1 NAME

Tree::Authz - inheritance-based authorization scheme

=head1 VERSION

0.01

=head1 DEVELOPER RELEASE

There's only a few methods in this class, so the interface should stabilise
pretty quickly. Feel free to suggest changes. For the moment, keep a close
eye on the CHANGES file when updating.

=head1 SYNOPSIS

    use Tree::Authz;

    my $groups = { superuser    => [ qw( spymasters politicians ) ],
                   spymasters   => [ qw( spies moles ) ],
                   spies        => [ 'informants' ],
                   informants   => [ 'base' ],
                   moles        => [ 'base' ],
                   politicians  => [ 'citizens' ],
                   citizens     => [ 'base' ],
                   };

    my $authz = Tree::Authz->setup_hierarchy( $groups, 'SpyLand' );

    my $superuser = $authz->get_group( 'superuser' );
    my $spies     = $authz->get_group( 'spies' );
    my $citizens  = $authz->get_group( 'citizens' );
    my $base      = $authz->get_group( 'base' );

    $spies   ->setup_permissions( [ qw( read_secrets wear_disguise ) ] );
    $citizens->setup_permissions( 'vote' );
    $base    ->setup_permissions( 'breathe' );

    foreach my $group ( $superuser, $spies, $citizens, $base ) {
        foreach my $ability ( qw( unspecified_ability
                                  spy
                                  spies
                                  read_secrets
                                  wear_disguise
                                  vote
                                  breathe
                                  can ) ) {

            if ( $group->can( $ability ) ) {
                printf "%s can '%s'\n", $group->group_name, $ability;
            }
            else {
                printf "%s cannot '%s'\n", $group->group_name, $ability;
            }
        }
    }

    # prints:

    superuser can 'unspecified_ability'     # superpowers!
    superuser can 'spy'
    superuser can 'spies'
    superuser can 'read_secrets'
    superuser can 'wear_disguise'
    superuser can 'vote'
    superuser can 'breathe'
    superuser can 'can'
    spies cannot 'unspecified_ability'
    spies can 'spy'
    spies can 'spies'
    spies can 'read_secrets'
    spies can 'wear_disguise'
    spies can 'vote'
    spies can 'breathe'
    spies can 'can'
    citizens cannot 'unspecified_ability'
    citizens cannot 'spy'
    citizens cannot 'spies'
    citizens cannot 'read_secrets'
    citizens cannot 'wear_disguise'
    citizens can 'vote'
    citizens can 'breathe'
    citizens can 'can'
    base cannot 'unspecified_ability'
    base cannot 'spy'
    base cannot 'spies'
    base cannot 'read_secrets'
    base cannot 'wear_disguise'
    base cannot 'vote'
    base cannot 'breathe'                   # !
    base cannot 'can'                       # !!

    # storing code on the nodes of the tree
    $spies->setup_abilities( read_secret => $coderef );

    print $spies->read_secret( '/path/to/secret/file' );

    $spies->setup_plugins( 'My::Spies::Skills' );

    $spies->fly( $jet ); # My::Spies::Skills::fly

=head1 DESCRIPTION

Class for inheritable, groups-based permissions system (Access Control List).

Custom methods can be placed on group objects. Authorization can be performed
either by checking whether the group name matches the required name, or by
testing (via C<can>) whether the group can perform the method required.

Two groups are specified by default. At the top, I<superuser>s can do anything
(C<< $superuser->can( $action ) >> always returns a coderef). At the bottom, the
I<base> group can do nothing (C<< $base->can( $action ) >> always returns undef).

All groups are automatically capable of authorizing actions named for the
singular and plural of the group name.

=head1 METHODS

Methods can be called on classes or instances, except where stated otherwise.

=head2 Namespaces and class methods

This class is designed to work in environments where multiple applications
run within the same process (i.e. websites under C<mod_perl>). If the optional
namespace parameter is supplied to C<setup_hierarchy>, the groups are isolated
to the specified namespace. All class methods should be called through the
 class returned from C<setup_hierarchy>.

If your program is not operating in such an environment (e.g. CGI scripts),
then you can completely ignore this parameter, and call class methods either
through C<Tree::Authz>, or through the string returned from C<setup_hierarchy>
(which, funnily enough, will be 'Tree::Authz').

=over 4

=item get_group( $group_name )

Factory method, returns a L<Tree::Authz|Tree::Authz> subclass object.

Sets up two permitted actions on the group - the singular and plural of
the group name. B<This might be too cute, and could change to just the group
name in a near future release>. Opinions welcome.

=item new( $group_name )

Alias for C<new>.

=cut

sub new {
    my ($proto, $group) = @_;

    croak 'No group name' unless $group;

    my $class = ref( $proto ) || $proto;

    unless ( $proto->group_exists( $group ) ) {
        carp( "Unknown group: $group - using 'base' instead" );
        $group = 'base';
    }

    my $self = \$group;

    bless $self, "${class}::$group";

    $self->_init;

    return $self;
}

# instance method
sub _init {
    my ($self) = @_;

    my $name = $self->group_name;

    my @cando = ( Lingua::EN::Inflect::Number::to_PL( $name ),
                  Lingua::EN::Inflect::Number::to_S(  $name ),
                  );

    $self->setup_permissions( \@cando );
}

sub get_group { goto &new }

=item group_name()

Instance method.

Returns the name of the group.

=cut

sub group_name { ${ $_[0] } }

=item group_exists( $group_name )

Returns true if the specified group exists B<anywhere> within the hierarchy.

=cut

sub group_exists { exists $_[0]->AllGroups->{ $_[1] } }

=item subgroup_exists( $subgroup_name, [ $group_name ] )

B<Method not implemented yet>.

Give me a nudge if this would be useful.

Returns true if the specified group exists anywhere in the hierarchy
underneath the current or specified group.

=cut

sub subgroup_exists { croak 'subgroup_exists method not implemented yet - email me' }

=item list_groups()

Returns an arrayref of all the group names in the hierarchy, sorted by name.

=cut

sub list_groups { [ sort keys %{ $_[0]->AllGroups } ] }

=item dump_hierarchy( [ $namespace ] )

Get a simple printout of the structure of your hierarchy.

This method C<require>s L<Devel::Symdump|Devel::Symdump>.

If you find yourself parsing the output and using it somehow in your code, let
me know, and I'll find a Better Way to provide the data. This method is just
intended for quick and dirty printouts and could B<change at any time>.

=cut

sub dump_hierarchy {
    my ($proto) = @_;

    my $class = ref( $proto ) || $proto;

    require Devel::Symdump;

    my @classes = split( "\n", Devel::Symdump->isa_tree );

    my @wanted;
    my $start = 0;
    my $end = 0;
    my $supers = "${class}::superuser";

    foreach my $possible ( @classes ) {
        $start = 1 if $possible =~ /^$supers/;
        if ( $start && $possible !~ /^$supers/ ) {
            $end = 1 if $possible =~ /^\w/;
        }
        push( @wanted, $possible ) if ( $start && ! $end && $possible =~ __PACKAGE__ );
    }

    return join( "\n", @wanted );
}

=item setup_hierarchy( $groups, [ $namespace ] )

Class method.

I<$groups> has:

    keys   - group names
    values - arrayrefs of subgroup name(s)

Sets up a hierarchy of Perl classes representing the group structure.

The hierarchy will be contained within the I<$namespace> top level if supplied.
This makes it easy to set up several independent hierarchies to use within the
same process, e.g. for different websites under C<mod_perl>.

Returns a class name through which group objects can be retrieved and other
class methods called. This will be 'Tree::Authz' if no namespace is specified.

=cut

sub setup_hierarchy {
    my ($proto, $groups_data, $namespace) = @_;

    croak( 'No groups data' ) unless $groups_data;

    my $class = ref( $proto ) || $proto;

    $class = "${namespace}::$class" if $namespace;

    my %groups;

    foreach my $group ( keys %$groups_data ) {
        my @isa = map { "${class}::$_" } @{ $groups_data->{ $group } };
        my $group_class = "${class}::${group}";
        $groups{ $group } = $group_class;
        no strict 'refs';
        @{"${group_class}::ISA"} = @isa;
    }

    my $supers_class = "${class}::superuser";
    my $base_class   = "${class}::base";

    {
        no strict 'refs';

        push( @{"${class}::ISA"}, __PACKAGE__ ) if $namespace;

        # add a base group
        push( @{"${base_class}::ISA"}, $class );

        # superuser always returns a subref from 'can', even if the specified
        # method doesn't exist.
        *{"${supers_class}::can"} =
            sub { UNIVERSAL::can( $_[0], $_[1] ) || sub {} };

        # base group cannot do anything
        *{"${base_class}::can"} = sub {
            my ($proto, @args) = @_;
            my $class = ref( $proto ) || $proto;
            return if $class =~ /::base$/;
            return UNIVERSAL::can( $proto, @args );
        };
    }

    # these calls have to come after the class hierarchy is set up
    $class->AllGroups( {} );
    $class->AllGroups->{ $_ } = $groups{ $_ } for keys %groups;
    $class->AllGroups->{ superuser } = $supers_class;
    $class->AllGroups->{ base }      = $base_class;

    return $class;
}

=item setup_permissions( $cando )

Instance method.

Adds methods to the class representing the group. I<$cando> is a single method
name, or arrayref of method names. No-op methods are added to the class
representing the group:

    my $spies = $authz->get_group( 'spies' );

    my $cando = [ qw( read_secret wear_disguise ) ];

    $spies->setup_permissions( $cando );

    if ( $spies->can( 'read_secret' ) ) {
        warn 'Compromised!';
    }

    warn 'Trust no-one' if $spies->can( 'wear_disguise' );

=cut

sub setup_permissions {
    my ($self, $cando) = @_;

    croak( 'Nothing to permit' ) unless $cando;
    my $class = ref( $self ) || croak( 'object method called on class name' );

    $class->_setup_perms( $cando );
}

=item setup_permissions_on_group( $group_name, $cando )

Class method version of C<setup_permissions>.

=cut

sub setup_permissions_on_group {
    my ($class, $group, $cando) = @_;

    croak( 'Parameter(s) missing' )   unless $cando;
    croak( 'Not an instance method' ) if ref( $class );

    my $group_class = "${class}::$group";

    $group_class->_setup_perms( $cando );
}

sub _setup_perms {
    my ($class, $cando) = @_;

    my @permits = ref( $cando ) ? @$cando : ( $cando );

    no strict 'refs';
    foreach my $permit ( @permits ) {
        *{"${class}::$permit"} = sub {};
    }
}

=item setup_abilities( $name => $coderef, [ $name2 => $coderef2 ], ... )

Instance method.

Adds methods to the class representing the group. Keys give method names and
values are coderefs that will be installed as methods on the group class:

    my $spies = $authz->get_group( 'spies' );

    my %able = ( read_secret => sub {
                    my ($self, $file) = @_;
                    open( SECRET, $file );
                    local $/;
                    <SECRET>;
                    },

                 find_moles => sub { ... },

                );

    $spies->setup_abilities( %able );

    if ( $spies->can( 'read_secret' ) ) {
        print $spies->read_secret( '/path/to/secret/file' );
    }

    # or

    if ( my $read = $spies->can( 'read_secret' ) ) {
        print $spies->$read( '/path/to/secret/file' );
    }

    # with an unknown $group
    my $get_secret = $group->can( 'read_secret' )       ||     # spy
                     $group->can( 'steal_document' )    ||     # mole
                     $group->can( 'create_secret' )     ||     # spymaster
                     $group->can( 'do_illicit_thing' )  ||     # politician
                     sub {};                                   # boring life

    my $secret = $group->$get_secret;

=cut

sub setup_abilities {
    my ($self, %code) = @_;

    croak( 'Nothing to set up' ) unless %code;

    my $class = ref( $self ) || croak( 'object method called on class name' );

    $class->_setup_abil( %code );
}

=item setup_abilities_on_group( $group_name, %code )

Class method version of C<setup_abilities>.

=cut

sub setup_abilities_on_group {
    my ($class, $group, %code) = @_;

    croak( 'Not an instance method' ) if ref( $class );
    croak( 'Nothing to set up' )      unless %code;

    my $group_class = "${class}::$group";

    $group_class->_setup_abil( %code );
}

sub _setup_abil {
    my ($class, %code) = @_;

    no strict 'refs';
    foreach my $method ( keys %code ) {
        *{"${class}::$method"} = $code{ $method };
    }
}


=item setup_plugins( $plugins )

Instance method.

Instead of adding a set of coderefs to a group's class, this method adds
a class to the C<@ISA> array of the group's class.

    package My::Spies;

    sub wear_disguise {}

    sub read_secret {
        my ($self, $file) = @_;
        open( SECRET, $file );
        local $/;
        <SECRET>;
    }

    package main;

    my $spies = $authz->get_group( 'spies' );

    $spies->setup_plugins( 'My::Spies' );

    if ( $spies->can( 'read_secret' ) ) {
        warn 'Compromised!';
        print $spies->read_secret( '/path/to/secret/file' );
    }

    warn 'Trust no-one' if $spies->can( 'wear_disguise' );

=cut


sub setup_plugins {
    my ($self, $plugins) = @_;

    croak( 'Nothing to plug in' ) unless $plugins;

    my $class = ref( $self ) || croak( 'object method called on class name' );

    $class->_setup_plugins( $plugins );
}

=item setup_plugins_on_group( $group_name, $plugins )

Class method version of C<setup_plugins>.

=cut

sub setup_plugins_on_group {
    my ($class, $group, $plugins) = @_;

    croak( 'Parameter(s) missing' )   unless $plugins;
    croak( 'Not an instance method' ) if ref( $class );

    my $group_class = "${class}::$group";

    $group_class->_setup_plugins( $plugins );
}

sub _setup_plugins {
    my ($class, $plugins) = @_;

    my @plugins = ref( $plugins ) ? @$plugins : ( $plugins );

    no strict 'refs';

    push( @{"${class}::ISA"}, $_ ) for @plugins;
}


=back

=cut

1;

=head1 TODO

More methods for returning meta information, e.g. immediate subgroups of a
group, all subgroups of a group, list available actions of a group and its
subgroups.

Might be nice to register users with groups.

Make group objects be singletons - not necessary if the only data they carry is
their own name.

Under C<mod_perl>, all setup of hierarchies and permissions must be completed
during server startup, before the startup process forks off Apache children.
It would be nice to have some way of communicating updates to other processes.
Alternatively, you could run the full startup sequence every time you need to
access a Tree::Authz group, but that seems sub-optimal.

=head1 DEPENDENCIES

L<Lingua::EN::Inflect::Number|Lingua::EN::Inflect::Number>,
L<Class::Data::Inheritable|Class::Data::Inheritable>.

Optional - L<Devel::Symdump|Devel::Symdump>.

L<Sub::Override|Sub::Override> for the test suite.

=head1 BUGS

Please report all bugs via the CPAN Request Tracker at
L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=Tree-Authz>.

=head1 COPYRIGHT AND LICENSE

Copyright 2004 by David Baird.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=head1 AUTHOR

David Baird, C<cpan@riverside-cms.co.uk>

=head1 SEE ALSO

L<DBIx::UserDB|DBIx::UserDB>, L<Data::ACL|Data::ACL>.

=cut

