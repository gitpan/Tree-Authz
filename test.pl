#!/usr/bin/perl

# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl test.pl'

#########################

# change 'tests => 1' to 'tests => last_test_to_print';

use Test::More tests => 59;
use Test::Exception;

use strict;
use warnings;

### load
BEGIN { use_ok( 'Tree::Authz' ) };

### setup_hierarchy
my $groups = { superuser    => [ qw( spymasters politicians ) ],
               spymasters   => [ qw( spies moles ) ],
               spies        => [ 'informants' ],
               informants   => [ 'base' ],
               moles        => [ 'base' ],
               politicians  => [ 'citizens' ],
               citizens     => [ 'base' ],
               };

my ($SpyLand, $NoNameLand);
lives_ok { $SpyLand = 'Tree::Authz'->setup_hierarchy( $groups, 'SpyLand' ) } 'groups set up' ;
lives_ok { $NoNameLand = Tree::Authz->setup_hierarchy( $groups ) } 'groups set up with no namespace' ;

### group_exists
ok( $SpyLand->group_exists( 'spies' ), 'spies group_exists in SpyLand' );
like( "SpyLand::Tree::Authz", qr/^$SpyLand$/, "got expected class name - $SpyLand" );

ok( $NoNameLand->group_exists( 'spies' ), 'spies group_exists in default namespace' );
like( "Tree::Authz", qr/^$NoNameLand$/, "got expected class name - $NoNameLand" );

### dump_hierarchy
my $tree;
lives_ok { $tree = $SpyLand->dump_hierarchy( 'SpyLand' ) } 'survived call to dump_hierarchy';

my $tree_out = <<TREE;
SpyLand::Tree::Authz::superuser
\tSpyLand::Tree::Authz::spymasters
\t\tSpyLand::Tree::Authz::spies
\t\t\tSpyLand::Tree::Authz::informants
\t\t\t\tSpyLand::Tree::Authz::base
\t\t\t\t\tSpyLand::Tree::Authz
\t\t\t\t\t\tTree::Authz
\t\tSpyLand::Tree::Authz::moles
\t\t\tSpyLand::Tree::Authz::base
\t\t\t\tSpyLand::Tree::Authz
\t\t\t\t\tTree::Authz
\tSpyLand::Tree::Authz::politicians
\t\tSpyLand::Tree::Authz::citizens
\t\t\tSpyLand::Tree::Authz::base
\t\t\t\tSpyLand::Tree::Authz
\t\t\t\t\tTree::Authz
TREE

$tree_out =~ s/\n$//;

like( $tree, qr/$tree_out/, 'got expected tree for SpyLand namespace' );

my $tree2;
lives_ok { $tree2 = $NoNameLand->dump_hierarchy } 'survived call to dump_hierarchy with no namespace';

my $tree2_out = <<TREE;
Tree::Authz::superuser
\tTree::Authz::spymasters
\t\tTree::Authz::spies
\t\t\tTree::Authz::informants
\t\t\t\tTree::Authz::base
\t\t\t\t\tTree::Authz
\t\tTree::Authz::moles
\t\t\tTree::Authz::base
\t\t\t\tTree::Authz
\tTree::Authz::politicians
\t\tTree::Authz::citizens
\t\t\tTree::Authz::base
\t\t\t\tTree::Authz
TREE

$tree2_out =~ s/\n$//;

like( $tree2, qr/$tree2_out/, 'got expected tree for default namespace' );

### get_group and new
my ($spies, $spies2, $superuser, $base);
lives_ok { $spies = $SpyLand->new( 'spies' ) } 'survived new';
lives_ok { $spies2 = $SpyLand->get_group( 'spies' ) } 'survived get_group';
isa_ok( $spies, "SpyLand::Tree::Authz::spies" );
isa_ok( $spies2, "SpyLand::Tree::Authz::spies" );
isa_ok( $superuser = $SpyLand->new( 'superuser' ), "SpyLand::Tree::Authz::superuser" );
isa_ok( $base = $SpyLand->new( 'base' ), "SpyLand::Tree::Authz::base" );

### group_exists
ok( $spies->group_exists( 'politicians' ), 'spies know that politicians group_exists' );

### group_name
like( $spies->group_name, qr/^spies$/, 'group_name' );

my $informants = $SpyLand->new( 'informants' ) || die 'Unexpected failure';

### default can
ok( !   $spies->can( 'jhsfuif' ), 'spies cannot jhsfuif' );
ok( $superuser->can( 'jhsfuif' ), 'but superuser can jhsfuif' );
ok( !    $base->can( 'can' ),     'and base can\'t even can!' );
ok(     $spies->can( 'spies' ),   'spies can spies' );
ok(     $spies->can( 'spy' ),     'spies can spy' );
ok( $informants->can( 'informants' ), 'informants can informants' );
ok( $informants->can( 'informant' ),  'informants can informant' );


my $spies_can = [ qw( read_secrets wear_disguise ) ];
my $informants_can = 'tell_tales';
my $base_can = 'breathe';

### setup_permissions
lives_ok {
    $spies->setup_permissions( $spies_can );
    $base->setup_permissions( $base_can );
    $informants->setup_permissions( $informants_can );
    } 'setup groups perms';

# can
ok( $spies->can( 'read_secrets' ), 'spies can read_secrets' );
ok( $spies->can( 'wear_disguise' ), 'spies can wear_disguise' );
ok( $spies->can( 'tell_tales' ), 'spies can tell_tales' );
ok( $informants->can( 'tell_tales' ), 'informants can tell_tales' );
ok( ! $informants->can( 'read_secrets' ), 'informants can NOT read_secrets' );
ok( ! $base->can( 'breathe' ), 'base can not even breathe!' );
ok( $spies->can( 'breathe' ) && $informants->can( 'breathe' ), 'but spies and informants can breathe' );

### setup_abilities
my %spies_able = ( encode_text => sub { my @chars = split( '', $_[1] );
                                        join( '', reverse @chars );
                                        },
                 );

lives_ok { $spies->setup_abilities( %spies_able ) } 'survived setup_abilities';
like( $spies->encode_text( 'abc' ), qr/^cba$/, 'spies can encode text' );
dies_ok { $informants->encode_text( 'abc' ) } 'informants die if they try to encode text!';

my $spymasters = $SpyLand->new( 'spymasters' ) || die 'Unexpected failure';
like( $spymasters->encode_text( 'abc' ), qr/^cba$/, 'spymasters can encode text too' );

my $politicians = $SpyLand->new( 'politicians' ) || die 'Unexpected failure';
dies_ok { $politicians->encode_text( 'abc' ) } 'politicians also die if they try to encode text!';

ok( $superuser->encode_text( 'abc' ) eq 'cba', 'superuser can encode text too' );

### setup_plugins
{
    package Spies::Extras;

    sub assassinate {
        my ($self, $target) = @_;
        return "DEAD $target";
    }

    sub escape {}
}

lives_ok { $spies->setup_plugins( 'Spies::Extras' ) } 'survived setup_plugins';

ok( $spymasters->can( 'assassinate' ), 'spymasters can do the method added to spies' );
ok( $spies->can( 'assassinate' ), 'as can spies' );
ok( ! $politicians->can( 'assassinate' ), 'but politicians can\'t' );
like( $spies->assassinate( 'victim' ), qr/^DEAD victim$/, 'added method works for spies' );
like( $spymasters->assassinate( 'other victim' ), qr/^DEAD other victim$/, 'added method works for spymasters' );
dies_ok { $politicians->assassinate( 'victim' ) } 'but politicians die';


### subgroup_exists
SKIP: {
    skip '- subgroup_exists not implemented', 3;

    ok( $spies->subgroup_exists( 'informants' ), 'informants are a subgroup of spies' );
    ok( ! $spies->subgroup_exists( 'moles' ), 'moles are not a subgroup of spies' );
    ok( $spymasters->subgroup_exists( 'informants' ), 'informants are a deep subgroup of $spymasters' );

};

### setup_permissions_on_group
my $cando = [ qw( shoot_gun fly_helicopter ) ];
dies_ok  { $spies->setup_permissions_on_group( 'spies', $cando ) } "can't setup_permissions_on_group through $spies";
lives_ok { $SpyLand->setup_permissions_on_group( 'spies', $cando ) } "can   setup_permissions_on_group through $SpyLand";
ok( $spies->can( 'fly_helicopter' ), 'permission granted' );

### setup_abilities_on_group
my %able = ( math => sub { 2 * 2 } );
dies_ok  { $spies->setup_abilities_on_group( 'spies', %able ) } "can't setup_abilities_on_group through $spies";
lives_ok { $SpyLand->setup_abilities_on_group( 'spies', %able ) } "can   setup_abilities_on_group through $SpyLand";
like( $spies->math, qr/^4$/, 'spies have new ability' );

### setup_plugins_on_group
{
    package My::Spies;

    sub wear_silly_disguise {}

    sub read_dirty_secret {
        my ($self, $file) = @_;
        open( SECRET, $file );
        local $/;
        <SECRET>;
    }
}

dies_ok  { $spies->setup_plugins_on_group( 'spies', 'My::Spies' ) } "can't setup_plugins_on_group through $spies";
lives_ok { $SpyLand->setup_plugins_on_group( 'spies', 'My::Spies' ) } "can   setup_plugins_on_group through $SpyLand";
ok( $spies->can( 'wear_silly_disguise' ), 'got new ability' );



