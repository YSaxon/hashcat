#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::MD4 qw (md4_hex);
use Digest::MD5 qw (md5_hex);
use Text::Iconv;


sub module_constraints { [[0, 256], [32, 32], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;

  
  my $digest = md5_hex ($salt . md4_hex ($converter->convert ($word)));

  my $hash = sprintf ("%s%s", $salt, $digest);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my ($hash, $word) = split (':', $line);

  return unless length ($hash) == 32;

  my $index1 = 16;
  my $salt = substr ($hash, 0, $index1);
  # my $digest = substr ($hash, $index1 + 1);

  # return unless defined $digest;
  return unless defined $salt;
  return unless defined $word;

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $salt);

  return ($new_hash, $word);
}

1;
