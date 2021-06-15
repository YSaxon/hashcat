#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::MD4 qw (md4_hex);
use Digest::MD4 qw (md4);

use Digest::MD5 qw (md5_hex);
use Text::Iconv;


sub module_constraints { [[0, 256], [32, 32], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;
  my $converter = Text::Iconv->new('utf8', 'UTF-16LE');

  # $ntpass= pack_if_HEX_notation(md4_hex ($converter->convert ($word)))
  # print "ntpass $ntpass\n"

  my $salt_bin = pack ("H*", $salt);
   
# md5_hex (uc ($salt ).
  my $hash_buf =  md4($converter->convert ($word));

  my $digest= md5_hex($salt_bin . $hash_buf);

  my $hash = sprintf ("%s:%s", $digest, $salt);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my ($hash, $salt, $word) = split (':', $line);

  return unless defined $hash;
  return unless defined $salt;
  return unless defined $word;

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $salt);

  return ($new_hash, $word);
}

1;
