#!/usr/bin/env perl

use Crypt::PBKDF2;

if (@ARGV < 2)
{
	print "[!] Error: please specify hash (first argument) and salt (second argument)\n";
	exit (1);
}

my $match_encoded = $ARGV[0];
my $salt_encoded = $ARGV[1];
my $match_decoded = `echo $match_encoded | base64 -d | xxd -p | tr -d '\n'`;
my $salt_decoded = `echo $salt_encoded | base64 -d | xxd -p | tr -d '\n'`;

my $match = pack ("H*",$match_decoded);
my $salt = pack ("H*",$salt_decoded);

my $error = 0;

if (!(length($match_decoded) eq 40))
{
	$error = 1;
	print "[!] Error: specified hash is not appropriate.\n";
}
if (!(length($salt_decoded) eq 8))
{
	$error = 1;
	print "[!] Error: specified salt is not appropriate.\n";
}
if ($error eq 1)
{
	exit(1);
}
my $iter = 1000;

my $pbkdf2 = Crypt::PBKDF2->new (hash_class => 'HMACSHA1', iterations => $iter);
my $success = 0;
my $num;

for ($num = 0; $num < 10000; $num++)
{
	my $pass = sprintf ("%04d", $num);

	my $hash = $pbkdf2->PBKDF2 ($salt, $pass);

	if ($match eq $hash)
	{
		$success = 1;
		printf ("Success! Your restrictions password is: %s\n",$pass);
		exit (0);
	}
}
if ($success eq 0)
{
	printf ("Failed... Couldn't find your restrictions password.")
}
exit (1);
