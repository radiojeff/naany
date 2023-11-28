#!/usr/bin/perl

# WWDXC NAANY report generator
# Rapidly written by Jeff, W7BRS
# BSD 3-Clause License

# USAGE:
#
# 1. Export your log to ADIF
# 2. Run this script like this:
#      perl naany FILENAME
#
#  where "FILENAME" is the filename of your ADIF export file.
#
# Wait approximately 1 second or less.. Then revel in the NAANY results.


# The code..


# Perl lets us define some templates when using the write function.
# how it gets printed out..
format STDOUT_TOP=
    | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 0 |
---------------------------------------------
.

format STDOUT=
@<<<| @<  @<  @<  @<  @<  @<  @<  @<  @<  @<|
$letter, $c[1], $c[2], $c[3], $c[4], $c[5], $c[6], $c[7], $c[8], $c[9], $c[0]
.


# OK so now to the real code..

# initialize the map.
foreach $l ( 'A'..'Z' )
{
   foreach $n ( 0..9 )
   {
     $nanny{$l}{$n} =  '-';
   }
}

# ok, lets start.
# the usage is perl naany.pl FILENAME
# where FILENAME is the ADIF of your log.  Just export to ADIF and that's fine.

$file = shift;

# count how many naanies you have total
my $naanies = 0;


# open the file and begin parsing...

open(F, "< $file") || die "No file $file  $!\n";


# for each row of the ADIF log.
while ($x = <F>)
{

   # skip unless it's a QSO
   next unless $x =~ /^<Band/i;

   # skip unless it's for 2023
   next unless $x =~ /<QSO_DATE:8>2023/i;

   # skip unless it's not North America
   next unless $x !~ /<CONT:2>NA/i;

   # candidate NAANY entity.. so let's figure out the magic...

   $x =~ /<Call:\d+>([^\s]+)/;
   $call = $1;
  
   # rules state "last number and first letter" ... so this will do that, I think..
   $call =~ /(\d)([A-Z])/;
   $num = $1;
   $let = $2;


   # store it in the map
   if ($nanny{$let}{$num} eq '-' ) {
       $nanny{$let}{$num} = 'X';
       $naanies++;
   }
}


# parsing done.  Now let's print a report.

my $need = '';

foreach $letter (sort keys %nanny)
{
   @c = ( $nanny{$letter}{0}, $nanny{$letter}{1},
          $nanny{$letter}{2}, $nanny{$letter}{3}, $nanny{$letter}{4}, $nanny{$letter}{5},
          $nanny{$letter}{6}, $nanny{$letter}{7}, $nanny{$letter}{8}, $nanny{$letter}{9});
   write;
   foreach $i (0..9)
   {
     if ($nanny{$letter}{$i} eq '-') {
         $need .= "${i}${letter}\n";
     }
   }
} 

# summary
print "\n",
      "Worked   ", $naanies, "\n",
      "Unworked ",  260-$naanies, "\n",
      "\n",
      "Needed\n",
      $need, "\n";
