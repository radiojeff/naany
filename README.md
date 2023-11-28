# NAANY Calculator

This is a suite of scripts and HTML content that produces
a web based calculator for the WWDXC NAANY award.

The Western Washington DX Club sponsors this "award".
[NAANY Award](https://www.wwdxc.org/awards/naany/)

The award is a count of the number of times a call-sign is logged
where the first number followed by a letter in the call-sign is counted.

* W1ABC counts for 1A
* K8BNM counts for 8B
* and so on.

There are 260 such combinations.  As per the rules, pnly 250 QSO are needed for a single NAANY.

The software here will accept the ADIF file exported by the user's log
program and analyze the log file.

The software here will produce web based content revealing the score of
the user as it relates to the calculation metrics of the NAANY award.

# Concept

The concept is simple: 

* A user uploads an ADIF FILE
* The software `process.php` will calculate how many NAANY awards exist in the log file.
* A user must have 250 QSO per each NAANY. The software does not look for more than 250 QSO per NAANY.  Perhaps future versions will set a mode for Super-NAANY where each NAANY is fully 260 QSO (for each letter and number combination).  Not this version.
* The software counts how many DX entities are represented by the NAANY(s) calculated.
* The software computes a final score based on the multipler standard.
* The software generates a modest certificate showing the results.
* The software provides "CSV" data which can be copied and inserted into a spreadsheet to further research contacts needed.

## Deployment

A suitable PHP environment is required.  Preferably 8.x or better.
It has not been tested on earlier versions of PHP.  It relies on the
uploadprogress extension.

The software attempts to harden the system, but nothing is foolproof:  [Details](DEPLOY.md)


## CREDITS

The Orca Whale image is licensed under Creative Commons: [CREDITS](CREDITS.md)


