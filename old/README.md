# The NAANY Award Calculator


This is a Software tool to calculate the score of the NAANY award.

See [WWDXC NAANY Award](https://www.wwdxc.org/awards/naany/)


# The Software

The program is a console application.  It is not GUI, it has no user
window interface.  You execute it from the command line.

# How to Build it

1. Open the Solution in Visual Studio
2. Build


# How to use it.

1. Export your log into ADIF format.   All logging software can do this.
Just find the option to export your log and save it as ADI (ADIF) format.
2. Open a command prompt (In Windows, from the "Start" menu, just run "cmd")
3. From the Text based command shell, invoke this Software as follows:

```
naany.exe CONT FILE
```

Where `CONT` is the continent that you want to exclude -- yours.  So for
those in North America, the `CONT` value is `NA`.

The `FILE` parameter is the path to the ADIF file you exported.

So, if you saved your file as `my_log_file.adi`  then the invocation would be

```
naany.exe na my_log_file.adi
```

The name of the `CONT` is not case sensitive.  `NA` and `na` are the same
thing.

4.  The Software will run and compute your score.  Let it finish.
5.  The Software **does NOT modify** your log file.
6.  The Software will stop and yield the score after the 260 NAANY score
    is reached, or the end of the file is reached -- whichever is first.


# Modified Score

While the Software will compute your raw NAANY score (0-260), the Software
also adds a bit of competition by calculating an additional score.

The additional score is your NAANY score multiplied by the number of
unique bands and the number of unique continents from which you derived
your NAANY score.   The continent count and the band count are multipliers.

Use the modified score, or use the raw basic NAANY score -- the choice is
yours and the only arbiter of the score that matters is the 
Western Washington DX Club officials.  The Software does not represent
or have the authority to give you official ranking or score.

# Bugs

There is probably a few bugs in it, but I cannot see them right
at the moment.  We'll find out more through better testing with
different ADIF files that are run through.

As far as things to fix:

1.  Make the Application a GUI application.  Open the ADIF, and show
visually the progress towards full NAANY.
2.  Or, make the application web-based (preferred) except it involves some
PHP work to address how to process data files without saving them.  I don't
want to store any log files (nor have access to them really).  Log files
are personal.
3.  Decide if the application should be interactive (ask questions and
require settings made or just run freely).   I'f prefer it was not
a busy application and just runs freely.  The settings/configuration should
not be a complicated affair.
4.  Generate a filter string that can be cut-pasted into any Spotting Network tool (VE7CC, or whatever...) so that finding the missing NAANY combinations is easier.  Also, figure out how to produce a cut-paste string that can be provided
to JTAlert software since a lot of the entries are likely from FT-8/FT-4 etc..


# Disclaimer

Use the Software to just get your NAANY score from your log file.  
This Software in no way whatsoever grants the user title, privilege or
rank, status, award, or anything at all.  It's just a utility.. Have fun.


