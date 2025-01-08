# Known Issues

This is a list of known issues.

## WSJT-X

This software by itself does not log records with `<DXCC...` fields.  That field is required
so that the `naany` script can figure out what *continent* the call sign is from.

The `naany` software cannot reverse lookup the continent strictly by callsign.  It needs
the `DXCC` field to reverse lookup the **entity to the continent** as defined in the
[ARRL DXCC Table](https://www.arrl.org/files/file/DXCC/2022_DXCC_Current.pdf).

A careful reader will find that each entity has a specific continent.

`naany` has built in look up table for matching a Entity (DXCC number) to the Continent.

WSJT does not create ADIF records with the DXCC field.  If users configure their
peer logging software to receive the data from WSJT then the peer logger **usually** will
insert the QSO record in the peer logging software **with the DXCC** field.

The work-around is:

1.  Import your WSJT `.adi` file into a true logging program.
2.  Export it back out as ADIF.
3.  Use **that** export file.

Until WSJT can record the `<DXCC...` field, the `naany` cannot comprehend pure
WSJT log files.


## Limited Log Size

The known issue that is critical to fix is the handling of very long logs.

The AJAX/PHP sling-shot of data into the `handler`is getting wedged after about 30,000 records.

I don't know why exactly. A time out issue?  The skeleton from which this was based
wasn't expressive on the handling of very very large files.

If you know AJAX/PHP well (and a bit of JavaScript if that matters) -- then take a look and
see if you can find the bug?


## Peculiar ADIF formats

You'd think ADIF was immune to variants of format.  It seems not to be.

`<TOKEN:DIGIT+:N> VALUE`

or 

`<TOKEN:DIGIT+> VALUE`

Where `DIGIT` is one or more numbers.  Some ADIF formats suffix the length of the
value with `N`.  I haven't bothered to look up why.


