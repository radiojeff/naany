# NAANY Calculator

This is a suite of scripts and HTML content that produces
a web based calculator for the WWDXC NAANY award.

The award is a count of the number of times a call-sign is logged
where the first number followed by a letter in the call-sign is counted.

W1ABC counts for 1A
K8BNM counts for 8B
and so on.

There are 260 such combinations.

The software here will accept the ADIF file exported by the user's log
program and analyze the log file.

The software here will produce web based content revealing the score of
the user as it relates to the calculation metrics of the NAANY award.

# Concept

The concept is simple.  When the user begins uploading a file, the
mechanism in the HTML relies on AJAX to make periodic polling of
PHP code to detect the progress.  When the file has been uploaded, 
a handler (handle-upload.php) performs the work against the uploaded file.

In this case, it parses the ADIF file.

When the parsing is done, a long array of data is returned as JSON back
to the AJAX asynchronous routine.   

After that successful callback, the dynamic content of the parent page
(index.html) is modified by adjusting the Style Class of certain elements
in the matrix (thus turning on/off the icons), and also dynamically populating
the text of certain `<DIV></DIV>` fields to suit.

The JSON bundle that comes out of the `handle-upload.php` is the key to
obtaining the results of the parse, therefore the results of whatever
action has taken place while parsing the ADIF file.

## Deployment

A suitable PHP environment is required.  Preferably 8.x or better.
It has not been tested on earlier versions of PHP.  It relies on the
uploadprogress extension.

## Credit

Credit to Ben Ramsey for the skeleton of the upload progress example.

[Upload Progress Example](https://github.com/php/pecl-php-uploadprogress/blob/master/examples/handle-upload.php)

Other changes were made by the author.
