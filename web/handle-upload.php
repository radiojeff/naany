<?php

/*
  +----------------------------------------------------------------------+
  | Uploadprogress extension                                             |
  +----------------------------------------------------------------------+
  | Copyright (c) The PHP Group                                          |
  +----------------------------------------------------------------------+
  | This source file is subject to version 3.01 of the PHP license,      |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.php.net/license/3_01.txt.                                 |
  | If you did not receive a copy of the PHP license and are unable to   |
  | obtain it through the world-wide-web, please send a note to          |
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Author: Ben Ramsey (ramsey@php.net)                                  |
  +----------------------------------------------------------------------+
*/

// NOTE: This code is only executed after the entire file has finished uploading
// to the server. Once the last byte reaches the server, this script begins
// execution.

// If the request is not a POST, tell the client the method is not allowed. This
// is not required to use the uploadprogress extension. It is only here for the
// sake of example.
if (strtoupper($_SERVER['REQUEST_METHOD']) !== 'POST') {
    header('HTTP/1.1 405 Method Not Allowed');
    exit;
}

// If there are no files in the request, tell the client it made a bad request.
// Again, this is not required to use uploadprogress. It is used as an example.
if (count($_FILES) === 0) {
    header('HTTP/1.1 400 Bad Request');
    exit;
}

// There is no reason to process the file upload in this example, so we simply
// return with a 200 status code to tell the client we received the file. This
// is not a recommendation for how your application should respond. It is
// only for the sake of example.

//////////////////////////////////////////////////////////////////////////
//
// Below is the core of the handle-update function...
//
// This is going to get called by the parent AJAX async callback
// mechanism.

// Communication between this script and the parent
// that initiates the AJAX callback needs this PHP script
// and the essential message (aside from the data of course)
// is this signal of OK when the job is done.

$naany = array('status' => 'ok');

// Conversion between the DXCC ID number and the Continent
// (used to figure out if a contact in the QSO Log is in or not in
// the same continent as the user.
// This is a utility.  A hash map might even have worked just as
// well, but I already had the C++ version of this function written.

function dx2cont($dxid)
{
    // Given an ARRL DXCC ID number - translate to the ARRL Continent Name
    switch ($dxid)
    {
    case 247: return "AS";
    case 246: return "EU";
    case 260: return "EU";
    case 4: return "AF";
    case 165: return "AF";
    case 207: return "AF";
    case 49: return "AF";
    case 195: return "AF";
    case 176: return "OC";
    case 489: return "OC";
    case 460: return "OC";
    case 468: return "AF";
    case 474: return "AF";
    case 293: return "AS";
    case 107: return "AF";
    case 24: return "AF";
    case 199: return "AN";
    case 18: return "AS";
    case 75: return "AS";
    case 514: return "EU";
    case 315: return "AS";
    case 117: return "EU";
    case 289: return "NA";
    case 511: return "OC";
    case 336: return "AS";
    case 436: return "AF";
    case 215: return "AS";
    case 470: return "AF";
    case 450: return "AF";
    case 438: return "AF";
    case 444: return "AF";
    case 187: return "AF";
    case 483: return "AF";
    case 190: return "OC";
    case 286: return "AF";
    case 430: return "AF";
    case 456: return "AF";
    case 82: return "NA";
    case 492: return "AS";
    case 432: return "AF";
    case 440: return "AF";
    case 400: return "AF";
    case 62: return "NA";
    case 159: return "AS-AF";
    case 129: return "SA";
    case 497: return "EU";
    case 424: return "AF";
    case 257: return "EU";
    case 482: return "AF";
    case 348: return "AS";
    case 458: return "AF";
    case 299: return "AS";
    case 46: return "OC";
    case 369: return "AS";
    case 414: return "AF";
    case 404: return "AF";
    case 381: return "AS";
    case 454: return "AF";
    case 90: return "SA";
    case 402: return "AF";
    case 160: return "OC";
    case 370: return "AS";
    case 306: return "AS";
    case 391: return "AS";
    case 376: return "AS";
    case 304: return "AS";
    case 372: return "AS";
    case 318: return "AS";
    case 506: return "AS";
    case 386: return "AS";
    case 505: return "AS";
    case 157: return "OC";
    case 203: return "EU";
    case 422: return "AF";
    case 60: return "NA";
    case 181: return "AF";
    case 112: return "SA";
    case 47: return "SA";
    case 125: return "SA";
    case 217: return "SA";
    case 13: return "AN";
    case 70: return "NA";
    case 446: return "AF";
    case 104: return "SA";
    case 272: return "EU";
    case 256: return "AF";
    case 149: return "EU";
    case 144: return "SA";
    case 211: return "NA";
    case 252: return "NA";
    case 401: return "AF";
    case 409: return "AF";
    case 411: return "AF";
    case 230: return "EU";
    case 375: return "OC";
    case 51: return "AF";
    case 510: return "AS";
    case 191: return "OC";
    case 234: return "OC";
    case 188: return "OC";
    case 501: return "EU";
    case 281: return "EU";
    case 21: return "EU";
    case 29: return "AF";
    case 32: return "AF";
    case 245: return "EU";
    case 14: return "AS";
    case 434: return "AF";
    case 330: return "AS";
    case 179: return "EU";
    case 52: return "EU";
    case 53: return "AF";
    case 27: return "EU";
    case 135: return "AS";
    case 262: return "AS";
    case 280: return "AS";
    case 227: return "EU";
    case 79: return "NA";
    case 169: return "AF";
    case 516: return "NA";
    case 162: return "OC";
    case 512: return "OC";
    case 84: return "NA";
    case 508: return "OC";
    case 36: return "NA";
    case 175: return "OC";
    case 509: return "OC";
    case 277: return "NA";
    case 453: return "AF";
    case 99: return "AF";
    case 124: return "AF";
    case 276: return "AF";
    case 213: return "NA";
    case 41: return "AF";
    case 131: return "AF";
    case 10: return "AF";
    case 298: return "OC";
    case 63: return "SA";
    case 223: return "EU";
    case 114: return "EU";
    case 265: return "EU";
    case 122: return "EU";
    case 279: return "EU";
    case 106: return "EU";
    case 294: return "EU";
    case 185: return "OC";
    case 507: return "OC";
    case 239: return "EU";
    case 287: return "EU";
    case 251: return "EU";
    case 120: return "SA";
    case 71: return "SA";
    case 78: return "NA";
    case 72: return "NA";
    case 116: return "SA";
    case 161: return "SA";
    case 216: return "NA";
    case 137: return "AS";
    case 88: return "NA";
    case 80: return "NA";
    case 387: return "AS";
    case 295: return "EU";
    case 378: return "AS";
    case 248: return "EU";
    case 225: return "EU";
    case 382: return "AF";
    case 77: return "NA";
    case 109: return "AF";
    case 97: return "NA";
    case 95: return "NA";
    case 98: return "NA";
    case 339: return "AS";
    case 177: return "OC";
    case 192: return "AS";
    case 363: return "AS";
    case 259: return "EU";
    case 118: return "EU";
    case 342: return "AS";
    case 291: return "NA";
    case 105: return "NA";
    case 166: return "OC";
    case 20: return "OC";
    case 103: return "OC";
    case 123: return "OC";
    case 174: return "OC";
    case 197: return "OC";
    case 110: return "OC";
    case 138: return "OC";
    case 9: return "OC";
    case 515: return "OC";
    case 297: return "OC";
    case 6: return "NA";
    case 182: return "NA";
    case 285: return "NA";
    case 202: return "NA";
    case 43: return "NA";
    case 266: return "EU";
    case 100: return "SA";
    case 254: return "EU";
    case 146: return "EU";
    case 212: return "EU";
    case 136: return "SA";
    case 354: return "AS";
    case 206: return "EU";
    case 224: return "EU";
    case 5: return "EU";
    case 167: return "EU";
    case 503: return "EU";
    case 504: return "EU";
    case 209: return "EU";
    case 221: return "EU";
    case 237: return "NA";
    case 222: return "EU";
    case 163: return "OC";
    case 91: return "SA";
    case 344: return "AS";
    case 263: return "EU";
    case 517: return "SA";
    case 520: return "SA";
    case 519: return "NA";
    case 518: return "NA";
    case 108: return "SA";
    case 56: return "SA";
    case 253: return "SA";
    case 273: return "SA";
    case 140: return "SA";
    case 61: return "EU";
    case 302: return "AF";
    case 305: return "AS";
    case 499: return "EU";
    case 379: return "AF";
    case 219: return "AF";
    case 284: return "EU";
    case 269: return "EU";
    case 466: return "AF";
    case 478: return "AF";
    case 236: return "EU";
    case 180: return "EU";
    case 45: return "EU";
    case 40: return "EU";
    case 282: return "OC";
    case 301: return "OC";
    case 31: return "OC";
    case 48: return "OC";
    case 490: return "OC";
    case 232: return "AF";
    case 278: return "EU";
    case 22: return "OC";
    case 390: return "EU-AS";
    case 242: return "EU";
    case 76: return "NA";
    case 308: return "NA";
    case 37: return "NA";
    case 406: return "AF";
    case 214: return "EU";
    case 408: return "AF";
    case 412: return "AF";
    case 420: return "AF";
    case 410: return "AF";
    case 428: return "AF";
    case 416: return "AF";
    case 442: return "AF";
    case 54: return "EU";
    case 126: return "EU";
    case 15: return "AS";
    case 292: return "AS";
    case 130: return "AS";
    case 288: return "EU";
    case 94: return "NA";
    case 66: return "NA";
    case 249: return "NA";
    case 464: return "AF";
    case 173: return "OC";
    case 168: return "OC";
    case 345: return "OC";
    case 1: return "NA";
    case 150: return "OC";
    case 111: return "AF";
    case 153: return "OC";
    case 38: return "OC";
    case 147: return "OC";
    case 171: return "OC";
    case 189: return "OC";
    case 303: return "OC";
    case 35: return "OC";
    case 12: return "NA";
    case 96: return "NA";
    case 65: return "NA";
    case 89: return "NA";
    case 172: return "OC";
    case 513: return "OC";
    case 141: return "SA";
    case 235: return "SA";
    case 238: return "SA";
    case 240: return "SA";
    case 241: return "SA";
    case 64: return "NA";
    case 33: return "AF";
    case 321: return "AS";
    case 324: return "AS";
    case 11: return "AS";
    case 142: return "AS";
    case 50: return "NA";
    case 204: return "NA";
    case 480: return "AF";
    case 312: return "AS";
    case 143: return "AS";
    case 152: return "AS";
    case 309: return "AS";
    case 3: return "AS";
    case 327: return "OC";
    case 333: return "AS";
    case 158: return "OC";
    case 384: return "AS";
    case 145: return "EU";
    case 86: return "NA";
    case 275: return "EU";
    case 74: return "NA";
    case 296: return "EU";
    case 148: return "SA";
    case 17: return "NA";
    case 452: return "AF";
    case 502: return "EU";
    case 521: return "AF";
    case 7: return "EU";
    case 233: return "EU";
    case 283: return "AS";
    case 250: return "AF";
    case 205: return "AF";
    case 274: return "AF";
    case 69: return "NA";
    case 270: return "OC";
    case 170: return "OC";
    case 34: return "OC";
    case 133: return "OC";
    case 16: return "OC";
    case 132: return "SA";
    case 462: return "AF";
    case 201: return "AF";
    default: return "UN";
    }
}



$fileHandle = 0;
$naanies = 0;
$x = '';

// Useful list to do final summary report
$letar = array('A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z');
$numar = array('0', '1', '2', '3', '4', '5', '6', '7', '8', '9');

// It's slightly easier if we just fill the matrix with not-worked
// flags.
foreach ($letar as $let)
{
  foreach ($numar as $num)
  {
     $sk = "slot_" . "$num" . "$let";
     $naany[$sk] = '0'; // we haven't worked this combo, yet.
  }
}

// The continent from the user post data
// We get it from POST data, but we also send it back for the display.
$naany['mycont'] = $_POST['mycont'];

// A scratch pad for the list of callsigns that satisfied the job
$satisfied = "";

// OK, Let's start the ball rolling...

header('HTTP/1.1 200 OK');
header('Content-Type: application/json');

// Not ready to declare "success => ok" until we finish parsing
// the uploaded file.

if (is_uploaded_file($_FILES['uploadprogressFile']['tmp_name'])) 
{
    // This works only on the contacts in the Log for the current year.
    // Whatever that year is, we only care about the current year.
    $curYear = date('Y');

    // Open the file uploaded, and begin parsing.
    $fileHandle = fopen($_FILES['uploadprogressFile']['tmp_name'], 'r');

    // Line by line, read from the QSO ADIF Log
    while (($x = fgets($fileHandle)) !== false) 
    {
      // ADIF log files are ONE LINE per QSO.
      // ALL QSO on each line have a Band marker.  We don't
      // care what the band is, but we know a line with 'Band'
      // is a line with a potential QSO to investigate.
      if ( preg_match('/^<BAND/i', $x, $matches))
      {
      
      // ADIF puts the QSO_DATE field.  It's going to be YYYYMMDD
      // format. So we only care about the first four digits YYYY
      if ( preg_match("/<QSO_DATE:\d+>${curYear}.*/i", $x, $matches))
      {

      // Here we find the DXCC ID of the Log entry.
      // We cannot depend on the CONT field, but we can depend
      // on the DXCC field... so we grab the value. (captured)
      if (preg_match('/<DXCC:\d+>(\d+).*/i', $x, $matches))
      {
          // The candidate DXCC ID of this Log entry
          $thiscont = dx2cont($matches[1]);

       // If the continent of this entry is the same as the user
       // we skip it.
       if ( strcmp($thiscont,$naany['mycont']) != 0) 
       {

       // At this point we have a QSO with a station in the current
       // year and NOT in their continent.. so let's keep parsing

       // Candidate NAANY entity.. so let's figure out the magic...
       // We want the call sign of the contact
       if (preg_match('/<CALL:\d+>([^\s]+).*/i', $x, $matches))
       {
           $call = strtoupper($matches[1]);
           // Unlikely to fail but we want to make sure we have 
           // the first DIGIT LETTER match found.
           if (preg_match('/(\d)([A-Z])/i', $call, $matches)) 
           {
               $num = $matches[1];
               $let = $matches[2];
               // The key to the map is the ID of the table
               // cell that corresponds to the DIGIT LETTER
               $sk = "slot_" . "$num" . "$let";
               if (strcmp($naany[$sk],"0") == 0)
               {
                   $sk = "slot_" . "$num" . "$let";
                   $naany[$sk] = "X";
                   $naanies++;
                   $satisfied .= "$call satisfied $num$let\n";
                   // break out and go back to top of loop to
                   // examine next QSO in log.
                   continue;
               } // notworked
           } // got call
        } // has call
      } // my cont
      } // dxcc
      } // date
      } // band
    } // while reading lines

    // Done with the file so far...
    fclose($fileHandle);

    // There are only 260 possible (26 letters x 10 call areas)
    $unworked = 260 - $naanies;
    $naany['worked-count'] = "$naanies";
    $naany['unworked-count'] = "$unworked";
     

    // Scratch pad for the generation of the JSON data for "needed" combos
    $need = '';

    if ($naanies == 260)
    {
        // The need nothing. They worked them all.
        $need = 'None!';
    } 
    else
    {
        $pretty_print_needcount = 0;
        foreach ($letar as $let)
        {
            foreach ($numar as $num)
            {
               $sk = "slot_" . "$num" . "$let";
               if (strcmp($naany[$sk],"0") == 0) 
               {
                   $need .= "$num" . "$let" . " ";
                   $pretty_print_needcount++;
                   // Print 16 combo's per line
                   if ($pretty_print_needcount % 16 == 0) {
                        $need .= "\n";
                   }
               }
            }
        }
    }

    $naany['needed'] = "$need";
    $naany['satisfied'] = $satisfied;
    $naany['naanies'] = "$naanies";
} // checking if a file

// All data that is consumed by the AJAX async callback is now
// sent back to the caller.... Enjoy.
echo json_encode($naany);

