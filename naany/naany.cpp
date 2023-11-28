/*
This file is part of naany, a tool to compute WWDXC NAANY Awards.

This is open source licensed under the BSD 3-Claause License.

BSD 3-Clause License

Copyright (c) 2023, Jeff Wandling W7BRS, and contributors.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <iostream>
#include <string>
#include <fstream>
#include <regex>
#include <iterator>
#include <cctype>
#include <algorithm>
#include <ctime>

typedef enum Continents : int
{
    CONT_UNKNOWN,
    CONT_NA,
    CONT_SA,
    CONT_EU,
    CONT_AF,
    CONT_AS,
    CONT_OC,
    CONT_AN,
    CONT_AS_AF,
    CONT_EU_AS,
    CONT_NONE,
    CONT_LAST,
} Continents;

typedef enum Bands : int
{
    BAND_UNKNOWN,
    BAND_6,
    BAND_10,
    BAND_12,
    BAND_15,
    BAND_17,
    BAND_20,
    BAND_30,
    BAND_40,
    BAND_60,
    BAND_80,
    BAND_160,
    BAND_NONE,
    BAND_LAST
} Bands;

std::string ContinentName[] =
{
    std::string("UNKNOWN"),
    std::string("NA"), std::string("SA"), std::string("EU"),
    std::string("AF"), std::string("AS"), std::string("OC"),
    std::string("AN"), std::string("AS_AF"), std::string("EU_AS"),
    std::string("NONE")
};

std::string BandName[] = {
    std::string("Unk"),
    std::string("6m"),
    std::string("10m"),
    std::string("12m"),
    std::string("15m"),
    std::string("17m"),
    std::string("20m"),
    std::string("30m"),
    std::string("40m"),
    std::string("60m"),
    std::string("80m"),
    std::string("160m"),
    std::string("None")
};


int my_cont;
int my_year;
int show_help();
int dx2cont(int);
int by_continent[CONT_LAST];
int by_band[BAND_LAST];
int naany[260];
int naanies;
int band_number;
int cont_id;

void dump();
void apply_metrics();

bool ichar_equals(char a, char b)
{
    return std::tolower(static_cast<unsigned char>(a)) ==
           std::tolower(static_cast<unsigned char>(b));
}

bool iequals(const std::string& a, const std::string& b)
{
    return a.size() == b.size() &&
           std::equal(a.begin(), a.end(), b.begin(), ichar_equals);
}

int main(int argc, char** argv)
{
    argc--;
    argv++;

    if (argc == 0) {
        return show_help();
    }

    // we need to get some input from the user.
    // we need the continent that they are excluding.

    std::string expected_continent(argv[0]);
    argc--;
    argv++;

    // By default, continent is NA
    my_cont = CONT_NA;
    bool bFoundCont = false;
    for (int cont_id = Continents::CONT_UNKNOWN;
        cont_id < Continents::CONT_LAST;
        cont_id++)
    {
        if (iequals(expected_continent, ContinentName[cont_id]))
        {
            my_cont = cont_id;
            bFoundCont = true;
            break;
        }
    }

    if (!bFoundCont) {
        std::cerr << "No continent specified to exclude." << std::endl;
        return show_help();
    }

    std::time_t t = std::time(nullptr);
    std::tm* const pTInfo = std::localtime(&t);
    my_year = 1900 + pTInfo->tm_year;
    naanies = 0;
    memset(&by_continent[0], 0, sizeof(int) * CONT_LAST);
    memset(&by_band[0], 0, sizeof(int) * BAND_LAST);
    memset(&naany[0], 0, sizeof(int) * 260);
    std::string line;
    std::regex const band("<Band:[0-9]+>([0-9]+).*",
        std::regex_constants::extended | std::regex::icase);
    std::string qso_date_regex = ".*<QSO_DATE:8>";
    qso_date_regex += std::to_string(my_year);
    qso_date_regex += ".*";
    std::regex const qso_date(qso_date_regex.c_str(),
        std::regex_constants::extended | std::regex::icase);
    std::regex const call_sign(".*<Call:[0-9]+>([^ ]+).*",
        std::regex_constants::extended | std::regex::icase);
    std::regex const dxcc(".*<DXCC:[0-9]+>([0-9]+).*",
        std::regex_constants::extended | std::regex::icase);
    std::ifstream is;

    is.open(argv[0]);

    if (!is)
    {
        std::cerr << "Cannot open ADIF file " << argv[0] << std::endl;
        return show_help();
    }


    printf(
        "+=============================================+\n"
        "| Western Washington DX Club NAANY Award      |\n"
        "|                                             |\n"
        "| For Rules and Information go to:            |\n"
        "| https://www.wwdxc.org/awards/naany/         |\n"
        "| Award Creator: Jack Bock K7ZR               |\n" 
        "|                                             |\n"
        "| WWDXC Un-offcial NAANY CALCULATOR           |\n"
        "| This is open source.                        |\n"
        "| Licensed under the BSD 3-Clause License     |\n"
        "| https://github.com/radiojeff/naany          |\n"
        "| By Jeff Wandling, W7BRS                     |\n"
        "|                                             |\n"
        "| Lets begin scoring your log...              |\n"
        "| This may take a while.  Please wait...      |\n"
        "+=============================================+\n"
    );


    bool finished_naany = false;
    while (!finished_naany && std::getline(is, line))
    {
        std::smatch m;
        cont_id = CONT_UNKNOWN;
        band_number = 0;

        if (std::regex_match(line, m, band)) {
            std::string band_value(m[1]);
            band_number = std::strtol(band_value.c_str(), NULL, 10);
        }
        else {
            continue;
        }

        if (!std::regex_match(line, m, qso_date)) {
            continue;
        }

        if (std::regex_match(line, m, dxcc)) {
            std::string dxid_label = m[1];
            int dxcc_id = std::strtol(dxid_label.c_str(), NULL, 10);
            cont_id = dx2cont(dxcc_id);
            if (cont_id == my_cont) {
                continue;
            }
        }

        if (std::regex_match(line, m, call_sign))
        {
            std::string call(m[1]);
            char num = -1;
            char letter = '\0';
            int done = 0;

            for (std::string::iterator itr = call.begin();
                !done && itr != call.end(); ++itr)
            {
                char c = *itr;
                if (num >= 0)
                {
                    // we found a number already.
                    // did we get another number?
                    if (c >= '0' && c <= '9') {
                        // replace it.
                        num = c;
                        continue;
                    }
                    // c isn't a number, it's a letter.
                    // we already have a number, so this is the combo
                    // we are looking for.
                    else
                    {
                        letter = c;
                        done = 1;
                        int letter_index = letter - 'A';
                        int number_index = num - '0';
                        if ( (letter_index * number_index ) < 260)
                        {
                            if (naany[(26 * number_index) 
                                + letter_index] == 0)
                            {
                                // first one with this combo
                                naanies++;
                                std::cout << call << " satisfied "
                                    << num << letter
                                    << " #" << naanies
                                    << std::endl;
                                apply_metrics();

                                // Do not waste time.. 
                                // Just print the score since they got 260
                                if (naanies == 260) {
                                    finished_naany = true;
                                }
                            }
                            // just keep score for this combo
                            naany[(26 * number_index) + letter_index]++;
                        }
                        break;
                    }
                }
                // if we hadn't found a number before...
                // this is the first number.
                if (c >= '0' && c <= '9') {
                    num = c;
                    continue;
                }
                else {
                    // we skip until we find a number.
                }
            }
        }
    }
    is.close();
    dump();
    return 0;
}

void apply_metrics()
{
    by_continent[cont_id]++;
    switch(band_number)
    {
    case 6: by_band[BAND_6]++; break;
    case 10: by_band[BAND_10]++; break;
    case 12: by_band[BAND_12]++; break;
    case 15: by_band[BAND_15]++; break;
    case 17: by_band[BAND_17]++; break;
    case 20: by_band[BAND_20]++; break;
    case 30: by_band[BAND_30]++; break;
    case 40: by_band[BAND_40]++; break;
    case 60: by_band[BAND_60]++; break;
    case 80: by_band[BAND_80]++; break;
    case 160: by_band[BAND_160]++; break;
    default: by_band[BAND_NONE]++;
    }
}

void dump()
{
    // now print out the list.
    std::string needed;

    printf("\n    ");
    for (int i = 0; i < 10; i++) {
        printf(" %d ", i);
    }
    printf("\n----------------------------------\n");
    for (int i = 0; i < 26; i++)
    {
        // row-wise per letter
        printf("%c | ", 'A' + i);
        for (int j = 0; j < 10; j++)
        {
            printf(" %c ",
                naany[(26 * j) + i] > 0 ? 'Y' : ' ');

            if (naany[(26 * j) + i] < 1) 
            {
                // they need this combo.
                char needed_letter = 'A' + i;
                char needed_number = '0' + j;
                needed += needed_number;
                needed += needed_letter;
                needed += "\n";
            }
        }
        printf("\n");
    }

    if ( needed.length() > 0) 
    {
       printf("\nWhat you need:\n");
       printf("%s\n", needed.c_str());
    }
    printf("\n");
    printf("Summary:   %d worked,  %d unworked.", naanies, 260 - naanies);

    printf("\n\nDetails:\n\nBy Band:\n");
    printf("Band\tCount\n");
    printf("---------------------\n");
    int uniq_bands = 0;
    for (int i = BAND_6; i < BAND_160; i++)
    {
        if (by_band[i] > 0) {
            uniq_bands++;
        }
        printf("%s\t%d\n", BandName[i].c_str(), by_band[i]);
    }

    printf("\nBy Continent:\n");
    printf("Cont\tCount\n");
    printf("---------------------\n");
    int uniq_cont = 0;
    for (int i = CONT_NA; i < CONT_NONE; i++)
    {
        if (by_continent[i] > 0) {
            uniq_cont++;
        }
        printf("%s\t%d\n", ContinentName[i].c_str(), by_continent[i]);
    }

    printf("\n\nSCORE: NAANY [%d] * Continents [%d] * Bands [%d] = %d\n",
        naanies, uniq_cont, uniq_bands, naanies * uniq_cont * uniq_bands);

    printf("Thanks for playing.\n\n");
}

int show_help()
{
    std::cout << "Usage:\n"
        "naany.exe CONT FILE_NAME_OF_ADIF\n"
        "\n"
        "Continent CONT is one of NA, SA, EU, AF, AS, OC, AN, AS_AF, EU_AS\n"
        "FILE_NAME_OF_ADIF is the filename of your ADIF log\n"
        "\n"
        "Example:\n"
        "If you are in EU, use:\n"
        "    naany.exe EU FILE_NAME_OF_ADIF\n"
        "If you are in NA, use:\n"
        "    naany.exe NA FILE_NAME_OF_ADIF\n"
        "If yu are in the AS_AF, use:\n"
        "    naany.exe AS_AF FILE_NAME_OF_ADIF\n"
        "\n"
        "and so on...\n";
    return -1;
}

int dx2cont(int dxcc_id)
{
    switch (dxcc_id) {
    case 247: return CONT_AS;
    case 246: return CONT_EU;
    case 260: return CONT_EU;
    case 4: return CONT_AF;
    case 165: return CONT_AF;
    case 207: return CONT_AF;
    case 49: return CONT_AF;
    case 195: return CONT_AF;
    case 176: return CONT_OC;
    case 489: return CONT_OC;
    case 460: return CONT_OC;
    case 468: return CONT_AF;
    case 474: return CONT_AF;
    case 293: return CONT_AS;
    case 107: return CONT_AF;
    case 24: return CONT_AF;
    case 199: return CONT_AN;
    case 18: return CONT_AS;
    case 75: return CONT_AS;
    case 514: return CONT_EU;
    case 315: return CONT_AS;
    case 117: return CONT_EU;
    case 289: return CONT_NA;
    case 511: return CONT_OC;
    case 336: return CONT_AS;
    case 436: return CONT_AF;
    case 215: return CONT_AS;
    case 470: return CONT_AF;
    case 450: return CONT_AF;
    case 438: return CONT_AF;
    case 444: return CONT_AF;
    case 187: return CONT_AF;
    case 483: return CONT_AF;
    case 190: return CONT_OC;
    case 286: return CONT_AF;
    case 430: return CONT_AF;
    case 456: return CONT_AF;
    case 82: return CONT_NA;
    case 492: return CONT_AS;
    case 432: return CONT_AF;
    case 440: return CONT_AF;
    case 400: return CONT_AF;
    case 62: return CONT_NA;
    case 159: return CONT_AS_AF;
    case 129: return CONT_SA;
    case 497: return CONT_EU;
    case 424: return CONT_AF;
    case 257: return CONT_EU;
    case 482: return CONT_AF;
    case 348: return CONT_AS;
    case 458: return CONT_AF;
    case 299: return CONT_AS;
    case 46: return CONT_OC;
    case 369: return CONT_AS;
    case 414: return CONT_AF;
    case 404: return CONT_AF;
    case 381: return CONT_AS;
    case 454: return CONT_AF;
    case 90: return CONT_SA;
    case 402: return CONT_AF;
    case 160: return CONT_OC;
    case 370: return CONT_AS;
    case 306: return CONT_AS;
    case 391: return CONT_AS;
    case 376: return CONT_AS;
    case 304: return CONT_AS;
    case 372: return CONT_AS;
    case 318: return CONT_AS;
    case 506: return CONT_AS;
    case 386: return CONT_AS;
    case 505: return CONT_AS;
    case 157: return CONT_OC;
    case 203: return CONT_EU;
    case 422: return CONT_AF;
    case 60: return CONT_NA;
    case 181: return CONT_AF;
    case 112: return CONT_SA;
    case 47: return CONT_SA;
    case 125: return CONT_SA;
    case 217: return CONT_SA;
    case 13: return CONT_AN;
    case 70: return CONT_NA;
    case 446: return CONT_AF;
    case 104: return CONT_SA;
    case 272: return CONT_EU;
    case 256: return CONT_AF;
    case 149: return CONT_EU;
    case 144: return CONT_SA;
    case 211: return CONT_NA;
    case 252: return CONT_NA;
    case 401: return CONT_AF;
    case 409: return CONT_AF;
    case 411: return CONT_AF;
    case 230: return CONT_EU;
    case 375: return CONT_OC;
    case 51: return CONT_AF;
    case 510: return CONT_AS;
    case 191: return CONT_OC;
    case 234: return CONT_OC;
    case 188: return CONT_OC;
    case 501: return CONT_EU;
    case 281: return CONT_EU;
    case 21: return CONT_EU;
    case 29: return CONT_AF;
    case 32: return CONT_AF;
    case 245: return CONT_EU;
    case 14: return CONT_AS;
    case 434: return CONT_AF;
    case 330: return CONT_AS;
    case 179: return CONT_EU;
    case 52: return CONT_EU;
    case 53: return CONT_AF;
    case 27: return CONT_EU;
    case 135: return CONT_AS;
    case 262: return CONT_AS;
    case 280: return CONT_AS;
    case 227: return CONT_EU;
    case 79: return CONT_NA;
    case 169: return CONT_AF;
    case 516: return CONT_NA;
    case 162: return CONT_OC;
    case 512: return CONT_OC;
    case 84: return CONT_NA;
    case 508: return CONT_OC;
    case 36: return CONT_NA;
    case 175: return CONT_OC;
    case 509: return CONT_OC;
    case 277: return CONT_NA;
    case 453: return CONT_AF;
    case 99: return CONT_AF;
    case 124: return CONT_AF;
    case 276: return CONT_AF;
    case 213: return CONT_NA;
    case 41: return CONT_AF;
    case 131: return CONT_AF;
    case 10: return CONT_AF;
    case 298: return CONT_OC;
    case 63: return CONT_SA;
    case 223: return CONT_EU;
    case 114: return CONT_EU;
    case 265: return CONT_EU;
    case 122: return CONT_EU;
    case 279: return CONT_EU;
    case 106: return CONT_EU;
    case 294: return CONT_EU;
    case 185: return CONT_OC;
    case 507: return CONT_OC;
    case 239: return CONT_EU;
    case 287: return CONT_EU;
    case 251: return CONT_EU;
    case 120: return CONT_SA;
    case 71: return CONT_SA;
    case 78: return CONT_NA;
    case 72: return CONT_NA;
    case 116: return CONT_SA;
    case 161: return CONT_SA;
    case 216: return CONT_NA;
    case 137: return CONT_AS;
    case 88: return CONT_NA;
    case 80: return CONT_NA;
    case 387: return CONT_AS;
    case 295: return CONT_EU;
    case 378: return CONT_AS;
    case 248: return CONT_EU;
    case 225: return CONT_EU;
    case 382: return CONT_AF;
    case 77: return CONT_NA;
    case 109: return CONT_AF;
    case 97: return CONT_NA;
    case 95: return CONT_NA;
    case 98: return CONT_NA;
    case 339: return CONT_AS;
    case 177: return CONT_OC;
    case 192: return CONT_AS;
    case 363: return CONT_AS;
    case 259: return CONT_EU;
    case 118: return CONT_EU;
    case 342: return CONT_AS;
    case 291: return CONT_NA;
    case 105: return CONT_NA;
    case 166: return CONT_OC;
    case 20: return CONT_OC;
    case 103: return CONT_OC;
    case 123: return CONT_OC;
    case 174: return CONT_OC;
    case 197: return CONT_OC;
    case 110: return CONT_OC;
    case 138: return CONT_OC;
    case 9: return CONT_OC;
    case 515: return CONT_OC;
    case 297: return CONT_OC;
    case 6: return CONT_NA;
    case 182: return CONT_NA;
    case 285: return CONT_NA;
    case 202: return CONT_NA;
    case 43: return CONT_NA;
    case 266: return CONT_EU;
    case 100: return CONT_SA;
    case 254: return CONT_EU;
    case 146: return CONT_EU;
    case 212: return CONT_EU;
    case 136: return CONT_SA;
    case 354: return CONT_AS;
    case 206: return CONT_EU;
    case 224: return CONT_EU;
    case 5: return CONT_EU;
    case 167: return CONT_EU;
    case 503: return CONT_EU;
    case 504: return CONT_EU;
    case 209: return CONT_EU;
    case 221: return CONT_EU;
    case 237: return CONT_NA;
    case 222: return CONT_EU;
    case 163: return CONT_OC;
    case 91: return CONT_SA;
    case 344: return CONT_AS;
    case 263: return CONT_EU;
    case 517: return CONT_SA;
    case 520: return CONT_SA;
    case 519: return CONT_NA;
    case 518: return CONT_NA;
    case 108: return CONT_SA;
    case 56: return CONT_SA;
    case 253: return CONT_SA;
    case 273: return CONT_SA;
    case 140: return CONT_SA;
    case 61: return CONT_EU;
    case 302: return CONT_AF;
    case 305: return CONT_AS;
    case 499: return CONT_EU;
    case 379: return CONT_AF;
    case 219: return CONT_AF;
    case 284: return CONT_EU;
    case 269: return CONT_EU;
    case 466: return CONT_AF;
    case 478: return CONT_AF;
    case 236: return CONT_EU;
    case 180: return CONT_EU;
    case 45: return CONT_EU;
    case 40: return CONT_EU;
    case 282: return CONT_OC;
    case 301: return CONT_OC;
    case 31: return CONT_OC;
    case 48: return CONT_OC;
    case 490: return CONT_OC;
    case 232: return CONT_AF;
    case 278: return CONT_EU;
    case 22: return CONT_OC;
    case 390: return CONT_EU_AS;
    case 242: return CONT_EU;
    case 76: return CONT_NA;
    case 308: return CONT_NA;
    case 37: return CONT_NA;
    case 406: return CONT_AF;
    case 214: return CONT_EU;
    case 408: return CONT_AF;
    case 412: return CONT_AF;
    case 420: return CONT_AF;
    case 410: return CONT_AF;
    case 428: return CONT_AF;
    case 416: return CONT_AF;
    case 442: return CONT_AF;
    case 54: return CONT_EU;
    case 126: return CONT_EU;
    case 15: return CONT_AS;
    case 292: return CONT_AS;
    case 130: return CONT_AS;
    case 288: return CONT_EU;
    case 94: return CONT_NA;
    case 66: return CONT_NA;
    case 249: return CONT_NA;
    case 464: return CONT_AF;
    case 173: return CONT_OC;
    case 168: return CONT_OC;
    case 345: return CONT_OC;
    case 1: return CONT_NA;
    case 150: return CONT_OC;
    case 111: return CONT_AF;
    case 153: return CONT_OC;
    case 38: return CONT_OC;
    case 147: return CONT_OC;
    case 171: return CONT_OC;
    case 189: return CONT_OC;
    case 303: return CONT_OC;
    case 35: return CONT_OC;
    case 12: return CONT_NA;
    case 96: return CONT_NA;
    case 65: return CONT_NA;
    case 89: return CONT_NA;
    case 172: return CONT_OC;
    case 513: return CONT_OC;
    case 141: return CONT_SA;
    case 235: return CONT_SA;
    case 238: return CONT_SA;
    case 240: return CONT_SA;
    case 241: return CONT_SA;
    case 64: return CONT_NA;
    case 33: return CONT_AF;
    case 321: return CONT_AS;
    case 324: return CONT_AS;
    case 11: return CONT_AS;
    case 142: return CONT_AS;
    case 50: return CONT_NA;
    case 204: return CONT_NA;
    case 480: return CONT_AF;
    case 312: return CONT_AS;
    case 143: return CONT_AS;
    case 152: return CONT_AS;
    case 309: return CONT_AS;
    case 3: return CONT_AS;
    case 327: return CONT_OC;
    case 333: return CONT_AS;
    case 158: return CONT_OC;
    case 384: return CONT_AS;
    case 145: return CONT_EU;
    case 86: return CONT_NA;
    case 275: return CONT_EU;
    case 74: return CONT_NA;
    case 296: return CONT_EU;
    case 148: return CONT_SA;
    case 17: return CONT_NA;
    case 452: return CONT_AF;
    case 502: return CONT_EU;
    case 521: return CONT_AF;
    case 7: return CONT_EU;
    case 233: return CONT_EU;
    case 283: return CONT_AS;
    case 250: return CONT_AF;
    case 205: return CONT_AF;
    case 274: return CONT_AF;
    case 69: return CONT_NA;
    case 270: return CONT_OC;
    case 170: return CONT_OC;
    case 34: return CONT_OC;
    case 133: return CONT_OC;
    case 16: return CONT_OC;
    case 132: return CONT_SA;
    case 462: return CONT_AF;
    case 201: return CONT_AF;
    default: return CONT_UNKNOWN;
    }
}

