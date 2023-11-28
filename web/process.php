<?php
declare(strict_types=1);

/////////////////////////////////////////////////////////
// This software is licensed under BSD 3-Clause License
// Copyright (c) Jeff Wandling W7BRS
/////////////////////////////////////////////////////////

// A NAANY requires at least this many of the 260 possible digit+letter
// combinations filled -- not all 260.
const NAANY_THRESHOLD = 250;

/*
 * --- Abuse hardening -------------------------------------------------------
 * Anything uploaded as "logfile" that doesn't look like ADIF within its
 * first few KB is treated as hostile rather than a parsing problem: it's
 * logged in a fixed, fail2ban-matchable format and the request is rejected
 * immediately with a bare, uninformative response -- no detailed error page,
 * no attempt to parse further. See fail2ban/ in this project directory for
 * the matching filter + jail definitions (not installed automatically --
 * review and install them yourself, since a jail that bans on a false
 * positive can lock out real users, including you).
 *
 * Deployment requirement: this path must exist and be writable by whatever
 * user PHP runs as (e.g. www-data under php-fpm/Apache):
 *   sudo mkdir -p /var/log/naany
 *   sudo chown www-data:www-data /var/log/naany
 *   sudo chmod 750 /var/log/naany
 */
const NAANY_BADINPUT_LOG = '/var/log/naany/badinput.log';

// How many leading bytes of an upload to sniff before deciding it isn't
// ADIF. 8KB comfortably covers the first 20-40 lines of any normal log
// (header plus several QSO records), while bounding the cost of sniffing
// a huge or adversarial upload.
const NAANY_SNIFF_BYTES = 8192;

/**
 * REMOTE_ADDR only -- deliberately NOT trusting X-Forwarded-For or similar
 * client-supplied headers, since those are trivially spoofable unless this
 * app is known to sit behind a specific, trusted reverse proxy that strips
 * or overwrites them. If this is ever deployed behind such a proxy, this
 * is the one place to change to read the real client IP correctly.
 */
function client_ip(): string {
    return $_SERVER['REMOTE_ADDR'] ?? 'unknown';
}

/**
 * Strips newlines/control characters and truncates -- without this, a
 * value an attacker controls (callsign, filename, etc.) could inject fake
 * log lines or otherwise corrupt what fail2ban parses.
 */
function sanitize_log_field(string $value, int $maxLen = 80): string {
    $value = preg_replace('/[\x00-\x1F\x7F]+/', ' ', $value) ?? '';
    $value = trim($value);
    if (strlen($value) > $maxLen) {
        $value = substr($value, 0, $maxLen) . '...';
    }
    return $value === '' ? '-' : $value;
}

/**
 * Single-line, fixed-format log entry for fail2ban to match on. Best-effort:
 * if the log can't be written (missing directory, permissions), this must
 * never throw or block the reject path -- it just also logs to PHP's own
 * error log so the operator notices the logging setup is broken.
 */
function log_bad_input(string $reason): void {
    $line = sprintf(
        "[%s] NAANY_BADINPUT ip=%s reason=%s callsign=%s ua=%s\n",
        date('c'),
        client_ip(),
        sanitize_log_field($reason, 40),
        sanitize_log_field($_POST['callsign'] ?? '-', 20),
        sanitize_log_field($_SERVER['HTTP_USER_AGENT'] ?? '-', 100)
    );
    $written = @file_put_contents(NAANY_BADINPUT_LOG, $line, FILE_APPEND | LOCK_EX);
    if ($written === false) {
        error_log('NAANY_BADINPUT logging failed (check ' . NAANY_BADINPUT_LOG . ' permissions): ' . $line);
    }
}

/**
 * Logs and immediately rejects with a bare, uninformative response -- no
 * styled error page, no specific reason given back to the client. Suspected
 * hostile input gets nothing to work with.
 */
function reject_silently(string $logReason): void {
    log_bad_input($logReason);
    http_response_code(400);
    header('Content-Type: text/plain');
    echo "Bad Request\n";
    exit;
}

/**
 * Cheap, early sniff test for "is this even plausibly ADIF" -- not a real
 * parse. Binary content (NUL bytes) is an immediate red flag; otherwise,
 * every legitimate ADIF file contains <eoh> and/or <eor> tags, so their
 * total absence from the first NAANY_SNIFF_BYTES is a strong signal this
 * isn't ADIF at all (wrong file type, garbage, or a deliberate probe).
 */
function looks_like_adif(string $sample): bool {
    if (strpos($sample, "\0") !== false) {
        return false;
    }
    return (bool) preg_match('/<(eoh|eor)>/i', $sample);
}

/*
 * DXCC entity ID => entity name, per the ARRL "current + deleted entities"
 * list (402 entities total). Embedded directly so this script has no
 * runtime dependency on any external reference file.
 */
const DXCC_ENTITY_NAMES = [
    1 => 'Canada',
    2 => 'Abu Ail Is.',
    3 => 'Afghanistan',
    4 => 'Agalega & St. Brandon Is.',
    5 => 'Aland Is.',
    6 => 'Alaska',
    7 => 'Albania',
    8 => 'Aldabra',
    9 => 'American Samoa',
    10 => 'Amsterdam & St. Paul Is.',
    11 => 'Andaman & Nicobar Is.',
    12 => 'Anguilla',
    13 => 'Antarctica',
    14 => 'Armenia',
    15 => 'Asiatic Russia',
    16 => 'New Zealand Subantarctic Islands',
    17 => 'Aves I.',
    18 => 'Azerbaijan',
    19 => 'Bajo Nuevo',
    20 => 'Baker & Howland Is.',
    21 => 'Balearic Is.',
    22 => 'Palau',
    23 => 'Blenheim Reef',
    24 => 'Bouvet',
    25 => 'British North Borneo',
    26 => 'British Somaliland',
    27 => 'Belarus (Republic of)',
    28 => 'Canal Zone',
    29 => 'Canary Is.',
    30 => 'Celebe & Molucca Is.',
    31 => 'C. Kiribati (British Phoenix Is.)',
    32 => 'Ceuta & Melilla',
    33 => 'Chagos Is.',
    34 => 'Chatham Is.',
    35 => 'Christmas I.',
    36 => 'Clipperton I.',
    37 => 'Cocos I.',
    38 => 'Cocos (Keeling) Is.',
    39 => 'Comoros',
    40 => 'Crete',
    41 => 'Crozet I.',
    42 => 'Damao, Diu',
    43 => 'Desecheo I.',
    44 => 'Desroches',
    45 => 'Dodecanese',
    46 => 'East Malaysia',
    47 => 'Easter I.',
    48 => 'E. Kiribati (Line Is.)',
    49 => 'Equatorial Guinea',
    50 => 'Mexico',
    51 => 'Eritrea',
    52 => 'Estonia',
    53 => 'Ethiopia',
    54 => 'European Russia',
    55 => 'Farquhar',
    56 => 'Fernando de Noronha',
    57 => 'French Equatorial Africa',
    58 => 'French Indo-China',
    59 => 'French West Africa',
    60 => 'Bahamas (Commonwealth of the)',
    61 => 'Franz Josef Land',
    62 => 'Barbados',
    63 => 'French Guiana',
    64 => 'Bermuda',
    65 => 'British Virgin Is.',
    66 => 'Belize',
    67 => 'French India',
    68 => 'Kuwait/Saudi Arabia Neutral Zone',
    69 => 'Cayman Is.',
    70 => 'Cuba',
    71 => 'Galapagos Is.',
    72 => 'Dominican Republic',
    74 => 'El Salvador',
    75 => 'Georgia',
    76 => 'Guatemala',
    77 => 'Grenada',
    78 => 'Haiti',
    79 => 'Guadeloupe',
    80 => 'Honduras',
    81 => 'Germany',
    82 => 'Jamaica',
    84 => 'Martinique',
    85 => 'Bonaire, Curacao',
    86 => 'Nicaragua',
    88 => 'Panama',
    89 => 'Turks & Caicos Is.',
    90 => 'Trinidad & Tobago',
    91 => 'Aruba',
    93 => 'Geyser Reef',
    94 => 'Antigua & Barbuda',
    95 => 'Dominica',
    96 => 'Montserrat',
    97 => 'St. Lucia',
    98 => 'St. Vincent',
    99 => 'Glorioso Is.',
    100 => 'Argentina',
    101 => 'Goa',
    102 => 'Gold Coast, Togoland',
    103 => 'Guam',
    104 => 'Bolivia',
    105 => 'Guantanamo Bay',
    106 => 'Guernsey',
    107 => 'Guinea',
    108 => 'Brazil',
    109 => 'Guinea-Bissau',
    110 => 'Hawaii',
    111 => 'Heard I.',
    112 => 'Chile',
    113 => 'Ifni',
    114 => 'Isle of Man',
    115 => 'Italian Somaliland',
    116 => 'Colombia',
    117 => 'ITU HQ',
    118 => 'Jan Mayen',
    119 => 'Java',
    120 => 'Ecuador',
    122 => 'Jersey',
    123 => 'Johnston I.',
    124 => 'Juan de Nova, Europa',
    125 => 'Juan Fernandez Is.',
    126 => 'Kaliningrad',
    127 => 'Kamaran Is.',
    128 => 'Karelo-Finnish Republic',
    129 => 'Guyana',
    130 => 'Kazakhstan',
    131 => 'Kerguelen Is.',
    132 => 'Paraguay',
    133 => 'Kermadec Is.',
    134 => 'Kingman Reef',
    135 => 'Kyrgyz Republic',
    136 => 'Peru',
    137 => 'Korea (Republic of)',
    138 => 'Kure I.',
    139 => 'Kuria Muria I.',
    140 => 'Suriname',
    141 => 'Falkland Is.',
    142 => 'Lakshadweep Is.',
    143 => 'Lao People\'s Democratic Rep',
    144 => 'Uruguay',
    145 => 'Latvia',
    146 => 'Lithuania',
    147 => 'Lord Howe I.',
    148 => 'Venezuela',
    149 => 'Azores',
    150 => 'Australia',
    151 => 'Malyj Vysotskij I.',
    152 => 'Macao',
    153 => 'Macquarie I.',
    154 => 'Yemen Arab Republic',
    155 => 'Malaya',
    157 => 'Nauru',
    158 => 'Vanuatu',
    159 => 'Maldives',
    160 => 'Tonga',
    161 => 'Malpelo I.',
    162 => 'New Caledonia',
    163 => 'Papua New Guinea',
    164 => 'Manchuria',
    165 => 'Mauritius',
    166 => 'Mariana Is.',
    167 => 'Market Reef',
    168 => 'Marshall Is.',
    169 => 'Mayotte',
    170 => 'New Zealand',
    171 => 'Mellish Reef',
    172 => 'Pitcairn I.',
    173 => 'Micronesia',
    174 => 'Midway I.',
    175 => 'French Polynesia',
    176 => 'Fiji (Republic of)',
    177 => 'Minami Torishima',
    178 => 'Minerva Reef',
    179 => 'Moldova (Republic of)',
    180 => 'Mount Athos',
    181 => 'Mozambique',
    182 => 'Navassa I.',
    183 => 'Netherlands Borneo',
    184 => 'Netherlands New Guinea',
    185 => 'Solomon Is.',
    186 => 'Newfoundland, Labrador',
    187 => 'Niger',
    188 => 'Niue',
    189 => 'Norfolk I.',
    190 => 'Samoa',
    191 => 'North Cook Is.',
    192 => 'Ogasawara',
    193 => 'Okinawa (Ryukyu Is.)',
    194 => 'Okino Tori-shima',
    195 => 'Annobon I.',
    196 => 'Palestine',
    197 => 'Palmyra & Jarvis Is.',
    198 => 'Papua Territory',
    199 => 'Peter 1 I.',
    200 => 'Portuguese Timor',
    201 => 'Prince Edward & Marion Is.',
    202 => 'Puerto Rico',
    203 => 'Andorra',
    204 => 'Revillagigedo',
    205 => 'Ascension I.',
    206 => 'Austria',
    207 => 'Rodrigues I.',
    208 => 'Ruanda-Urundi',
    209 => 'Belgium',
    210 => 'Saar',
    211 => 'Sable I.',
    212 => 'Bulgaria',
    213 => 'Saint Martin',
    214 => 'Corsica',
    215 => 'Cyprus',
    216 => 'San Andres & Providencia',
    217 => 'San Felix & San Ambrosio',
    218 => 'Czechoslovakia',
    219 => 'Sao Tome & Principe',
    220 => 'Sarawak',
    221 => 'Denmark',
    222 => 'Faroe Is.',
    223 => 'United Kingdom of Great Britain',
    224 => 'Finland',
    225 => 'Sardinia',
    226 => 'Saudi Arabia/Iraq Neutral Zone',
    227 => 'France',
    228 => 'Serrana Bank & Roncador Cay',
    229 => 'German Democratic Republic',
    230 => 'Germany (Federal Rep of)',
    231 => 'Sikkim',
    232 => 'Somalia',
    233 => 'Gibraltar',
    234 => 'South Cook Is.',
    235 => 'South Georgia I.',
    236 => 'Greece',
    237 => 'Greenland',
    238 => 'South Orkney Is.',
    239 => 'Hungary',
    240 => 'South Sandwich Is.',
    241 => 'South Shetland Is.',
    242 => 'Iceland',
    243 => 'People\'s Democratic Rep. of Yemen',
    244 => 'Southern Sudan',
    245 => 'Ireland',
    246 => 'Sovereign Military Order of Malta',
    247 => 'Spratly Is.',
    248 => 'Italy',
    249 => 'St. Kitts & Nevis',
    250 => 'St. Helena',
    251 => 'Liechtenstein',
    252 => 'St. Paul I.',
    253 => 'St. Peter & St. Paul Rocks',
    254 => 'Luxembourg',
    255 => 'St. Maarten, Saba, St. Eustatius',
    256 => 'Madeira Is.',
    257 => 'Malta',
    258 => 'Sumatra',
    259 => 'Svalbard',
    260 => 'Monaco',
    261 => 'Swan Is.',
    262 => 'Tajikistan',
    263 => 'Netherlands',
    264 => 'Tangier',
    265 => 'Northern Ireland',
    266 => 'Norway',
    267 => 'Territory of New Guinea',
    268 => 'Tibet',
    269 => 'Poland',
    270 => 'Tokelau Is.',
    271 => 'Trieste',
    272 => 'Portugal',
    273 => 'Trindade & Martim Vaz Is.',
    274 => 'Tristan da Cunha & Gough I.',
    275 => 'Romania',
    276 => 'Tromelin I.',
    277 => 'St. Pierre & Miquelon',
    278 => 'San Marino',
    279 => 'Scotland',
    280 => 'Turkmenistan',
    281 => 'Spain',
    282 => 'Tuvalu',
    283 => 'UK Sovereign Base Areas on Cyprus',
    284 => 'Sweden',
    285 => 'Virgin Is.',
    286 => 'Uganda',
    287 => 'Switzerland',
    288 => 'Ukraine',
    289 => 'United Nations HQ',
    291 => 'United States of America',
    292 => 'Uzbekistan',
    293 => 'Viet Nam',
    294 => 'Wales',
    295 => 'Vatican',
    296 => 'Serbia',
    297 => 'Wake I.',
    298 => 'Wallis & Futuna Is.',
    299 => 'West Malaysia',
    301 => 'W. Kiribati (Gilbert Is. )',
    302 => 'Western Sahara',
    303 => 'Willis I.',
    304 => 'Bahrain',
    305 => 'Bangladesh',
    306 => 'Bhutan',
    307 => 'Zanzibar',
    308 => 'Costa Rica',
    309 => 'Myanmar',
    312 => 'Cambodia',
    315 => 'Sri Lanka',
    318 => 'China',
    321 => 'Hong Kong',
    324 => 'India',
    327 => 'Indonesia',
    330 => 'Iran (Islamic Repub of)',
    333 => 'Iraq',
    336 => 'Israel',
    339 => 'Japan',
    342 => 'Jordan',
    344 => 'Democratic People\'s Rep. of Korea',
    345 => 'Brunei Darussalam',
    348 => 'Kuwait',
    354 => 'Lebanon',
    363 => 'Mongolia',
    369 => 'Nepal',
    370 => 'Oman',
    372 => 'Pakistan (Islamic Rep of)',
    375 => 'Philippines',
    376 => 'Qatar',
    378 => 'Saudi Arabia',
    379 => 'Seychelles',
    381 => 'Singapore (Republic of)',
    382 => 'Djibouti',
    384 => 'Syrian Arab Republic',
    386 => 'Taiwan',
    387 => 'Thailand',
    390 => 'Republic of Turkiye',
    391 => 'United Arab Emirates',
    400 => 'Algeria (People\'s Dem Rep of)',
    401 => 'Angola',
    402 => 'Botswana (Republic of)',
    404 => 'Burundi',
    406 => 'Cameroon',
    408 => 'Central Africa',
    409 => 'Cabo Verde (Rep of)',
    410 => 'Chad',
    411 => 'Comoros',
    412 => 'Republic of the Congo',
    414 => 'Democratic Republic of the Congo',
    416 => 'Benin',
    420 => 'Gabon',
    422 => 'Gambia (Republic of the)',
    424 => 'Ghana',
    428 => 'Cote d\'Ivoire',
    430 => 'Kenya',
    432 => 'Lesotho',
    434 => 'Liberia',
    436 => 'Libya',
    438 => 'Madagascar',
    440 => 'Malawi',
    442 => 'Mali',
    444 => 'Mauritania',
    446 => 'Morocco (Kingdom of)',
    450 => 'Nigeria',
    452 => 'Zimbabwe',
    453 => 'Reunion I.',
    454 => 'Rwanda',
    456 => 'Senegal',
    458 => 'Sierra Leone',
    460 => 'Rotuma I.',
    462 => 'South Africa',
    464 => 'Namibia',
    466 => 'Sudan',
    468 => 'Kingdom of Eswatini',
    470 => 'Tanzania (United Republic of)',
    474 => 'Tunisia',
    478 => 'Egypt',
    480 => 'Burkina Faso',
    482 => 'Zambia',
    483 => 'Togo',
    488 => 'Walvis Bay',
    489 => 'Conway Reef',
    490 => 'Banaba I. (Ocean I.)',
    492 => 'Yemen',
    493 => 'Penguin Is.',
    497 => 'Croatia',
    499 => 'Slovenia',
    501 => 'Bosnia-Herzegovina',
    502 => 'North Macedonia (Republic of)',
    503 => 'Czech Republic',
    504 => 'Slovak Republic',
    505 => 'Pratas I.',
    506 => 'Scarborough Reef',
    507 => 'Temotu Province',
    508 => 'Austral I.',
    509 => 'Marquesas Is.',
    510 => 'Palestine',
    511 => 'Timor-Leste',
    512 => 'Chesterfield Is.',
    513 => 'Ducie I.',
    514 => 'Montenegro',
    515 => 'Swains I.',
    516 => 'Saint Barthelemy',
    517 => 'Curacao',
    518 => 'Sint Maarten',
    519 => 'Saba & St. Eustatius',
    520 => 'Bonaire',
    521 => 'South Sudan (Republic of)',
    522 => 'Republic of Kosovo',
];

/*
 * DXCC entity ID => continent code (NA/SA/EU/AS/AF/OC/AN; a few
 * continent-straddling entities use "XX-YY"). Sourced from cont-to-dxcc,
 * which only covers currently-active entities (deleted/historical ones
 * are intentionally absent -- treated as "continent unknown" at lookup
 * time rather than guessed).
 */
const DXCC_CONTINENT = [
    1 => 'NA',
    3 => 'AS',
    4 => 'AF',
    5 => 'EU',
    6 => 'NA',
    7 => 'EU',
    9 => 'OC',
    10 => 'AF',
    11 => 'AS',
    12 => 'NA',
    13 => 'AN',
    14 => 'AS',
    15 => 'AS',
    16 => 'OC',
    17 => 'NA',
    18 => 'AS',
    20 => 'OC',
    21 => 'EU',
    22 => 'OC',
    24 => 'AF',
    27 => 'EU',
    29 => 'AF',
    31 => 'OC',
    32 => 'AF',
    33 => 'AF',
    34 => 'OC',
    35 => 'OC',
    36 => 'NA',
    37 => 'NA',
    38 => 'OC',
    40 => 'EU',
    41 => 'AF',
    43 => 'NA',
    45 => 'EU',
    46 => 'OC',
    47 => 'SA',
    48 => 'OC',
    49 => 'AF',
    50 => 'NA',
    51 => 'AF',
    52 => 'EU',
    53 => 'AF',
    54 => 'EU',
    56 => 'SA',
    60 => 'NA',
    61 => 'EU',
    62 => 'NA',
    63 => 'SA',
    64 => 'NA',
    65 => 'NA',
    66 => 'NA',
    69 => 'NA',
    70 => 'NA',
    71 => 'SA',
    72 => 'NA',
    74 => 'NA',
    75 => 'AS',
    76 => 'NA',
    77 => 'NA',
    78 => 'NA',
    79 => 'NA',
    80 => 'NA',
    82 => 'NA',
    84 => 'NA',
    86 => 'NA',
    88 => 'NA',
    89 => 'NA',
    90 => 'SA',
    91 => 'SA',
    94 => 'NA',
    95 => 'NA',
    96 => 'NA',
    97 => 'NA',
    98 => 'NA',
    99 => 'AF',
    100 => 'SA',
    103 => 'OC',
    104 => 'SA',
    105 => 'NA',
    106 => 'EU',
    107 => 'AF',
    108 => 'SA',
    109 => 'AF',
    110 => 'OC',
    111 => 'AF',
    112 => 'SA',
    114 => 'EU',
    116 => 'SA',
    117 => 'EU',
    118 => 'EU',
    120 => 'SA',
    122 => 'EU',
    123 => 'OC',
    124 => 'AF',
    125 => 'SA',
    126 => 'EU',
    129 => 'SA',
    130 => 'AS',
    131 => 'AF',
    132 => 'SA',
    133 => 'OC',
    135 => 'AS',
    136 => 'SA',
    137 => 'AS',
    138 => 'OC',
    140 => 'SA',
    141 => 'SA',
    142 => 'AS',
    143 => 'AS',
    144 => 'SA',
    145 => 'EU',
    146 => 'EU',
    147 => 'OC',
    148 => 'SA',
    149 => 'EU',
    150 => 'OC',
    152 => 'AS',
    153 => 'OC',
    157 => 'OC',
    158 => 'OC',
    159 => 'AS-AF',
    160 => 'OC',
    161 => 'SA',
    162 => 'OC',
    163 => 'OC',
    165 => 'AF',
    166 => 'OC',
    167 => 'EU',
    168 => 'OC',
    169 => 'AF',
    170 => 'OC',
    171 => 'OC',
    172 => 'OC',
    173 => 'OC',
    174 => 'OC',
    175 => 'OC',
    176 => 'OC',
    177 => 'OC',
    179 => 'EU',
    180 => 'EU',
    181 => 'AF',
    182 => 'NA',
    185 => 'OC',
    187 => 'AF',
    188 => 'OC',
    189 => 'OC',
    190 => 'OC',
    191 => 'OC',
    192 => 'AS',
    195 => 'AF',
    197 => 'OC',
    199 => 'AN',
    201 => 'AF',
    202 => 'NA',
    203 => 'EU',
    204 => 'NA',
    205 => 'AF',
    206 => 'EU',
    207 => 'AF',
    209 => 'EU',
    211 => 'NA',
    212 => 'EU',
    213 => 'NA',
    214 => 'EU',
    215 => 'AS',
    216 => 'NA',
    217 => 'SA',
    219 => 'AF',
    221 => 'EU',
    222 => 'EU',
    223 => 'EU',
    224 => 'EU',
    225 => 'EU',
    227 => 'EU',
    230 => 'EU',
    232 => 'AF',
    233 => 'EU',
    234 => 'OC',
    235 => 'SA',
    236 => 'EU',
    237 => 'NA',
    238 => 'SA',
    239 => 'EU',
    240 => 'SA',
    241 => 'SA',
    242 => 'EU',
    245 => 'EU',
    246 => 'EU',
    247 => 'AS',
    248 => 'EU',
    249 => 'NA',
    250 => 'AF',
    251 => 'EU',
    252 => 'NA',
    253 => 'SA',
    254 => 'EU',
    256 => 'AF',
    257 => 'EU',
    259 => 'EU',
    260 => 'EU',
    262 => 'AS',
    263 => 'EU',
    265 => 'EU',
    266 => 'EU',
    269 => 'EU',
    270 => 'OC',
    272 => 'EU',
    273 => 'SA',
    274 => 'AF',
    275 => 'EU',
    276 => 'AF',
    277 => 'NA',
    278 => 'EU',
    279 => 'EU',
    280 => 'AS',
    281 => 'EU',
    282 => 'OC',
    283 => 'AS',
    284 => 'EU',
    285 => 'NA',
    286 => 'AF',
    287 => 'EU',
    288 => 'EU',
    289 => 'NA',
    291 => 'NA',
    292 => 'AS',
    293 => 'AS',
    294 => 'EU',
    295 => 'EU',
    296 => 'EU',
    297 => 'OC',
    298 => 'OC',
    299 => 'AS',
    301 => 'OC',
    302 => 'AF',
    303 => 'OC',
    304 => 'AS',
    305 => 'AS',
    306 => 'AS',
    308 => 'NA',
    309 => 'AS',
    312 => 'AS',
    315 => 'AS',
    318 => 'AS',
    321 => 'AS',
    324 => 'AS',
    327 => 'OC',
    330 => 'AS',
    333 => 'AS',
    336 => 'AS',
    339 => 'AS',
    342 => 'AS',
    344 => 'AS',
    345 => 'OC',
    348 => 'AS',
    354 => 'AS',
    363 => 'AS',
    369 => 'AS',
    370 => 'AS',
    372 => 'AS',
    375 => 'OC',
    376 => 'AS',
    378 => 'AS',
    379 => 'AF',
    381 => 'AS',
    382 => 'AF',
    384 => 'AS',
    386 => 'AS',
    387 => 'AS',
    390 => 'EU-AS',
    391 => 'AS',
    400 => 'AF',
    401 => 'AF',
    402 => 'AF',
    404 => 'AF',
    406 => 'AF',
    408 => 'AF',
    409 => 'AF',
    410 => 'AF',
    411 => 'AF',
    412 => 'AF',
    414 => 'AF',
    416 => 'AF',
    420 => 'AF',
    422 => 'AF',
    424 => 'AF',
    428 => 'AF',
    430 => 'AF',
    432 => 'AF',
    434 => 'AF',
    436 => 'AF',
    438 => 'AF',
    440 => 'AF',
    442 => 'AF',
    444 => 'AF',
    446 => 'AF',
    450 => 'AF',
    452 => 'AF',
    453 => 'AF',
    454 => 'AF',
    456 => 'AF',
    458 => 'AF',
    460 => 'OC',
    462 => 'AF',
    464 => 'AF',
    466 => 'AF',
    468 => 'AF',
    470 => 'AF',
    474 => 'AF',
    478 => 'AF',
    480 => 'AF',
    482 => 'AF',
    483 => 'AF',
    489 => 'OC',
    490 => 'OC',
    492 => 'AS',
    497 => 'EU',
    499 => 'EU',
    501 => 'EU',
    502 => 'EU',
    503 => 'EU',
    504 => 'EU',
    505 => 'AS',
    506 => 'AS',
    507 => 'OC',
    508 => 'OC',
    509 => 'OC',
    510 => 'AS',
    511 => 'OC',
    512 => 'OC',
    513 => 'OC',
    514 => 'EU',
    515 => 'OC',
    516 => 'NA',
    517 => 'SA',
    518 => 'NA',
    519 => 'NA',
    520 => 'SA',
    521 => 'AF',
    522 => 'EU', // Kosovo -- newest entity, not yet in the source cont-to-dxcc fragment
];

/*
 * DXCC entity ID => customary/recognizable callsign prefix (e.g. 150 =>
 * 'VK' for Australia). Sourced from Current_Deleted.txt's official Prefix
 * column, then hand-corrected where the list's first-listed option wasn't
 * the prefix operators actually recognize (e.g. the raw list's first
 * option for the USA is 'K', for Canada is 'VA', for Germany is 'DA' --
 * corrected here to 'W', 'VE', 'DL'). Used only for the grid-cell display
 * text in the NAANY report; contact lists still show the numeric DXCC ID.
 */
const DXCC_PREFIXES = [
    1 => 'VE',
    2 => 'J2/A',
    3 => 'YA',
    4 => '3B6',
    5 => 'OH0',
    6 => 'KL',
    7 => 'ZA',
    8 => 'VQ9',
    9 => 'KH8',
    10 => 'FT',
    11 => 'VU4',
    12 => 'VP2E',
    13 => 'CE9',
    14 => 'EK',
    15 => 'UA',
    16 => 'ZL9',
    17 => 'YV0',
    18 => '4J',
    19 => 'HK0',
    20 => 'KH1',
    21 => 'EA6',
    22 => 'T8',
    23 => '1B',
    24 => '3Y',
    25 => 'ZC5',
    26 => 'VQ6',
    27 => 'EU',
    28 => 'KZ5',
    29 => 'EA8',
    30 => 'PK6',
    31 => 'T31',
    32 => 'EA9',
    33 => 'VQ9',
    34 => 'ZL7',
    35 => 'VK9',
    36 => 'FO',
    37 => 'TI9',
    38 => 'VK9',
    39 => 'FH',
    40 => 'SV9',
    41 => 'FT',
    42 => 'CR8',
    43 => 'KP5',
    44 => 'VQ9',
    45 => 'SV5',
    46 => '9M6',
    47 => 'CE0',
    48 => 'T32',
    49 => '3C',
    50 => 'XE',
    51 => 'E3',
    52 => 'ES',
    53 => 'ET',
    54 => 'UA',
    55 => 'VQ9',
    56 => 'PP0',
    57 => 'FQ8',
    58 => 'FI8',
    59 => 'FF',
    60 => 'C6',
    61 => 'R1',
    62 => '8P',
    63 => 'FY',
    64 => 'VP9',
    65 => 'VP2V',
    66 => 'V3',
    67 => 'FN8',
    68 => '8Z5',
    69 => 'ZF',
    70 => 'CL',
    71 => 'HC8',
    72 => 'HI',
    74 => 'YS',
    75 => '4L',
    76 => 'TG',
    77 => 'J3',
    78 => 'HH',
    79 => 'FG',
    80 => 'HQ',
    81 => 'DL',
    82 => '6Y',
    84 => 'FM',
    85 => 'PJ',
    86 => 'YN',
    88 => 'HO',
    89 => 'VP5',
    90 => '9Y',
    91 => 'P4',
    93 => '1G',
    94 => 'V2',
    95 => 'J7',
    96 => 'VP2M',
    97 => 'J6',
    98 => 'J8',
    99 => 'FT',
    100 => 'LO',
    101 => 'CR8',
    102 => 'ZD4',
    103 => 'KH2',
    104 => 'CP',
    105 => 'KG4',
    106 => 'GU',
    107 => '3X',
    108 => 'PP',
    109 => 'J5',
    110 => 'KH6',
    111 => 'VK',
    112 => 'CA',
    113 => 'EA9',
    114 => 'GD',
    115 => 'I5',
    116 => 'HJ',
    117 => '4U',
    118 => 'JX',
    119 => 'PK1',
    120 => 'HC',
    122 => 'GJ',
    123 => 'KH3',
    124 => 'FT',
    125 => 'CE0',
    126 => 'UA2',
    127 => 'VS9K',
    128 => 'UN1',
    129 => '8R',
    130 => 'UN',
    131 => 'FT',
    132 => 'ZP',
    133 => 'ZL8',
    134 => 'KH5K',
    135 => 'EX',
    136 => 'OA',
    137 => 'HL',
    138 => 'KH7K',
    139 => 'VS9H',
    140 => 'PZ',
    141 => 'VP8',
    142 => 'VU7',
    143 => 'XW',
    144 => 'CV',
    145 => 'YL',
    146 => 'LY',
    147 => 'VK2',
    148 => 'YV',
    149 => 'CU',
    150 => 'VK',
    151 => 'R1',
    152 => 'XX9',
    153 => 'VK7',
    154 => '4W',
    155 => 'VS2',
    157 => 'C2',
    158 => 'YJ',
    159 => '8Q',
    160 => 'A3',
    161 => 'HK0',
    162 => 'FK',
    163 => 'P2',
    164 => 'C9',
    165 => '3B8',
    166 => 'KH0',
    167 => 'OJ0',
    168 => 'V7',
    169 => 'FH',
    170 => 'ZK',
    171 => 'VK9',
    172 => 'VP6',
    173 => 'V6',
    174 => 'KH4',
    175 => 'FO',
    176 => '3D2',
    177 => 'JD1',
    178 => '1M',
    179 => 'ER',
    180 => 'SV',
    181 => 'C8',
    182 => 'KP1',
    183 => 'PK5',
    184 => 'JZ0',
    185 => 'H4',
    186 => 'VO',
    187 => '5U',
    188 => 'E6',
    189 => 'VK9',
    190 => '5W',
    191 => 'E5',
    192 => 'JD1',
    193 => 'KR6',
    194 => '7J1',
    195 => '3C0',
    196 => 'ZC6',
    197 => 'KH5',
    198 => 'P2',
    199 => '3Y',
    200 => 'CR8',
    201 => 'ZS8',
    202 => 'KP3',
    203 => 'C3',
    204 => 'XA4',
    205 => 'ZD8',
    206 => 'OE',
    207 => '3B9',
    208 => '9U5',
    209 => 'ON',
    210 => '9S4',
    211 => 'CY0',
    212 => 'LZ',
    213 => 'FS',
    214 => 'TK',
    215 => '5B',
    216 => 'HK0',
    217 => 'CE0',
    218 => 'OK',
    219 => 'S9',
    220 => 'VS4',
    221 => 'OU',
    222 => 'OY',
    223 => 'G',
    224 => 'OF',
    225 => 'IS0',
    226 => '8Z4',
    227 => 'F',
    228 => 'HK0',
    229 => 'DM',
    230 => 'DA',
    231 => 'AC3',
    232 => 'T5',
    233 => 'ZB2',
    234 => 'E5',
    235 => 'VP0',
    236 => 'SV',
    237 => 'OX',
    238 => 'VP0',
    239 => 'HA',
    240 => 'VP0',
    241 => 'VP0',
    242 => 'TF',
    243 => 'VS9A',
    244 => 'ST0',
    245 => 'EI',
    246 => '1A',
    247 => '1S',
    248 => 'I',
    249 => 'V4',
    250 => 'ZD7',
    251 => 'HB0',
    252 => 'CY9',
    253 => 'PP0',
    254 => 'LX',
    255 => 'PJ',
    256 => 'CT3',
    257 => '9H',
    258 => 'PK4',
    259 => 'JW',
    260 => '3A',
    261 => 'KS4',
    262 => 'EY',
    263 => 'PA',
    264 => 'CN2',
    265 => 'GI',
    266 => 'LA',
    267 => 'P2',
    268 => 'AC4',
    269 => 'SN',
    270 => 'ZK3',
    271 => 'I1',
    272 => 'CQ',
    273 => 'PP0',
    274 => 'ZD9',
    275 => 'YO',
    276 => 'FT',
    277 => 'FP',
    278 => 'T7',
    279 => 'GM',
    280 => 'EZ',
    281 => 'EA',
    282 => 'T2',
    283 => 'ZC4',
    284 => 'SA',
    285 => 'KP2',
    286 => '5X',
    287 => 'HB',
    288 => 'UR',
    289 => '4U',
    291 => 'W',
    292 => 'UJ',
    293 => '3W',
    294 => 'GW',
    295 => 'HV',
    296 => 'YT',
    297 => 'KH9',
    298 => 'FW',
    299 => '9M2',
    301 => 'T30',
    302 => 'S0',
    303 => 'VK9',
    304 => 'A9',
    305 => 'S2',
    306 => 'A5',
    307 => 'VQ1',
    308 => 'TI',
    309 => 'XY',
    312 => 'XU',
    315 => '4P',
    318 => 'B',
    321 => 'VR',
    324 => 'VU',
    327 => 'YB',
    330 => 'EP',
    333 => 'YI',
    336 => '4X',
    339 => 'JA',
    342 => 'JY',
    344 => 'P5',
    345 => 'V8',
    348 => '9K',
    354 => 'OD',
    363 => 'JT',
    369 => '9N',
    370 => 'A4',
    372 => 'AP',
    375 => 'DU',
    376 => 'A7',
    378 => 'HZ',
    379 => 'S7',
    381 => '9V',
    382 => 'J2',
    384 => 'YK',
    386 => 'BU',
    387 => 'HS',
    390 => 'TA',
    391 => 'A6',
    400 => '7R',
    401 => 'D2',
    402 => 'A2',
    404 => '9U',
    406 => 'TJ',
    408 => 'TL',
    409 => 'D4',
    410 => 'TT',
    411 => 'D6',
    412 => 'TN',
    414 => '9O',
    416 => 'TY',
    420 => 'TR',
    422 => 'C5',
    424 => '9G',
    428 => 'TU',
    430 => '5Y',
    432 => '7P',
    434 => 'EL',
    436 => '5A',
    438 => '5R',
    440 => '7Q',
    442 => 'TZ',
    444 => '5T',
    446 => 'CN',
    450 => '5N',
    452 => 'Z2',
    453 => 'FR',
    454 => '9X',
    456 => '6V',
    458 => '9L',
    460 => '3D2',
    462 => 'ZR',
    464 => 'V5',
    466 => 'ST',
    468 => '3DA',
    470 => '5H',
    474 => '3V',
    478 => 'SU',
    480 => 'XT',
    482 => '9I',
    483 => '5V',
    488 => 'ZS9',
    489 => '3D2',
    490 => 'T33',
    492 => '7O',
    493 => 'ZS0',
    497 => '9A',
    499 => 'S5',
    501 => 'E7',
    502 => 'Z3',
    503 => 'OK',
    504 => 'OM',
    505 => 'BV9P',
    506 => 'BS7',
    507 => 'H40',
    508 => 'FO',
    509 => 'FO',
    510 => 'E4',
    511 => '4W',
    512 => 'FK',
    513 => 'VP6',
    514 => '4O',
    515 => 'KH8',
    516 => 'FJ',
    517 => 'PJ2',
    518 => 'PJ7',
    519 => 'PJ5',
    520 => 'PJ4',
    521 => 'Z8',
    522 => 'Z6',
];

const CONTINENT_NAMES = [
    'NA' => 'North America',
    'SA' => 'South America',
    'EU' => 'Europe',
    'AS' => 'Asia',
    'AF' => 'Africa',
    'OC' => 'Oceania',
    'AN' => 'Antarctica',
];

const QSO_CANDIDATE = 'candidate';
const QSO_SAME_CONTINENT = 'same_continent';
const QSO_CONTINENT_UNKNOWN = 'continent_unknown';

/**
 * Resolve whether a DXCC entity's continent membership includes the
 * operator's home continent. A few entities straddle two continents
 * (e.g. "AS-AF") and count as being in both. Returns null -- "unknown",
 * not "false" -- for entities absent from DXCC_CONTINENT (deleted/historical
 * entities that cont-to-dxcc doesn't cover), since we don't want to guess.
 */
function is_home_in_continent_lookup_by_dxcc_id(int $dxccId, string $homeContinent): ?bool {
    if (!isset(DXCC_CONTINENT[$dxccId])) {
        return null;
    }
    $continents = explode('-', DXCC_CONTINENT[$dxccId]);
    return in_array($homeContinent, $continents, true);
}

/**
 * NAANY requires DX contacts -- a QSO with a station on the operator's own
 * continent can never count toward a cell, regardless of whether it's the
 * operator's own specific DXCC entity.
 */
function is_qso_candidate(string $dxcc, string $homeContinent): string {
    $inHomeContinent = is_home_in_continent_lookup_by_dxcc_id((int) $dxcc, $homeContinent);
    if ($inHomeContinent === null) {
        return QSO_CONTINENT_UNKNOWN;
    }
    return $inHomeContinent ? QSO_SAME_CONTINENT : QSO_CANDIDATE;
}

const MODE_CW = 'CW';
const MODE_PHONE = 'Phone';
const MODE_DIGITAL = 'Digital';
const MODE_UNKNOWN = 'Unknown';

// Phone covers every voice mode variant loggers actually write to ADIF's
// MODE field -- SSB is the modern value, but USB/LSB/AM/FM still show up
// directly in real-world logs. Digital is deliberately the catch-all: new
// digital modes appear constantly (FT8, FT4, JS8, ...), so anything that
// isn't CW or a recognized phone mode is treated as digital rather than
// requiring an ever-growing whitelist. A blank/missing MODE field is the
// only thing that falls through to Unknown.
const MODE_PHONE_VALUES = ['SSB', 'USB', 'LSB', 'AM', 'FM'];

function naany_mode_category(string $mode): string {
    $mode = strtoupper(trim($mode));
    if ($mode === '') {
        return MODE_UNKNOWN;
    }
    if ($mode === 'CW') {
        return MODE_CW;
    }
    if (in_array($mode, MODE_PHONE_VALUES, true)) {
        return MODE_PHONE;
    }
    return MODE_DIGITAL;
}

/*
 * Isolation: each HTTP request is its own independent PHP execution.
 * As long as this script never writes to a shared file, session, or
 * cache, one upload can never become visible to another request —
 * no extra locking or per-user directories are needed for that.
 *
 * No persistence: we only read PHP's own auto-managed temp copy of the
 * upload (tmp_name) and let PHP delete it when the request ends. This
 * script never calls move_uploaded_file() and never writes its own copy.
 */

function fail(string $message): void {
    http_response_code(400);
    echo '<!doctype html><html lang="en"><head><meta charset="utf-8">';
    echo '<title>Upload Error</title></head><body>';
    echo '<h1>Upload Error</h1><p>' . htmlspecialchars($message) . '</p>';
    echo '<p><a href="index.html">Try again</a></p>';
    echo '</body></html>';
    exit;
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    fail('This endpoint only accepts file uploads via POST.');
}

// The form only ever sends these three POST fields (the log itself travels
// via $_FILES, not $_POST). Anything else showing up is form tampering --
// extra fields stuffed in by a script, not something a real browser
// submission of this form could ever produce -- so it's treated the same
// as hostile upload content, not a normal validation failure.
const EXPECTED_POST_FIELDS = ['year', 'callsign', 'home_continent'];
$unexpectedFields = array_diff(array_keys($_POST), EXPECTED_POST_FIELDS);
if ($unexpectedFields !== []) {
    $fieldList = implode(',', array_map(
        static fn($f) => sanitize_log_field((string) $f, 20),
        $unexpectedFields
    ));
    reject_silently('unexpected-post-field:' . $fieldList);
}

if (!isset($_FILES['logfile'])) {
    fail('No file field named "logfile" was submitted.');
}

if (!isset($_POST['year']) || !ctype_digit($_POST['year']) || strlen($_POST['year']) !== 4) {
    fail('A 4-digit year is required.');
}
$targetYear = $_POST['year'];

if (!isset($_POST['callsign']) || trim($_POST['callsign']) === '') {
    fail('Your callsign is required.');
}
$operatorCallsign = strtoupper(trim($_POST['callsign']));

// No real amateur radio callsign has ever been issued anywhere near this
// long (the longest known real-world callsigns top out around 12
// characters); this is generous headroom, not a realistic limit, so
// exceeding it is a strong, cheap signal of a hostile/scripted submission
// rather than an honest typo.
if (strlen($operatorCallsign) > 16) {
    reject_silently('callsign-too-long');
}

const VALID_CONTINENTS = ['NA', 'SA', 'EU', 'AS', 'AF', 'OC', 'AN'];

if (!isset($_POST['home_continent']) || !in_array($_POST['home_continent'], VALID_CONTINENTS, true)) {
    fail('Your home continent is required.');
}
$homeContinent = $_POST['home_continent'];

$sealThreshold = NAANY_THRESHOLD;

$upload = $_FILES['logfile'];

if ($upload['error'] !== UPLOAD_ERR_OK) {
    $messages = [
        UPLOAD_ERR_INI_SIZE   => 'The file exceeds the server upload size limit.',
        UPLOAD_ERR_FORM_SIZE  => 'The file exceeds the form upload size limit.',
        UPLOAD_ERR_PARTIAL    => 'The file was only partially uploaded.',
        UPLOAD_ERR_NO_FILE    => 'No file was uploaded.',
        UPLOAD_ERR_NO_TMP_DIR => 'Server is missing a temporary folder.',
        UPLOAD_ERR_CANT_WRITE => 'Server failed to write the temporary file.',
        UPLOAD_ERR_EXTENSION  => 'A server extension blocked the upload.',
    ];
    fail($messages[$upload['error']] ?? 'Unknown upload error.');
}

if (!is_uploaded_file($upload['tmp_name'])) {
    fail('Upload validation failed.');
}

$handle = fopen($upload['tmp_name'], 'r');
if ($handle === false) {
    fail('Could not open the uploaded file for reading.');
}

$sniff = fread($handle, NAANY_SNIFF_BYTES);
if ($sniff === false || !looks_like_adif($sniff)) {
    reject_silently('not-adif');
}
rewind($handle);

/*
 * NAANY cell rule: strip any "/..." portable / call-area suffix first
 * (it is not part of the callsign), then find the LAST digit in what
 * remains and pair it with the letter immediately following it.
 * Returns null if the (stripped) call has no digit, or no letter
 * immediately follows the last digit.
 */
function naany_cell(string $baseCall): ?string {
    $lastDigitPos = -1;
    $len = strlen($baseCall);
    for ($i = 0; $i < $len; $i++) {
        if (ctype_digit($baseCall[$i])) {
            $lastDigitPos = $i;
        }
    }
    if ($lastDigitPos === -1 || $lastDigitPos + 1 >= $len) {
        return null;
    }
    $letter = $baseCall[$lastDigitPos + 1];
    if (!ctype_alpha($letter)) {
        return null;
    }
    return $baseCall[$lastDigitPos] . strtoupper($letter);
}

/*
 * Parse one ADIF record's field content into NAME => value pairs.
 * ADIF tags are <FIELDNAME:LENGTH> or <FIELDNAME:LENGTH:TYPE>, and the
 * value is exactly LENGTH bytes immediately after the closing '>' —
 * not delimited by the next '<', per the ADIF spec.
 */
function parse_adif_record(string $record): array {
    $fields = [];
    $offset = 0;
    $len = strlen($record);
    while ($offset < $len) {
        $ltPos = strpos($record, '<', $offset);
        if ($ltPos === false) {
            break;
        }
        $gtPos = strpos($record, '>', $ltPos);
        if ($gtPos === false) {
            break;
        }
        $tagContent = substr($record, $ltPos + 1, $gtPos - $ltPos - 1);
        $parts = explode(':', $tagContent);
        $name = strtoupper(trim($parts[0]));

        if (isset($parts[1]) && ctype_digit($parts[1])) {
            $valueLen = (int) $parts[1];
            $value = substr($record, $gtPos + 1, $valueLen);
            if ($name !== '') {
                $fields[$name] = $value;
            }
            $offset = $gtPos + 1 + $valueLen;
        } else {
            // Zero-length / typeless marker tag — nothing to consume as a value.
            $offset = $gtPos + 1;
        }
    }
    return $fields;
}

// --- Read the whole upload once ---------------------------------------------
// Records are delimited by <EOR> tags, NOT by newlines.
$data = stream_get_contents($handle);
fclose($handle);
if ($data === false) {
    fail('Could not read the uploaded file.');
}

$eohPos = stripos($data, '<eoh>');
$eorPosFirst = stripos($data, '<eor>');
if ($eohPos !== false && ($eorPosFirst === false || $eohPos < $eorPosFirst)) {
    $data = substr($data, $eohPos + 5);
}

$rawRecords = preg_split('/<eor>/i', $data);
array_pop($rawRecords); // trailing text after the final <EOR> (if any) is discarded

$digits = str_split('0123456789');
$letters = range('A', 'Z');

// --- Main record loop --------------------------------------------------------

$recordCount = 0;
$malformedRecords = 0;
$missingDxccRecords = 0;
$homeContinentRecords = 0;
$unknownContinentRecords = 0;
$inYearCallCount = 0;
$seenBaseCalls = [];
$candidates = []; // flat, file-order list of ['call'=>, 'cell'=>, 'dxcc'=>]

foreach ($rawRecords as $recordText) {
    $fields = parse_adif_record($recordText);
    $recordCount++;

    $call = isset($fields['CALL']) ? strtoupper(trim($fields['CALL'])) : '';
    $qsoDate = isset($fields['QSO_DATE']) ? trim($fields['QSO_DATE']) : '';
    $dxcc = isset($fields['DXCC']) ? trim($fields['DXCC']) : '';
    $modeCategory = naany_mode_category($fields['MODE'] ?? '');

    do {
        if ($call === '' || strlen($qsoDate) < 8) {
            $malformedRecords++;
            break;
        }

        $year = substr($qsoDate, 0, 4);
        if ($year !== $targetYear) {
            break;
        }
        $inYearCallCount++;

        if ($dxcc === '') {
            $missingDxccRecords++;
            break;
        }

        $candidacy = is_qso_candidate($dxcc, $homeContinent);
        if ($candidacy === QSO_SAME_CONTINENT) {
            $homeContinentRecords++;
            break;
        }
        if ($candidacy === QSO_CONTINENT_UNKNOWN) {
            $unknownContinentRecords++;
            break;
        }

        $slashPos = strpos($call, '/');
        $baseCall = $slashPos !== false ? substr($call, 0, $slashPos) : $call;
        if ($baseCall === '') {
            break;
        }

        if (isset($seenBaseCalls[$baseCall])) {
            break; // repeat contact with a call already credited — no new evidence
        }
        $seenBaseCalls[$baseCall] = true;

        $cell = naany_cell($baseCall);
        if ($cell === null) {
            break;
        }

        $candidates[] = ['call' => $baseCall, 'cell' => $cell, 'dxcc' => $dxcc, 'mode' => $modeCategory];
    } while (false);
}

// --- NAANY scoring -----------------------------------------------------------
// 260 possible cells: digit 0-9 paired with letter A-Z. NAANYs are built
// sequentially, one at a time, directly off the file-ordered $candidates list:
// scan from the start, filling the current NAANY's still-empty cells one by
// one; a candidate whose cell is *already* filled for the current NAANY is a
// duplicate combination for this round -- it's skipped, not discarded. The
// instant the current NAANY reaches $sealThreshold (250) filled cells, it is
// sealed immediately and no further candidates are added to it, even if more
// are available. The next NAANY then re-scans the *same* candidate list from
// the beginning, skipping only candidates a prior NAANY actually consumed --
// so anything skipped as a duplicate is never lost, only deferred to whichever
// later NAANY needs it. This guarantees no candidate is ever used in more
// than one NAANY, and a complete NAANY never shows more than the 250 cells it
// actually needed.

$allCells = [];
foreach ($digits as $d) {
    foreach ($letters as $l) {
        $allCells[] = $d . $l;
    }
}

$candidateUsed = array_fill(0, count($candidates), false);
$slateFilled = []; // NAANY number => [cell => ['call' => ..., 'dxcc' => ...]]
$maxLayers = 0;
$partialFilled = [];

while (true) {
    $filled = [];
    foreach ($candidates as $i => $candidate) {
        if ($candidateUsed[$i]) {
            continue; // already consumed by an earlier, sealed NAANY
        }
        $cell = $candidate['cell'];
        if (isset($filled[$cell])) {
            continue; // duplicate combination this round -- deferred, not discarded
        }
        $filled[$cell] = $candidate;
        $candidateUsed[$i] = true;
        if (count($filled) >= $sealThreshold) {
            break; // sealed -- stop adding to this NAANY
        }
    }

    if (count($filled) < $sealThreshold) {
        $partialFilled = $filled;
        break;
    }

    $maxLayers++;
    $slateFilled[$maxLayers] = $filled;

    if (!in_array(false, $candidateUsed, true)) {
        break; // nothing left unused at all -- the partial NAANY is empty
    }
}

$partialLayer = $maxLayers + 1;
$naanyEarned = $maxLayers >= 1;
$distinctWorkedCalls = count($seenBaseCalls);

// How many of the 260 cells does each complete NAANY actually cover, and
// which ones went unneeded? (A complete NAANY always has exactly 250 filled,
// unless the final pass used up every remaining candidate before sealing.)
$layerFilledCells = [];  // layer => [cell, ...] that have a candidate
$layerMissingCells = []; // layer => [cell, ...] that don't
for ($layer = 1; $layer <= $maxLayers; $layer++) {
    $filledList = [];
    $missingList = [];
    foreach ($allCells as $cell) {
        if (isset($slateFilled[$layer][$cell])) {
            $filledList[] = $cell;
        } else {
            $missingList[] = $cell;
        }
    }
    $layerFilledCells[$layer] = $filledList;
    $layerMissingCells[$layer] = $missingList;
}

// --- NAANY CC: DXCC entity diversity, best among all complete NAANYs -------
$naanyCC = null; // null = no complete NAANY yet, so this isn't measurable
$bestCCLayer = null; // which layer achieved $naanyCC -- the certificate showcases this one
for ($layer = 1; $layer <= $maxLayers; $layer++) {
    $entities = [];
    foreach ($slateFilled[$layer] as $qso) {
        $entities[$qso['dxcc']] = true;
    }
    if ($naanyCC === null || count($entities) > $naanyCC) {
        $naanyCC = count($entities);
        $bestCCLayer = $layer;
    }
}

// --- Mode-category breakdown: NAANY CC split into CW / Phone / Digital ----
// Same idea as NAANY CC, but counted separately within each mode bucket for
// the same slate -- a QSO's mode never changes which cell or DXCC entity it
// supplies, so this is just a finer-grained view of a slate already built.
function naany_mode_breakdown(array $slate): array {
    $counts = [MODE_CW => 0, MODE_PHONE => 0, MODE_DIGITAL => 0, MODE_UNKNOWN => 0];
    $entities = [MODE_CW => [], MODE_PHONE => [], MODE_DIGITAL => [], MODE_UNKNOWN => []];
    foreach ($slate as $qso) {
        $cat = $qso['mode'];
        $counts[$cat]++;
        $entities[$cat][$qso['dxcc']] = true;
    }
    $result = [];
    foreach ($counts as $cat => $n) {
        $result[$cat] = ['cells' => $n, 'cc' => count($entities[$cat])];
    }
    return $result;
}

$layerModeBreakdown = []; // layer => [category => ['cells' => ..., 'cc' => ...]]
for ($layer = 1; $layer <= $maxLayers; $layer++) {
    $layerModeBreakdown[$layer] = naany_mode_breakdown($slateFilled[$layer]);
}
$partialModeBreakdown = naany_mode_breakdown($partialFilled);

$dxccNames = DXCC_ENTITY_NAMES;

// --- Certificate prep ---------------------------------------------------
// The certificate showcases the single best (most DX-diverse) complete
// NAANY slate, if any was earned at all.
$reportGeneratedAt = date('F j, Y');
$certOperator = $operatorCallsign;

$certEndorsement = 'Mixed Mode';
if ($naanyEarned) {
    $certModeBreakdown = $layerModeBreakdown[$bestCCLayer];
    if ($certModeBreakdown[MODE_CW]['cells'] === $sealThreshold) {
        $certEndorsement = 'All CW';
    } elseif ($certModeBreakdown[MODE_PHONE]['cells'] === $sealThreshold) {
        $certEndorsement = 'All SSB';
    }
}

// --- NAANY Score: reduces the whole result to a single comparable number ---
// maxLayers * NAANY_CC * threshold rewards both breadth (how many NAANYs)
// and diversity (how many distinct DXCC entities), scaled by how hard the
// chosen mode is (250 vs. 260). Partial-NAANY QSOs are added as a small
// tiebreaker/progress bonus on top. When maxLayers is 0 that first term is
// multiplied by zero and vanishes on its own -- no separate zero-NAANY
// formula is needed, and since a partial's QSO count is always < threshold
// (that's what makes it a partial, not a seal), zero complete NAANYs can
// never out-score even a single one: 1 * 1 * threshold already exceeds any
// possible partial QSO count.
$naanyScore = $maxLayers * ($naanyCC ?? 0) * $sealThreshold + count($partialFilled);

?><!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>NAANY Upload Report v1.6</title>
  <style>
    body { font-family: system-ui, sans-serif; margin: 2rem; }
    table { border-collapse: collapse; margin-bottom: 1.5rem; }
    th, td { border: 1px solid #000; padding: 4px 8px; text-align: center; }
    th { background: #eee; }
    .summary th { text-align: left; }
    .grid { table-layout: fixed; }
    .grid th, .grid td { width: 34px; }
    .grid td { height: 24px; font-size: 0.65rem; padding: 1px; box-sizing: border-box; font-variant-numeric: tabular-nums; overflow: hidden; white-space: nowrap; }
    .grid td.filled { background: #d4f7d4; }
    .grid td.empty { background: #f9d6d6; }
    .missing td { font-variant-numeric: tabular-nums; }
    .status-panel { display: flex; gap: 2.5rem; align-items: flex-start; flex-wrap: wrap; margin-bottom: 1.5rem; }
    .status-panel table.summary { margin-bottom: 0; }
    .explainer { max-width: 32rem; }
    .score-explainer { max-width: 42rem; margin-bottom: 1.5rem; }
    .explainer p { margin-top: 0; }
    .legend { list-style: none; margin: 0.5rem 0 0; padding: 0; }
    .legend li { display: flex; align-items: center; gap: 0.6rem; margin-bottom: 0.4rem; }
    .swatch { display: inline-flex; align-items: center; justify-content: center; width: 28px; height: 20px; border: 1px solid #000; font-size: 0.65rem; font-variant-numeric: tabular-nums; }
    .swatch.filled { background: #d4f7d4; }
    .swatch.empty { background: #f9d6d6; }
    .contact-list { list-style: none; margin: 0 0 1.5rem; padding: 0; }
    .contact-list li { padding: 1px 0; }
  </style>
  <style>
    /* --- Certificate --------------------------------------------------
       Plain HTML has no notion of a "page" -- that concept only exists in
       print/PDF rendering. CSS supplies it via break-after (and the older,
       more widely-supported page-break-after alias). Wrapping the
       certificate in its own container and forcing a break after it means
       the rest of the report starts on a fresh printed page instead of
       running on directly beneath the certificate -- so printing just the
       first page prints only the certificate. No visible effect on screen.
    */
    .cert-page { page-break-after: always; break-after: page; }
    @page { size: landscape; margin: 0.5in; }

    :root {
      --cert-bg: #f0f3ed;
      --cert-ink: #10140f;
      --cert-accent: #1f4d36;
      --cert-accent-light: #4c7a5e;
    }
    .cert-page { font-family: Georgia, 'Times New Roman', serif; color: var(--cert-ink); }
    .certificate {
      max-width: 7in;
      margin: 2rem auto;
      font-size: 0.78em;
      background: var(--cert-bg);
      border: 2px solid var(--cert-accent);
      outline: 1px solid var(--cert-accent-light);
      outline-offset: -14px;
      padding: 3em 3.5em;
      position: relative;
      overflow: hidden;
      box-shadow: 0 10px 30px rgba(0, 0, 0, 0.35);
    }
    /* Faded background image -- public-domain/CC-licensed orca illustration
       (see img-lic.txt for attribution), converted to grayscale and shown
       at low opacity as a watermark. Drawn first in document order so it
       naturally sits beneath all later content without needing z-index. */
    .cert-bg {
      position: absolute;
      inset: 0;
      background-repeat: no-repeat;
      background-position: center;
      background-size: contain;
      opacity: 0.14;
      pointer-events: none;
    }
    .cert-corner {
      position: absolute;
      width: 2.2em;
      height: 2.2em;
      font-size: 1.6em;
      color: var(--cert-accent);
      line-height: 1;
    }
    .cert-corner.tl { top: 0.6em; left: 0.6em; }
    .cert-corner.tr { top: 0.6em; right: 0.6em; }
    .cert-corner.bl { bottom: 0.6em; left: 0.6em; }
    .cert-corner.br { bottom: 0.6em; right: 0.6em; }
    .cert-sponsor {
      text-align: center;
      font-size: 1.35em;
      font-weight: bold;
      letter-spacing: 0.1em;
      text-transform: uppercase;
      color: var(--cert-accent);
      position: relative;
    }
    .cert-title {
      text-align: center;
      font-family: 'Trajan Pro', Georgia, serif;
      font-variant: small-caps;
      font-size: 2.6em;
      margin: 0.3em 0 0;
      color: var(--cert-ink);
      letter-spacing: 0.04em;
      position: relative;
    }
    .cert-full-name {
      text-align: center;
      font-style: italic;
      font-size: 1.1em;
      margin: 0.2em 0 1.6em;
      color: #2f4a3a;
      position: relative;
    }
    .cert-presented-to {
      text-align: center;
      font-size: 1em;
      text-transform: uppercase;
      letter-spacing: 0.1em;
      color: #2f4a3a;
      margin-bottom: 0.3em;
      position: relative;
    }
    .cert-recipient {
      text-align: center;
      font-family: Georgia, 'Times New Roman', serif;
      font-weight: bold;
      font-size: 2.9em;
      letter-spacing: 0.08em;
      color: var(--cert-ink);
      margin: 0 0 0.3em;
      position: relative;
    }
    .cert-score {
      text-align: center;
      margin: 0 0 1.4em;
      position: relative;
    }
    .cert-score .cert-score-value {
      display: block;
      font-family: Georgia, 'Times New Roman', serif;
      font-weight: bold;
      font-size: 2.3em;
      letter-spacing: 0.04em;
      color: var(--cert-accent);
    }
    .cert-score .cert-score-label {
      display: block;
      font-size: 0.75em;
      text-transform: uppercase;
      letter-spacing: 0.12em;
      color: #2f4a3a;
      margin-top: 0.1em;
    }
    .cert-body-text {
      text-align: center;
      max-width: 90%;
      margin: 0 auto 1.4em;
      line-height: 1.6;
      font-size: 1.02em;
      position: relative;
    }
    .cert-body-text strong { color: var(--cert-ink); }
    .cert-stats {
      display: flex;
      justify-content: center;
      gap: 2.5em;
      margin: 1.4em 0;
      flex-wrap: wrap;
      position: relative;
    }
    .cert-stat { text-align: center; }
    .cert-stat .cert-value {
      font-size: 1.8em;
      font-weight: bold;
      color: var(--cert-accent);
      display: block;
    }
    .cert-stat .cert-label {
      font-size: 0.75em;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: #2f4a3a;
    }
    .cert-endorsement { text-align: center; margin: 0.4em 0 1.6em; position: relative; }
    .cert-endorsement .cert-ribbon {
      display: inline-block;
      padding: 0.35em 1.4em;
      border: 1px solid var(--cert-accent);
      border-radius: 999px;
      font-size: 0.85em;
      letter-spacing: 0.12em;
      text-transform: uppercase;
      color: var(--cert-accent);
      background: rgba(31, 77, 54, 0.08);
    }
    .cert-mode-breakdown {
      text-align: center;
      font-size: 0.85em;
      color: #2f4a3a;
      margin-bottom: 2em;
      position: relative;
    }
    .cert-signatures {
      display: flex;
      justify-content: space-between;
      align-items: flex-end;
      margin-top: 2.5em;
      padding: 0 1em;
      position: relative;
    }
    .cert-sig-block { text-align: center; width: 40%; }
    .cert-sig-line {
      border-top: 1px solid var(--cert-ink);
      margin-bottom: 0.3em;
      height: 2.2em;
      display: flex;
      align-items: flex-end;
      justify-content: center;
      font-family: 'Brush Script MT', cursive;
      font-size: 1.3em;
    }
    .cert-sig-label {
      font-size: 0.75em;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: #2f4a3a;
    }
    .cert-seal {
      position: absolute;
      right: 3.5em;
      bottom: 9.5em;
      width: 5.5em;
      height: 5.5em;
      border-radius: 50%;
      border: 2px solid var(--cert-accent);
      outline: 1px dashed var(--cert-accent-light);
      outline-offset: -6px;
      display: flex;
      align-items: center;
      justify-content: center;
      text-align: center;
      font-size: 0.6em;
      letter-spacing: 0.06em;
      text-transform: uppercase;
      color: var(--cert-accent);
      background: radial-gradient(circle, rgba(31, 77, 54, 0.12), transparent 70%);
      transform: rotate(-12deg);
    }
    .cert-footnote {
      text-align: center;
      font-size: 0.7em;
      color: #5b6e5f;
      margin-top: 1.4em;
      position: relative;
    }
    @media print {
      .certificate { box-shadow: none; }
    }
  </style>
</head>
<body>
<?php if ($naanyEarned): ?>
  <div class="cert-page">
    <div class="certificate">
      <div class="cert-bg" style="background-image: url('data:image/jpeg;base64,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');"></div>

      <span class="cert-corner tl">&#10048;</span>
      <span class="cert-corner tr">&#10048;</span>
      <span class="cert-corner bl">&#10048;</span>
      <span class="cert-corner br">&#10048;</span>

      <div class="cert-sponsor">Western Washington DX Club</div>
      <h1 class="cert-title">NAANY</h1>
      <div class="cert-full-name">The Nightmare Alex Alpha-Numeric Yearly Award</div>

      <div class="cert-presented-to">This certifies that</div>
      <div class="cert-recipient"><?= htmlspecialchars($certOperator) ?></div>
      <div class="cert-score">
        <span class="cert-score-value"><?= number_format($naanyScore) ?></span>
        <span class="cert-score-label">NAANY Score</span>
      </div>

      <p class="cert-body-text">
        has worked distinct amateur radio stations outside <?= htmlspecialchars(CONTINENT_NAMES[$homeContinent] ?? $homeContinent) ?>
        covering at least <strong><?= $sealThreshold ?> of 260</strong> possible
        digit&ndash;letter combinations during the calendar year
        <strong><?= htmlspecialchars($targetYear) ?></strong>, thereby earning this NAANY award.
      </p>

      <div class="cert-stats">
        <div class="cert-stat">
          <span class="cert-value"><?= $maxLayers ?></span>
          <span class="cert-label">NAANYs Earned</span>
        </div>
        <div class="cert-stat">
          <span class="cert-value"><?= $naanyCC ?></span>
          <span class="cert-label">NAANY&nbsp;DX</span>
        </div>
        <div class="cert-stat">
          <span class="cert-value"><?= count($slateFilled[$bestCCLayer]) ?></span>
          <span class="cert-label">Combinations</span>
        </div>
      </div>

      <div class="cert-endorsement">
        <span class="cert-ribbon">Endorsement: <?= htmlspecialchars($certEndorsement) ?></span>
      </div>
      <div class="cert-mode-breakdown">
<?php
        $certModeParts = [];
        foreach ($certModeBreakdown as $cat => $stat) {
            if ($stat['cells'] > 0) {
                $certModeParts[] = htmlspecialchars($cat) . ': ' . $stat['cells'] . ' QSOs (DX ' . $stat['cc'] . ')';
            }
        }
        echo implode(' &nbsp;&middot;&nbsp; ', $certModeParts);
?>
      </div>

      <div class="cert-signatures">
        <div class="cert-sig-block">
          <div class="cert-sig-line">Tom Sykes</div>
          <div class="cert-sig-label">Awards Manager, NU7J</div>
        </div>
        <div class="cert-sig-block">
          <div class="cert-sig-line"><?= htmlspecialchars($reportGeneratedAt) ?></div>
          <div class="cert-sig-label">Date Issued</div>
        </div>
      </div>

      <div class="cert-seal">Official<br>WWDXC<br>Seal</div>

      <div class="cert-footnote">
        Generated from <?= htmlspecialchars($upload['name']) ?> (year <?= htmlspecialchars($targetYear) ?>,
        home continent <?= htmlspecialchars(CONTINENT_NAMES[$homeContinent] ?? $homeContinent) ?>) &mdash;
        NAANY #<?= $bestCCLayer ?> of <?= $maxLayers ?>, the most DX-diverse complete slate in the log.
      </div>
    </div>
  </div>
<?php endif; ?>
  <h1>NAANY Upload Report v1.6</h1>
  <p><a href="index.html">Upload another file</a></p>
  <div class="status-panel">
    <table class="summary">
      <tr><th>Year Applied</th><td><?= htmlspecialchars($targetYear) ?></td></tr>
      <tr><th>Home Continent</th><td><?= htmlspecialchars(CONTINENT_NAMES[$homeContinent] ?? '(unknown)') ?>, <?= htmlspecialchars($homeContinent) ?></td></tr>
      <tr><th>Total QSO Records (all years)</th><td><?= $recordCount ?></td></tr>
      <tr><th>QSO Records in <?= htmlspecialchars($targetYear) ?></th><td><?= $inYearCallCount ?></td></tr>
      <tr><th>Distinct Worked Callsigns in <?= htmlspecialchars($targetYear) ?></th><td><?= $distinctWorkedCalls ?></td></tr>
<?php if ($malformedRecords > 0): ?>
      <tr><th>Skipped Records</th><td><?= $malformedRecords ?> (missing CALL or QSO_DATE)</td></tr>
<?php endif; ?>
<?php if ($missingDxccRecords > 0): ?>
      <tr><th>Skipped Records (missing DXCC ID)</th><td><?= $missingDxccRecords ?></td></tr>
<?php endif; ?>
<?php if ($homeContinentRecords > 0): ?>
      <tr><th>Skipped Records (same continent)</th><td><?= $homeContinentRecords ?></td></tr>
<?php endif; ?>
<?php if ($unknownContinentRecords > 0): ?>
      <tr><th>Skipped Records (continent unknown)</th><td><?= $unknownContinentRecords ?></td></tr>
<?php endif; ?>
      <tr><th>Number of NAANY Achieved</th><td><?= $maxLayers ?></td></tr>
      <tr><th>NAANY CC</th><td><?= $naanyCC ?? 'N/A' ?></td></tr>
    </table>

    <div class="explainer">
      <p><strong>Counting rule:</strong> only QSOs with stations outside your selected home continent count as qualifying NAANY QSOs.</p>
      <p>
        A NAANY is earned by working distinct callsigns that together cover at least
        <?= $sealThreshold ?> of the 260 possible combinations of a digit (0-9) and a
        letter (A-Z) — taken from the last digit in a worked callsign and the letter
        immediately following it.
      </p>
      <p>
        A log can earn more than one NAANY if it has enough distinct callsigns
        to reach that threshold multiple times over, using a different callsign
        for each combination in each additional NAANY.
      </p>
      <p>
        As a bonus (contest within a contest) the NAANY CC is the number
        of distinct DXCC entities represented across the best (most
        geographically diverse) complete NAANY in the log. Each NAANY also
        breaks that same count down by mode: CW, Phone (SSB/USB/LSB/AM/FM),
        and Digital (RTTY, PSK, FTx, JTx, MFSK, etc.).
      </p>
      <p><strong>Legend:</strong></p>
      <ul class="legend">
        <li><span class="swatch filled">VK</span> Filled — shows the DXCC entity prefix of the qualifying callsign</li>
        <li><span class="swatch empty"></span> Empty — no qualifying contact yet for this combination</li>
      </ul>
    </div>
  </div>

  <p class="score-explainer">
    <strong>NAANY Score:</strong> <?= number_format($naanyScore) ?>
    &mdash; (NAANY count &times; NAANY CC &times; <?= $sealThreshold ?>) + QSOs in the partial NAANY.
    This reduces the full result to one comparable number: breadth (how many NAANYs),
    diversity (NAANY CC), and progress toward the next one (the partial's QSO count) all
    feed into it, so one complete NAANY always outscores zero, no matter how close a
    partial got.
  </p>

<?php if ($naanyEarned): ?>
<?php for ($layer = 1; $layer <= $maxLayers; $layer++): ?>
  <h2>NAANY #<?= $layer ?></h2>
  <p>
    <?= count($layerFilledCells[$layer]) ?> of 260 combinations filled (need at least <?= $sealThreshold ?>).
    Each QSO shows the DXCC entity prefix of the callsign that filled it.
<?php if (count($layerMissingCells[$layer]) > 0): ?>
    Missing: <?= htmlspecialchars(implode(', ', $layerMissingCells[$layer])) ?>.
<?php endif; ?>
  </p>
  <p>
    NAANY CC by mode —
<?php foreach ($layerModeBreakdown[$layer] as $cat => $stat): ?>
<?php if ($stat['cells'] > 0): ?>
    <?= htmlspecialchars($cat) ?>: <?= $stat['cells'] ?> QSOs (DX <?= $stat['cc'] ?>).
<?php endif; ?>
<?php endforeach; ?>
  </p>
  <table class="grid">
    <tr>
      <th></th>
<?php foreach ($digits as $d): ?>
      <th><?= $d ?></th>
<?php endforeach; ?>
    </tr>
<?php foreach ($letters as $l): ?>
    <tr>
      <th><?= $l ?></th>
<?php foreach ($digits as $d): ?>
<?php $cell = $d . $l; ?>
<?php if (isset($slateFilled[$layer][$cell])): ?>
<?php $qso = $slateFilled[$layer][$cell]; ?>
      <td class="filled"><?= htmlspecialchars(DXCC_PREFIXES[(int) $qso['dxcc']] ?? $qso['dxcc']) ?></td>
<?php else: ?>
      <td class="empty"></td>
<?php endif; ?>
<?php endforeach; ?>
    </tr>
<?php endforeach; ?>
  </table>
<?php endfor; ?>

<?php for ($layer = 1; $layer <= $maxLayers; $layer++): ?>
  <h2>NAANY #<?= $layer ?> — Contact List</h2>
  <ul class="contact-list">
<?php foreach ($allCells as $cell): ?>
<?php if (isset($slateFilled[$layer][$cell])): ?>
<?php $qso = $slateFilled[$layer][$cell]; $dxccId = $qso['dxcc']; ?>
    <li><?= htmlspecialchars($cell) ?>, <?= htmlspecialchars($qso['call']) ?>, "<?= htmlspecialchars($dxccNames[(int) $dxccId] ?? '(unknown)') ?>", <?= htmlspecialchars($dxccId) ?></li>
<?php else: ?>
    <li><?= htmlspecialchars($cell) ?>, unneeded, "unneeded", -1</li>
<?php endif; ?>
<?php endforeach; ?>
  </ul>
<?php endfor; ?>
<?php endif; ?>

  <h2>NAANY #<?= $partialLayer ?> (Partial)</h2>
  <p>
    NAANY CC by mode (partial, so far) —
<?php foreach ($partialModeBreakdown as $cat => $stat): ?>
<?php if ($stat['cells'] > 0): ?>
    <?= htmlspecialchars($cat) ?>: <?= $stat['cells'] ?> QSOs (DX <?= $stat['cc'] ?>).
<?php endif; ?>
<?php endforeach; ?>
  </p>
  <table class="grid">
    <tr>
      <th></th>
<?php foreach ($digits as $d): ?>
      <th><?= $d ?></th>
<?php endforeach; ?>
    </tr>
<?php foreach ($letters as $l): ?>
    <tr>
      <th><?= $l ?></th>
<?php foreach ($digits as $d): ?>
<?php $cell = $d . $l; ?>
<?php if (isset($partialFilled[$cell])): ?>
      <td class="filled"><?= htmlspecialchars(DXCC_PREFIXES[(int) $partialFilled[$cell]['dxcc']] ?? $partialFilled[$cell]['dxcc']) ?></td>
<?php else: ?>
      <td class="empty"></td>
<?php endif; ?>
<?php endforeach; ?>
    </tr>
<?php endforeach; ?>
  </table>

  <h2>NAANY #<?= $partialLayer ?> (Partial) — Contact List</h2>
  <ul class="contact-list">
<?php foreach ($allCells as $cell): ?>
<?php if (isset($partialFilled[$cell])): ?>
<?php $qso = $partialFilled[$cell]; $dxccId = $qso['dxcc']; ?>
    <li><?= htmlspecialchars($cell) ?>, <?= htmlspecialchars($qso['call']) ?>, "<?= htmlspecialchars($dxccNames[(int) $dxccId] ?? '(unknown)') ?>", <?= htmlspecialchars($dxccId) ?></li>
<?php else: ?>
    <li><?= htmlspecialchars($cell) ?>, needed, "needed", -1</li>
<?php endif; ?>
<?php endforeach; ?>
  </ul>
</body>
</html>
