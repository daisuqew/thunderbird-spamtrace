SPAM TRACE
==========

Trace the origins of spam emails on a map.

A Thunderbird MailExtension that analyzes the email you are viewing, estimates its
spam/phishing risk, and shows where the message came from - fully offline by default.

- Extension ID: spam-trace@itinfusion.jp
- Requires Thunderbird 128+


FEATURES
--------

- Header analysis - Received route, sender IP / ASN / country, and SPF/DKIM/DMARC results.
- Phishing checks - links in the body (sender domain vs. link domain) and brand-impersonation patterns.
- 0-100 risk score with the reasons behind it.
- Offline route map - continents from Natural Earth, sender/relay markers, and a hop table.
- One-click feedback - "Suspicious Email" (also sets Thunderbird's Junk flag) or "Legitimate";
  the add-on learns from this to refine future scores.
- Automatic alert window for high-risk messages (threshold configurable in Settings).
- 6 languages - English, Japanese, Chinese (Simplified), Spanish, German, French.


PRIVACY
-------

- Offline by default - no network requests and no telemetry. IP-to-country resolution uses a
  database bundled inside the add-on.
- The add-on reads message headers, and reads the body only to extract links (for phishing) and
  to compute a hash. Your message subject and body text are never stored or sent - only hashes
  are kept, on your computer.
- Optional online features (all OFF by default; each requests its own permission when enabled):
    - ipwho.is - detailed IP geolocation / ASN over HTTPS (only header-derived IPs are sent).
    - check.torproject.org - download of the public Tor exit-node list over HTTPS.
    - Statistics upload - POSTs a statistics JSON (hashes, IPs, ASN, country, scores) to a
      server URL you configure.


INSTALL
-------

- From a file: Add-ons Manager -> the gear button -> "Install Add-on From File..." -> select the .xpi.
- From ATN: (link to be added once the listing is public.)


PERMISSIONS
-----------

- messagesRead    Read the displayed message's headers; scan the body only for links and a hash
                  (never stored/sent). Required by Thunderbird even to read headers.
- messagesUpdate  Set the Junk flag when you mark a message as suspicious.
- accountsRead    Detect Sent/Drafts/Templates/Outbox (folder specialUse) to exclude your own
                  outgoing mail.
- storage         Save settings, caches, and learning data locally.
- downloads       Save phishing logs / JSON exports to Downloads/spam-trace/ on request.
- (optional) <all_urls>                        Only to POST statistics to a server URL you configure.
- (optional) https://ipwho.is/*                Only if you enable online geolocation.
- (optional) https://check.torproject.org/*    Only if you enable the Tor check.


BUNDLED DATA & ATTRIBUTION
--------------------------

- IP -> country:
    IP geolocation data provided by DB-IP.com (https://db-ip.com/).
    This product includes the DB-IP Lite database, licensed under the Creative Commons
    Attribution 4.0 International License (https://creativecommons.org/licenses/by/4.0/).
    This attribution is also shown in the UI when the local database is used.
- World map:
    Natural Earth (https://www.naturalearthdata.com/) 1:50m land - public domain.


BUILDING THE BUNDLED DATA
-------------------------

The two data files under spam-trace-addon/data/ are generated from public sources by the
scripts in build/ (pure Node - no GDAL or npm packages required).

Obtaining the source data (not committed to this repo):

- DB-IP "IP to Country Lite" CSV - download the free monthly file from
  https://db-ip.com/db/download/ip-to-country-lite (e.g. dbip-country-lite-YYYY-MM.csv.gz).
- Natural Earth 1:50m land shapefile - download ne_50m_land.zip from
  https://www.naturalearthdata.com/downloads/50m-physical-vectors/50m-land/ and unzip it.

Commands:

    # data/ip-country-v4.bin  <-  DB-IP "IP to Country Lite" CSV (.csv or .csv.gz)
    node build/build-ip-country.js dbip-country-lite-YYYY-MM.csv.gz spam-trace-addon/data/ip-country-v4.bin

    # data/land.json  <-  Natural Earth ne_50m_land shapefile (unzip the bundle first)
    node build/build-land.js path/to/ne_50m_land.shp spam-trace-addon/data/land.json

Source data used for the current build: DB-IP IP-to-Country Lite (2026-09) and Natural Earth
1:50m ne_50m_land. Swap to 1:110m/1:10m by pointing build-land.js at that shapefile.


PACKAGING THE ADD-ON (XPI)
--------------------------

Zip the contents of the extension directory (not the parent folder) and use the .xpi extension:

    cd spam-trace-addon
    zip -r -X ../spam-trace-1.0.0.xpi . -x '*.DS_Store'


REPOSITORY LAYOUT
-----------------

- spam-trace-addon/   The extension source (this directory is what gets packaged).
- build/              Data-conversion scripts (build-ip-country.js, build-land.js).


LICENSE
-------

- Extension code: to be set by the author (e.g., MPL-2.0 / MIT / GPL-3.0).
- Bundled data keeps its own license: DB-IP Lite (CC BY 4.0), Natural Earth (public domain) -
  see Attribution above.


AUTHOR
------

Dais Watan - dwatanabe@itinfusion.jp
