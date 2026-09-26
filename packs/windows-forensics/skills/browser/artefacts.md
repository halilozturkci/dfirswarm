---
id: browser/artefacts
title: Browsers, and proving what a person looked at
when: Policy violation, phishing, download provenance, or a search that started the case.
needs: [filesystem/extract]
tools: [browser_history, sqlite_query, esedb_query, utf16_urls]
requires_host: [esedbexport]
---

Per browser, the files that matter:

    Chrome and Edge (Chromium)
        AppData\Local\<vendor>\User Data\Default\
            History          visits, urls, downloads
            Cookies  Login Data  Web Data  Bookmarks
            Sessions\  Preferences
    Firefox
        AppData\Roaming\Mozilla\Firefox\Profiles\<p>\
            places.sqlite    formhistory.sqlite   cookies.sqlite
    Legacy Edge and Internet Explorer
        AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat

Copy the database and its `-wal` beside it before you query. `browser_history`
does this for you; querying in place risks a partial read and a write you are
not allowed to make. The write-ahead log often holds the most recent rows, so a
query that ignores it misses exactly the visits you want.

Read `visits` joined to `urls`, not `urls` alone: the visit carries the time and
the transition type, and the transition is how you tell a typed address from a
redirect from a link click. A `typed_count` above zero means somebody entered it.

Provenance of a download: the `downloads` table, the `Zone.Identifier` alternate
stream on the file itself, and the cache entry. The stream can carry the host
URL that delivered it. Its absence does not prove the file did not come through
a browser: the destination may not support ADS, or the stream may have been
removed. Treat presence as provenance evidence and absence as inconclusive.

An installer in the virtualisation drag-and-drop staging directory did not come
from a download at all. Check that before you build a story around a URL.

`WebCacheV01.dat` is not only a browser artefact. Windows Update, Office, the
Store and local file access all write into it. A hostname found in it is not
necessarily a hostname the user visited, and in one published run a string from
an unrelated content-delivery allowlist was published as the malware's download
origin. Tie a hostname to a visit record with a time before you name it.
