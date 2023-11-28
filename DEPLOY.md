# NAANY deployment & fail2ban hardening checklist

Reference for deploying the app and wiring up the abuse-detection hardening.

Everything below (Apache, log directory, fail2ban) is per-server, not
per-directory, so it applies identically regardless of which of the two
you're actively using, and covers both at once.

## 1. Apache

**No vhost changes needed.** NAANY rides on the existing `your-domain.com` vhost
(`/etc/apache2/sites-enabled/your-domain.com.conf`) as a subdirectory under its
`DocumentRoot` (`/var/www/your-domain`). That vhost already serves PHP and has
`AllowOverride None`, so a `.htaccess` wouldn't work there anyway — but
none is needed:

- `upload_max_filesize` / `post_max_size` are already generous enough
  globally, in `/etc/php/8.2/apache2/php.ini`:
  ```
  upload_max_filesize = 20M
  post_max_size = 256M
  ```
  (Real-world ADIF logs tested so far are a few MB at most.) If a much
  larger log ever gets rejected with an upload-size error, raise these two
  values in that same php.ini and `sudo systemctl reload apache2` — still
  no vhost edit required.

## 2. Sync the app files

From this project directory to whichever test path(s) you're using:

```
# cp index.html /var/www/your-domain/naany
# cp process.php /var/www/your-domain/naany
```

## 3. Log directory for the abuse detector

`process.php`'s `log_bad_input()` writes here; create it once per server
(adjust the owner if PHP doesn't run as `www-data`):
```
sudo mkdir -p /var/log/naany
sudo chown www-data:www-data /var/log/naany
sudo chmod 750 /var/log/naany
```
Until this exists, bad-input events still get logged via PHP's own
`error_log()` (visible in Apache's error log) as a fallback — nothing is
silently lost, but fail2ban can't watch that fallback location, so this
step is required before the jail does anything useful.

**Also create the log file itself, not just the directory.** fail2ban
refuses to start a jail whose `logpath` doesn't exist yet ("Have not
found any log file for naany-badinput jail") — `process.php` only
creates the file the first time a bad upload actually happens, which
won't have occurred yet on a fresh install:
```
sudo touch /var/log/naany/badinput.log
sudo chown www-data:www-data /var/log/naany/badinput.log
sudo chmod 640 /var/log/naany/badinput.log
```

## 4. Install the fail2ban filter + jail

Both files are in `fail2ban/` in this project directory, already written
and verified against sample log lines with `fail2ban-regex`.
```
sudo cp fail2ban/naany-badinput.conf /etc/fail2ban/filter.d/naany-badinput.conf
sudo cp fail2ban/naany.conf          /etc/fail2ban/jail.d/naany.conf
```

Verify the filter actually matches before trusting it:
```
sudo fail2ban-regex /var/log/naany/badinput.log /etc/fail2ban/filter.d/naany-badinput.conf
```
(Once some real or test bad-input lines exist in that file. You can also
point `fail2ban-regex` at a scratch file with a few lines pasted in before
the real log exists.)

Dry-run the whole config, then restart:
```
sudo fail2ban-client -d
sudo systemctl restart fail2ban
```

## 5. Confirm it's live

```
sudo fail2ban-client status naany-badinput
```
Should show the jail with 0 currently banned, filter = naany-badinput,
and the correct logpath.

Trigger it for real (from a machine NOT your own, or expect to unban
yourself immediately after — see below): upload something that isn't
ADIF, or a wildly long callsign, or add a bogus extra form field. Four
such hits within 10 minutes from the same IP should ban it.

## 6. Unban (know this before you need it)

```
sudo fail2ban-client set naany-badinput unbanip <IP>
```
A false positive bans real users too — if something looks wrong after
deploying, check `fail2ban-client status naany-badinput` first and unban
rather than guessing.

## 7. Tuning reference

Current jail settings (`fail2ban/naany.conf`): `maxretry = 4`,
`findtime = 10m`, `bantime = 1h`, action = `iptables-allports` (drops
the IP on every port, not just this app). Deliberately conservative —
raise `bantime` and/or lower `maxretry` only after watching it run for a
while with no false positives.

## What actually triggers a ban

All three reasons log through the same `NAANY_BADINPUT` line and route to
a bare "Bad Request" response (no detail given back to the client):

1. Uploaded file doesn't look like ADIF within the first ~8KB (no
   `<eoh>`/`<eor>` tag anywhere, or binary/NUL-byte content).
2. Callsign field longer than 16 characters.
3. Any POST field other than `year`, `callsign`, `home_continent` is
   present (the form never sends anything else).

Ordinary mistakes (missing year, empty callsign, bad continent value)
still get the normal styled error page — those aren't abuse signals, just
honest form errors, and don't touch the fail2ban log at all.
