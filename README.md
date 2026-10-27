# php2shell-check

Work out whether **your own** server is patched against PHP2Shell
(CVE-2026-109618 and CVE-2026-109619, CVSS v4.0 9.2, unauthenticated RCE,
published 20-21 October 2026).

## Why `php -v` is not enough

Distros backport the fix into the version number they already ship. A fully
patched Ubuntu 24.04 still prints:

```
$ php -v
PHP 8.3.6 (cli) ...
```

Only the *package* version moves (`8.3.6-0ubuntu0.24.04.12` -> `...13`). So on a
package-installed PHP, `php -v` can tell you "vulnerable-looking", never
"patched". The proof is in the changelog: `debian/patches/CVE-2026-109618_109619.patch`
shows up in `/usr/share/doc/<package>/changelog.Debian.gz`, or in
`rpm -q --changelog <package>`.

It is not the same everywhere:

| Source | Version number | Trust it? |
|---|---|---|
| php.net source build, official Docker image | upstream | yes, compare to the fixed version |
| Debian 12/13 security archive, Alpine, Remi, Sury, cPanel EasyApache | upstream | yes |
| Ubuntu, AlmaLinux, Rocky, RHEL, CloudLinux (incl. alt-php) | frozen, fixes backported | **no**, read the changelog |

Also, installed is not running: until Apache / PHP-FPM / LiteSpeed / FrankenPHP is
restarted, the old code is still in memory. The collector detects processes that still
map replaced (`(deleted)`) files and the tool tells you to restart them.

## Affected and fixed versions

* Affected: every PHP from 5.4 through 8.5.11, on every SAPI that serves web
  (mod_php, PHP-FPM, php-cgi, FrankenPHP, LiteSpeed). PHP rates mod_php highest risk.
* Fixed upstream in **8.5.12, 8.4.27, 8.3.36, 8.2.35**.
* 8.1, 8.0, 7.4: no regular upstream release, only minimal source backports.
* 5.4 - 7.3: no fix.
* A third issue, **CVE-2026-115560**, was undocumented and unfixed as of 25 October 2026.
  This tool has no logic for it.

## Usage

### Web page (`docs/index.html`)

Single static file, no dependencies, no backend, no network calls (a
Content-Security-Policy forbids them). Serve `docs/` with GitHub Pages or open the file locally.

1. Copy the collector command from the page and run it on your server.
2. Paste the output into the page. You get a verdict per finding
   (PATCHED / VULNERABLE / NEEDS REVIEW), the reasoning, and a copy-paste fix command
   for the right package manager.

The page also accepts `php -v`, `dpkg -l 'php*'`, `rpm -qa 'php*'` and `apk info -v`
output. These are less certain: `php -v` can never conclude "patched" for a low version
number, and package lists carry no changelogs, so backporting distros land on NEEDS REVIEW.

### Collector (`collect.sh`)

One POSIX `sh` script, read-only, no `sudo`. It prints a compact block starting with `#P2S1`:
PHP binaries (strict allowlist, so `php-config`, `phpize`, `phpenmod`, `phpquery` and `phpdbg` are ignored),
version and build date per binary, owning package and version, a changelog grep for
`109618|109619|php2shell`, running web SAPI processes, mod_php modules, and whether any
PHP process maps `(deleted)` files. It executes `<php> -v` on the binaries it finds, nothing else.
Run it as root if you want it to see web workers owned by other users.

```sh
sh collect.sh
```

The page shows it as a single pasteable command (`sh -c "$(cat <<'P2S' ... P2S )"`).
`tools/sync_collector.py` keeps the page and `collect.sh` identical; a test enforces it.

### CLI (`php2shell-audit.py`)

Same logic, Python 3.8+, standard library only.

```sh
python3 php2shell-audit.py                 # inspect this machine
python3 php2shell-audit.py --json          # machine-readable
python3 php2shell-audit.py --no-colour
python3 php2shell-audit.py --input block.txt   # judge a saved collector block (or - for stdin)
```

Exit codes: `0` everything patched, `1` something vulnerable, `2` needs manual review,
`3` no PHP found.

### Tests

```sh
python3 -m pytest
```

Covers the verdict table, real `dpkg` / `rpm` / `apk` parsing, the collector against a fake
PHP tree, and (if `node` is installed) that the web page agrees with the Python code.

## How a verdict is reached

1. Package changelog cites the CVE -> **PATCHED** (this is what proves a backport).
2. Version at or above the upstream fix for its branch (or newer than 8.5) -> **PATCHED**.
3. Below the fix and not owned by any package (self-compiled) -> **VULNERABLE**.
4. Below the fix, packaged:
   * distro ships upstream numbers (Debian, Alpine, Remi, Sury, EasyApache) and the branch has a fix -> **VULNERABLE**;
   * 5.4-7.3 -> **VULNERABLE**;
   * otherwise (a backporting or unknown distro, no changelog proof) -> **NEEDS REVIEW**:
     most likely not patched yet, but a missing changelog line is not proof.
5. A patched binary on disk with a running process that still maps replaced files -> **NEEDS REVIEW** (restart).

## Verification status

Exercised against real tooling: `dpkg` / `dpkg-query` / `/usr/share/doc/*/changelog.Debian.gz` (Ubuntu host),
the collector under `dash` and `bash`, and the Python parsers against dpkg, rpm and apk output samples.

**Not yet exercised against a real system: the `rpm` and `apk` code paths** (`rpm -qf`, `rpm -q --changelog`,
`apk info -W`, `apk info -v` in both `collect.sh` and `php2shell-audit.py`), and the `php:*` Docker images.
They follow the tools' documented output and are covered only by fixtures written from that documentation.
Treat RPM/Alpine results as unproven until someone runs the collector on AlmaLinux/Alpine and confirms.

## Scope and limitations

* **This does not scan or probe any server.** It reads text you paste, or, for the
  collector and CLI, the local machine you run them on. There is no remote mode and there
  never will be. The page makes no network requests and stores nothing.
* **It does not tell you whether you have been compromised.** A patched server may already
  have been exploited. For detection, use CISA's SIGMA rule from their alert (linked below).
* **`session.upload_progress.enabled=Off` is a stopgap, not a fix.** Patch and restart.
* A missing changelog line is not proof of a missing patch (a vendor might word it differently,
  or doc files may be stripped in containers), which is why those cases are NEEDS REVIEW and not VULNERABLE.
* Vendor builds that are not in the usual locations (custom prefixes, containers you did not
  run the collector inside) are not seen. Run it inside each container/chroot.
* Reading `/proc/<pid>/maps` of other users' processes needs root; without it the stale-process check is partial and says so.
* CVE-2026-115560 is unresolved as of 25 October 2026 and not covered.

## Links

* CISA alert (includes the SIGMA rule): <https://www.cisa.gov/news-events/alerts/2026/10/21/critical-vulnerabilities-php-require-immediate-patching>
* GitHub security advisories (primary source on the vulnerabilities themselves):
  CVE-2026-109618 <https://github.com/advisories/GHSA-w8hw-w9fx-j79w>,
  CVE-2026-109619 <https://github.com/advisories/GHSA-6wmf-4rv5-p3rp>
* CERT-EU advisory 2026-018: <https://cert.europa.eu/publications/security-advisories/2026-018/>
* Canadian Cyber Centre AL26-026: <https://cyber.gc.ca/en/alerts-advisories/al26-026-critical-vulnerabilities-impacting-php-cve-2026-109618-cve-2026-109619>
* PHP releases (fixed versions): <https://www.php.net/releases/>

## License

MIT, see [LICENSE](LICENSE).
