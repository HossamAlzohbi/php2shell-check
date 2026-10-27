# How php2shell-check works

This is the design document behind `README.md`. It explains the pipeline step
by step, and — more importantly — *why* each step is built the way it is. The
recurring theme is a single rule:

> **Absence of evidence is never treated as proof of patching.** The only way to
> reach PATCHED on an old-looking version number is positive proof (a changelog
> that cites the CVE). Everything else lands on VULNERABLE or NEEDS REVIEW.

The whole tool exists because `php -v` cannot answer the question on its own
(see the README's "Why `php -v` is not enough"). Distributions backport the fix
without moving the upstream `x.y.z` number, so the number alone is ambiguous on
exactly the systems most people run.

There are three implementations of this logic, and they are kept in lockstep:

* `php2shell-audit.py` — the reference implementation (Python 3.8+, stdlib only).
* `collect.sh` — a read-only POSIX `sh` collector that gathers the same facts on
  a server and prints a compact `#P2S1` block.
* the JavaScript in `docs/index.html` — a reimplementation of the *verdict* half,
  so the web page reaches the same conclusions in the browser with no backend.

`tools/sync_collector.py` embeds `collect.sh` verbatim into the page, and a test
(`test_page_embeds_current_collector`) fails if they drift. A second test
(`test_js_parity.py`) runs the page's JS under `node` and asserts it agrees with
the Python on every fixture.

---

## The pipeline

The tool works in two halves: **collect** facts, then **judge** them. The halves
are deliberately separate — collection touches the system, judging is pure. The
judging half never runs a command, so it is fully testable from fixtures and
runs identically in Python and in the browser.

### 1. Find the PHP binaries (allowlist, not blacklist)

`collect_live()` (and `collect.sh`) look for PHP executables in `$PATH` plus a
fixed set of `EXTRA_DIRS` — the places vendor stacks hide PHP (`/opt/remi/...`,
`/opt/cpanel/ea-php*/...`, `/opt/alt/php*/...`, LiteSpeed's `lsphp`, Plesk's
per-version trees). It also globs for `libphp*.so` Apache modules (`MOD_GLOBS`).

A candidate filename is accepted only if it matches `BIN_RE`:

```
^(?:php|php-fpm|php-cgi|lsphp|frankenphp)(?:\d+(?:\.\d+)*)?$
```

This is an **allowlist, and that is a deliberate security decision.** The naive
approach — "anything starting with `php`" with a blacklist of known-innocent
names — is wrong for two reasons:

* **A blacklist is open by default.** You have to predict every non-runtime tool
  that ships as `php*`: `php-config`, `phpize`, `phpenmod`, `phpdismod`,
  `phpquery`, `phpdbg`, `php-parse`, and whatever the next distro invents.
  Miss one and the tool runs it and tries to parse a version out of unrelated
  output — at best noise, at worst a wrong verdict. An allowlist is closed by
  default: an unknown `php-something` is simply ignored.
* **It bounds what we execute.** The tool runs each accepted binary as
  `<bin> -v` to read its version. An allowlist guarantees we only ever exec the
  handful of real SAPIs, never some arbitrary `php*` script that happened to be
  on `$PATH`. `phpdbg` in particular is an interactive debugger; running it in
  the wrong mode is exactly what you don't want a read-only auditor to do.

The allowlist is anchored (`^...$`) so `php-config` cannot match as a prefix of
`php`. `test_collector_output_and_allowlist` plants `php-config`, `phpize` and
friends in a fake tree and asserts they are never picked up.

### 2. Read each binary's version

`probe_binary()` runs `<bin> -v` (falling back to `version`) and extracts
`PHP (\d+\.\d+\.\d+\S*)` and the `built:` date. For Apache modules, which can't
be executed, it greps the `.so` for the `PHP/x.y.z` signature string instead.

### 3. Resolve the owning package and its changelog

`lookup_pkg()` asks the system package manager who owns the resolved binary path.
This is where the whole distinction between "self-compiled" and "distro package"
is decided, and where backport proof is found:

* **dpkg**: `dpkg -S <path>` → package name; then read
  `/usr/share/doc/<pkg>/changelog.Debian.gz` (or the uncompressed variants) and
  look for the CVE citation.
* **rpm**: `rpm -qf --qf '%{NAME}'` → bare package name (the `--qf '%{NAME}'` is
  important: without it `rpm -qf` returns `name-version-release.arch`, which is
  not a name you can feed back to `rpm -q`); then `rpm -q --changelog <pkg>`.
* **apk**: `apk info -W <path>` → the owner, which Alpine reports as a full
  `name-version-release`, e.g. `php83-8.3.36-r0`. `parse_apk_owner()` splits that
  into `("php83", "8.3.36-r0")`. Alpine has no per-package changelog, so there is
  no backport-proof path for apk — it is judged purely on the (upstream) number.

> **A note on the apk parse.** The `apk info -W` owner string is *not* a bare
> package name, unlike the rpm `%{NAME}` output. An earlier version fed the full
> `php83-8.3.36-r0` string back into `apk info -v` and derived an empty version.
> That bug was found by running the collector inside a real Alpine container (see
> the README's verification status) and is now covered by `test_apk_owner` and
> `test_collector`'s equivalent shell path.

### 4. Judge every finding

`judge()` turns `(version, packaged, family, evidence)` into a verdict and a
human sentence. The processes half separately flags any running web worker that
still maps a replaced file. Then the results are printed (or emitted as JSON).

---

## Why versions are compared as tuples, not strings

`parse_version()` turns a version string into a 3-tuple of ints:

```python
"PHP 8.3.6"            -> (8, 3, 6)
"1:8.3.6-0ubuntu0.1"   -> (8, 3, 6)   # epoch and distro suffix stripped
"8.3.14-r0"            -> (8, 3, 14)
```

The comparison "is this at or above the fix?" is then `v[2] >= FIXED_IN[branch]`
on integers. **String comparison would be silently wrong**, because version
numbers are not lexically ordered:

* `"8.3.9" > "8.3.36"` is `True` as strings (`'9' > '3'`), but `8.3.9` is *older*
  than `8.3.36` and still vulnerable. A string compare would call it patched.
* `"8.3.6"` vs the fix `"8.3.36"`: lexically `"8.3.6" > "8.3.36"` is `True` again,
  another false PATCHED.

Integer-tuple comparison is the only correct ordering for dotted numeric
versions. The branch `(major, minor)` is used as a key into `FIXED_IN` so each
release line is compared against *its own* fix (8.2→35, 8.3→36, 8.4→27, 8.5→12),
never against a single global threshold.

The regex also strips the Debian epoch (`1:`) and everything after the upstream
`x.y.z`, because the fix boundary is defined by upstream patch number; the distro
suffix is handled separately, by the changelog and the family classifier.

---

## Why there is a 200 kB cap on changelog reading

`MAX_CHANGELOG_BYTES = 200_000`. Both the dpkg file read and the
`rpm -q --changelog` output are scanned only up to this many bytes
(`changelog_hit()` in Python; `head -c 200000` in `collect.sh`).

The reasoning:

* **Changelogs are newest-first.** A Debian `changelog.Debian.gz` and
  `rpm -q --changelog` both list the most recent entry at the top. A backport of
  a late-October-2026 CVE is, by definition, in the newest entry. If the citation
  is not in the first 200 kB, it is not in the part of the file that could plausibly
  describe a current security update.
* **Some changelogs are enormous.** A long-lived package can carry years of
  history — megabytes once decompressed. Reading all of it into memory and
  line-scanning it, on every PHP binary found, for a string that (if present) is
  near the top, is wasted work with a pathological worst case.
* **It is a safety bound, not a correctness input.** 200 kB is far larger than
  any plausible run of recent entries, so it never changes a real verdict; it
  only caps the cost of a degenerate file. `test_changelog_hit` asserts both that
  a top-of-file citation is found and that one deliberately buried past the cap is
  not.

Note this cap did not exist in the first cut of the tool — it was added as a
hardening step, with the test above, after the Docker verification runs.

---

## The decision tree

This is the complete logic of `judge()`, in order. The first matching rule wins.
`packaged` is `True` (owned by a distro package), `False` (self-compiled /
unowned), or `None` (we only have `php -v` output). `evidence` is `True`
(changelog cites the CVE), `False` (changelog checked, no mention), or `None`
(no changelog available). `family` is `upstream`, `backporting`, or `None`.

```
version doesn't parse to x.y.z
    └─> NEEDS REVIEW ("could not read a version")

evidence == True  (changelog cites CVE-2026-109618/109619)
    └─> PATCHED   ← the only way an old-looking number earns PATCHED

branch > (8, 5)   (newer than every affected release)
    └─> PATCHED

version[2] >= FIXED_IN[branch]   (at or above the upstream fix for its line)
    └─> PATCHED

── below here: below the fix, and no changelog proof ──

packaged is None   (only `php -v`; can't see a package or changelog)
    └─> NEEDS REVIEW ("php -v can't tell if a backport moved into this number;
                       check the owning package's changelog")

packaged is False  (self-compiled / not owned by any package)
    └─> VULNERABLE ("no distro backport to hope for")

── below here: packaged, below the fix, changelog gives no proof ──

branch < (7, 4)    (end of life, no fix exists)
    └─> VULNERABLE

family == "upstream" and the branch has a fix
    (Debian security archive, Alpine, Remi, Sury, cPanel EasyApache —
     distros whose package number tracks php.net)
    └─> VULNERABLE ("ships upstream numbers and this is below the fix")

otherwise  (a backporting or unknown distro, no changelog citation)
    └─> NEEDS REVIEW ("distros keep the old number when they backport;
                       no citation found; most likely not patched — update and re-check")
```

### How `family` is decided

`classify_family()` looks at the package version suffix first, then falls back to
the OS id:

* suffix contains `sury`/`remi`, or name starts `ea-php` → **upstream**
* name starts `alt-php`, or suffix contains `ubuntu` → **backporting**
* suffix matches `[~+]debN` → **upstream** (Debian security archive)
* suffix matches `.elN`/`.clN`/`.amznN`, or contains `cloudlinux`/`alma` → **backporting**
* suffix ends `-rN` (Alpine) → **upstream**
* else fall back to the OS id: `UPSTREAM_IDS = {debian, alpine}`,
  `BACKPORTING_IDS = {ubuntu, rhel, centos, almalinux, rocky, cloudlinux, ol, amzn, sles, opensuse-leap}`

The suffix is checked before the OS id so a third-party repo (Remi or Sury on an
Ubuntu host, say) is classified by *what the package actually is*, not by the
base distro.

### The stale-process rule (installed ≠ running)

Patching the files on disk does not patch the code already resident in a running
`apache2` / `httpd` / `php-fpm` process. `scan_processes()` reads
`/proc/<pid>/maps` and flags any process still mapping a file marked `(deleted)`
(the kernel's sign that the mapped file was replaced underneath it). Such a
process yields a **NEEDS REVIEW** with a "restart the service" fix, even when the
on-disk binary is PATCHED. Reading another user's `/proc` maps needs root; when
it can't, the tool says so in a note rather than guessing.

---

## Why absence of evidence is never PATCHED

This is the single invariant the whole table is built to protect. Trace every
path that could reach PATCHED and you find each one requires *positive* proof:

1. **`evidence == True`** — a changelog line literally naming the CVE. This is a
   fact the vendor asserted.
2. **`version[2] >= FIXED_IN[branch]`** — the number is at or above the upstream
   fix. On upstream-numbered distros this *is* proof; on a backporting distro a
   number this high would only exist if they shipped the real fix.
3. **`branch > (8, 5)`** — newer than anything affected.

There is deliberately no rule of the form "packaged, recent-looking, probably
fine → PATCHED". When a backporting distro shows an old number and the changelog
does **not** mention the CVE, the honest answer is *we don't know* — maybe the
backport landed and the changelog wording differs, maybe the doc files were
stripped in a container, maybe it genuinely isn't patched yet. That is
**NEEDS REVIEW**, never PATCHED and never a confident VULNERABLE:

* calling it PATCHED would be a dangerous false negative — the whole reason the
  tool exists is that the version number lies on these systems;
* calling it VULNERABLE would be a false positive that trains people to ignore
  the tool.

So the missing-proof case is reported as exactly what it is: unresolved, with the
one command (`zgrep`/`rpm -q --changelog` on the owning package) that would
resolve it. The only time a low number is called VULNERABLE outright is when we
*do* have proof there can be no backport: it is self-compiled (no package to
carry one), or the branch is end-of-life with no fix in existence, or the distro
is known to ship upstream numbers (so a low number means the fix simply isn't
installed).
