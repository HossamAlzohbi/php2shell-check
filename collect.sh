# php2shell-check collector (v1). POSIX sh, read-only, no sudo.
# It reads package metadata and /proc, and runs `<php> -v` on PHP binaries
# found in standard locations. It sends nothing anywhere.
RE='^(php|php-fpm|php-cgi|lsphp|frankenphp)([0-9]+(\.[0-9]+)*)?$'
CVE_RE='109618|109619|php2shell'
T=''; command -v timeout >/dev/null 2>&1 && T='timeout 5'

san() { printf '%s' "$1" | tr '|\n\r' '/  ' | cut -c1-120; }

osval() { sed -n "s/^$1=//p" /etc/os-release 2>/dev/null | head -n1 | tr -d '"'; }

if command -v dpkg-query >/dev/null 2>&1; then PM=dpkg
elif command -v rpm >/dev/null 2>&1; then PM=rpm
elif command -v apk >/dev/null 2>&1; then PM=apk
else PM=none; fi

# Sets PKG PKGV EV for a file ($1 = resolved path, $2 = path as found).
lookup() {
  PKG=''; PKGV=''; EV=na
  case "$PM" in
  dpkg)
    for q in "$1" "$2"; do
      [ -n "$PKG" ] && break
      PKG=$(dpkg -S "$q" 2>/dev/null | sed -n '1s/[:,].*//p')
    done
    if [ -n "$PKG" ]; then
      PKGV=$(dpkg-query -W -f='${Version}' "$PKG" 2>/dev/null)
      for f in /usr/share/doc/"$PKG"/changelog.Debian.gz /usr/share/doc/"$PKG"/changelog.gz /usr/share/doc/"$PKG"/changelog.Debian; do
        [ -r "$f" ] || continue
        case "$f" in
          *.gz) m=$(gzip -dc "$f" 2>/dev/null | head -c 200000 | grep -iE "$CVE_RE" | head -n1) ;;
          *) m=$(head -c 200000 "$f" 2>/dev/null | grep -iE "$CVE_RE" | head -n1) ;;
        esac
        if [ -n "$m" ]; then EV="yes:$(san "$m")"; break; fi
        EV=no
      done
    fi ;;
  rpm)
    o=$(rpm -qf --qf '%{NAME}\n' "$1" 2>/dev/null) || o=''
    PKG=$(printf '%s\n' "$o" | head -n1)
    if [ -n "$PKG" ]; then
      PKGV=$(rpm -q --qf '%{VERSION}-%{RELEASE}\n' "$PKG" 2>/dev/null | head -n1)
      cl=$(rpm -q --changelog "$PKG" 2>/dev/null | head -c 200000)
      if [ -n "$cl" ]; then
        m=$(printf '%s\n' "$cl" | grep -iE "$CVE_RE" | head -n1)
        if [ -n "$m" ]; then EV="yes:$(san "$m")"; else EV=no; fi
      fi
    fi ;;
  apk)
    # `apk info -W` names the owner as a full name-version-release, e.g.
    # "/usr/bin/php83 is owned by php83-8.3.36-r0" -> PKG=php83, PKGV=8.3.36-r0.
    owner=$(apk info -W "$1" 2>/dev/null | sed -n 's/.* owned by //p' | head -n1)
    if [ -n "$owner" ]; then
      PKGV=$(printf '%s\n' "$owner" | sed -n 's/^.*-\([0-9][^-]*-r[0-9]*\)$/\1/p')
      if [ -n "$PKGV" ]; then PKG=${owner%-"$PKGV"}; else PKG=$owner; fi
    fi ;;
  esac
}

# Running web/PHP processes: one P| line per process, E| line for its exe.
PROCS=$( { ps -eo pid=,comm= 2>/dev/null || ps -o pid,comm 2>/dev/null; } | while read -r pid comm; do
  case "$pid" in *[!0-9]*|'') continue ;; esac
  case "$comm" in
    apache2|httpd|litespeed|lshttpd|frankenphp) ;;
    php*|lsphp*) printf '%s\n' "$comm" | grep -Eq "$RE" || continue ;;
    *) continue ;;
  esac
  exe=$(readlink "/proc/$pid/exe" 2>/dev/null)
  m=$(awk '$6 ~ /libphp/ && lp=="" {lp=$6}
           $NF=="(deleted)" && $6 ~ /^\/(usr|opt|lib|lib32|lib64|bin|sbin|snap)\// {st=1; if (sp=="") sp=$6}
           END {printf "%s|%d|%s\n", (lp==""?"-":lp), st+0, (sp==""?"-":sp)}' "/proc/$pid/maps" 2>/dev/null)
  ro=0; [ -n "$m" ] || { ro=1; m='-|0|-'; }
  lp=${m%%|*}; r=${m#*|}; st=${r%%|*}; sp=${r#*|}
  printf 'P|%s|%s|%s|%s|%s\n' "$comm" "$lp" "$st" "$sp" "$ro"
  [ -n "$exe" ] && printf 'E|%s\n' "${exe% (deleted)}"
done )

candidates() {
  for d in $(printf '%s' "$PATH" | tr ':' ' ') /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin \
      /usr/local/php*/bin /usr/local/php*/sbin /opt/remi/php*/root/usr/bin /opt/remi/php*/root/usr/sbin \
      /opt/cpanel/ea-php*/root/usr/bin /opt/cpanel/ea-php*/root/usr/sbin /opt/alt/php*/usr/bin \
      /opt/alt/php*/usr/sbin /usr/local/lsws/lsphp*/bin /opt/plesk/php/*/bin /opt/plesk/php/*/sbin; do
    [ -d "$d" ] || continue
    for f in "$d"/*; do
      b=${f##*/}
      case "$b" in php*|lsphp*|frankenphp*) ;; *) continue ;; esac
      printf '%s\n' "$b" | grep -Eq "$RE" && [ -f "$f" ] && [ -x "$f" ] && printf '%s\n' "$f"
    done
  done
  printf '%s\n' "$PROCS" | sed -n 's/^E|//p'
}

printf '#P2S1\n'
printf 'os|id=%s|ver=%s|name=%s\n' "$(osval ID)" "$(osval VERSION_ID)" "$(san "$(osval PRETTY_NAME)")"
printf 'pm|name=%s\n' "$PM"
if [ "$(id -u 2>/dev/null)" = 0 ]; then printf 'user|root=1\n'; else printf 'user|root=0\n'; fi

# Resolve symlinks (php -> /etc/alternatives/php -> php8.3) and de-duplicate.
RESOLVED=$(candidates | while read -r f; do
  [ -f "$f" ] && [ -x "$f" ] || continue
  rp=$(readlink -f "$f" 2>/dev/null); [ -n "$rp" ] || rp=$f
  printf '%s|%s\n' "$rp" "$f"
done | sort -t'|' -u -k1,1)

printf '%s\n' "$RESOLVED" | while read -r line; do
  [ -n "$line" ] || continue
  rp=${line%%|*}; f=${line#*|}
  out=$($T "$rp" -v </dev/null 2>&1)
  ver=$(printf '%s\n' "$out" | grep -oE 'PHP [0-9]+\.[0-9]+\.[0-9]+[^ ]*' | head -n1 | cut -c5-)
  if [ -z "$ver" ]; then
    out=$($T "$rp" version </dev/null 2>&1)
    ver=$(printf '%s\n' "$out" | grep -oE 'PHP [0-9]+\.[0-9]+\.[0-9]+[^ ]*' | head -n1 | cut -c5-)
  fi
  built=$(printf '%s\n' "$out" | sed -n 's/.*built: \([A-Za-z][a-z][a-z]  *[0-9][0-9]*  *[0-9][0-9][0-9][0-9]\).*/\1/p' | head -n1 | tr -s ' ')
  lookup "$rp" "$f"
  printf 'bin|path=%s|ver=%s|built=%s|pkg=%s|pkgver=%s|ev=%s\n' "$(san "$rp")" "$ver" "$built" "$PKG" "$PKGV" "$EV"
done

# Apache mod_php: libphp*.so mapped by a running server, or present on disk.
PROCLP=$(printf '%s\n' "$PROCS" | awk -F'|' '$1=="P" && $3!="-" {print $3}' | sort -u)
{ printf '%s\n' "$PROCLP"
  for f in /usr/lib/apache2/modules/libphp*.so /usr/lib64/httpd/modules/libphp*.so \
           /usr/lib/httpd/modules/libphp*.so /usr/local/apache2/modules/libphp*.so; do
    [ -f "$f" ] && printf '%s\n' "$f"
  done; } | sed '/^$/d' | sort -u | while read -r m; do
  [ -f "$m" ] || continue
  rp=$(readlink -f "$m" 2>/dev/null); [ -n "$rp" ] || rp=$m
  ver=$(grep -aoE 'PHP/[0-9]+\.[0-9]+\.[0-9]+' "$rp" 2>/dev/null | head -n1 | cut -c5-)
  loaded=0; printf '%s\n' "$PROCLP" | grep -Fxq "$m" && loaded=1
  lookup "$rp" "$m"
  printf 'mod|path=%s|ver=%s|pkg=%s|pkgver=%s|ev=%s|loaded=%s\n' "$(san "$rp")" "$ver" "$PKG" "$PKGV" "$EV" "$loaded"
done

printf '%s\n' "$PROCS" | grep '^P|' | sort | uniq -c | awk '{
  n=$1; $1=""; sub(/^ /,""); split($0,a,"|")
  printf "proc|comm=%s|libphp=%s|stale=%s|stalepath=%s|ro=%s|n=%d\n", a[2],a[3],a[4],a[5],a[6],n }'
printf 'end|ok\n'
