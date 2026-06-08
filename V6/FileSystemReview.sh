#!/usr/bin/env bash
# filesystem_review.sh - Pregled bezbednosti fajl sistema (Sekcija 6)
# Pokretanje: sudo ./filesystem_review.sh

RED='\033[0;31m'; YEL='\033[1;33m'; GRN='\033[0;32m'; CYN='\033[0;36m'; NC='\033[0m'
WARN=0; CRIT=0

warn() { echo -e "${YEL}[UPOZORENJE]${NC} $1"; WARN=$((WARN+1)); }
crit() { echo -e "${RED}[KRITICNO]  ${NC} $1"; CRIT=$((CRIT+1)); }
ok()   { echo -e "${GRN}[OK]        ${NC} $1"; }
info() { echo -e "${CYN}[INFO]      ${NC} $1"; }
hdr()  { echo; echo -e "${CYN}════════════════════════════════════════${NC}"; \
         echo -e "${CYN}  $1${NC}"; \
         echo -e "${CYN}════════════════════════════════════════${NC}"; }

[[ $EUID -ne 0 ]] && warn "Nije pokrenuto kao root — rezultati mogu biti nepotpuni."
echo -e "\n${CYN}  FILESYSTEM REVIEW | $(hostname) | $(date '+%d.%m.%Y %H:%M:%S')${NC}\n"

# ── 1) FSTAB ────────────────────────────────────────────────
hdr "1. Montirane particije (/etc/fstab)"
# noatime cuva access time za forenziku; noexec/nosuid na /tmp i /home
# sprecavaju pokretanje malvera i zloupotrebu SUID bita.

if [[ ! -f /etc/fstab ]]; then
    warn "/etc/fstab ne postoji."
else
    grep -vE '^\s*#|^\s*$' /etc/fstab | sed 's/^/   /'
    echo
    while IFS= read -r line; do
        [[ "$line" =~ ^\s*# || -z "${line// }" ]] && continue
        MP=$(echo "$line" | awk '{print $2}')
        OPT=$(echo "$line" | awk '{print $4}')

        echo "$OPT" | grep -qw "noatime" \
            && ok "$MP — noatime postoji." \
            || warn "$MP nema 'noatime' — access time se azurira (otezava forenziku)."

        if echo "$MP" | grep -qE '^(/tmp|/home|/var)$'; then
            echo "$OPT" | grep -qw "noexec" \
                && ok "$MP — noexec postoji." \
                || crit "$MP nema 'noexec' — korisnici mogu izvrsavati binarne fajlove!"
        fi

        if echo "$MP" | grep -qE '^(/tmp|/home|/dev)$'; then
            echo "$OPT" | grep -qw "nosuid" \
                && ok "$MP — nosuid postoji." \
                || crit "$MP nema 'nosuid' — SUID binarni fajlovi mogu biti zloupotrebljeni!"
        fi
    done < /etc/fstab
fi

# ── 2) OSETLJIVI FAJLOVI ────────────────────────────────────
hdr "2. Permisije osetljivih sistemskih fajlova"
# /etc/shadow, sudoers i SSH kljucevi ne smeju biti citljivi svim korisnicima.

for ENTRY in \
    "/etc/shadow:Hesovi lozinki" \
    "/etc/shadow-:Backup hesova lozinki" \
    "/etc/passwd:Lista korisnika" \
    "/etc/sudoers:Sudo konfiguracija" \
    "/etc/ssh/ssh_host_rsa_key:SSH RSA kljuc" \
    "/etc/ssh/ssh_host_ed25519_key:SSH ED25519 kljuc" \
    "/etc/mysql/my.cnf:MySQL konfiguracija" \
    "/etc/mysql/debian.cnf:MySQL debian-sys-maint lozinka"
do
    FPATH="${ENTRY%%:*}"; DESC="${ENTRY#*:}"
    [[ ! -e "$FPATH" ]] && continue
    PERM=$(stat -c "%a" "$FPATH" 2>/dev/null)
    OWNER=$(stat -c "%U:%G" "$FPATH" 2>/dev/null)
    WORLD=$(echo "$PERM" | rev | cut -c1)
    if [[ "$WORLD" -ge 4 ]]; then
        crit "$FPATH ($DESC) citljiv svim! ($PERM, $OWNER)"
    elif [[ "$WORLD" -ge 2 ]]; then
        crit "$FPATH ($DESC) pisljiv svim! ($PERM, $OWNER)"
    else
        ok "$FPATH — $PERM ($OWNER)"
    fi
done

info "Trazim SSL/TLS privatne kljuceve..."
find /etc/ssl /etc/apache2 /etc/nginx /etc/letsencrypt -name "*.key" 2>/dev/null \
| grep -v "\.pub$" | while read -r f; do
    PERM=$(stat -c "%a" "$f" 2>/dev/null); WORLD=$(echo "$PERM" | rev | cut -c1)
    [[ "$WORLD" -ge 4 ]] \
        && crit "SSL kljuc $f citljiv svim! ($PERM)" \
        || ok "SSL kljuc $f — $PERM"
done

# ── 3) BACKUP FAJLOVI ───────────────────────────────────────
hdr "3. Backup fajlovi i kopije osetljivih podataka"
# .bak/.old kopije shadow/passwd mogu otkriti hesove lozinki
# cak i kada je originalni /etc/shadow pravilno zasticen.

for FPATH in /etc/shadow.backup /etc/shadow.bak /etc/shadow.old \
             /etc/passwd.backup /etc/passwd.bak /etc/passwd.old; do
    [[ ! -f "$FPATH" ]] && continue
    PERM=$(stat -c "%a" "$FPATH" 2>/dev/null); WORLD=$(echo "$PERM" | rev | cut -c1)
    [[ "$WORLD" -ge 4 ]] \
        && crit "Opasna kopija $FPATH je CITLJIVA SVIM! ($PERM)" \
        || warn "Pronadjena kopija $FPATH ($PERM) — proveriti da li je potrebna."
done

info "Trazim .bak/.old fajlove u /etc:"
find /etc -maxdepth 2 \( -name "*.bak" -o -name "*.old" -o -name "*.orig" \) 2>/dev/null \
| while read -r f; do
    warn "Backup fajl: $f ($(stat -c '%a' "$f" 2>/dev/null))"
done

if [[ -d /backup ]]; then
    PERM=$(stat -c "%a" /backup 2>/dev/null); WORLD=$(echo "$PERM" | rev | cut -c1)
    [[ "$WORLD" -ge 4 ]] \
        && crit "/backup direktorijum citljiv svim korisnicima! ($PERM)" \
        || ok "/backup postoji i nije world-readable ($PERM)."
    find /backup -maxdepth 2 \( -name "*.tgz" -o -name "*.tar.gz" \) 2>/dev/null \
    | while read -r f; do
        PERM=$(stat -c "%a" "$f" 2>/dev/null); WORLD=$(echo "$PERM" | rev | cut -c1)
        [[ "$WORLD" -ge 4 ]] \
            && crit "Arhiva $f citljiva svim! ($PERM)" \
            || warn "Arhiva $f pronadjena ($PERM)."
    done
else
    ok "/backup direktorijum ne postoji."
fi

# ── 4) SUID/SGID ────────────────────────────────────────────
hdr "4. SUID/SGID binarni fajlovi"
# SUID fajlovi se izvrsavaju sa privilegijama vlasnika (cesto root).
# Nepoznati SUID root binarni fajlovi mogu biti iskorisceni za
# eskalaciju privilegija (GTFOBins).

KNOWN_SUID=(
    /usr/bin/passwd /usr/bin/sudo /usr/bin/su /usr/bin/newgrp
    /usr/bin/gpasswd /usr/bin/chfn /usr/bin/chsh /usr/bin/mount
    /usr/bin/umount /usr/bin/pkexec /usr/bin/at /usr/bin/crontab
    /usr/bin/wall /usr/lib/openssh/ssh-keysign /usr/sbin/pppd
    /usr/lib/dbus-1.0/dbus-daemon-launch-helper
    /bin/ping /bin/ping6 /bin/su /bin/mount /bin/umount
    /sbin/unix_chkpwd /usr/sbin/unix_chkpwd
)

SUID_FILES=$(find /bin /sbin /usr /opt /home /tmp /var /etc -perm -4000 -type f 2>/dev/null)
SUID_COUNT=0; SUID_UNKNOWN=0

while IFS= read -r f; do
    [[ -z "$f" ]] && continue
    SUID_COUNT=$((SUID_COUNT+1))
    IS_KNOWN=0
    for k in "${KNOWN_SUID[@]}"; do [[ "$f" == "$k" ]] && IS_KNOWN=1 && break; done
    if [[ "$IS_KNOWN" -eq 0 ]]; then
        OWNER=$(stat -c "%U" "$f" 2>/dev/null); PERM=$(stat -c "%a" "$f" 2>/dev/null)
        [[ "$OWNER" == "root" ]] \
            && crit "Nepoznat SUID root binary: $f ($PERM)" \
            || warn "Nepoznat SUID binary: $f ($PERM, vlasnik: $OWNER)"
        SUID_UNKNOWN=$((SUID_UNKNOWN+1))
    fi
done <<< "$SUID_FILES"

info "SUID fajlova ukupno: $SUID_COUNT | Nepoznatih: $SUID_UNKNOWN"
[[ "$SUID_UNKNOWN" -eq 0 ]] && ok "Svi SUID fajlovi su poznati sistemski binarni fajlovi."

info "SGID fajlovi:"
find /bin /sbin /usr /opt /home /tmp /var /etc -perm -2000 -type f 2>/dev/null \
| head -20 | sed 's/^/   /'

# ── 5) WORLD-READABLE / WORLD-WRITABLE ──────────────────────
hdr "5. World-readable i world-writable fajlovi"
# Fajlovi koje moze citati ili menjati BILO KO su opasni —
# napadac moze procitati konfiguracije ili ubaciti maliciozni kod.

info "World-readable+writable fajlovi (-perm -006):"
WR=$(find /etc /home /var /opt /tmp /root -type f -perm -006 2>/dev/null | head -30)
[[ -n "$WR" ]] \
    && { warn "Pronadjeni world-readable+writable fajlovi:"; echo "$WR" | sed 's/^/   /'; } \
    || ok "Nisu pronadjeni world-readable+writable fajlovi."

echo
info "World-writable fajlovi (-perm -002):"
WW=$(find /etc /home /var /opt /tmp /root -type f -perm -002 2>/dev/null | head -30)
if [[ -n "$WW" ]]; then
    warn "Pronadjeni world-writable fajlovi:"
    echo "$WW" | while read -r f; do
        OWNER=$(stat -c "%U" "$f" 2>/dev/null)
        [[ "$OWNER" == "root" ]] \
            && echo -e "   ${RED}$f${NC} <- vlasnik je root!" \
            || echo -e "   ${YEL}$f${NC}"
    done
    WARN=$((WARN+1))
else
    ok "Nisu pronadjeni world-writable fajlovi."
fi

# ── 6) WORLD-WRITABLE DIRS BEZ STICKY BITA ──────────────────
hdr "6. World-writable direktorijumi bez sticky bita"
# Bez sticky bita korisnici mogu brisati fajlove drugih,
# sto omogucava TOCTOU i symlink napade.

WDIRS=$(find /etc /home /var /opt /tmp /root -type d -perm -002 ! -perm -1000 2>/dev/null | head -20)
[[ -n "$WDIRS" ]] \
    && { warn "Pronadjeni world-writable direktorijumi bez sticky bita:"; echo "$WDIRS" | sed 's/^/   /'; WARN=$((WARN+1)); } \
    || ok "Nisu pronadjeni world-writable direktorijumi bez sticky bita."

# ── 7) ORPHANED FAJLOVI ─────────────────────────────────────
hdr "7. Fajlovi bez vlasnika ili grupe (orphaned)"
# Napadac moze kreirati korisnika sa istim UID-om i preuzeti
# kontrolu nad tim fajlovima.

NOUSER=$(find /etc /home /var /opt /tmp /root /usr -nouser 2>/dev/null | head -20)
[[ -n "$NOUSER" ]] \
    && { warn "Fajlovi bez vlasnika:"; echo "$NOUSER" | sed 's/^/   /'; } \
    || ok "Svi fajlovi imaju validnog vlasnika."

NOGROUP=$(find /etc /home /var /opt /tmp /root /usr -nogroup 2>/dev/null | head -20)
[[ -n "$NOGROUP" ]] \
    && { warn "Fajlovi bez grupe:"; echo "$NOGROUP" | sed 's/^/   /'; } \
    || ok "Svi fajlovi imaju validnu grupu."

# ── REZIME ───────────────────────────────────────────────────
echo
echo -e "${CYN}════════════════════════════════════════${NC}"
echo -e "${CYN}  REZIME NALAZA${NC}"
echo -e "${CYN}════════════════════════════════════════${NC}"
echo -e "  ${RED}Kriticnih:   ${CRIT}${NC}"
echo -e "  ${YEL}Upozorenja:  ${WARN}${NC}"
echo -e "  Ukupno:      $((CRIT+WARN))"
echo
[[ "$CRIT" -gt 0 ]] && echo -e "${RED}  !! Hitno adresirati kriticne nalaze !!${NC}" \
|| [[ "$WARN" -gt 0 ]] && echo -e "${YEL}  Preporucuje se pregled upozorenja.${NC}" \
|| echo -e "${GRN}  Konfiguracija fajl sistema izgleda uredna.${NC}"
echo