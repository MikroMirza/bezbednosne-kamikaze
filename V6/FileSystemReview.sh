#!/usr/bin/env bash
# filesystem_review.sh - Pregled bezbednosti fajl sistema
#
# Pokriva sekciju 6 (Filesystem Review) iz Secure Deployment Environment:
#   1) Montirane particije (/etc/fstab) - noatime, noexec, nosuid provere
#   2) Osetljivi sistemski fajlovi - permisije na /etc/shadow, kljucevima itd.
#   3) Backup fajlovi - kopije shadow/passwd, /backup direktorijum
#   4) SUID/SGID binarni fajlovi - fajlovi koji se izvrsavaju sa privilegijama vlasnika
#   5) World-readable i world-writable fajlovi - fajlovi citljivi/pisljivi svim korisnicima
#   6) Fajlovi bez vlasnika (orphaned) - fajlovi ciji UID/GID ne postoje
#
# Pokretanje: sudo ./filesystem_review.sh

RED='\033[0;31m'; YEL='\033[1;33m'; GRN='\033[0;32m'; CYN='\033[0;36m'; NC='\033[0m'
WARN=0; CRIT=0

warn() { echo -e "${YEL}[UPOZORENJE]${NC} $1"; WARN=$((WARN+1)); }
crit() { echo -e "${RED}[KRITICNO]  ${NC} $1"; CRIT=$((CRIT+1)); }
ok()   { echo -e "${GRN}[OK]        ${NC} $1"; }
info() { echo -e "${CYN}[INFO]      ${NC} $1"; }
hdr()  {
    echo
    echo -e "${CYN}════════════════════════════════════════${NC}"
    echo -e "${CYN}  $1${NC}"
    echo -e "${CYN}════════════════════════════════════════${NC}"
}

[[ $EUID -ne 0 ]] && warn "Skripta nije pokrenuta kao root — neki rezultati mogu biti nepotpuni."

echo
echo -e "${CYN}╔══════════════════════════════════════════╗${NC}"
echo -e "${CYN}║      FILESYSTEM REVIEW - Audit           ║${NC}"
echo -e "${CYN}║  Hostname: $(hostname)${NC}"
echo -e "${CYN}║  Datum:    $(date '+%d.%m.%Y %H:%M:%S')${NC}"
echo -e "${CYN}╚══════════════════════════════════════════╝${NC}"

# ─────────────────────────────────────────────────────────────
# 1) MONTIRANE PARTICIJE — /etc/fstab
# ─────────────────────────────────────────────────────────────
hdr "1. Montirane particije (/etc/fstab)"
# Bezbednosni znacaj:
# - noatime: bez ovog flega, svaki pristup fajlu azurira inode access time.
#   U slucaju upada, access time je dragocen forenzicki podatak.
# - noexec: sprecava izvrsavanje binarnih fajlova sa te particije.
#   Kljucno za /tmp i /home — napadac ne moze da uploaduje i pokrene malver.
# - nosuid: sprecava interpretaciju SUID bita na toj particiji.
#   Bez ovoga, napadac moze da postavi SUID root binary u /tmp i eskalira privilegije.

if [[ ! -f /etc/fstab ]]; then
    warn "/etc/fstab ne postoji."
else
    info "Sadrzaj /etc/fstab (bez komentara):"
    grep -vE '^\s*#|^\s*$' /etc/fstab | sed 's/^/   /'
    echo

    # Prolazimo kroz svaki unos u fstab
    while IFS= read -r line; do
        # Preskoci komentare i prazne linije
        [[ "$line" =~ ^\s*# || -z "${line// }" ]] && continue

        MOUNTPOINT=$(echo "$line" | awk '{print $2}')
        OPTIONS=$(echo "$line"    | awk '{print $4}')

        # noatime provera — za sve particije
        if echo "$OPTIONS" | grep -qw "noatime"; then
            ok "$MOUNTPOINT ima 'noatime' (access time se ne belezi)."
        else
            warn "$MOUNTPOINT nema 'noatime' — access time fajlova se azurira, sto otezava forenziku upada."
        fi

        # noexec provera — posebno vazno za /tmp, /home, /var
        if echo "$MOUNTPOINT" | grep -qE '^(/tmp|/home|/var)$'; then
            if echo "$OPTIONS" | grep -qw "noexec"; then
                ok "$MOUNTPOINT ima 'noexec' — izvrsavanje binarnih fajlova je onemoguceno."
            else
                crit "$MOUNTPOINT nema 'noexec' — korisnici mogu pokretati binarne fajlove sa ove particije!"
            fi
        fi

        # nosuid provera — /tmp, /home, /dev
        if echo "$MOUNTPOINT" | grep -qE '^(/tmp|/home|/dev)$'; then
            if echo "$OPTIONS" | grep -qw "nosuid"; then
                ok "$MOUNTPOINT ima 'nosuid' — SUID bit se ignorise."
            else
                crit "$MOUNTPOINT nema 'nosuid' — SUID binarni fajlovi na ovoj particiji mogu biti zloupotrebljeni!"
            fi
        fi

    done < /etc/fstab

    echo
    info "Trenutno montirane particije (mount):"
    mount | grep -vE '^(sysfs|proc|devtmpfs|devpts|tmpfs|cgroup|debugfs|securityfs|pstore|bpf|tracefs|hugetlbfs|mqueue|fusectl|configfs|ramfs)' | sed 's/^/   /'
fi

# ─────────────────────────────────────────────────────────────
# 2) OSETLJIVI SISTEMSKI FAJLOVI
# ─────────────────────────────────────────────────────────────
hdr "2. Permisije osetljivih sistemskih fajlova"
# Bezbednosni znacaj:
# - /etc/shadow sadrzi hesove lozinki — citljiv samo root-u (400 ili 640)
# - /etc/passwd mora biti citljiv svima, ali ne i pisljiv
# - /etc/sudoers kontrolise ko moze da koristi sudo — mora biti zasticen
# - SSL privatni kljucevi moraju biti citljivi samo root-u ili www-data

# Format: "putanja ocekivane_max_permisije opis"
SENSITIVE_FILES=(
    "/etc/shadow:000:Hesovi lozinki korisnika"
    "/etc/shadow-:000:Backup hesova lozinki"
    "/etc/passwd:644:Lista korisnika sistema"
    "/etc/group:644:Lista grupa sistema"
    "/etc/sudoers:440:Sudo konfiguracija"
    "/etc/ssh/ssh_host_rsa_key:600:SSH RSA privatni kljuc"
    "/etc/ssh/ssh_host_ecdsa_key:600:SSH ECDSA privatni kljuc"
    "/etc/ssh/ssh_host_ed25519_key:600:SSH ED25519 privatni kljuc"
    "/etc/mysql/my.cnf:640:MySQL konfiguracija (sadrzi lozinku)"
    "/etc/mysql/debian.cnf:600:MySQL debian-sys-maint lozinka"
)

for ENTRY in "${SENSITIVE_FILES[@]}"; do
    FPATH=$(echo "$ENTRY" | cut -d: -f1)
    MAX_PERM=$(echo "$ENTRY" | cut -d: -f2)
    DESC=$(echo "$ENTRY" | cut -d: -f3)

    if [[ ! -e "$FPATH" ]]; then
        continue
    fi

    ACTUAL_PERM=$(stat -c "%a" "$FPATH" 2>/dev/null)
    OWNER=$(stat -c "%U:%G" "$FPATH" 2>/dev/null)

    # Provjeri da li je world-readable (zadnja cifra permisija)
    WORLD_BIT=$(echo "$ACTUAL_PERM" | rev | cut -c1)

    if [[ "$WORLD_BIT" -ge 4 ]]; then
        crit "$FPATH ($DESC) je citljiv svim korisnicima! Permisije: $ACTUAL_PERM, vlasnik: $OWNER"
    elif [[ "$WORLD_BIT" -ge 2 ]]; then
        crit "$FPATH ($DESC) je pisljiv svim korisnicima! Permisije: $ACTUAL_PERM, vlasnik: $OWNER"
    else
        ok "$FPATH — permisije: $ACTUAL_PERM, vlasnik: $OWNER"
    fi
done

# SSL privatni kljucevi — pretrazuj uobicajene lokacije
echo
info "Trazim SSL/TLS privatne kljuceve na sistemu:"
SSL_KEYS=$(find /etc/ssl /etc/apache2 /etc/nginx /etc/letsencrypt -name "*.key" -o -name "*private*" 2>/dev/null | grep -v "\.pub$")
if [[ -n "$SSL_KEYS" ]]; then
    while IFS= read -r keyfile; do
        PERM=$(stat -c "%a" "$keyfile" 2>/dev/null)
        OWNER=$(stat -c "%U:%G" "$keyfile" 2>/dev/null)
        WORLD_BIT=$(echo "$PERM" | rev | cut -c1)
        if [[ "$WORLD_BIT" -ge 4 ]]; then
            crit "SSL kljuc $keyfile je citljiv svim korisnicima! Permisije: $PERM"
        else
            ok "SSL kljuc $keyfile — permisije: $PERM, vlasnik: $OWNER"
        fi
    done <<< "$SSL_KEYS"
else
    info "Nisu pronadjeni SSL privatni kljucevi na standardnim lokacijama."
fi

# ─────────────────────────────────────────────────────────────
# 3) BACKUP FAJLOVI
# ─────────────────────────────────────────────────────────────
hdr "3. Backup fajlovi i kopije osetljivih podataka"
# Bezbednosni znacaj:
# Administratori cesto prave backup kopije konfiguracionih fajlova
# (shadow.backup, passwd.bak itd.) i zaborave da ih zastite.
# Napadac moze procitati hesove lozinki iz takvih kopija
# cak i ako je originalni /etc/shadow pravilno zasticen.

info "Trazim kopije osetljivih fajlova:"

# Poznate opasne kopije
DANGEROUS_COPIES=(
    "/etc/shadow.backup"
    "/etc/shadow.bak"
    "/etc/shadow.old"
    "/etc/passwd.backup"
    "/etc/passwd.bak"
    "/etc/passwd.old"
    "/root/.bash_history"
)

for FPATH in "${DANGEROUS_COPIES[@]}"; do
    if [[ -f "$FPATH" ]]; then
        PERM=$(stat -c "%a" "$FPATH" 2>/dev/null)
        WORLD_BIT=$(echo "$PERM" | rev | cut -c1)
        if [[ "$WORLD_BIT" -ge 4 ]]; then
            crit "Nadjena opasna kopija: $FPATH je CITLJIVA SVIM KORISNICIMA! Permisije: $PERM"
        else
            warn "Nadjena kopija osetljivog fajla: $FPATH (permisije: $PERM) — proveriti da li je potrebna."
        fi
    fi
done

echo
info "Trazim .bak/.backup/.old kopije u /etc:"
find /etc -maxdepth 2 \( -name "*.bak" -o -name "*.backup" -o -name "*.old" -o -name "*.orig" \) 2>/dev/null | while read -r f; do
    PERM=$(stat -c "%a" "$f" 2>/dev/null)
    warn "Backup fajl pronadjen: $f (permisije: $PERM)"
done

echo
info "Provjera /backup direktorijuma:"
if [[ -d /backup ]]; then
    BACKUP_PERM=$(stat -c "%a" /backup 2>/dev/null)
    WORLD_BIT=$(echo "$BACKUP_PERM" | rev | cut -c1)
    if [[ "$WORLD_BIT" -ge 4 ]]; then
        crit "/backup direktorijum je citljiv svim korisnicima (permisije: $BACKUP_PERM)!"
        info "Sadrzaj /backup:"
        ls -la /backup 2>/dev/null | sed 's/^/   /'
    else
        ok "/backup postoji i nije world-readable (permisije: $BACKUP_PERM)."
    fi
else
    ok "/backup direktorijum ne postoji."
fi

# Tgz/zip arhive koje mogu sadrzati osetljive podatke
echo
info "Trazim arhive (.tgz, .tar.gz, .zip) u /etc, /root, /home, /backup:"
find /etc /root /home /backup -maxdepth 3 \( -name "*.tgz" -o -name "*.tar.gz" -o -name "*.zip" -o -name "*.tar" \) 2>/dev/null | while read -r f; do
    PERM=$(stat -c "%a" "$f" 2>/dev/null)
    WORLD_BIT=$(echo "$PERM" | rev | cut -c1)
    if [[ "$WORLD_BIT" -ge 4 ]]; then
        crit "Arhiva $f je citljiva svim korisnicima! Permisije: $PERM"
    else
        warn "Pronadjena arhiva: $f (permisije: $PERM) — proveriti sadrzaj."
    fi
done

# ─────────────────────────────────────────────────────────────
# 4) SUID/SGID BINARNI FAJLOVI
# ─────────────────────────────────────────────────────────────
hdr "4. SUID/SGID binarni fajlovi"
# Bezbednosni znacaj:
# SUID fajlovi se izvrsavaju sa privilegijama vlasnika (cesto root), a ne
# sa privilegijama korisnika koji ih pokrece. Ako napadac pronadje SUID
# binary koji nije legitiman ili ima ranjivu verziju, moze eskalirati
# privilegije na root (GTFOBins napad).

# Poznati legitimni SUID binarni fajlovi na Ubuntu/Debian sistemima
KNOWN_SUID=(
    "/usr/bin/passwd"
    "/usr/bin/sudo"
    "/usr/bin/su"
    "/usr/bin/newgrp"
    "/usr/bin/gpasswd"
    "/usr/bin/chfn"
    "/usr/bin/chsh"
    "/usr/bin/mount"
    "/usr/bin/umount"
    "/usr/bin/pkexec"
    "/usr/bin/at"
    "/usr/lib/openssh/ssh-keysign"
    "/usr/lib/dbus-1.0/dbus-daemon-launch-helper"
    "/usr/sbin/pppd"
    "/bin/ping"
    "/bin/ping6"
    "/bin/su"
    "/bin/mount"
    "/bin/umount"
    "/sbin/unix_chkpwd"
    "/usr/bin/crontab"
    "/usr/bin/wall"
    "/usr/bin/write"
    "/usr/sbin/unix_chkpwd"
)

info "Trazim sve SUID fajlove na sistemu..."
SUID_FILES=$(find /bin /sbin /usr /opt /home /tmp /var /etc -perm -4000 -type f 2>/dev/null)

SUID_COUNT=0
SUID_UNKNOWN=0

while IFS= read -r sfile; do
    [[ -z "$sfile" ]] && continue
    SUID_COUNT=$((SUID_COUNT+1))
    OWNER=$(stat -c "%U" "$sfile" 2>/dev/null)
    PERM=$(stat -c "%a" "$sfile" 2>/dev/null)

    IS_KNOWN=0
    for known in "${KNOWN_SUID[@]}"; do
        [[ "$sfile" == "$known" ]] && IS_KNOWN=1 && break
    done

    if [[ "$IS_KNOWN" -eq 0 ]]; then
        if [[ "$OWNER" == "root" ]]; then
            crit "Nepoznat SUID root binary: $sfile (permisije: $PERM, vlasnik: $OWNER)"
        else
            warn "Nepoznat SUID binary: $sfile (permisije: $PERM, vlasnik: $OWNER)"
        fi
        SUID_UNKNOWN=$((SUID_UNKNOWN+1))
    fi
done <<< "$SUID_FILES"

echo
info "Pronadjeno SUID fajlova ukupno: $SUID_COUNT"
info "Od toga nepoznatih/sumnjivih: $SUID_UNKNOWN"

if [[ "$SUID_UNKNOWN" -eq 0 ]]; then
    ok "Svi pronadjeni SUID fajlovi su poznati sistemski binarni fajlovi."
fi

echo
info "Trazim sve SGID fajlove na sistemu..."
SGID_FILES=$(find /bin /sbin /usr /opt /home /tmp /var /etc -perm -2000 -type f 2>/dev/null)
SGID_COUNT=$(echo "$SGID_FILES" | grep -c . || true)
info "Pronadjeno SGID fajlova: $SGID_COUNT"
if [[ "$SGID_COUNT" -gt 0 ]]; then
    echo "$SGID_FILES" | head -20 | sed 's/^/   /'
    [[ "$SGID_COUNT" -gt 20 ]] && info "... i jos $(( SGID_COUNT - 20 )) fajlova."
fi

# ─────────────────────────────────────────────────────────────
# 5) WORLD-READABLE I WORLD-WRITABLE FAJLOVI
# ─────────────────────────────────────────────────────────────
hdr "5. World-readable i world-writable fajlovi"
# Bezbednosni znacaj:
# World-readable (-006): fajl moze da cita BILO KO na sistemu.
#   Opasno za konfiguracije, kljuceve, log fajlove sa osetljivim podacima.
# World-writable (-002): fajl moze da modifikuje BILO KO.
#   Ako root pokrece takav skript (npr. cron), napadac moze ubaciti maliciozni kod.

info "Trazim world-readable AND world-writable fajlove (-perm -006), iskljucujuci /proc i /sys..."
WR_FILES=$(find /etc /home /var /opt /tmp /root -type f -perm -006 2>/dev/null | head -50)

if [[ -n "$WR_FILES" ]]; then
    warn "Pronadjeni world-readable+writable fajlovi (prvih 50):"
    echo "$WR_FILES" | while read -r f; do
        PERM=$(stat -c "%a" "$f" 2>/dev/null)
        OWNER=$(stat -c "%U:%G" "$f" 2>/dev/null)
        echo -e "   ${YEL}$f${NC} (permisije: $PERM, vlasnik: $OWNER)"
    done
    WARN=$((WARN+1))
else
    ok "Nisu pronadjeni world-readable+writable fajlovi."
fi

echo
info "Trazim world-writable fajlove (-perm -002), iskljucujuci /proc i /sys..."
WWRITE_FILES=$(find /etc /home /var /opt /tmp /root -type f -perm -002 2>/dev/null | head -50)

if [[ -n "$WWRITE_FILES" ]]; then
    WWRITE_COUNT=$(echo "$WWRITE_FILES" | wc -l)
    warn "Pronadjeno world-writable fajlova: $WWRITE_COUNT (prvih 50):"
    echo "$WWRITE_FILES" | while read -r f; do
        PERM=$(stat -c "%a" "$f" 2>/dev/null)
        OWNER=$(stat -c "%U:%G" "$f" 2>/dev/null)

        # Posebno upozorenje ako je vlasnik root — napadac moze modifikovati fajl
        if [[ "$(stat -c '%U' "$f" 2>/dev/null)" == "root" ]]; then
            echo -e "   ${RED}$f${NC} (permisije: $PERM, vlasnik: $OWNER) ← vlasnik je root!"
        else
            echo -e "   ${YEL}$f${NC} (permisije: $PERM, vlasnik: $OWNER)"
        fi
    done
    WARN=$((WARN+1))
else
    ok "Nisu pronadjeni world-writable fajlovi."
fi

echo
info "Trazim world-writable DIREKTORIJUME bez sticky bita:"
# Sticky bit na direktorijumu znaci da korisnik moze brisati samo SVOJE fajlove.
# Bez njega, svako moze brisati/zamenjivati fajlove drugih u tom direktorijumu.
WWRITE_DIRS=$(find /etc /home /var /opt /tmp /root -type d -perm -002 ! -perm -1000 2>/dev/null | head -30)

if [[ -n "$WWRITE_DIRS" ]]; then
    warn "Pronadjeni world-writable direktorijumi BEZ sticky bita:"
    echo "$WWRITE_DIRS" | while read -r d; do
        PERM=$(stat -c "%a" "$d" 2>/dev/null)
        OWNER=$(stat -c "%U:%G" "$d" 2>/dev/null)
        echo -e "   ${YEL}$d${NC} (permisije: $PERM, vlasnik: $OWNER)"
    done
    WARN=$((WARN+1))
else
    ok "Nisu pronadjeni world-writable direktorijumi bez sticky bita."
fi

# ─────────────────────────────────────────────────────────────
# 6) FAJLOVI BEZ VLASNIKA (ORPHANED)
# ─────────────────────────────────────────────────────────────
hdr "6. Fajlovi bez vlasnika ili grupe (orphaned)"
# Bezbednosni znacaj:
# Fajlovi ciji UID/GID ne postoje u /etc/passwd ili /etc/group
# ukazuju na lose uklonjen korisnicki nalog ili zaostale artefakte.
# Napadac moze kreirati novog korisnika sa istim UID-om i preuzeti
# kontrolu nad tim fajlovima.

info "Trazim fajlove bez vlasnika (nouser)..."
NOUSER=$(find /etc /home /var /opt /tmp /root /usr -nouser 2>/dev/null | head -30)
if [[ -n "$NOUSER" ]]; then
    NOUSER_COUNT=$(echo "$NOUSER" | wc -l)
    warn "Pronadjeno $NOUSER_COUNT fajlova bez vlasnika:"
    echo "$NOUSER" | sed 's/^/   /'
else
    ok "Svi fajlovi imaju validnog vlasnika."
fi

echo
info "Trazim fajlove bez grupe (nogroup)..."
NOGROUP=$(find /etc /home /var /opt /tmp /root /usr -nogroup 2>/dev/null | head -30)
if [[ -n "$NOGROUP" ]]; then
    NOGROUP_COUNT=$(echo "$NOGROUP" | wc -l)
    warn "Pronadjeno $NOGROUP_COUNT fajlova bez grupe:"
    echo "$NOGROUP" | sed 's/^/   /'
else
    ok "Svi fajlovi imaju validnu grupu."
fi

# ─────────────────────────────────────────────────────────────
# REZIME
# ─────────────────────────────────────────────────────────────
echo
echo -e "${CYN}════════════════════════════════════════${NC}"
echo -e "${CYN}  REZIME NALAZA${NC}"
echo -e "${CYN}════════════════════════════════════════${NC}"
echo -e "  ${RED}Kriticnih nalaza:  ${CRIT}${NC}"
echo -e "  ${YEL}Upozorenja:        ${WARN}${NC}"
TOTAL=$((CRIT + WARN))
echo -e "  Ukupno problema:   ${TOTAL}"
echo

if [[ "$CRIT" -gt 0 ]]; then
    echo -e "${RED}  !! Hitno je potrebno adresirati kriticne nalaze !!${NC}"
elif [[ "$WARN" -gt 0 ]]; then
    echo -e "${YEL}  Preporucuje se pregled upozorenja.${NC}"
else
    echo -e "${GRN}  Osnovna konfiguracija fajl sistema izgleda uredna.${NC}"
fi
echo