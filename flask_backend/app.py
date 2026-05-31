import os
import zipfile
import subprocess
import shutil
import sys
import time
import json
from flask import Flask, request, jsonify

app = Flask(__name__)
PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(PROJECT_DIR, 'uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Putanje do resursa
ROOTFS_TEMPLATE = os.path.join(PROJECT_DIR, 'rootfs.ext4')
VMLINUX_PATH = os.path.join(PROJECT_DIR, 'vmlinux')
MOUNT_POINT = '/media/floppy'

# Apsolutna putanja do Firecracker-a
FIRECRACKER_PATH = '/home/leon/firecracker'

@app.route('/submit', methods=['POST'])
def submit_code():
    if 'file' not in request.files:
        return jsonify({"error": "Nema fajla u zahtevu"}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "Fajl nema ime"}), 400

    # 1. Ciscenje i priprema uploads foldera
    if os.path.exists(UPLOAD_FOLDER):
        shutil.rmtree(UPLOAD_FOLDER)
    os.makedirs(UPLOAD_FOLDER)

    zip_path = os.path.join(UPLOAD_FOLDER, 'user_code.zip')
    file.save(zip_path)

    # 2. Otpakivanje ZIP arhive
    extract_path = os.path.join(UPLOAD_FOLDER, 'extracted')
    try:
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(extract_path)
    except zipfile.BadZipFile:
        return jsonify({"error": "Neispravan ZIP fajl"}), 400

    # 3. AKTIVNA STATICKA ANALIZA (Bandit) - Blokiranje ako ima ranjivosti
    try:
        bandit_path = os.path.join(PROJECT_DIR, 'venv', 'bin', 'bandit')
        # Pokrecemo bandit i trazimo JSON izvestaj u stdout
        rezultat_skeniranja = subprocess.run(
            [bandit_path, '-r', extract_path, '-f', 'json'],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        
        # Bandit vraca returncode 0 ako nema ranjivosti. Ako je > 0, nesto je pronasao!
        if rezultat_skeniranja.returncode != 0:
            podaci_o_greskama = json.loads(rezultat_skeniranja.stdout)
            if podaci_o_greskama.get("results"):
                prva_greska = podaci_o_greskama["results"][0]
                
                # Sastavljamo detaljan izvestaj za korisnika
                detalji_ranjivosti = {
                    "detektovana_ranjivost": prva_greska.get("issue_text"),
                    "kod_ranjivosti": prva_greska.get("test_id"),
                    "nivo_opasnosti": prva_greska.get("issue_severity"),
                    "linija_koda": prva_greska.get("line_number"),
                    "sporni_kod": prva_greska.get("code").strip() if prva_greska.get("code") else ""
                }
                
                return jsonify({
                    "status": "BLOKIRANO",
                    "error": "Zlonamerni ili nesigurni kod je detektovan! Izvrsenje u Firecracker-u je obustavljeno.",
                    "detalji_analize": detalji_ranjivosti
                }), 403 # 403 Forbidden status
                
    except Exception as e:
        return jsonify({"error": f"Greska prilikom staticke analize: {str(e)}"}), 500

    # 4. Montiranje diska i ubacivanje koda (Pokrece se samo ako je Bandit prosao!)
    try:
        mount_check = subprocess.run(['mountpoint', '-q', MOUNT_POINT])
        if mount_check.returncode != 0:
            subprocess.run(['sudo', 'mount', '-o', 'loop', ROOTFS_TEMPLATE, MOUNT_POINT], check=True)

        vm_app_dir = os.path.join(MOUNT_POINT, 'app')
        os.makedirs(vm_app_dir, exist_ok=True)

        shutil.copy(os.path.join(extract_path, 'test_script.py'), os.path.join(vm_app_dir, 'test_script.py'))

        out_fajl = os.path.join(vm_app_dir, 'output.txt')
        if os.path.exists(out_fajl):
            os.remove(out_fajl)

        req_path = os.path.join(extract_path, 'requirements.txt')
        if os.path.exists(req_path):
            vm_libs_dir = os.path.join(vm_app_dir, 'libs')
            os.makedirs(vm_libs_dir, exist_ok=True)
            
            pip_path = os.path.join(PROJECT_DIR, 'venv', 'bin', 'pip')
            subprocess.run([
                pip_path, 'install', '-r', req_path, '--target', vm_libs_dir, '--no-cache-dir'
            ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)

    except Exception as e:
        print(f"PROCES GRESKA: {str(e)}", file=sys.stderr)
        return jsonify({"error": f"Greska sa diskom: {str(e)}"}), 500
    finally:
        mount_check = subprocess.run(['mountpoint', '-q', MOUNT_POINT])
        if mount_check.returncode == 0:
            subprocess.run(['sudo', 'umount', MOUNT_POINT], check=True)

    # 5. POKRETANJE FIRECRACKER MIKRO-MASINE
    try:
        socket_path = "/tmp/firecracker.socket"
        if os.path.exists(socket_path):
            os.remove(socket_path)

        logfile = open(os.path.join(PROJECT_DIR, 'fc_start.log'), 'w')
        subprocess.Popen(
            [FIRECRACKER_PATH, '--api-sock', socket_path],
            stdout=logfile, stderr=logfile, stdin=subprocess.DEVNULL
        )

        time.sleep(0.3)

        # A) Kernel
        kernel_config = {
            "kernel_image_path": VMLINUX_PATH,
            "boot_args": "console=ttyS0 reboot=k panic=1 pci=off"
        }
        subprocess.run([
            'curl', '--unix-socket', socket_path, '-X', 'PUT',
            'http://localhost/boot-source', '-H', 'Content-Type: application/json',
            '-d', json.dumps(kernel_config)
        ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # B) Drive
        drive_config = {
            "drive_id": "rootfs",
            "path_on_host": ROOTFS_TEMPLATE,
            "is_root_device": True,
            "is_read_only": False
        }
        subprocess.run([
            'curl', '--unix-socket', socket_path, '-X', 'PUT',
            'http://localhost/drives/rootfs', '-H', 'Content-Type: application/json',
            '-d', json.dumps(drive_config)
        ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # C) Start
        start_config = {"action_type": "InstanceStart"}
        subprocess.run([
            'curl', '--unix-socket', socket_path, '-X', 'PUT',
            'http://localhost/actions', '-H', 'Content-Type: application/json',
            '-d', json.dumps(start_config)
        ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        time.sleep(1.5)

    except Exception as e:
        print(f"FIRECRACKER GRESKA: {str(e)}", file=sys.stderr)
        return jsonify({"error": f"Greska pri pokretanju masine: {str(e)}"}), 500

    # 6. CITANJE REZULTATA IZ DISKA NAKON GASENJA
    izlaz_iz_koda = "Nema ispisa (Skripta nije generisala output)."
    try:
        subprocess.run(['sudo', 'pkill', '-9', 'firecracker'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(['sudo', 'mount', '-o', 'loop', ROOTFS_TEMPLATE, MOUNT_POINT], check=True)
        
        rezultat_putanja = os.path.join(MOUNT_POINT, 'app', 'output.txt')
        if os.path.exists(rezultat_putanja):
            with open(rezultat_putanja, 'r') as f:
                izlaz_iz_koda = f.read()
    except Exception as e:
        print(f"GRESKA KOD CITANJA REZULTATA: {str(e)}", file=sys.stderr)
    finally:
        mount_check = subprocess.run(['mountpoint', '-q', MOUNT_POINT])
        if mount_check.returncode == 0:
            subprocess.run(['sudo', 'umount', MOUNT_POINT], check=True)

    return jsonify({
        "status": "Uspesno izvrseno!",
        "rezultat_izvrsavanja": izlaz_iz_koda
    }), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True, use_reloader=False)
