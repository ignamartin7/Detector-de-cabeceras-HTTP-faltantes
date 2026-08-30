import requests
import argparse
import urllib3
import sys

# Desactiva las advertencias de certificados TLS inválidos (útil para pentesting interno y CTFs)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Matriz de cabeceras de seguridad principales y sus riesgos asociados
SECURITY_HEADERS = {
    "Strict-Transport-Security": "Permite ataques Man-in-the-Middle (MitM) y downgrade a HTTP no seguro (SSL Stripping).",
    "Content-Security-Policy": "Aumenta drásticamente la superficie de exposición para Cross-Site Scripting (XSS) y la inyección de datos.",
    "X-Frame-Options": "Vulnerabilidad a Clickjacking al permitir que la página sea embebida en iframes maliciosos de terceros.",
    "X-Content-Type-Options": "Permite ataques de MIME-sniffing, donde el navegador puede ejecutar contenido engañoso (ej. un script camuflado como imagen).",
    "Referrer-Policy": "Fuga de información sensible (como tokens en URLs) hacia otros dominios a través de la cabecera Referer.",
    "Permissions-Policy": "Permite que scripts de terceros abusen de APIs del navegador (cámara, micrófono, geolocalización) si el sitio es comprometido."
}

# Códigos de color ANSI para la terminal
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
RESET = '\033[0m'
BOLD = '\033[1m'

def analyze_headers(url):
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    print(f"\n{BOLD}[*] Analizando cabeceras de seguridad para: {url}{RESET}\n")

    try:
        # User-Agent estándar para evitar bloqueos iniciales por WAFs básicos
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        
        # Realizamos la petición (verify=False para ignorar errores de certificados autofirmados)
        response = requests.get(url, headers=headers, verify=False, timeout=10)
        
        # Las cabeceras HTTP son case-insensitive, las pasamos a minúsculas para evitar falsos positivos
        response_headers = {k.lower(): v for k, v in response.headers.items()}
        
        present_headers = []
        missing_headers = []

        for header, risk in SECURITY_HEADERS.items():
            if header.lower() in response_headers:
                present_headers.append(header)
            else:
                missing_headers.append((header, risk))

        print(f"{BOLD}{GREEN}[+] CABECERAS DE SEGURIDAD IMPLEMENTADAS:{RESET}")
        if present_headers:
            for h in present_headers:
                print(f"    ✔️  {h}")
        else:
            print("    ⚠️  Ninguna cabecera de seguridad principal fue detectada.")

        print(f"\n{BOLD}{RED}[-] CABECERAS DE SEGURIDAD FALTANTES:{RESET}")
        if missing_headers:
            for h, r in missing_headers:
                print(f"    ❌ {BOLD}{h}{RESET}")
                print(f"       {YELLOW}Riesgo:{RESET} {r}")
        else:
            print("    🚀 ¡Excelente! Todas las cabeceras base están configuradas.")
            
        print("\n" + "-"*60 + "\n")

    except requests.exceptions.RequestException as e:
        print(f"{RED}[!] Error de conexión con el objetivo:{RESET} {e}")
        sys.exit(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Escáner de cabeceras de seguridad HTTP")
    parser.add_argument("url", help="URL del sitio a analizar (ej. google.com o https://ejemplo.com)")
    args = parser.parse_args()
    
    analyze_headers(args.url)