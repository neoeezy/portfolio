#!/usr/bin/env python3
import socket
import ssl
import argparse
import requests

# ---------------------------------------
# Scan des ports
# ---------------------------------------
def scan_ports(host, start_port, end_port):
    print(f"\n🔍 Scan des ports {start_port}-{end_port} sur {host}...\n")

    for port in range(start_port, end_port + 1):
        s = socket.socket()
        s.settimeout(0.3)

        try:
            s.connect((host, port))
            print(f"[✔] Port ouvert : {port}")
        except:
            pass
        finally:
            s.close()

# ---------------------------------------
# Récupération des en-têtes HTTP
# ---------------------------------------
def http_headers(host):
    print(f"\n🌐 Récupération des en-têtes HTTP pour https://{host}\n")

    try:
        r = requests.get(f"https://{host}", timeout=3)
        for k, v in r.headers.items():
            print(f"{k}: {v}")
    except Exception as e:
        print(f"[Erreur] Impossible d'obtenir les en-têtes HTTP : {e}")

# ---------------------------------------
# Récupération du certificat TLS
# ---------------------------------------
def tls_certificate(host):
    print(f"\n🔐 Extraction du certificat TLS pour {host}\n")

    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
            s.connect((host, 443))
            cert = s.getpeercert()

        for k, v in cert.items():
            print(f"{k}: {v}")

    except Exception as e:
        print(f"[Erreur] Impossible de récupérer le certificat TLS : {e}")

# ---------------------------------------
# Arguments CLI
# ---------------------------------------
def main():
    parser = argparse.ArgumentParser(description="CyberScan - Outil simple de scan cybersécurité")

    parser.add_argument("--target", required=True, help="Cible à analyser (IP ou domaine)")
    parser.add_argument("--ports", help="Plage de ports ex: 20-80")
    parser.add_argument("--http", action="store_true", help="Afficher en-têtes HTTP")
    parser.add_argument("--tls", action="store_true", help="Afficher certificat TLS")

    args = parser.parse_args()

    host = args.target

    # Scan ports
    if args.ports:
        try:
            start, end = map(int, args.ports.split("-"))
            scan_ports(host, start, end)
        except:
            print("Format des ports invalide (utilise ex: 20-100)")

    # HTTP headers
    if args.http:
        http_headers(host)

    # Certificat TLS
    if args.tls:
        tls_certificate(host)

if __name__ == "__main__":
    main()

