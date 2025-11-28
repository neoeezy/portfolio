"""
CyberScan - Outil de scan cybersécurité simple
Fichier: cyberscan.py

But: Ce fichier contient à la fois le code et une documentation (README + explication pour ta soutenance OpenClassrooms).

Usage (exemples):
  python3 cyberscan.py --target example.com --ports 20-1024 --http --tls
  python3 cyberscan.py --target 192.168.1.10 --ports 22,80,443 --timeout 1

AVERTISSEMENT LÉGAL (LIRE!)
Ne scanne que des hôtes pour lesquels vous avez l'autorisation explicite (vos machines, labo, cibles de test).
L'utilisation de ce script contre des systèmes sans permission peut être illégale et entraîner des sanctions.
Ce projet est éducatif et défensif.

Description courte pour la soutenance
------------------------------------
Objectif : Montrer les principes de base d'un scan réseau/web simple — découverte de ports TCP ouverts,
collecte d'en-têtes HTTP et inspection basique de certificats TLS.

Fonctions incluses
- scan_ports : scan TCP connect (fast, portable)
- fetch_http_headers : récupère en-têtes HTTP et status code (si --http)
- get_tls_cert_info : lit le certificat TLS (si --tls)
- threads pour accélérer le scan de ports

Comment expliquer techniquement (pour ta soutenance)
1. Principe du scan de ports : tentative de connexion TCP "3-way" mais ici on fait un connect(),
   ce qui est simple et portable (pas besoin de paquets raw ni privilèges root).
2. Risques & limitations : connect() peut être lent; pare-feu peut filtrer; résultats faux négatifs si
   rate-limiting/IDS.
3. HTTP headers : serveur révèle souvent sa version (Server header) — utile mais pas toujours fiable.
4. TLS : lecture du certificat permet de vérifier l'émetteur, CN/SAN, et dates de validité.
5. Éthique & légalité : demander autorisation, expliquer impact sur la disponibilité.

Extensions possibles pour la suite (si tu veux montrer amélioration)
- intégration d'un fuzzing basique d'URLs ou répertoires (wordlist)
- détection de versions vulnérables via comparaisons CVE (base de données)
- export JSON/CSV pour reporting
- interface web légère (Flask) pour démonstration sur ton laptop


------------------------- FIN DU README EMBARQUÉ -------------------------
"""

import socket
import ssl
import argparse
import threading
from queue import Queue
import sys
import time
from datetime import datetime
from urllib.parse import urlparse
import http.client

# ----------- Configuration par défaut -----------
DEFAULT_TIMEOUT = 2.0
DEFAULT_THREADS = 100
COMMON_PORTS = [21,22,23,25,53,80,110,139,143,443,445,3306,3389,8080]

# ----------- Fonctions utilitaires -----------

def parse_ports(ports_str):
    """Parse '22,80,8000-8100' -> sorted list of ints"""
    ports = set()
    if not ports_str:
        return COMMON_PORTS
    for part in ports_str.split(','):
        part = part.strip()
        if '-' in part:
            a,b = part.split('-',1)
            try:
                a = int(a); b = int(b)
                ports.update(range(min(a,b), max(a,b)+1))
            except ValueError:
                continue
        else:
            try:
                ports.add(int(part))
            except ValueError:
                continue
    return sorted(p for p in ports if 1 <= p <= 65535)


def is_port_open(host, port, timeout=DEFAULT_TIMEOUT):
    """Try a TCP connect to see whether the port is open."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        s.close()
        return True
    except Exception:
        return False


# ----------- Scanner de ports multi-threadé -----------

def scan_ports(host, ports, timeout=DEFAULT_TIMEOUT, threads=DEFAULT_THREADS):
    q = Queue()
    for p in ports:
        q.put(p)
    open_ports = []

    def worker():
        while not q.empty():
            port = q.get()
            if is_port_open(host, port, timeout):
                open_ports.append(port)
            q.task_done()

    workers = []
    for _ in range(min(threads, len(ports))):
        t = threading.Thread(target=worker, daemon=True)
        t.start()
        workers.append(t)
    q.join()
    return sorted(open_ports)


# ----------- HTTP headers -----------

def fetch_http_headers(target_host, port=80, timeout=DEFAULT_TIMEOUT):
    """Fetch HTTP headers (basic). Returns dict with status and headers or None on error."""
    try:
        # use http.client to avoid extra dependencies
        conn = http.client.HTTPConnection(target_host, port=port, timeout=timeout)
        conn.request('HEAD', '/')
        res = conn.getresponse()
        headers = {k: v for k,v in res.getheaders()}
        return {'status': res.status, 'reason': res.reason, 'headers': headers}
    except Exception:
        return None


# ----------- TLS certificate info -----------

def get_tls_cert_info(host, port=443, timeout=DEFAULT_TIMEOUT):
    """Retrieve certificate and return simple parsed info or None."""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                # cert is a dict; we'll extract common fields
                subject = dict(x[0] for x in cert.get('subject', ())) if cert.get('subject') else {}
                issuer = dict(x[0] for x in cert.get('issuer', ())) if cert.get('issuer') else {}
                notBefore = cert.get('notBefore')
                notAfter = cert.get('notAfter')
                altNames = cert.get('subjectAltName', ())
                return {'subject': subject, 'issuer': issuer, 'notBefore': notBefore, 'notAfter': notAfter, 'altNames': altNames}
    except Exception:
        return None


# ----------- CLI / Main -----------

def main():
    parser = argparse.ArgumentParser(description='CyberScan - scanner simple (éducatif)')
    parser.add_argument('--target', '-t', required=True, help='Nom d\'hôte ou IP cible (ex : example.com ou 192.168.1.10)')
    parser.add_argument('--ports', '-p', default=None, help='Ports à scanner (ex: 22,80,8000-8100). Par défaut ports courants.')
    parser.add_argument('--http', action='store_true', help='Récupérer les en-têtes HTTP si port 80/8080 ouvert')
    parser.add_argument('--tls', action='store_true', help='Lire le certificat TLS (port 443)')
    parser.add_argument('--timeout', type=float, default=DEFAULT_TIMEOUT, help='Timeout en secondes (défaut 2s)')
    parser.add_argument('--threads', type=int, default=DEFAULT_THREADS, help='Nombre de threads pour le scan de ports')
    args = parser.parse_args()

    target = args.target
    # if user passed a URL, extract host
    if '://' in target:
        target = urlparse(target).hostname or target

    print(f"CyberScan - démarrage: {target}")
    start = time.time()

    ports = parse_ports(args.ports)
    print(f"Ports à tester: {len(ports)} (ex: {ports[:10]})")

    open_ports = scan_ports(target, ports, timeout=args.timeout, threads=args.threads)
    print('\n=== Résultat scan ports ===')
    if open_ports:
        for p in open_ports:
            print(f"Port {p} : ouvert")
    else:
        print("Aucun port ouvert détecté dans la plage fournie (ou filtré).")

    # HTTP
    if args.http:
        # check common http ports among open_ports
        for p in [80,8080,8000]:
            if p in open_ports:
                print(f"\n=== En-têtes HTTP sur {target}:{p} ===")
                info = fetch_http_headers(target, port=p, timeout=args.timeout)
                if info:
                    print(f"Status: {info['status']} {info['reason']}")
                    for k,v in info['headers'].items():
                        print(f"{k}: {v}")
                else:
                    print('Impossible de récupérer les en-têtes HTTP.')
                break
        else:
            print('\nAucun port HTTP (80/8080/8000) ouvert détecté — impossible de récupérer les en-têtes.')

    # TLS
    if args.tls:
        if 443 in open_ports:
            print(f"\n=== Certificat TLS sur {target}:443 ===")
            cert = get_tls_cert_info(target, port=443, timeout=args.timeout)
            if cert:
                print('Sujet:', cert['subject'])
                print('Émetteur:', cert['issuer'])
                print('Valide du', cert['notBefore'], 'au', cert['notAfter'])
                if cert['altNames']:
                    print('SANs:', cert['altNames'])
            else:
                print('Impossible de récupérer le certificat TLS.')
        else:
            # try anyway (maybe filtered in scan)
            print('\nPort 443 non listé ouvert; tentative de lecture TLS de toute façon...')
            cert = get_tls_cert_info(target, port=443, timeout=args.timeout)
            if cert:
                print('Sujet:', cert['subject'])
                print('Émetteur:', cert['issuer'])
                print('Valide du', cert['notBefore'], 'au', cert['notAfter'])
            else:
                print('Impossible de récupérer le certificat TLS (hôte fermé ou filtré).')

    delta = time.time() - start
    print(f"\nScan terminé en {delta:.2f} s")


if __name__ == '__main__':
    main()


# ----------------- Notes pour la soutenance (à lire) -----------------
# Exemples de démonstration que tu peux utiliser en live (sur ta VM ou un serveur test):
# - Lancer le scanner sur une machine locale dans un réseau de labo
# - Montrer que le header Server peut révéler la version (ex: 'Apache/2.4.41')
# - Montrer le certificat TLS et expliquer CN/SAN et dates (expired vs valid)
# - Expliquer pourquoi certains ports peuvent être 'filtered' et donner des exemples d'IDS

# Limitations importantes:
# - Ce script fait un TCP connect() : simple, mais bruyant et détectable.
# - Pour des scans plus avancés, utiliser nmap ou bibliothèques spécialisées.
# - Threads trop nombreux peuvent saturer la machine ou le réseau.

# Licence: MIT
