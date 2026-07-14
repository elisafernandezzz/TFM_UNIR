import dns.resolver
import ssl
import socket
import requests
from difflib import SequenceMatcher
import os
import whois
from datetime import datetime, timezone
from urllib.parse import urlparse
import ipaddress


VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
APIVOID_API_KEY = os.getenv("APIVOID_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")

if not VIRUSTOTAL_API_KEY:
    print("No se ha encontrado la API key de VirusTotal.")
    exit()


PALABRAS_SENSIBLES = [
    "login", "secure", "verify", "account", "password",
    "signin", "support", "auth", "cuenta", "verificar",
    "seguridad", "contraseña", "acceso"
]


def similitud(dominio, dominio_legitimo):
    return SequenceMatcher(None, dominio, dominio_legitimo).ratio()


def tiene_palabras_sensibles(dominio):
    encontradas = []

    for palabra in PALABRAS_SENSIBLES:
        if palabra in dominio.lower():
            encontradas.append(palabra)

    return encontradas

def obtener_ip(dominio):
    try:
        return socket.gethostbyname(dominio)
    except:
        return None


def tiene_mx(dominio):
    try:
        dns.resolver.resolve(dominio, "MX")
        return True
    except:
        return False


def tiene_https(dominio):
    try:
        contexto = ssl.create_default_context()

        with socket.create_connection((dominio, 443), timeout=5) as sock:
            with contexto.wrap_socket(sock, server_hostname=dominio):
                return True

    except:
        return False


def edad_dominio(dominio):
    try:
        info = whois.whois(dominio)

        fecha_creacion = info.creation_date

        if isinstance(fecha_creacion, list):
            fecha_creacion = fecha_creacion[0]

        if fecha_creacion is None:
            return {
                "estado": "sin_fecha",
                "dias": None
            }

        if fecha_creacion.tzinfo is None:
            fecha_creacion = fecha_creacion.replace(tzinfo=timezone.utc)

        hoy = datetime.now(timezone.utc)

        return {
            "estado": "ok",
            "dias": (hoy - fecha_creacion).days
        }

    except Exception as e:
        mensaje = str(e)

        if "No match for" in mensaje:
            return {
                "estado": "no_registrado",
                "dias": None
            }

        return {
            "estado": "error",
            "dias": None,
            "detalle": mensaje
        }

def limpiar_objetivo(entrada):
    entrada = entrada.strip()

    # Si el usuario mete "ejemplo.com/login" sin esquema,
    # urlparse lo interpreta mal. Le añadimos uno temporal.
    if "://" not in entrada:
        entrada_parseable = "http://" + entrada
    else:
        entrada_parseable = entrada

    parsed = urlparse(entrada_parseable)

    host = parsed.hostname

    if not host:
        return None

    # Quitar punto final: ejemplo.com.
    host = host.rstrip(".").lower()

    # Quitar www si quieres comparar reputación del dominio raíz
    # Ojo: esto es opcional. Puedes comentarlo.
    if host.startswith("www."):
        host = host[4:]

    return host   


def reputacion_apivoid(dominio):
    if not APIVOID_API_KEY:
        return {
            "evaluado": False,
            "malicioso": False,
            "detalle": "APIVoid no evaluado: falta la API key."
        }

    url = "https://api.apivoid.com/v2/domain-reputation"

    headers = {
        "Content-Type": "application/json",
        "X-API-Key": APIVOID_API_KEY
    }

    payload = {
        "domain": dominio
    }

    try:
        respuesta = requests.post(url, headers=headers, json=payload, timeout=10)

        if respuesta.status_code != 200:
            return {
                "evaluado": False,
                "malicioso": False,
                "detalle": f"No se pudo consultar APIVoid. Código: {respuesta.status_code}"
            }

        datos = respuesta.json()

        # APIVoid puede cambiar ligeramente la estructura de respuesta.
        # Por eso se usa .get() para evitar errores.
        data = datos.get("data", {})
        report = data.get("report", {})
        blacklist = report.get("blacklist", {})
        detections = blacklist.get("detections", 0)

        if detections > 0:
            return {
                "evaluado": True,
                "malicioso": True,
                "detalle": f"APIVoid: dominio detectado en {detections} listas negras."
            }

        return {
            "evaluado": True,
            "malicioso": False,
            "detalle": "APIVoid no muestra detecciones en listas negras."
        }

    except Exception as e:
        return {
            "evaluado": False,
            "malicioso": False,
            "detalle": f"Error consultando APIVoid: {e}"
        }
    
def reputacion_abuseipdb(dominio):
    if not ABUSEIPDB_API_KEY:
        return {
            "evaluado": False,
            "malicioso": False,
            "detalle": "AbuseIPDB no evaluado: falta la API key."
        }

    ip = obtener_ip(dominio)

    if not ip:
        return {
            "evaluado": False,
            "malicioso": False,
            "detalle": "No se pudo obtener la IP del dominio para consultar AbuseIPDB."
        }

    url = "https://api.abuseipdb.com/api/v2/check"

    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }

    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }

    try:
        respuesta = requests.get(url, headers=headers, params=params, timeout=10)

        if respuesta.status_code != 200:
            return {
                "evaluado": False,
                "malicioso": False,
                "detalle": f"No se pudo consultar AbuseIPDB. Código: {respuesta.status_code}"
            }

        datos = respuesta.json()
        data = datos.get("data", {})

        score = data.get("abuseConfidenceScore", 0)
        total_reports = data.get("totalReports", 0)

        if score >= 25:
            return {
                "evaluado": True,
                "malicioso": True,
                "detalle": (
                    f"AbuseIPDB: IP {ip} con abuseConfidenceScore {score} "
                    f"y {total_reports} reportes."
                )
            }

        return {
            "evaluado": True,
            "malicioso": False,
            "detalle": (
                f"AbuseIPDB: IP {ip} sin reputación negativa relevante. "
                f"Score: {score}, reportes: {total_reports}."
            )
        }

    except Exception as e:
        return {
            "evaluado": False,
            "malicioso": False,
            "detalle": f"Error consultando AbuseIPDB: {e}"
        }

def reputacion_virustotal(dominio):
    url = f"https://www.virustotal.com/api/v3/domains/{dominio}"

    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }

    try:
        respuesta = requests.get(url, headers=headers, timeout=10)

        if respuesta.status_code == 404:
            return {
                "evaluado": True,
                "malicioso": False,
                "detalle": "El dominio no aparece en VirusTotal."
            }

        if respuesta.status_code != 200:
            return {
                "evaluado": False,
                "malicioso": False,
                "detalle": f"No se pudo consultar VirusTotal. Código: {respuesta.status_code}"
            }

        datos = respuesta.json()

        stats = datos["data"]["attributes"]["last_analysis_stats"]

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)

        if malicious > 0 or suspicious > 0:
            return {
                "evaluado": True,
                "malicioso": True,
                "detalle": (
                    f"VirusTotal: {malicious} motores lo marcan como malicioso "
                    f"y {suspicious} como sospechoso."
                )
            }
        else:
            return {
                "evaluado": True,
                "malicioso": False,
                "detalle": (
                    f"VirusTotal no muestra detecciones negativas. "
                    f"Harmless: {harmless}, undetected: {undetected}."
                )
            }

    except Exception as e:
        return {
            "evaluado": False,
            "malicioso": False,
            "detalle": f"Error consultando VirusTotal: {e}"
        }


def analizar_dominio(dominio, dominio_legitimo):
    puntuacion = 0

    print("\n--- Análisis del dominio ---")
    print("Dominio analizado:", dominio)
    print("Dominio legítimo:", dominio_legitimo)

    # 1. Similitud léxica
    sim = similitud(dominio, dominio_legitimo)

    print("\n1. Similitud léxica:", round(sim, 2))

    if sim > 0.70 and dominio != dominio_legitimo:
        print("   Riesgo: el dominio se parece al legítimo.")
        puntuacion += 30
    else:
        print("   Sin riesgo claro por similitud.")

    # 2. Palabras sensibles
    palabras = tiene_palabras_sensibles(dominio)

    print("\n2. Palabras sensibles:", palabras)

    if palabras:
        print("   Riesgo: contiene palabras usadas en phishing.")
        puntuacion += 20
    else:
        print("   No se detectan palabras sensibles.")

    # 3. Registros MX
    print("\n3. Registros MX:")

    if tiene_mx(dominio):
        print("   Riesgo leve: el dominio tiene correo configurado.")
        puntuacion += 10
    else:
        print("   No tiene registros MX.")

    # 4. HTTPS
    print("\n4. HTTPS:")

    if tiene_https(dominio):
        print("   Tiene certificado HTTPS.")
        puntuacion += 10
    else:
        print("   No se detecta HTTPS.")

    # 5. Antigüedad del dominio mediante WHOIS
    print("\n5. Antigüedad del dominio:")

    whois_resultado = edad_dominio(dominio)

    if whois_resultado["estado"] == "ok":
        dias = whois_resultado["dias"]

        print(f"   El dominio tiene aproximadamente {dias} días.")

        if dias < 30:
            print("   Riesgo: el dominio ha sido registrado recientemente.")
            puntuacion += 30
        else:
            print("   El dominio no parece reciente.")

    elif whois_resultado["estado"] == "no_registrado":
        print("   El dominio no aparece registrado en WHOIS.")
        print("   No se puede calcular su antigüedad.")

    elif whois_resultado["estado"] == "sin_fecha":
        print("   WHOIS responde, pero no incluye fecha de creación.")

    else:
        print("   No se pudo consultar WHOIS correctamente.")
        print("   Detalle:", whois_resultado.get("detalle"))

    # 6. Reputación en APIVoid
    print("\n7. Reputación en APIVoid:")

    apivoid = reputacion_apivoid(dominio)
    print("  ", apivoid["detalle"])

    if apivoid["malicioso"]:
        puntuacion += 30

    # 7. Reputación de IP en AbuseIPDB
    print("\n8. Reputación de IP en AbuseIPDB:")

    abuseipdb = reputacion_abuseipdb(dominio)
    print("  ", abuseipdb["detalle"])

    if abuseipdb["malicioso"]:
        puntuacion += 30

    # 8. Reputación en VirusTotal
    print("\n6. Reputación en VirusTotal:")

    vt = reputacion_virustotal(dominio)
    print("  ", vt["detalle"])

    if vt["malicioso"]:
        puntuacion += 40

    # Resultado final
    print("\n--- Resultado final ---")
    print("Puntuación:", puntuacion)

    if puntuacion >= 70:
        print("Nivel de riesgo: ALTO")
    elif puntuacion >= 35:
        print("Nivel de riesgo: MEDIO")
    else:
        print("Nivel de riesgo: BAJO")


entrada_sospechosa = input("Introduce el dominio o URL sospechosa: ").strip()
entrada_legitima = input("Introduce el dominio o URL legítima: ").strip()

dominio = limpiar_objetivo(entrada_sospechosa)
dominio_legitimo = limpiar_objetivo(entrada_legitima)

if not dominio or not dominio_legitimo:
    print("No se pudo extraer un dominio válido de la entrada.")
    exit()

analizar_dominio(dominio, dominio_legitimo)