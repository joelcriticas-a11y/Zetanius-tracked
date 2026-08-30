import os
import json
import socket
import ipaddress
import webbrowser
import time
from datetime import datetime

import requests


# ============================================================
#                    ZETANIUS TRACKER
#                         VERSION 2.0
# ============================================================

GREEN = "\033[92m"
DARK_GREEN = "\033[32m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
WHITE = "\033[97m"
GRAY = "\033[90m"
RESET = "\033[0m"
BOLD = "\033[1m"

IP_API = "https://ipwho.is"
RDAP_API = "https://rdap.org/ip"


def clear():
    os.system("cls" if os.name == "nt" else "clear")


def line(char="═", length=62, color=GREEN):
    print(color + char * length + RESET)


def banner():
    clear()

    print(RED + r"""
             █████████████████████████████████████████
         █████████████████████████████████████████████████
      ███████████████████████████████████████████████████████
    ███████████████████████████████████████████████████████████
  ███████████████████████████████████████████████████████████████
 █████████████████████████████████████████████████████████████████
███████████████████████████████████████████████████████████████████
███████████████████████████         ███████████████████████████████
█████████████████████████     █████     ██████████████████████████
████████████████████████    █████████    █████████████████████████
███████████████████████   █████████████   ████████████████████████
██████████████████████   ███████████████   ███████████████████████
██████████████████████  █████████████████  ███████████████████████
██████████████████████  █████████████████  ███████████████████████
██████████████████████   ███████████████   ███████████████████████
███████████████████████   █████████████   ████████████████████████
████████████████████████    █████████    █████████████████████████
█████████████████████████     █████     ██████████████████████████
███████████████████████████         ██████████████████████████████
 █████████████████████████████████████████████████████████████████
  ███████████████████████████████████████████████████████████████
    ███████████████████████████████████████████████████████████
      █████████████████████████████████████████████████████
         █████████████████████████████████████████████
             █████████████████████████████████████████
""" + RESET)

    print(GREEN + r"""
 ███████╗███████╗████████╗ █████╗ ███╗   ██╗██╗██╗   ██╗███████╗
 ╚══███╔╝██╔════╝╚══██╔══╝██╔══██╗████╗  ██║██║██║   ██║██╔════╝
   ███╔╝ █████╗     ██║   ███████║██╔██╗ ██║██║██║   ██║███████╗
  ███╔╝  ██╔══╝     ██║   ██║  ██║██║╚██╗██║██║╚██╗ ██╔╝╚════██║
 ███████╗███████╗   ██║   ██║  ██║██║ ╚████║██║ ╚████╔╝ ███████║
 ╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝  ╚══════╝
""" + RESET)

    print()
    print(
        RED +
        "                 Z E T A N I U S   T R A C K E R" +
        RESET
    )
    print(
        DARK_GREEN +
        "                 ───────────────────────────────" +
        RESET
    )
    print()
    print(
        GREEN +
        "                    [ DARK OSINT ENGINE ]" +
        RESET
    )
    print(
        GREEN +
        "                         [ ONLINE ]" +
        RESET
    )
    print()

    print(GREEN + "╔" + "═" * 60 + "╗" + RESET)
    print(
        GREEN +
        "║" +
        WHITE +
        "             IP INTELLIGENCE SYSTEM              " +
        GREEN +
        "║" +
        RESET
    )
    print(
        GREEN +
        "║" +
        DARK_GREEN +
        "              PUBLIC DATA ANALYSIS              " +
        GREEN +
        "║" +
        RESET
    )
    print(GREEN + "╚" + "═" * 60 + "╝" + RESET)
    print()


def validar_ip(texto):
    try:
        return ipaddress.ip_address(texto.strip())
    except ValueError:
        return None


def consultar_ip(ip):
    try:
        respuesta = requests.get(
            f"{IP_API}/{ip}",
            timeout=10,
            headers={
                "User-Agent": "Zetanius-Tracker/2.0"
            }
        )

        if not respuesta.ok:
            return None

        datos = respuesta.json()

        if datos.get("success") is False:
            return None

        return datos

    except (requests.RequestException, ValueError):
        return None


def reverse_dns(ip):
    try:
        return socket.gethostbyaddr(str(ip))[0]
    except (socket.herror, socket.gaierror, OSError):
        return "N/D"


def consultar_rdap(ip):
    try:
        respuesta = requests.get(
            f"{RDAP_API}/{ip}",
            timeout=10,
            headers={
                "Accept": "application/rdap+json",
                "User-Agent": "Zetanius-Tracker/2.0"
            }
        )

        if not respuesta.ok:
            return None

        return respuesta.json()

    except (requests.RequestException, ValueError):
        return None


def extraer_vcard(vcard):
    resultado = {}

    if not isinstance(vcard, list):
        return resultado

    if len(vcard) < 2:
        return resultado

    campos = vcard[1]

    if not isinstance(campos, list):
        return resultado

    for campo in campos:

        if not isinstance(campo, list):
            continue

        if len(campo) < 4:
            continue

        nombre = campo[0]
        valor = campo[3]

        if nombre == "fn":
            resultado["name"] = valor

        elif nombre == "org":
            resultado["organization"] = valor

        elif nombre == "tel":
            resultado["phone"] = valor

        elif nombre == "email":
            resultado["email"] = valor

        elif nombre == "url":
            resultado["website"] = valor

    return resultado


def obtener_contactos_publicos(rdap):
    contactos = []

    if not rdap:
        return contactos

    entidades = rdap.get("entities", [])

    if not isinstance(entidades, list):
        return contactos

    roles_validos = {
        "registrant",
        "registrar",
        "administrative",
        "technical",
        "abuse"
    }

    for entidad in entidades:

        if not isinstance(entidad, dict):
            continue

        roles = entidad.get("roles", [])

        if not isinstance(roles, list):
            continue

        if not any(
            rol in roles
            for rol in roles_validos
        ):
            continue

        info = extraer_vcard(
            entidad.get("vcardArray")
        )

        if info:
            info["roles"] = roles
            contactos.append(info)

    return contactos


def analizar_security(datos):

    security = datos.get("security", {})

    if not isinstance(security, dict):
        security = {}

    vpn = security.get("vpn")
    proxy = security.get("proxy")
    tor = security.get("tor")
    hosting = security.get("hosting")
    anonymous = security.get("anonymous")
    threat = security.get("threat")

    score = 0
    razones = []

    if vpn is True:
        score += 25
        razones.append("VPN indicator")

    if proxy is True:
        score += 25
        razones.append("Proxy indicator")

    if tor is True:
        score += 35
        razones.append("Tor indicator")

    if hosting is True:
        score += 15
        razones.append("Hosting indicator")

    if anonymous is True:
        score += 20
        razones.append("Anonymous network indicator")

    if threat is True:
        score += 30
        razones.append("Threat indicator")

    score = min(score, 100)

    if score >= 60:
        nivel = "HIGH"
    elif score >= 30:
        nivel = "MEDIUM"
    else:
        nivel = "LOW"

    return {
        "vpn": vpn if vpn is not None else "N/D",
        "proxy": proxy if proxy is not None else "N/D",
        "tor": tor if tor is not None else "N/D",
        "hosting": hosting if hosting is not None else "N/D",
        "anonymous": (
            anonymous
            if anonymous is not None
            else "N/D"
        ),
        "threat": (
            threat
            if threat is not None
            else "N/D"
        ),
        "score": score,
        "level": nivel,
        "reasons": razones
    }


def status(nombre, correcto):

    if correcto:
        print(
            GREEN +
            f"  [+] {nombre:<30}" +
            WHITE +
            " OK" +
            RESET
        )
    else:
        print(
            YELLOW +
            f"  [-] {nombre:<30}" +
            WHITE +
            " N/D" +
            RESET
        )


def value(datos, key, default="N/D"):

    resultado = datos.get(key, default)

    if resultado is None or resultado == "":
        return default

    return resultado


def evento(rdap, accion):

    if not rdap:
        return "N/D"

    for item in rdap.get("events", []):

        if item.get("eventAction") == accion:
            return item.get(
                "eventDate",
                "N/D"
            )

    return "N/D"


def crear_reporte(
    ip,
    datos,
    rdns,
    rdap,
    contactos,
    security
):

    conexion = datos.get(
        "connection",
        {}
    )

    timezone = datos.get(
        "timezone",
        {}
    )

    if not isinstance(conexion, dict):
        conexion = {}

    if not isinstance(timezone, dict):
        timezone = {}

    return {
        "tool": "Zetanius Tracker",
        "version": "2.0",
        "timestamp": datetime.now().isoformat(),

        "ip": str(ip),

        "ip_information": {
            "address": value(
                datos,
                "ip",
                str(ip)
            ),
            "type": value(
                datos,
                "type"
            ),
            "continent": value(
                datos,
                "continent"
            ),
            "country": value(
                datos,
                "country"
            ),
            "country_code": value(
                datos,
                "country_code"
            ),
            "region": value(
                datos,
                "region"
            ),
            "city": value(
                datos,
                "city"
            ),
            "postal": value(
                datos,
                "postal"
            ),
            "latitude": value(
                datos,
                "latitude"
            ),
            "longitude": value(
                datos,
                "longitude"
            ),
            "timezone": timezone.get(
                "id",
                "N/D"
            )
        },

        "network": {
            "isp": conexion.get(
                "isp",
                "N/D"
            ),
            "organization": conexion.get(
                "org",
                "N/D"
            ),
            "asn": conexion.get(
                "asn",
                "N/D"
            ),
            "domain": conexion.get(
                "domain",
                "N/D"
            )
        },

        "dns": {
            "reverse_dns": rdns
        },

        "rdap": {
            "name": value(
                rdap or {},
                "name"
            ),
            "handle": value(
                rdap or {},
                "handle"
            ),
            "start_address": value(
                rdap or {},
                "startAddress"
            ),
            "end_address": value(
                rdap or {},
                "endAddress"
            ),
            "country": value(
                rdap or {},
                "country"
            ),
            "registry": value(
                rdap or {},
                "port43"
            ),
            "registration": evento(
                rdap,
                "registration"
            )
        },

        "public_organization_contacts": contactos,

        "security": security
    }


def guardar_json(reporte, ip):

    nombre = (
        "zetanius_" +
        str(ip).replace(
            ":",
            "_"
        ) +
        ".json"
    )

    try:

        with open(
            nombre,
            "w",
            encoding="utf-8"
        ) as archivo:

            json.dump(
                reporte,
                archivo,
                indent=4,
                ensure_ascii=False
            )

        return nombre

    except OSError:
        return None


def abrir_mapa(datos):

    lat = datos.get("latitude")
    lon = datos.get("longitude")

    if lat is None or lon is None:
        return

    url = (
        "https://www.google.com/maps/"
        f"search/?api=1&query={lat},{lon}"
    )

    try:
        webbrowser.open(url)
    except Exception:
        pass


def mostrar_reporte(reporte):

    info = reporte["ip_information"]
    network = reporte["network"]
    dns = reporte["dns"]
    rdap = reporte["rdap"]
    contacts = reporte[
        "public_organization_contacts"
    ]
    security = reporte["security"]

    print()

    line()

    print(
        GREEN +
        "                    ZETANIUS REPORT" +
        RESET
    )

    line()

    print()
    print(
        RED +
        "  ┌─[ TARGET ]" +
        RESET
    )

    print(
        GREEN +
        "  │ IP             : " +
        WHITE +
        str(info["address"]) +
        RESET
    )

    print(
        GREEN +
        "  │ Type           : " +
        WHITE +
        str(info["type"]) +
        RESET
    )

    print(
        GREEN +
        "  │ Reverse DNS    : " +
        WHITE +
        str(dns["reverse_dns"]) +
        RESET
    )

    print(
        GREEN +
        "  └────────────────────────────────────────────" +
        RESET
    )

    print()
    print(
        RED +
        "  ┌─[ LOCATION ]" +
        RESET
    )

    campos = [
        ("Continent", info["continent"]),
        ("Country", info["country"]),
        ("Country Code", info["country_code"]),
        ("Region", info["region"]),
        ("City", info["city"]),
        ("Postal", info["postal"]),
        ("Latitude", info["latitude"]),
        ("Longitude", info["longitude"]),
        ("Timezone", info["timezone"])
    ]

    for nombre, valor_campo in campos:

        print(
            GREEN +
            f"  │ {nombre:<14} : " +
            WHITE +
            str(valor_campo) +
            RESET
        )

    print(
        GREEN +
        "  └────────────────────────────────────────────" +
        RESET
    )

    print()
    print(
        RED +
        "  ┌─[ NETWORK ]" +
        RESET
    )

    campos = [
        ("ISP", network["isp"]),
        ("Organization", network["organization"]),
        ("ASN", network["asn"]),
        ("Domain", network["domain"])
    ]

    for nombre, valor_campo in campos:

        print(
            GREEN +
            f"  │ {nombre:<14} : " +
            WHITE +
            str(valor_campo) +
            RESET
        )

    print(
        GREEN +
        "  └────────────────────────────────────────────" +
        RESET
    )

    print()
    print(
        RED +
        "  ┌─[ RDAP ]" +
        RESET
    )

    campos = [
        ("Network", rdap["name"]),
        ("Handle", rdap["handle"]),
        ("Start", rdap["start_address"]),
        ("End", rdap["end_address"]),
        ("Registry", rdap["registry"]),
        ("Registered", rdap["registration"])
    ]

    for nombre, valor_campo in campos:

        print(
            GREEN +
            f"  │ {nombre:<14} : " +
            WHITE +
            str(valor_campo) +
            RESET
        )

    print(
        GREEN +
        "  └────────────────────────────────────────────" +
        RESET
    )

    print()
    print(
        RED +
        "  ┌─[ PUBLIC CONTACTS ]" +
        RESET
    )

    if contacts:

        for contacto in contacts:

            roles = ", ".join(
                contacto.get(
                    "roles",
                    []
                )
            )

            print(
                GREEN +
                "  │ Role           : " +
                WHITE +
                roles +
                RESET
            )

            print(
                GREEN +
                "  │ Name           : " +
                WHITE +
                str(
                    contacto.get(
                        "name",
                        "N/D"
                    )
                ) +
                RESET
            )

            print(
                GREEN +
                "  │ Email          : " +
                WHITE +
                str(
                    contacto.get(
                        "email",
                        "N/D"
                    )
                ) +
                RESET
            )

            print(
                GREEN +
                "  │ Phone          : " +
                WHITE +
                str(
                    contacto.get(
                        "phone",
                        "N/D"
                    )
                ) +
                RESET
            )

            print(
                GREEN +
                "  │ Website        : " +
                WHITE +
                str(
                    contacto.get(
                        "website",
                        "N/D"
                    )
                ) +
                RESET
            )

            print(
                GREEN +
                "  │" +
                RESET
            )

    else:

        print(
            YELLOW +
            "  │ No public organization contact found." +
            RESET
        )

    print(
        GREEN +
        "  └────────────────────────────────────────────" +
        RESET
    )

    print()
    print(
        RED +
        "  ┌─[ SECURITY ]" +
        RESET
    )

    campos = [
        ("VPN", security["vpn"]),
        ("Proxy", security["proxy"]),
        ("Tor", security["tor"]),
        ("Hosting", security["hosting"]),
        ("Anonymous", security["anonymous"]),
        ("Threat", security["threat"])
    ]

    for nombre, valor_campo in campos:

        print(
            GREEN +
            f"  │ {nombre:<14} : " +
            WHITE +
            str(valor_campo) +
            RESET
        )

    print()

    if security["level"] == "HIGH":
        color = RED
    elif security["level"] == "MEDIUM":
        color = YELLOW
    else:
        color = GREEN

    print(
        color +
        f"  │ RISK           : {security['level']}" +
        RESET
    )

    print(
        WHITE +
        f"  │ Score          : "
        f"{security['score']}/100" +
        RESET
    )

    if security["reasons"]:

        print(
            GREEN +
            "  │ Indicators:" +
            RESET
        )

        for reason in security["reasons"]:

            print(
                YELLOW +
                f"  │   • {reason}" +
                RESET
            )

    else:

        print(
            GREEN +
            "  │ Indicators     : None" +
            RESET
        )

    print(
        GREEN +
        "  └────────────────────────────────────────────" +
        RESET
    )

    print()

    line()


def analizar(ip):

    print()

    print(
        RED +
        "  [*] INITIALIZING ZETANIUS ENGINE..." +
        RESET
    )

    time.sleep(0.4)

    print()

    datos = consultar_ip(ip)

    status(
        "IP Intelligence",
        datos is not None
    )

    if datos is None:

        print(
            RED +
            "\n  [!] Unable to obtain IP data." +
            RESET
        )

        return

    time.sleep(0.15)

    rdns = reverse_dns(ip)

    status(
        "Reverse DNS",
        rdns != "N/D"
    )

    time.sleep(0.15)

    rdap = consultar_rdap(ip)

    status(
        "RDAP Registry",
        rdap is not None
    )

    time.sleep(0.15)

    contactos = obtener_contactos_publicos(
        rdap
    )

    status(
        "Public Organization Contacts",
        len(contactos) > 0
    )

    time.sleep(0.15)

    security = analizar_security(datos)

    status(
        "Security Intelligence",
        True
    )

    time.sleep(0.25)

    reporte = crear_reporte(
        ip,
        datos,
        rdns,
        rdap,
        contactos,
        security
    )

    mostrar_reporte(reporte)

    json_file = guardar_json(
        reporte,
        ip
    )

    if json_file:

        print(
            GREEN +
            f"  [+] JSON REPORT: {json_file}" +
            RESET
        )

    abrir_mapa(datos)

    print()

    print(
        GREEN +
        "  [✓] ANALYSIS COMPLETE" +
        RESET
    )

    print(
        GRAY +
        "  Geolocation is approximate and "
        "public contacts refer to organizations." +
        RESET
    )

    line()


def main():

    banner()

    print(
        GREEN +
        "  Enter a public IPv4 or IPv6 address." +
        RESET
    )

    print(
        GRAY +
        "  Type 'exit' to close Zetanius." +
        RESET
    )

    print()

    while True:

        entrada = input(
            RED +
            "  ZETANIUS > " +
            RESET
        ).strip()

        if entrada.lower() in (
            "exit",
            "quit",
            "salir"
        ):

            print()
            print(
                RED +
                "  [!] ZETANIUS ENGINE OFFLINE" +
                RESET
            )
            break

        ip = validar_ip(entrada)

        if ip is None:

            print(
                RED +
                "  [!] INVALID IP ADDRESS" +
                RESET
            )
            continue

        if not ip.is_global:

            print(
                YELLOW +
                "  [!] ENTER A PUBLIC/GLOBAL IP" +
                RESET
            )
            continue

        analizar(ip)
        print()


if __name__ == "__main__":
    main()
