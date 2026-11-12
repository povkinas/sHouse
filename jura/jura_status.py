#!/usr/bin/env python3
"""Jura Z10 kavos aparato būsenos tikrinimas vietiniame tinkle.

Aparatas su JURA WiFi Connect moduliu klauso TCP/UDP 51515 prievado.
Skriptas:

  1. suranda aparato IP pagal MAC adresą (ARP lentelė + tinklo „pažadinimas“),
     arba, jei MAC nenurodytas, per jura-connect paiešką (UDP/TCP 51515);
  2. jei aparatas dar nesuporuotas, paleidžia vienkartinį suporavimą
     (aparato ekrane reikia paspausti OK);
  3. nuskaito būseną (klaidos, įspėjimai, priežiūros procentai, skaitikliai)
     ir ją atspausdina.

Protokolą įgyvendina biblioteka `jura_connect` (pip install jura_connect).
Visos komandos tik skaito; nieko nevirina ir nekeičia nustatymų.

Pavyzdžiai:
  python3 jura_status.py --mac 00:11:22:33:44:55
  python3 jura_status.py                      # be MAC, ieško pats
  python3 jura_status.py --mac ... --json     # JSON išvestis
"""

from __future__ import annotations

import argparse
import concurrent.futures
import ipaddress
import json
import os
import platform
import re
import socket
import subprocess
import sys

JURA_PORT = 51515
DEFAULT_NAME = "Z10"

# Z10 variantų EF kodai iš J.O.E. katalogo (jura-connect machine-types --filter Z10):
#   EF545  – Z10 (EA/SA/NAA/INTA/...), pirmoji karta
#   EF1106 – Z10 (EB/SB/NAB/INTB/...)
#   EF1208 – Z10 (EC/SC)
Z10_TYPES = ("EF545", "EF1106", "EF1208")

# Lietuviški įspėjimų pavadinimai dažniausioms būsenoms.
ALERT_LT = {
    "insert_tray": "Įdėkite lašų padėklą",
    "fill_water": "Įpilkite vandens",
    "empty_grounds": "Išvalykite tirščių talpą",
    "empty_tray": "Ištuštinkite lašų padėklą",
    "insert_coffee_bin": "Įdėkite tirščių talpą",
    "outlet_missing": "Nėra kavos snapelio",
    "rear_cover_missing": "Nėra galinio dangtelio",
    "milk_alert": "Pieno įspėjimas",
    "fill_system": "Užpildykite sistemą",
    "system_filling": "Sistema pildoma",
    "no_beans": "Baigiasi pupelės",
    "welcome": "Sveikinimo ekranas",
    "heating_up": "Kaista",
    "coffee_ready": "Paruoštas kavai",
    "please_wait": "Palaukite",
    "coffee_rinsing": "Skalaujama",
    "fill_powder": "Įberkite maltos kavos",
    "system_emptying": "Sistema ištuštinama",
    "remove_water_tank": "Išimkite vandens talpą",
    "press_rinse": "Paspauskite skalavimą",
    "goodbye": "Išsijungia",
    "error_status": "Aparato klaida",
    "enjoy_product": "Gėrimas paruoštas",
    "filter_alert": "Reikia keisti filtrą",
    "descale_alert": "Reikia nukalkinti",
    "cleaning_alert": "Reikia išvalyti",
    "cappu_rinse_alert": "Reikia praskalauti pieno sistemą",
    "cappu_clean_alert": "Reikia išvalyti pieno sistemą",
    "energy_safe": "Energijos taupymo režimas",
    "locked_keys": "Mygtukai užrakinti",
    "close_tab": "Uždarykite dangtelį",
    "steam_ready": "Garai paruošti",
    "switch_off_delay_active": "Išsijungia (vėlinimas)",
}

MAINT_LT = {
    "cleaning": "Valymas",
    "descale": "Nukalkinimas",
    "filter_change": "Filtro keitimas",
    "cappu_rinse": "Pieno sist. skalavimas",
    "coffee_rinse": "Kavos sist. skalavimas",
    "cappu_clean": "Pieno sist. valymas",
}


def log(msg: str) -> None:
    print(msg, file=sys.stderr)


# --------------------------------------------------------------------------- #
# MAC -> IP
# --------------------------------------------------------------------------- #

def norm_mac(mac: str) -> str | None:
    """Sutvarko MAC į 'aa:bb:cc:dd:ee:ff'. Priima ':', '-', '.' ir be skirtukų."""
    mac = mac.strip().lower()
    parts = re.split(r"[:\-]", mac)
    if len(parts) == 6 and all(1 <= len(p) <= 2 for p in parts):
        parts = [p.zfill(2) for p in parts]  # macOS arp rodo „a:b:c“ be nulių
    else:
        hexonly = re.sub(r"[^0-9a-f]", "", mac)
        if len(hexonly) != 12:
            return None
        parts = [hexonly[i:i + 2] for i in range(0, 12, 2)]
    if not all(re.fullmatch(r"[0-9a-f]{2}", p) for p in parts):
        return None
    return ":".join(parts)


def read_arp_table() -> dict[str, str]:
    """Grąžina {mac: ip} iš OS ARP/neighbor lentelės."""
    table: dict[str, str] = {}
    commands = []
    system = platform.system()
    if system == "Linux":
        commands = [["ip", "neigh", "show"], ["arp", "-an"]]
    elif system == "Darwin" or "BSD" in system:
        commands = [["arp", "-an"]]
    elif system == "Windows":
        commands = [["arp", "-a"]]
    else:
        commands = [["arp", "-an"]]

    ip_re = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")
    mac_re = re.compile(r"([0-9a-fA-F]{1,2}(?:[:\-][0-9a-fA-F]{1,2}){5})")
    for cmd in commands:
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=10).stdout
        except (OSError, subprocess.SubprocessError):
            continue
        for line in out.splitlines():
            ip_m, mac_m = ip_re.search(line), mac_re.search(line)
            if ip_m and mac_m:
                mac = norm_mac(mac_m.group(1))
                if mac and mac != "ff:ff:ff:ff:ff:ff":
                    table.setdefault(mac, ip_m.group(1))
        if table:
            break
    # Linux atsarginis variantas be `ip`/`arp` įrankių
    if not table and os.path.exists("/proc/net/arp"):
        with open("/proc/net/arp") as fh:
            for line in fh.readlines()[1:]:
                cols = line.split()
                if len(cols) >= 4:
                    mac = norm_mac(cols[3])
                    if mac and mac != "00:00:00:00:00:00":
                        table.setdefault(mac, cols[0])
    return table


def local_networks(subnet: str | None) -> list[ipaddress.IPv4Network]:
    if subnet:
        return [ipaddress.ip_network(subnet, strict=False)]
    nets = []
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("10.255.255.255", 1))  # paketas neišsiunčiamas
            ip = s.getsockname()[0]
        nets.append(ipaddress.ip_network(f"{ip}/24", strict=False))
    except OSError:
        pass
    return nets


def _poke(ip: str) -> None:
    """Priverčia OS išsiųsti ARP užklausą: bando TCP 51515 prisijungimą."""
    try:
        with socket.create_connection((ip, JURA_PORT), timeout=0.3):
            pass
    except OSError:
        pass


def sweep(nets: list[ipaddress.IPv4Network]) -> None:
    hosts = [str(h) for n in nets for h in n.hosts()]
    log(f"Skenuoju {len(hosts)} adresų ({', '.join(map(str, nets))}), kad užsipildytų ARP lentelė...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=128) as ex:
        list(ex.map(_poke, hosts))


def find_ip_by_mac(mac: str, subnet: str | None) -> str | None:
    table = read_arp_table()
    if mac in table:
        return table[mac]
    nets = local_networks(subnet)
    if not nets:
        log("Nepavyko nustatyti vietinio tinklo; nurodykite --subnet, pvz. 192.168.1.0/24")
        return None
    sweep(nets)
    return read_arp_table().get(mac)


# --------------------------------------------------------------------------- #
# jura-connect CLI
# --------------------------------------------------------------------------- #

def jc(*args: str, capture: bool = True, timeout: float = 120) -> subprocess.CompletedProcess:
    cmd = [sys.executable, "-m", "jura_connect", *args]
    return subprocess.run(cmd, capture_output=capture, text=True, timeout=timeout)


def ensure_library() -> None:
    try:
        import jura_connect  # noqa: F401
    except ImportError:
        log("Trūksta bibliotekos `jura_connect` (reikia Python ≥ 3.11).")
        log("Įdiekite:  python3 -m pip install jura_connect")
        sys.exit(2)


def discover_ip() -> str | None:
    log("MAC nenurodytas – ieškau Jura aparato tinkle (UDP/TCP 51515)...")
    res = jc("discover", timeout=180)
    text = (res.stdout or "") + (res.stderr or "")
    ips = re.findall(r"(\d{1,3}(?:\.\d{1,3}){3})", text)
    ips = [ip for ip in dict.fromkeys(ips) if not ip.endswith(".255")]
    if not ips:
        log(text.strip())
        return None
    if len(ips) > 1:
        log(f"Rasta keletas kandidatų: {', '.join(ips)}; imu pirmąjį.")
    ip = ips[0]
    mac = next((m for m, i in read_arp_table().items() if i == ip), None)
    if mac:
        log(f"Aparato MAC: {mac}  (kitą kartą galite naudoti --mac {mac})")
    return ip


def stored_credentials(name: str) -> dict | None:
    res = jc("creds", "--json")
    try:
        rows = json.loads(res.stdout)
    except (json.JSONDecodeError, TypeError):
        return None
    return next((r for r in rows if r.get("name") == name), None)


def pair(ip: str, name: str, machine_type: str | None, pin: str | None) -> bool:
    log("")
    log(f"Aparatas dar nesuporuotas. Poruoju su {ip} kaip '{name}'.")
    log(">>> Žiūrėkite į kavos aparato ekraną ir paspauskite OK, kai pasirodys „Connect“. <<<")
    args = ["pair", ip, "--name", name]
    if machine_type:
        args += ["--machine-type", machine_type]
    if pin:
        args += ["--pin", pin]
    res = jc(*args, capture=False, timeout=180)
    return res.returncode == 0


def read_info(ip: str, name: str, machine_type: str | None, pin: str | None) -> dict | None:
    args = ["command", "--name", name, "--address", ip, "--json"]
    if machine_type:
        args += ["--machine-type", machine_type]
    if pin:
        args += ["--pin", pin]
    args.append("info")
    res = jc(*args, timeout=90)
    if res.returncode != 0:
        log((res.stderr or res.stdout or "").strip())
        return None
    try:
        return json.loads(res.stdout)["value"]
    except (json.JSONDecodeError, KeyError, TypeError):
        log("Nepavyko perskaityti atsakymo:\n" + res.stdout)
        return None


# --------------------------------------------------------------------------- #
# Išvestis
# --------------------------------------------------------------------------- #

def lt(alert: str) -> str:
    return ALERT_LT.get(alert, alert.replace("_", " "))


def print_report(ip: str, mac: str | None, info: dict) -> None:
    st = info.get("status", {})
    errors = st.get("errors", [])
    infos = st.get("info", [])
    process = st.get("process", [])

    if errors:
        overall = "REIKIA DĖMESIO"
    elif "heating_up" in infos:
        overall = "Kaista"
    elif "coffee_ready" in infos or not (infos or process):
        overall = "Paruoštas"
    else:
        overall = "Veikia"

    print("=" * 46)
    print(f" Jura Z10   {ip}" + (f"   ({mac})" if mac else ""))
    print("=" * 46)
    print(f" Būsena:       {overall}")
    if errors:
        print(" Klaidos:      " + "; ".join(lt(a) for a in errors))
    if infos:
        print(" Informacija:  " + "; ".join(lt(a) for a in infos))
    if process:
        print(" Priežiūra:    " + "; ".join(lt(a) for a in process))
    blocked = st.get("blocked_products") or []
    if blocked:
        print(" Negalima gaminti: " + ", ".join(blocked))

    pct = {k: v for k, v in info.get("maintenance_percent", {}).items() if k != "raw_hex"}
    shown = {k: v for k, v in pct.items() if isinstance(v, int) and 0 <= v <= 100}
    if shown:
        print("\n Iki kitos priežiūros:")
        for k, v in shown.items():
            bar = "#" * (v // 10) + "." * (10 - v // 10)
            print(f"   {MAINT_LT.get(k, k):24s} [{bar}] {v:3d}%")

    cnt = {k: v for k, v in info.get("maintenance_counters", {}).items() if k != "raw_hex"}
    if cnt:
        print("\n Atlikta priežiūrų (kartai):")
        for k, v in cnt.items():
            print(f"   {MAINT_LT.get(k, k):24s} {v}")
    print()


# --------------------------------------------------------------------------- #

def main() -> int:
    ap = argparse.ArgumentParser(description="Jura Z10 būsenos tikrinimas pagal MAC adresą")
    ap.add_argument("--mac", default=os.environ.get("JURA_MAC"),
                    help="aparato (WiFi Connect modulio) MAC adresas; arba aplinkos kintamasis JURA_MAC")
    ap.add_argument("--ip", help="praleisti paiešką ir naudoti šį IP")
    ap.add_argument("--subnet", help="skenuojamas tinklas, pvz. 192.168.1.0/24 (numatytasis – jūsų /24)")
    ap.add_argument("--name", default=DEFAULT_NAME, help="slapyvardis kredencialų saugykloje (numatytasis: Z10)")
    ap.add_argument("--machine-type", choices=Z10_TYPES,
                    help="Z10 variantas: EF545 (A), EF1106 (B), EF1208 (C); nurodo pavadinimus ir įspėjimų reikšmes")
    ap.add_argument("--pin", help="aparato sąrankos PIN, jei jis nustatytas")
    ap.add_argument("--json", action="store_true", help="išvesti JSON")
    args = ap.parse_args()

    ensure_library()

    mac = None
    if args.mac:
        mac = norm_mac(args.mac)
        if not mac:
            log(f"Netinkamas MAC adresas: {args.mac}")
            return 2

    ip = args.ip
    if not ip and mac:
        log(f"Ieškau įrenginio su MAC {mac}...")
        ip = find_ip_by_mac(mac, args.subnet)
        if not ip:
            log("Įrenginys su tokiu MAC nerastas. Ar aparatas įjungtas ir prisijungęs prie WiFi?")
            log("Pastaba: WiFi Connect modulis kartais „užmiega“ – įjunkite aparatą ir bandykite dar kartą.")
            return 1
    if not ip:
        ip = discover_ip()
        if not ip:
            log("Jura aparatas tinkle nerastas.")
            return 1
    log(f"Aparatas rastas: {ip}")

    creds = stored_credentials(args.name)
    if not creds:
        if not pair(ip, args.name, args.machine_type, args.pin):
            log("Suporuoti nepavyko.")
            return 1

    info = read_info(ip, args.name, args.machine_type, args.pin)
    if info is None:
        log("Nepavyko nuskaityti būsenos (aparatas gali būti išjungtas arba užimtas J.O.E. programėlės).")
        return 1

    if args.json:
        print(json.dumps({"ip": ip, "mac": mac, **info}, indent=2, ensure_ascii=False))
    else:
        print_report(ip, mac, info)
    return 0


if __name__ == "__main__":
    sys.exit(main())
