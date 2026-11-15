"""Pregunta 1 --- Los PCAP de QUT DNP3, tienen carga util interpretable?

Responde la pregunta 1 del brief (eda/INSTRUCCIONES.md). Mide, sobre los PCAP
de entrenamiento de las siete carpetas de escenario:

1. si hay capa DNP3 reconocible y en que puerto,
2. si los codigos de funcion son extraibles e interpretables,
3. si se recuperan los parametros de los comandos y no solo las cabeceras,
4. si la separacion master.pcap / slave.pcap se corresponde con comando y
   respuesta,
5. si los pares comando/respuesta se pueden emparejar, y con que informacion.

Solo lee `training/`. El tramo `testing/` no se abre.

Uso:  python eda/scripts/01_qut_payload.py [max_paquetes_por_pcap]
"""

import collections
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import comun  # noqa: E402
import dnp3  # noqa: E402

ESCENARIOS = [
    ("Attacks", "Attacks/attacks/training"),
    ("Control", "Control/control/training"),
    ("Flooding", "Flooding/flooding/training"),
    ("Injection", "Injection/injection/training"),
    ("MITM", "MITM/MITM/training"),
    ("Masqurading", "Masqurading/masquerading/training"),
    ("Replay", "Replay/replay/training"),
]
ROLES = ("master", "slave", "attacker")

# Funciones de aplicacion que llevan parametros de control.
FUNC_CONTROL = {2, 3, 4, 5, 6}


def analizar(path, max_packets):
    r = {
        "existe": os.path.exists(path),
        "bytes": os.path.getsize(path) if os.path.exists(path) else 0,
        "func_app": collections.Counter(),
        "func_enlace": collections.Counter(),
        "objetos": collections.Counter(),
        "puertos_tcp": collections.Counter(),
        "pares_ip": collections.Counter(),
        "dir_enlace": collections.Counter(),
        "n_tramas": 0, "n_solo_enlace": 0, "n_app": 0,
        "obj_completos": 0, "obj_incompletos": 0,
        "bloques_ok": 0, "bloques_total": 0,
        "n_valores": 0,
        "parametros": [],
        "firma": [],       # (func, seq) en orden, para comparar capturas
        "eventos": [],     # (ts, func, seq, src_enlace, dst_enlace)
        "contadores": {},
    }
    if not r["existe"]:
        return r
    for fr, c in dnp3.read_pcap(path, max_packets=max_packets):
        r["contadores"] = dict(c)
        if fr is None:
            break
        r["n_tramas"] += 1
        r["func_enlace"][fr.link_func_name] += 1
        r["puertos_tcp"][(fr.sport, fr.dport)] += 1
        r["pares_ip"][(fr.src_ip, fr.dst_ip)] += 1
        r["dir_enlace"][(fr.source, fr.dest)] += 1
        r["bloques_ok"] += fr.bloques_ok
        r["bloques_total"] += fr.bloques_total
        if fr.func is None:
            r["n_solo_enlace"] += 1
            continue
        r["n_app"] += 1
        r["func_app"][fr.func_name] += 1
        if len(r["firma"]) < 20000:
            r["firma"].append((fr.func, fr.app_seq))
        r["eventos"].append((fr.ts, fr.func, fr.app_seq, fr.source, fr.dest))
        for ob in fr.objects:
            r["objetos"][(ob["grupo"], ob["variacion"])] += 1
            if ob.get("completo"):
                r["obj_completos"] += 1
            else:
                r["obj_incompletos"] += 1
            vals = ob.get("valores", [])
            r["n_valores"] += len(vals)
            if fr.func in FUNC_CONTROL and len(r["parametros"]) < 10:
                for v in vals:
                    r["parametros"].append(
                        {"ts": fr.ts, "funcion": fr.func_name,
                         "grupo": ob["grupo"], "variacion": ob["variacion"],
                         "valor": v})
    return r


def emparejar(eventos, ventana=5.0):
    """Empareja peticion y respuesta dentro de una misma captura.

    Clave: numero de secuencia de aplicacion. Se toma la primera respuesta
    posterior a la peticion dentro de `ventana` segundos.
    """
    peticiones = [e for e in eventos if e[1] < 128]
    respuestas = [e for e in eventos if e[1] >= 128 and e[1] != 130]
    por_seq = collections.defaultdict(collections.deque)
    for e in sorted(respuestas, key=lambda x: x[0]):
        por_seq[e[2]].append(e)
    n_ok = 0
    lat = []
    for p in sorted(peticiones, key=lambda x: x[0]):
        cola = por_seq.get(p[2])
        while cola and cola[0][0] < p[0]:
            cola.popleft()
        if cola and 0 <= cola[0][0] - p[0] <= ventana:
            lat.append(cola.popleft()[0] - p[0])
            n_ok += 1
    lat.sort()
    return {
        "peticiones": len(peticiones),
        "respuestas": len(respuestas),
        "emparejadas": n_ok,
        "tasa": (n_ok / len(peticiones)) if peticiones else None,
        "latencia_mediana_ms": (lat[len(lat) // 2] * 1000) if lat else None,
        "latencia_p95_ms": (lat[int(0.95 * len(lat))] * 1000) if lat else None,
    }


def comparar_firmas(a, b):
    """Fraccion de coincidencia entre las secuencias (func, seq) de dos capturas."""
    n = min(len(a), len(b))
    if n == 0:
        return None
    iguales = sum(1 for i in range(n) if a[i] == b[i])
    return {"comparados": n, "iguales": iguales, "fraccion": iguales / n}


def main():
    comun.preparar()
    max_packets = int(sys.argv[1]) if len(sys.argv) > 1 else 0
    max_packets = max_packets or None

    datos = {}
    for nombre, rel in ESCENARIOS:
        datos[nombre] = {}
        for sub in ("frequent", "infrequent"):
            base = os.path.join(comun.QUT, rel, sub)
            if not os.path.isdir(base):
                continue
            ent = {}
            for rol in ROLES:
                print("  %s/%s/%s.pcap" % (nombre, sub, rol), file=sys.stderr)
                ent[rol] = analizar(os.path.join(base, "%s.pcap" % rol),
                                    max_packets)
            for rol in ROLES:
                if ent[rol]["eventos"]:
                    ent[rol]["emparejamiento"] = emparejar(ent[rol]["eventos"])
            ent["firma_master_vs_slave"] = comparar_firmas(
                ent["master"]["firma"], ent["slave"]["firma"])
            datos[nombre][sub] = ent

    L = []
    w = L.append
    w("# Pregunta 1 - carga util DNP3 en QUT (solo tramo training)")
    w("")
    w("Limite de paquetes por PCAP: %s" % (max_packets or "sin limite"))
    w("")
    w("## 1.1 Capa DNP3, puerto y validez de las tramas")
    w("")
    w("%-14s %-5s %-9s %10s %10s %10s %9s %9s" % (
        "escenario", "sub", "rol", "paquetes", "tcp:20000", "tramas",
        "CRC malo", "bloq. ok"))
    for nombre, subs in datos.items():
        for sub, ent in subs.items():
            for rol in ROLES:
                r = ent[rol]
                if not r["existe"]:
                    w("%-14s %-5s %-9s  NO EXISTE" % (nombre, sub[:5], rol))
                    continue
                c = r["contadores"]
                pb = ("%d/%d" % (r["bloques_ok"], r["bloques_total"])
                      if r["bloques_total"] else "-")
                w("%-14s %-5s %-9s %10d %10d %10d %9d %9s" % (
                    nombre, sub[:5], rol, c.get("paquetes", 0),
                    c.get("puerto_dnp3", 0), r["n_tramas"],
                    c.get("crc_malo", 0), pb))
    w("")
    w("## 1.2 Codigos de funcion de aplicacion")
    w("")
    for nombre, subs in datos.items():
        for sub, ent in subs.items():
            for rol in ROLES:
                r = ent[rol]
                if not r["n_tramas"]:
                    continue
                top = ", ".join("%s=%d" % kv
                                for kv in r["func_app"].most_common(8))
                w("%-14s %-10s %-9s solo-enlace=%d app=%d | %s"
                  % (nombre, sub, rol, r["n_solo_enlace"], r["n_app"],
                     top or "(ninguna)"))
    w("")
    w("## 1.3 Objetos y recuperacion de parametros")
    w("")
    for nombre, subs in datos.items():
        for sub, ent in subs.items():
            for rol in ROLES:
                r = ent[rol]
                if not r["objetos"]:
                    continue
                top = ", ".join("g%dv%d=%d" % (g, v, n)
                                for (g, v), n in r["objetos"].most_common(10))
                w("%-14s %-10s %-9s cab.completas=%d incompletas=%d "
                  "valores=%d" % (nombre, sub, rol, r["obj_completos"],
                                  r["obj_incompletos"], r["n_valores"]))
                w("%34s %s" % ("", top))
                for p in r["parametros"][:4]:
                    w("%34s PARAM %s g%dv%d %s"
                      % ("", p["funcion"], p["grupo"], p["variacion"],
                         json.dumps(p["valor"], ensure_ascii=False)))
    w("")
    w("## 1.4 master.pcap frente a slave.pcap")
    w("")
    w("Si la separacion fuese comando/respuesta, master.pcap tendria solo")
    w("peticiones y slave.pcap solo respuestas. Se mide la mezcla en cada uno.")
    w("")
    w("%-14s %-11s %-9s %12s %12s %9s" % (
        "escenario", "sub", "rol", "peticiones", "respuestas", "% petic."))
    for nombre, subs in datos.items():
        for sub, ent in subs.items():
            for rol in ("master", "slave"):
                r = ent[rol]
                if not r["n_app"]:
                    continue
                pet = sum(n for f, n in r["func_app"].items()
                          if f in ("READ", "WRITE", "SELECT", "OPERATE",
                                   "DIRECT_OPERATE", "DIRECT_OPERATE_NR",
                                   "CONFIRM", "ENABLE_UNSOLICITED",
                                   "DISABLE_UNSOLICITED", "DELAY_MEASURE"))
                resp = r["n_app"] - pet
                w("%-14s %-11s %-9s %12d %12d %8.1f%%"
                  % (nombre, sub, rol, pet, resp,
                     100.0 * pet / r["n_app"]))
            f = ent.get("firma_master_vs_slave")
            if f:
                w("%-14s %-11s coincidencia de la secuencia (func,seq) "
                  "master vs slave: %d/%d = %.2f%%"
                  % (nombre, sub, f["iguales"], f["comparados"],
                     100 * f["fraccion"]))
    w("")
    w("## 1.5 Emparejamiento de comando y respuesta dentro de una captura")
    w("")
    w("Clave: numero de secuencia de aplicacion + orden temporal.")
    w("")
    w("%-14s %-11s %-9s %11s %11s %11s %9s %9s" % (
        "escenario", "sub", "rol", "peticiones", "respuestas", "empareja",
        "tasa", "lat.med"))
    for nombre, subs in datos.items():
        for sub, ent in subs.items():
            for rol in ROLES:
                e = ent[rol].get("emparejamiento")
                if not e or not e["peticiones"]:
                    continue
                w("%-14s %-11s %-9s %11d %11d %11d %8.1f%% %7.1fms"
                  % (nombre, sub, rol, e["peticiones"], e["respuestas"],
                     e["emparejadas"], 100 * (e["tasa"] or 0),
                     e["latencia_mediana_ms"] or float("nan")))
    w("")

    comun.escribir("p1_qut_payload.txt", "\n".join(L))

    serial = {}
    for nombre, subs in datos.items():
        serial[nombre] = {}
        for sub, ent in subs.items():
            serial[nombre][sub] = {
                "firma_master_vs_slave": ent["firma_master_vs_slave"],
                "roles": {rol: {
                    "bytes": ent[rol]["bytes"],
                    "n_tramas": ent[rol]["n_tramas"],
                    "n_app": ent[rol]["n_app"],
                    "n_solo_enlace": ent[rol]["n_solo_enlace"],
                    "func_app": dict(ent[rol]["func_app"]),
                    "func_enlace": dict(ent[rol]["func_enlace"]),
                    "objetos": {"g%dv%d" % k: v
                                for k, v in ent[rol]["objetos"].items()},
                    "obj_completos": ent[rol]["obj_completos"],
                    "obj_incompletos": ent[rol]["obj_incompletos"],
                    "bloques_ok": ent[rol]["bloques_ok"],
                    "bloques_total": ent[rol]["bloques_total"],
                    "n_valores": ent[rol]["n_valores"],
                    "contadores": ent[rol]["contadores"],
                    "emparejamiento": ent[rol].get("emparejamiento"),
                    "parametros": ent[rol]["parametros"],
                    "pares_ip": {"%s>%s" % k: v
                                 for k, v in ent[rol]["pares_ip"].items()},
                    "dir_enlace": {"%s>%s" % k: v
                                   for k, v in ent[rol]["dir_enlace"].items()},
                } for rol in ROLES},
            }
    with open(os.path.join(comun.SALIDAS, "p1_qut_payload.json"), "w") as fh:
        json.dump(serial, fh, indent=1, ensure_ascii=False, default=str)


if __name__ == "__main__":
    main()
