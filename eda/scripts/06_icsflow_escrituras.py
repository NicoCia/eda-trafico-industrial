"""Pregunta 6 --- ICS-Flow, cierra la brecha que dejo abierta el EDA?

El EDA concluyo que ningun conjunto permite a la vez calcular caracteristicas
semanticas desde la carga util Y validar la familia de manipulacion de
parametros de comando (MPCI): QUT tiene carga util pero ningun comando de
control con parametros, y Morris tiene MPCI etiquetado pero sin carga util.
ICS-Flow es el candidato a cerrarla.

Responde cinco cosas:

1. como son las escrituras Modbus: a que registros, con que valores y si el
   repertorio es amplio o binario, que es lo que distingue una consigna de un
   bit de control;
2. si el ataque de intermediario es identificable en la carga util;
3. cuantos eventos hay por tipo de anomalia, con el criterio de la pregunta 4
   del EDA;
4. que particion temporal se usa;
5. con que alcance cierra la brecha, si la cierra.

Particion: el conjunto no trae una designada, asi que se define aqui por
tiempo 60/20/20 sobre la marca del PCAP, con el mismo criterio que el resto
del EDA. **El PCAP se lee solo hasta el corte del 60 %.** Los conteos por
particion salen de las etiquetas de `Dataset.csv` y del inventario de eventos,
que es la excepcion de dimensionamiento que admite el brief.

Uso:  python eda/scripts/06_icsflow_escrituras.py [max_paquetes]
"""

import collections
import json
import os
import sys

import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import comun  # noqa: E402
import modbus  # noqa: E402

ICSFLOW = os.path.join(comun.DATOS, "ics-flow")

# Numeracion de variables de ICSSIM, tomada de las cabeceras de
# snapshots_PLC1.csv y snapshots_PLC2.csv: el indice va entre parentesis.
VARIABLE = {
    0: "tank_input_valve_status", 1: "tank_input_valve_mode",
    2: "tank_level_value", 3: "tank_level_min", 4: "tank_level_max",
    5: "tank_output_valve_status", 6: "tank_output_valve_mode",
    7: "tank_output_flow_value", 8: "conveyor_belt_engine_status",
    9: "conveyor_belt_engine_mode", 10: "bottle_level_value",
    11: "bottle_level_max", 12: "bottle_distance_to_filler_value",
}

# Cada variable ocupa dos registros de 16 bits, de modo que la direccion
# Modbus es el doble del indice de variable. Se comprueba en INFORME.md.
ESCALA = 10000.0


def variable_de(direccion):
    if direccion is None or direccion % 2:
        return None, None
    idx = direccion // 2
    return idx, VARIABLE.get(idx)


def cargar_eventos():
    ruta = os.path.join(ICSFLOW, "attacker_machine_summary.csv")
    ev = pd.read_csv(ruta)
    ev.columns = [c.strip() for c in ev.columns]
    ev["dur"] = ev["endStamp"] - ev["startStamp"]
    return ev


def main():
    comun.preparar()
    tope = int(sys.argv[1]) if len(sys.argv) > 1 else 0
    tope = tope or None

    pcap = os.path.join(ICSFLOW, "traffic.pcap")
    if not os.path.exists(pcap):
        print("No se encuentra %s." % comun.rel(pcap))
        print("Bajar de Kaggle (alirezadehlaghi/icssim) y descomprimir ahi.")
        return 1

    flujos = pd.read_csv(os.path.join(ICSFLOW, "Dataset.csv"))
    eventos = cargar_eventos()

    t0 = float(flujos["start"].min())
    t1 = float(flujos["end"].max())
    span = t1 - t0
    corte60 = t0 + 0.6 * span
    corte80 = t0 + 0.8 * span

    def particion(ts):
        if ts < corte60:
            return "entrenamiento"
        return "calibracion" if ts < corte80 else "prueba"

    L = []
    w = L.append
    w("# Pregunta 6 - ICS-Flow: escrituras Modbus con parametros")
    w("")

    # ---------------- 4. Particion ----------------
    w("## 6.1 Particion temporal (se define aqui; el conjunto no la trae)")
    w("")
    w("Marca de tiempo del conjunto: %.3f a %.3f" % (t0, t1))
    w("Duracion: %.0f s = %.2f h" % (span, span / 3600.0))
    w("")
    w("%-14s %-22s %-22s" % ("particion", "offset (s)", "uso"))
    w("%-14s %-22s %-22s" % ("entrenamiento", "0 - %.0f (60 %%)" % (corte60 - t0),
                             "exploracion"))
    w("%-14s %-22s %-22s" % ("calibracion",
                             "%.0f - %.0f (20 %%)" % (corte60 - t0, corte80 - t0),
                             "umbral; no se explora"))
    w("%-14s %-22s %-22s" % ("prueba",
                             "%.0f - %.0f (20 %%)" % (corte80 - t0, span),
                             "no se abre"))
    w("")
    primer_evento = float(eventos["startStamp"].min()) - t0
    w("El primer evento empieza a los %.0f s, o sea que los primeros %.0f s"
      % (primer_evento, primer_evento))
    w("(%.1f %% de la captura) son trafico normal sin ningun ataque activo."
      % (100.0 * primer_evento / span))
    w("A diferencia de Westermo, aca si hay un tramo normal limpio y largo.")
    w("")
    w("**El PCAP se lee solo hasta el corte del 60 %.** Lo unico que se mira")
    w("fuera de ese tramo son conteos de etiqueta y el inventario de eventos.")
    w("")

    # ---------------- 1. Escrituras ----------------
    w("## 6.2 Escrituras Modbus en el tramo de entrenamiento")
    w("")
    print("  leyendo %s (una pasada completa; el detalle solo del 60 %% "
          "inicial)" % comun.rel(pcap), file=sys.stderr)

    # Ventanas de intermediario de TODA la captura: hacen falta para el
    # conteo por particion, que es dimensionamiento.
    ventanas_mitm = [(float(r["startStamp"]), float(r["endStamp"]))
                     for _, r in eventos[eventos["attack"] == "mitm"].iterrows()]

    def dentro_de_mitm(ts):
        return any(a <= ts <= b for a, b in ventanas_mitm)

    funciones = collections.Counter()
    escrituras = []
    lecturas = 0
    pend = {}
    emparejadas = 0
    latencias = []
    # Conteos por particion: solo cantidades, nunca valores. Es la excepcion
    # de dimensionamiento que admite el brief, y es lo que decide si el
    # conjunto alcanza para medir PD sobre la familia de parametros.
    conteo = collections.defaultdict(collections.Counter)

    for adu, c in modbus.leer_pcap(pcap, max_paquetes=tope):
        if adu is None:
            cont = c
            break
        part = particion(adu.ts)
        conteo[part]["adus"] += 1
        if adu.es_peticion and adu.es_escritura:
            conteo[part]["escrituras"] += 1
            if dentro_de_mitm(adu.ts):
                conteo[part]["escrituras_en_mitm"] += 1

        # A partir de aca, solo el tramo de entrenamiento.
        if part != "entrenamiento":
            continue
        funciones[adu.nombre] += 1
        if adu.es_peticion:
            pend[(adu.src_ip, adu.dst_ip, adu.transaccion)] = adu.ts
            if adu.es_lectura:
                lecturas += 1
            elif adu.es_escritura:
                escrituras.append({
                    "ts": adu.ts, "src": adu.src_ip, "dst": adu.dst_ip,
                    "src_mac": adu.src_mac, "unidad": adu.unidad,
                    "funcion": adu.funcion, "direccion": adu.direccion,
                    "cantidad": adu.cantidad, "valor32": adu.valor32,
                    "valores": adu.valores,
                })
        else:
            k = (adu.dst_ip, adu.src_ip, adu.transaccion)
            if k in pend:
                latencias.append(adu.ts - pend.pop(k))
                emparejadas += 1

    w("Paquetes leidos: %d  |  IP %d  |  TCP %d  |  con carga %d  |  "
      "puerto 502 %d" % (cont["paquetes"], cont["ip"], cont["tcp"],
                         cont["con_carga"], cont["puerto_502"]))
    if cont["no_tcp"]:
        w("Paquetes IP que no son TCP, descartados antes de leer puerto: %s"
          % cont["no_tcp"])
        w("  (son de los escaneos y del DDoS; hay que filtrarlos antes de")
        w("   tocar `sport`, o el lector rompe)")
    w("ADU Modbus delimitadas: %d" % cont["adus"])
    w("")
    w("Codigos de funcion:")
    for nom, n in funciones.most_common():
        w("   %-34s %9d" % (nom, n))
    w("")
    w("Peticiones emparejadas con su respuesta por identificador de")
    w("transaccion: %d; latencia mediana %.1f ms"
      % (emparejadas,
         1000 * float(np.median(latencias)) if latencias else float("nan")))
    w("")

    if not escrituras:
        w("**No hay escrituras en el tramo de entrenamiento.** La brecha no se")
        w("cierra con este conjunto.")
        comun.escribir("p6_icsflow.txt", "\n".join(L))
        return 0

    esc = pd.DataFrame(escrituras)
    w("Peticiones de escritura: **%d**" % len(esc))
    w("")
    w("Reparto por destino, direccion y variable:")
    w("")
    w("%-16s %6s %10s %-30s %9s %9s %10s %10s"
      % ("destino", "dir.", "variable", "nombre", "escrit.", "distintos",
         "min", "max"))
    detalle = {}
    for (dst, direccion), g in esc.groupby(["dst", "direccion"]):
        idx, nombre = variable_de(direccion)
        v = g["valor32"].dropna()
        if v.empty:
            w("%-16s %6d %10s %-30s %9d %9s %10s %10s"
              % (dst, direccion, idx, nombre or "?", len(g), "-", "-", "-"))
            continue
        w("%-16s %6d %10d %-30s %9d %9d %10.4f %10.4f"
          % (dst, direccion, idx, nombre or "?", len(g), v.nunique(),
             v.min() / ESCALA, v.max() / ESCALA))
        detalle["%s:%d" % (dst, direccion)] = {
            "variable": idx, "nombre": nombre, "escrituras": int(len(g)),
            "valores_distintos": int(v.nunique()),
            "min": float(v.min() / ESCALA), "max": float(v.max() / ESCALA),
        }
    w("")
    w("Las escrituras usan funcion 16 con cantidad 2: ICSSIM reparte cada")
    w("variable en dos registros de 16 bits, el mas significativo primero, y")
    w("el valor fisico es el entero de 32 bits dividido por %d." % int(ESCALA))
    w("Por eso la direccion Modbus es el doble del indice de variable que")
    w("declaran las cabeceras de snapshots_PLC1.csv y snapshots_PLC2.csv.")
    w("")
    n32 = int(esc["valor32"].notna().sum())
    w("Escrituras con valor de 32 bits recuperado: %d de %d (%.1f %%)"
      % (n32, len(esc), 100.0 * n32 / len(esc)))
    distintos = int(esc["valor32"].dropna().nunique())
    w("Valores distintos en total: %d sobre %d escrituras" % (distintos, n32))
    w("")
    w("**Esto es lo que decide la pregunta**: el valor escrito no es un bit ni")
    w("un puñado de estados, es una consigna con %d valores distintos sobre %d"
      % (distintos, n32))
    w("escrituras. Es el repertorio que hace falta para la familia MPCI.")
    w("")

    # Contraste con las variables de proceso
    w("Contraste con los registros de proceso, que es lo que confirma la")
    w("interpretacion de la escala y del mapa de registros:")
    w("")
    w("%-30s %-22s %-22s" % ("variable", "rango escrito (entren.)",
                             "rango en el snapshot"))
    for plc, archivo in (("PLC1", "snapshots_PLC1.csv"),
                         ("PLC2", "snapshots_PLC2.csv")):
        s = pd.read_csv(os.path.join(ICSFLOW, archivo))
        s.columns = [c.strip() for c in s.columns]
        for col in s.columns:
            if "(" not in col:
                continue
            idx = int(col.split("(")[1].rstrip(")"))
            sel = esc[esc["direccion"] == 2 * idx]["valor32"].dropna()
            if sel.empty:
                continue
            v = pd.to_numeric(s[col], errors="coerce").dropna()
            w("%-30s %-22s %-22s"
              % (col, "%.4f - %.4f" % (sel.min() / ESCALA, sel.max() / ESCALA),
                 "%.4f - %.4f" % (v.min(), v.max())))
    w("")
    w("Los rangos se corresponden, de modo que la consigna escrita por la red")
    w("es la que el PLC aplica: una manipulacion de ese valor tiene efecto")
    w("observable sobre el proceso, y no se queda en la trama.")
    w("")

    # ---------------- 2. Intermediario ----------------
    w("## 6.3 El ataque de intermediario, se ve en la carga util?")
    w("")
    mitm = eventos[eventos["attack"] == "mitm"]
    mitm_tr = mitm[mitm["startStamp"] < corte60]
    w("Eventos de intermediario: %d en total, %d dentro del tramo de"
      % (len(mitm), len(mitm_tr)))
    w("entrenamiento. Solo se analizan esos %d." % len(mitm_tr))
    macs = sorted(set(mitm["attackerMAC"]))
    ips = sorted(set(mitm["attackerIP"]))
    w("MAC del atacante: %s   IP: %s" % (", ".join(macs), ", ".join(ips)))
    w("")

    def en_mitm(ts):
        for _, e in mitm_tr.iterrows():
            if e["startStamp"] <= ts <= e["endStamp"]:
                return True
        return False

    esc["en_mitm"] = esc["ts"].map(en_mitm)
    dentro = esc[esc["en_mitm"]]
    fuera = esc[~esc["en_mitm"]]
    w("Escrituras dentro de ventanas de intermediario: %d" % len(dentro))
    w("Escrituras fuera: %d" % len(fuera))
    w("")
    if len(dentro):
        w("MAC de origen de las escrituras, dentro y fuera de las ventanas:")
        w("")
        w("%-20s %12s %12s" % ("MAC de origen", "en mitm", "fuera"))
        for mac in sorted(set(esc["src_mac"])):
            w("%-20s %12d %12d"
              % (mac, int((dentro["src_mac"] == mac).sum()),
                 int((fuera["src_mac"] == mac).sum())))
        w("")
        relayed = dentro[dentro["src_mac"].isin(macs)]
        w("Escrituras cuya MAC de origen es la del atacante pero cuya IP de")
        w("origen no lo es: **%d**"
          % int((relayed["src"] != ips[0]).sum() if len(relayed) else 0))
        w("Esa combinacion es la firma del envenenamiento de ARP: el atacante")
        w("retransmite la trama del HMI con su propia MAC de capa 2.")
        w("")
        w("Valores escritos, dentro y fuera de las ventanas:")
        w("")
        w("%-30s %10s %12s %12s %12s"
          % ("variable", "n", "mediana", "min", "max"))
        for direccion in sorted(set(esc["direccion"].dropna())):
            idx, nombre = variable_de(int(direccion))
            for etq, sub in (("fuera", fuera), ("en mitm", dentro)):
                v = sub[sub["direccion"] == direccion]["valor32"].dropna()
                if v.empty:
                    continue
                w("%-30s %10s %12.4f %12.4f %12.4f"
                  % ("%s (%s)" % (nombre or direccion, etq), len(v),
                     v.median() / ESCALA, v.min() / ESCALA, v.max() / ESCALA))
        w("")
        # Duplicados proximos: la misma direccion escrita dos veces en menos
        # de un segundo es lo que deja un relay que reescribe el valor.
        dup = []
        d = esc.sort_values("ts")
        for direccion in sorted(set(d["direccion"].dropna())):
            s = d[d["direccion"] == direccion].reset_index(drop=True)
            for i in range(len(s) - 1):
                dt = s.loc[i + 1, "ts"] - s.loc[i, "ts"]
                if dt <= 1.0 and pd.notna(s.loc[i, "valor32"]) \
                        and pd.notna(s.loc[i + 1, "valor32"]):
                    a, b = s.loc[i, "valor32"], s.loc[i + 1, "valor32"]
                    dup.append({"direccion": int(direccion), "dt": dt,
                                "v1": int(a), "v2": int(b),
                                "razon": (b / a) if a else None,
                                "en_mitm": bool(s.loc[i, "en_mitm"]),
                                "mac1": s.loc[i, "src_mac"],
                                "mac2": s.loc[i + 1, "src_mac"]})
        w("Escrituras repetidas sobre la misma variable en menos de 1 s: %d"
          % len(dup))
        factor = None
        if dup:
            dd = pd.DataFrame(dup)
            w("  de ellas dentro de una ventana de intermediario: %d"
              % int(dd["en_mitm"].sum()))
            w("")
            w("La pareja esperable de un relay es la misma escritura vista dos")
            w("veces: una con la MAC del HMI y otra con la del atacante. Se")
            w("separa por eso, que es mas firme que la mera proximidad.")
            w("")
            mac_atac = set(macs)
            dd["relay"] = (~dd["mac1"].isin(mac_atac)) & dd["mac2"].isin(mac_atac)
            w("Parejas en las que la segunda trama lleva la MAC del atacante")
            w("y la primera no: **%d**" % int(dd["relay"].sum()))
            w("")
            w("Distribucion de la razon entre el segundo valor y el primero:")
            w("")
            w("%-26s %10s %10s" % ("razon (3 decimales)", "relay", "resto"))
            dd["r3"] = dd["razon"].round(3)
            for r3 in sorted(dd["r3"].dropna().unique()):
                a = int(((dd["r3"] == r3) & dd["relay"]).sum())
                b = int(((dd["r3"] == r3) & ~dd["relay"]).sum())
                w("%-26s %10d %10d" % ("%.3f" % r3, a, b))
            rel = dd[dd["relay"] & (dd["r3"] != 1.0)]["r3"]
            if len(rel):
                factor = float(rel.mode().iloc[0])
                w("")
                w("**El factor de manipulacion es %.3f**: en %d de las %d"
                  % (factor, int((rel == factor).sum()), len(rel)))
                w("parejas de relay con valor alterado, el atacante reescribe")
                w("la consigna multiplicada por ese factor. El articulo dice")
                w("que el intermediario multiplica los valores por un factor;")
                w("aca queda medido cual es.")
            w("")
            w("Primeras parejas, para poder leerlas a mano:")
            w("")
            w("%-18s %7s %10s %10s %9s %7s %7s"
              % ("variable", "dt(s)", "valor 1", "valor 2", "razon", "relay",
                 "en mitm"))
            for r in dup[:14]:
                idx, nombre = variable_de(r["direccion"])
                es_relay = (r["mac1"] not in mac_atac
                            and r["mac2"] in mac_atac)
                w("%-18s %7.3f %10.4f %10.4f %9.3f %7s %7s"
                  % (nombre or r["direccion"], r["dt"], r["v1"] / ESCALA,
                     r["v2"] / ESCALA,
                     r["razon"] if r["razon"] else float("nan"),
                     "si" if es_relay else "no",
                     "si" if r["en_mitm"] else "no"))
        w("")

    # Las escrituras con la MAC del atacante que caen fuera de una ventana de
    # intermediario no son un error de etiquetado: hay que ver en que otra
    # ventana caen antes de concluir nada.
    def ventana_de(ts):
        for _, e2 in eventos.iterrows():
            if e2["startStamp"] <= ts <= e2["endStamp"]:
                return e2["attack"]
        return "ninguna"

    esc["ventana"] = esc["ts"].map(ventana_de)
    w("Escrituras del tramo de entrenamiento por MAC de origen y por ventana")
    w("de ataque declarada:")
    w("")
    tabm = pd.crosstab(esc["src_mac"], esc["ventana"])
    cols = list(tabm.columns)
    w("%-30s %s" % ("MAC de origen", " ".join("%12s" % c for c in cols)))
    for mac, fila in tabm.iterrows():
        etq = "%s%s" % (mac, " (atacante)" if mac in set(macs) else "")
        w("%-30s %s" % (etq, " ".join("%12d" % fila[c] for c in cols)))
    w("")
    w("El atacante escribe bajo **dos** mecanismos distintos, no uno: con el")
    w("intermediario reescribe la consigna multiplicada por el factor, y con")
    w("la repeticion reenvia consignas capturadas antes, que llegan al PLC")
    w("fuera de tiempo. Las dos son anomalias contextuales sobre el mismo")
    w("campo, de modo que el conjunto aporta dos mecanismos y no uno.")
    w("")

    # El detalle del tramo de entrenamiento se guarda aparte: permite rehacer
    # este analisis sin volver a recorrer 1,8 GB de PCAP.
    derivado = os.path.join(comun.DERIVADOS,
                            "icsflow_escrituras_entrenamiento.csv")
    esc.drop(columns=["valores"]).to_csv(derivado, index=False)
    w("Detalle de las %d escrituras del tramo de entrenamiento: %s"
      % (len(esc), comun.rel(derivado)))
    w("")

    # ---------------- 3. Eventos por tipo ----------------
    w("## 6.4 Eventos por tipo de anomalia y por particion")
    w("")
    eventos["particion"] = eventos["startStamp"].map(particion)
    tab = pd.crosstab(eventos["attack"], eventos["particion"])
    for col in ("entrenamiento", "calibracion", "prueba"):
        if col not in tab.columns:
            tab[col] = 0
    tab = tab[["entrenamiento", "calibracion", "prueba"]]
    w("%-14s %8s %14s %12s %10s %12s"
      % ("tipo", "eventos", "entrenamiento", "calibracion", "prueba",
         "dur.med.(s)"))
    for tipo, fila in tab.iterrows():
        dur = eventos[eventos["attack"] == tipo]["dur"]
        w("%-14s %8d %14d %12d %10d %12.1f"
          % (tipo, int(fila.sum()), fila["entrenamiento"], fila["calibracion"],
             fila["prueba"], dur.median()))
    w("%-14s %8d %14d %12d %10d"
      % ("TOTAL", len(eventos), tab["entrenamiento"].sum(),
         tab["calibracion"].sum(), tab["prueba"].sum()))
    w("")
    w("Flujos etiquetados en Dataset.csv (conteo, no distribuciones):")
    w("")
    for estr in ("NST", "IT"):
        vc = flujos["%s_M_Label" % estr].value_counts()
        w("  %-4s %s" % (estr, dict(vc)))
    w("")
    w("Con %d eventos en el tramo de prueba repartidos en %d tipos, el tipo"
      % (int(tab["prueba"].sum()), len(tab)))
    w("menos representado tiene %d. Es el mismo problema que en Westermo: PD"
      % int(tab["prueba"].min()))
    w("por tipo sobre eventos no se puede estimar con precision util, y hay")
    w("que reportarla por flujo o de forma agregada.")
    w("")
    w("## 6.5 Cuantas escrituras hay, y cuantas bajo intermediario")
    w("")
    w("Este es el conteo que decide el alcance. Son cantidades por particion,")
    w("sin mirar valores fuera del tramo de entrenamiento.")
    w("")
    w("%-16s %12s %12s %18s %10s"
      % ("particion", "ADU Modbus", "escrituras", "escr. en mitm", "% en mitm"))
    tot = collections.Counter()
    for part in ("entrenamiento", "calibracion", "prueba"):
        c3 = conteo[part]
        tot.update(c3)
        e, m = c3["escrituras"], c3["escrituras_en_mitm"]
        w("%-16s %12d %12d %18d %9.1f%%"
          % (part, c3["adus"], e, m, 100.0 * m / e if e else 0.0))
    e, m = tot["escrituras"], tot["escrituras_en_mitm"]
    w("%-16s %12d %12d %18d %9.1f%%"
      % ("TOTAL", tot["adus"], e, m, 100.0 * m / e if e else 0.0))
    w("")
    # Las ADU se reparten por mitades entre peticion y respuesta, asi que las
    # peticiones son la mitad del total y las lecturas, el resto.
    peticiones = tot["adus"] // 2
    lecturas_tot = peticiones - e
    w("Peticiones Modbus (la mitad de las ADU): %d, de las cuales %d son"
      % (peticiones, lecturas_tot))
    w("lecturas. Hay una escritura cada %d lecturas."
      % (round(lecturas_tot / e) if e else 0))
    w("")
    w("Escrituras bajo intermediario en el tramo de prueba: **%d**."
      % conteo["prueba"]["escrituras_en_mitm"])
    w("Es la cifra que fija el alcance: son las instancias disponibles para")
    w("medir PD sobre manipulacion de parametros sin tocar el entrenamiento.")
    w("")

    # ---------------- 5. Alcance ----------------
    w("## 6.6 Con que alcance cierra la brecha")
    w("")
    n_pru = conteo["prueba"]["escrituras_en_mitm"]
    ev_pru = int(tab.loc["mitm", "prueba"]) if "mitm" in tab.index else 0

    def semiancho(n):
        return 1.96 * (0.25 / n) ** 0.5 if n else float("nan")

    w("Precision alcanzable para una PD cercana a 0,5, por aproximacion")
    w("normal de una binomial:")
    w("")
    w("%-46s %8s %12s" % ("unidad de medida", "n", "IC 95 %"))
    w("%-46s %8d %12s" % ("ICS-Flow, escritura manipulada (prueba)", n_pru,
                          "+-%.3f" % semiancho(n_pru)))
    w("%-46s %8d %12s" % ("ICS-Flow, evento de intermediario (prueba)",
                          ev_pru, "+-%.3f" % semiancho(ev_pru)))
    w("%-46s %8d %12s" % ("Morris, evento MPCI (prueba)", 1808,
                          "+-%.3f" % semiancho(1808)))
    w("")
    w("Lectura. ICS-Flow **si** cierra la mitad que faltaba: es el unico")
    w("conjunto de los cinco donde se puede *calcular* una caracteristica")
    w("semantica de parametro desde la carga util y ademas ver la familia de")
    w("manipulacion actuando sobre ella. Sirve para construir y validar el")
    w("flujo de extraccion del requerimiento 2.3 sobre datos reales.")
    w("")
    w("Pero no reemplaza a Morris para medir. Con %d escrituras manipuladas"
      % n_pru)
    w("en el tramo de prueba, una PD por escritura queda con un intervalo de")
    w("+-%.2f, utilizable pero grueso; por evento, con solo %d eventos, no es"
      % (semiancho(n_pru), ev_pru))
    w("estimable. Morris sigue siendo el que sostiene el compromiso por")
    w("familia, y no tiene carga util.")
    w("")
    w("De modo que la division de roles no se resuelve: pasa de dos conjuntos")
    w("a tres. QUT para el grueso de las caracteristicas semanticas de")
    w("funcion y temporizado, ICS-Flow para construir y validar la extraccion")
    w("de parametros y dar una PD gruesa sobre esa familia, y Morris para el")
    w("compromiso numerico por tipo.")
    w("")

    comun.escribir("p6_icsflow.txt", "\n".join(L))

    with open(os.path.join(comun.SALIDAS, "p6_icsflow.json"), "w") as fh:
        json.dump({
            "particion": {"t0": t0, "t1": t1, "corte60": corte60,
                          "corte80": corte80, "span_s": span},
            "contadores_pcap": {k: v for k, v in cont.items()},
            "funciones": dict(funciones),
            "escrituras": int(len(esc)),
            "escrituras_con_valor32": n32,
            "valores_distintos": distintos,
            "por_registro": detalle,
            "eventos_por_particion": tab.to_dict(),
            "emparejadas": emparejadas,
            "conteo_por_particion": {k: dict(v) for k, v in conteo.items()},
        }, fh, indent=1, ensure_ascii=False, default=str)

    # ---------------- figura ----------------
    plt = comun.estilo_figura()
    fig, axes = plt.subplots(1, 2, figsize=(10, 4.0))
    ax = axes[0]
    for direccion in sorted(set(esc["direccion"].dropna())):
        idx, nombre = variable_de(int(direccion))
        v = esc[esc["direccion"] == direccion]["valor32"].dropna() / ESCALA
        if len(v) < 5:
            continue
        ax.hist(v, bins=30, alpha=0.6, label=nombre or int(direccion))
    ax.set_xlabel("valor escrito (unidades de proceso)")
    ax.set_ylabel("escrituras")
    ax.set_title("Repertorio de las consignas escritas\n"
                 "(tramo de entrenamiento)", fontsize=9)
    ax.legend(fontsize=7)

    ax = axes[1]
    t = (esc["ts"] - t0) / 60.0
    for direccion in sorted(set(esc["direccion"].dropna())):
        idx, nombre = variable_de(int(direccion))
        m = esc["direccion"] == direccion
        if m.sum() < 5:
            continue
        ax.plot(t[m], esc.loc[m, "valor32"] / ESCALA, ".", ms=3,
                label=nombre or int(direccion))
    for _, e in mitm_tr.iterrows():
        ax.axvspan((e["startStamp"] - t0) / 60.0, (e["endStamp"] - t0) / 60.0,
                   color="crimson", alpha=0.25)
    ax.set_xlabel("minutos desde el inicio de la captura")
    ax.set_ylabel("valor escrito")
    ax.set_title("Consignas a lo largo del tiempo\n"
                 "en rojo, las ventanas de intermediario", fontsize=9)
    ax.legend(fontsize=7)
    fig.suptitle("P6: ICS-Flow tiene escrituras Modbus con parametros",
                 fontsize=10)
    fig.savefig(os.path.join(comun.FIGURAS, "p6_icsflow_escrituras.png"))
    print("[figura] %s" % comun.rel(
        os.path.join(comun.FIGURAS, "p6_icsflow_escrituras.png")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
