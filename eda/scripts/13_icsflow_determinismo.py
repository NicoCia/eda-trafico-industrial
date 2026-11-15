"""Pregunta 13 --- Determinismo (D2) de ICS-Flow, medido.

La tabla de criterios de comparabilidad le asigna a ICS-Flow **D2 =
cumple**, y
esa celda nunca se midio: el conjunto ya estaba en disco y ya se habia
recorrido entero para la pregunta 6, pero sobre otra pregunta. El criterio D2
exige, textual, que el determinismo "debe verificarse sobre los datos
---periodicidad, entropia de direcciones y puertos--- y no asumirse por la
descripcion del conjunto".

Este script corre sobre ICS-Flow **las mismas medidas** que
`05_determinismo.py` calcula para Westermo y QUT, de modo que las cifras sean
comparables celda por celda: indice de dispersion de la tasa por ventana de
1 s, coeficiente de variacion del intervalo entre paquetes (agregado y por
conversacion), entropia de direcciones y puertos, estabilidad del conjunto de
pares por Jaccard, repertorio de tamanos de paquete y mezcla de protocolos.

REUSO
-----
`caracterizar`, `imprimir`, `entropia`, `autocorr_segmentos` y las constantes
VENTANA, VENTANA_PARES y LAG_MAX se **importan** de `05_determinismo.py` sin
modificarlo: las definiciones son literalmente las mismas, no una copia.

Lo unico que se reescribe es el lector de paquetes. `05_determinismo.leer_
paquetes` acumula una tupla de Python por paquete antes de armar el
DataFrame, y el tramo de entrenamiento de ICS-Flow tiene unos 25 millones de
paquetes: esa lista no entra en memoria. `leer_paquetes_icsflow` clasifica
cada paquete con **la misma cadena de condiciones** --- IP/TCP, IP/UDP,
IP-%d, ARP, ETH-0x%04x, con MAC en lugar de IP cuando no hay capa IP --- pero
guarda codigos enteros en vectores de numpy y recien al final arma el
DataFrame con categorias. El resultado es el mismo DataFrame de columnas
(t, src, dst, sport, dport, size, proto) que espera `caracterizar`.

PARTICION
---------
La misma que fijo el script 06: 60/20/20 por tiempo sobre la marca de
`Dataset.csv`, y **el PCAP se lee solo hasta el corte del 60 %**. Como en
Westermo, se informan dos definiciones de normal:

  (a) todo el tramo de entrenamiento, eventos incluidos;
  (b) solo los huecos entre eventos, que es el normal mas estricto posible
      sobre esta captura.

y un tercer bloque a nivel de flujo con `NST_B_Label == 0`, que es el analogo
exacto del bloque (c) de Westermo --- ICS-Flow trae el mismo esquema de 54
columnas, generado con la misma herramienta.

Uso:  python eda/scripts/13_icsflow_determinismo.py [max_paquetes]
"""

import bisect
import collections
import importlib
import json
import os
import socket
import sys

import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import comun  # noqa: E402

det = importlib.import_module("05_determinismo")

ICSFLOW = os.path.join(comun.DATOS, "ics-flow")
LOTE = 2_000_000          # paquetes por volcado a vectores de numpy


def particion_icsflow():
    """Replica la particion temporal que fijo el script 06.

    Devuelve (t0, t1, corte60_absoluto). Sale de `Dataset.csv`, no del PCAP,
    igual que en 06, para que las dos preguntas usen el mismo corte.
    """
    fl = pd.read_csv(os.path.join(ICSFLOW, "Dataset.csv"),
                     usecols=["start", "end"])
    t0 = float(fl["start"].min())
    t1 = float(fl["end"].max())
    return t0, t1, t0 + 0.6 * (t1 - t0)


def eventos_icsflow():
    """Intervalos absolutos (inicio, fin) de los eventos de ataque."""
    ev = pd.read_csv(os.path.join(ICSFLOW, "attacker_machine_summary.csv"))
    ev.columns = [c.strip() for c in ev.columns]
    iv = sorted((float(a), float(b))
                for a, b in zip(ev["startStamp"], ev["endStamp"]))
    fus = []
    for a, b in iv:
        if fus and a <= fus[-1][1]:
            fus[-1] = (fus[-1][0], max(fus[-1][1], b))
        else:
            fus.append((a, b))
    return fus, ev


def leer_paquetes_icsflow(ruta, hasta_abs, max_paquetes=None):
    """DataFrame (t, src, dst, sport, dport, size, proto) hasta `hasta_abs`.

    Misma clasificacion que `05_determinismo.leer_paquetes`; solo cambia el
    almacenamiento, que va por lotes a vectores de numpy para que 25 millones
    de paquetes entren en memoria.
    """
    import dpkt

    cod_nodo = {}
    cod_proto = {}

    def cod(d, v):
        c = d.get(v)
        if c is None:
            c = len(d)
            d[v] = c
        return c

    lt, lsrc, ldst, lsp, ldp, lsz, lpr = [], [], [], [], [], [], []
    bloques = []
    n = 0

    def volcar():
        if not lt:
            return
        bloques.append((
            np.array(lt, dtype=np.float64),
            np.array(lsrc, dtype=np.int32), np.array(ldst, dtype=np.int32),
            np.array(lsp, dtype=np.int32), np.array(ldp, dtype=np.int32),
            np.array(lsz, dtype=np.int32), np.array(lpr, dtype=np.int16)))
        for L in (lt, lsrc, ldst, lsp, ldp, lsz, lpr):
            del L[:]

    t0 = None
    with open(ruta, "rb") as fh:
        for ts, buf in dpkt.pcap.Reader(fh):
            if t0 is None:
                t0 = ts
            if ts > hasta_abs:
                break
            n += 1
            if max_paquetes and n > max_paquetes:
                break
            try:
                eth = dpkt.ethernet.Ethernet(buf)
            except Exception:
                continue
            size = len(buf)
            ip = eth.data
            if isinstance(ip, dpkt.ip.IP):
                src = socket.inet_ntoa(ip.src)
                dst = socket.inet_ntoa(ip.dst)
                tr = ip.data
                if isinstance(tr, dpkt.tcp.TCP):
                    proto, sp, dp = "TCP", tr.sport, tr.dport
                elif isinstance(tr, dpkt.udp.UDP):
                    proto, sp, dp = "UDP", tr.sport, tr.dport
                else:
                    proto, sp, dp = "IP-%d" % ip.p, -1, -1
            elif isinstance(ip, dpkt.arp.ARP):
                src = ":".join("%02x" % b for b in eth.src)
                dst = ":".join("%02x" % b for b in eth.dst)
                proto, sp, dp = "ARP", -1, -1
            else:
                src = ":".join("%02x" % b for b in eth.src)
                dst = ":".join("%02x" % b for b in eth.dst)
                proto = "ETH-0x%04x" % eth.type
                sp = dp = -1
            lt.append(ts - t0)
            lsrc.append(cod(cod_nodo, src))
            ldst.append(cod(cod_nodo, dst))
            lsp.append(sp)
            ldp.append(dp)
            lsz.append(size)
            lpr.append(cod(cod_proto, proto))
            if len(lt) >= LOTE:
                volcar()
                print("    %d millones de paquetes" % (n // 1_000_000),
                      file=sys.stderr)
    volcar()
    if not bloques:
        return pd.DataFrame(columns=["t", "src", "dst", "sport", "dport",
                                     "size", "proto"]), t0, 0
    cols = [np.concatenate([b[i] for b in bloques]) for i in range(7)]
    nodos = [k for k, _ in sorted(cod_nodo.items(), key=lambda kv: kv[1])]
    protos = [k for k, _ in sorted(cod_proto.items(), key=lambda kv: kv[1])]
    df = pd.DataFrame({
        "t": cols[0],
        "src": pd.Categorical.from_codes(cols[1], categories=nodos),
        "dst": pd.Categorical.from_codes(cols[2], categories=nodos),
        "sport": cols[3], "dport": cols[4], "size": cols[5],
        "proto": pd.Categorical.from_codes(cols[6], categories=protos)})
    return df, t0, n


def huecos(intervalos, inicio, fin):
    """Complemento de `intervalos` dentro de [inicio, fin]."""
    out = []
    prev = inicio
    for a, b in intervalos:
        a, b = max(a, inicio), min(b, fin)
        if b <= inicio or a >= fin:
            continue
        if a > prev:
            out.append((prev, a))
        prev = max(prev, b)
    if fin > prev:
        out.append((prev, fin))
    return out


def dentro(t, intervalos):
    i = bisect.bisect_right([a for a, _ in intervalos], t) - 1
    return i >= 0 and t <= intervalos[i][1]


def mascara_fuera(t, intervalos):
    """Version vectorizada de `not dentro(t, intervalos)`, elemento a elemento.

    Misma semantica que `dentro` --- el ultimo intervalo que empieza antes de
    `t`, y `t` dentro de su fin ---, pero sin un bucle de Python sobre 25
    millones de elementos.
    """
    t = np.asarray(t, dtype=float)
    if not intervalos:
        return np.ones(t.size, dtype=bool)
    ini = np.array([a for a, _ in intervalos], dtype=float)
    fin = np.array([b for _, b in intervalos], dtype=float)
    i = np.searchsorted(ini, t, side="right") - 1
    valido = i >= 0
    adentro = np.zeros(t.size, dtype=bool)
    adentro[valido] = t[valido] <= fin[i[valido]]
    return ~adentro


def main():
    comun.preparar()
    tope = int(sys.argv[1]) if len(sys.argv) > 1 else 0
    tope = tope or None

    pcap = os.path.join(ICSFLOW, "traffic.pcap")
    if not os.path.exists(pcap):
        print("No se encuentra %s." % comun.rel(pcap))
        return 1

    L = []
    w = L.append
    w("# Pregunta 13 - determinismo (D2) de ICS-Flow")
    w("")
    w("La tabla de criterios de comparabilidad le pone a ICS-Flow D2 = cumple")
    w("sin haberlo medido. D2 exige verificarlo sobre los datos. Aca se")
    w("corren las mismas medidas que 05_determinismo.py aplica a Westermo y")
    w("a QUT, importadas de ese script sin modificarlo, para que las cifras")
    w("se puedan comparar celda por celda.")
    w("")
    w("Lectura de las medidas (la misma que fija el script 05):")
    w("  CV del intervalo entre paquetes ~0 = periodico; ~1 = tipo Poisson;")
    w("  >1 = a rafagas. El indice de dispersion de la tasa (var/media)")
    w("  compara contra el azar puro sin que el nivel medio confunda.")
    w("  Entropia normalizada ~0 = un solo interlocutor; ~1 = reparto")
    w("  uniforme. Jaccard ~1 = el mismo conjunto de pares conversa en cada")
    w("  ventana.")
    w("")

    t0, t1, corte_abs = particion_icsflow()
    span = t1 - t0
    iv_abs, ev = eventos_icsflow()

    w("## 13.1 Particion y eventos")
    w("")
    w("Particion identica a la del script 06: 60/20/20 por tiempo sobre la")
    w("marca de Dataset.csv. **El PCAP se lee solo hasta el corte del 60 %.**")
    w("   marca del conjunto : %.3f a %.3f" % (t0, t1))
    w("   duracion           : %.0f s = %.2f h" % (span, span / 3600.0))
    w("   corte del 60 %%      : offset %.0f s" % (corte_abs - t0))
    w("")
    w("Eventos de ataque declarados en attacker_machine_summary.csv: %d"
      % len(ev))
    w("   por tipo: %s" % dict(collections.Counter(ev["attack"])))
    primer = float(ev["startStamp"].min()) - t0
    w("   el primero empieza en el offset %.0f s" % primer)
    w("")

    print("  leyendo %s hasta el corte del 60 %%" % comun.rel(pcap),
          file=sys.stderr)
    df, ts_primero, leidos = leer_paquetes_icsflow(pcap, corte_abs, tope)
    w("Paquetes leidos hasta el corte: %d" % leidos)
    w("Primer paquete del PCAP: %.3f (%.3f s %s que la marca de Dataset.csv)"
      % (ts_primero, abs(ts_primero - t0),
         "despues" if ts_primero > t0 else "antes"))
    w("El eje de tiempo `t` de aqui en adelante cuenta desde el primer")
    w("paquete del PCAP, igual que en el script 05.")
    w("")

    # Intervalos en el eje relativo al primer paquete del PCAP.
    tr = corte_abs - ts_primero
    iv = [(a - ts_primero, b - ts_primero) for a, b in iv_abs]
    iv = [(a, min(b, tr)) for a, b in iv if a < tr]
    cubierto = sum(b - a for a, b in iv)
    hu = huecos(iv, 0.0, tr)

    w("Tramo de entrenamiento: 0 a %.0f s." % tr)
    w("Eventos activos durante %.0f s (%.1f %% del tramo), en %d intervalos."
      % (cubierto, 100 * cubierto / tr, len(iv)))
    w("Quedan %.0f s limpios (%.1f %%) en %d huecos."
      % (tr - cubierto, 100 * (tr - cubierto) / tr, len(hu)))
    w("")

    resultados = {}

    w("## 13.2 (a) ICS-Flow, todo el tramo de entrenamiento")
    w("")
    ra = det.caracterizar(df, "icsflow_entrenamiento_todo", [(0.0, tr)])
    det.imprimir(ra, w)
    w("")
    resultados["icsflow_todo"] = ra

    w("## 13.3 (b) ICS-Flow, solo los huecos entre eventos")
    w("")
    mask = mascara_fuera(df["t"].to_numpy(), iv)
    rb = det.caracterizar(df[mask], "icsflow_entrenamiento_limpio", hu)
    det.imprimir(rb, w)
    w("")
    resultados["icsflow_limpio"] = rb
    del mask

    w("## 13.4 (c) ICS-Flow a nivel de flujo, NST_B_Label = 0")
    w("")
    w("Analogo exacto del bloque (c) de Westermo: ICS-Flow trae el mismo")
    w("esquema de 54 columnas, generado con la misma herramienta.")
    w("")
    fl = pd.read_csv(os.path.join(ICSFLOW, "Dataset.csv"))
    fl = fl[(fl["start"] < corte_abs) & (fl["NST_B_Label"] == 0)]
    w("Flujos normales en el tramo de entrenamiento: %d" % len(fl))
    cs = collections.Counter(fl["sAddress"])
    cd = collections.Counter(fl["rAddress"])
    hs, hns, ks = det.entropia(cs)
    hd, hnd, kd = det.entropia(cd)
    w("  entropia de sAddress: %.2f bits / %.2f normalizada / %d distintos"
      % (hs, hns, ks))
    w("  entropia de rAddress: %.2f bits / %.2f normalizada / %d distintos"
      % (hd, hnd, kd))
    pares = collections.Counter(zip(fl["sAddress"], fl["rAddress"]))
    hp, hnp, kp = det.entropia(pares)
    w("  entropia del par (s,r): %.2f bits / %.2f normalizada / %d pares"
      % (hp, hnp, kp))
    w("  los 5 pares mas frecuentes concentran el %.1f %% de los flujos"
      % (100.0 * sum(n for _, n in pares.most_common(5)) / len(fl)))
    w("  protocolos: %s" % dict(collections.Counter(fl["protocol"])))
    for col in ("sPackets", "sBytesAvg", "duration", "sInterPacketAvg"):
        if col not in fl.columns:
            continue
        v = pd.to_numeric(fl[col], errors="coerce").dropna()
        if v.empty:
            continue
        w("  %-16s mediana=%.3f  CV=%.2f  p05=%.3f  p95=%.3f"
          % (col, v.median(),
             (v.std() / v.mean()) if v.mean() else float("nan"),
             v.quantile(0.05), v.quantile(0.95)))
    resultados["icsflow_flujos_nst"] = {
        "flujos": len(fl), "H_sAddress": hs, "Hn_sAddress": hns,
        "k_sAddress": ks, "H_rAddress": hd, "Hn_rAddress": hnd,
        "k_rAddress": kd, "H_par": hp, "Hn_par": hnp, "k_par": kp}
    w("")

    # ------------------------- comparacion -------------------------
    w("## 13.5 Comparacion con Westermo y QUT")
    w("")
    ruta_p2 = os.path.join(comun.SALIDAS, "p2_determinismo.json")
    previos = {}
    if os.path.exists(ruta_p2):
        with open(ruta_p2) as fh:
            previos = json.load(fh)
    else:
        w("No esta p2_determinismo.json; correr antes 05_determinismo.py.")
    orden = [("icsflow_limpio", "ICS-Flow limpio", resultados),
             ("icsflow_todo", "ICS-Flow con eventos", resultados),
             ("westermo_limpio", "Westermo limpio", previos),
             ("westermo_todo", "Westermo con eventos", previos),
             ("qut_control_frequent", "QUT Control todo", previos),
             ("qut_control_frequent_dnp3", "QUT Control solo DNP3", previos)]
    w("%-22s %9s %8s %8s %8s %8s %8s %7s %7s %6s"
      % ("conjunto / definicion", "paquetes", "pps", "disp.", "dt CV",
         "Hn org", "Hn dst", "pares", "Jaccard", "tams"))
    comp = {}
    for clave, etq, fuente in orden:
        r = fuente.get(clave)
        if not r or not r.get("paquetes"):
            continue
        w("%-22s %9d %8.1f %8.2f %8.2f %8.2f %8.2f %7d %7.2f %6d"
          % (etq, r["paquetes"], r["tasa_pps"], r.get("fano", float("nan")),
             r.get("dt_cv", float("nan")), r["Hn_src"], r["Hn_dst"],
             r["pares_distintos"],
             r.get("jaccard_pares_mediana", float("nan")),
             r["tam_distintos"]))
        comp[etq] = {k: r.get(k) for k in
                     ("paquetes", "tasa_pps", "fano", "dt_cv", "Hn_src",
                      "Hn_dst", "Hn_sport", "Hn_dport", "pares_distintos",
                      "jaccard_pares_mediana", "tam_distintos",
                      "autocorr_lag1", "autocorr_pico_lag_s")}
    w("")
    w("disp. = indice de dispersion de la tasa por ventana de 1 s")
    w("(var/media): por debajo de 1 el trafico es mas regular que un proceso")
    w("de Poisson. dt CV = coeficiente de variacion del intervalo entre")
    w("paquetes agregado. Hn = entropia normalizada. tams = cantidad de")
    w("tamanos de paquete distintos.")
    w("")

    comun.escribir("p13_icsflow_determinismo.txt", "\n".join(L))
    with open(os.path.join(comun.SALIDAS,
                           "p13_icsflow_determinismo.json"), "w") as fh:
        json.dump({"icsflow": resultados, "comparacion": comp,
                   "particion": {"t0": t0, "t1": t1,
                                 "corte60_abs": corte_abs,
                                 "corte60_offset": corte_abs - t0,
                                 "paquetes_leidos": leidos}},
                  fh, indent=1, ensure_ascii=False, default=str)

    # ------------------------------ figura ------------------------------
    try:
        plt = comun.estilo_figura()
        etiquetas, fanos, cvs = [], [], []
        for clave, etq, fuente in orden:
            r = fuente.get(clave)
            if not r or "dt_cv" not in r:
                continue
            etiquetas.append(etq.replace(" ", "\n", 1))
            fanos.append(r.get("fano", float("nan")))
            cvs.append(r["dt_cv"])
        x = np.arange(len(etiquetas))
        fig, axes = plt.subplots(1, 2, figsize=(11, 4.4))
        ax = axes[0]
        ax.bar(x, fanos, width=0.55,
               color=["#2E7D32" if f < 1 else "#C62828" for f in fanos])
        ax.axhline(1.0, color="k", ls="--", lw=1.1, label="azar puro")
        for xi, v in zip(x, fanos):
            ax.text(xi, v, " %.2f" % v, ha="center", va="bottom", fontsize=8)
        ax.set_xticks(x)
        ax.set_xticklabels(etiquetas, fontsize=7)
        ax.set_ylabel("indice de dispersion de la tasa (var/media)")
        ax.set_title("Volumen por ventana de 1 s", fontsize=9)
        ax.legend(fontsize=8)
        ax = axes[1]
        ax.bar(x, cvs, width=0.55, color="#4C72B0")
        ax.axhline(1.0, color="k", ls="--", lw=1.1, label="tipo Poisson")
        for xi, v in zip(x, cvs):
            ax.text(xi, v, " %.2f" % v, ha="center", va="bottom", fontsize=8)
        ax.set_xticks(x)
        ax.set_xticklabels(etiquetas, fontsize=7)
        ax.set_ylabel("CV del intervalo entre paquetes")
        ax.set_title("Separacion entre paquetes", fontsize=9)
        ax.legend(fontsize=8)
        fig.suptitle("P13: ICS-Flow frente a Westermo y QUT", fontsize=10)
        fig.savefig(os.path.join(comun.FIGURAS, "p13_regularidad.png"))
        print("[figura] p13_regularidad.png")
    except Exception as e:
        print("figura no generada: %s" % e, file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
