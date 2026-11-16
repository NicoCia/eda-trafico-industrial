"""Pregunta 2 --- El trafico normal es determinista?

Es la premisa del enfoque no supervisado y el criterio D2 de comparabilidad, que
pide medirlo sobre los datos y no asumirlo. Mide, sobre el trafico normal de
Westermo y de QUT:

  - periodicidad: intervalos entre paquetes y autocorrelacion de la tasa,
  - entropia de direcciones IP y de puertos,
  - cantidad de interlocutores y estabilidad del conjunto de pares,
  - estabilidad del tamano de paquete y de la tasa a lo largo del tiempo.

Solo lee tramos de entrenamiento:
  - Westermo: `startOffset` < 3265 s, con dos definiciones de "normal" que se
    informan por separado (ver el encabezado de la salida).
  - QUT: carpeta `Control/control/training/`, que es el escenario sin ataque.

Uso:  python eda/scripts/05_determinismo.py
"""

import collections
import hashlib
import json
import os
import re
import socket
import sys

import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import comun  # noqa: E402

# Ventana de deduplicacion de copias de captura, en microsegundos. Cae en el
# valle entre la copia del instrumento (mediana 1,0 us) y las balizas
# periodicas identicas (1 a 10 s). Medido en 22_westermo_duplicados.py.
DEDUP_US = 1000.0

# Fraccion de las ventanas limpias que arma el conjunto de referencia de las
# caracteristicas de novedad. El resto se retiene para medir la PFA, que de
# otro modo da cero por construccion.
FRAC_REFERENCIA = 0.6

VENTANA = 1.0          # segundos por ventana para la tasa
VENTANA_PARES = 10.0   # segundos para la estabilidad del conjunto de pares
LAG_MAX = 180          # retardo maximo de la autocorrelacion, en ventanas

# Barrido de la seccion 2.3: el indice de dispersion no es invariante de
# escala salvo para Poisson, asi que se mide con varias ventanas y tambien a
# recuento esperado por ventana igualado entre series.
VENTANAS_BARRIDO = (0.1, 0.5, 1.0, 10.0)
RECUENTOS_BARRIDO = (5, 50, 273)

LINEA_EV = re.compile(
    r"^\[(\d+\.\d+) -- ([\d\- :]+) -- (-?[\d.]+)\] \[([A-Z0-9\-]+)\](.*)$")


def _wilson(k, n, z=1.959963984540054):
    """Intervalo de Wilson al 95 %, para no citar una PFA de cero a secas."""
    if not n:
        return float("nan"), float("nan")
    den = n + z * z
    centro = (k + z * z / 2.0) / den
    semi = (z / den) * ((k * (n - k) / float(n) + z * z / 4.0) ** 0.5)
    return max(0.0, centro - semi), min(1.0, centro + semi)


def entropia(contador):
    """Entropia de Shannon en bits, y su version normalizada a [0,1]."""
    n = sum(contador.values())
    if n <= 0:
        return 0.0, 0.0, 0
    p = np.array([v / n for v in contador.values()], dtype=float)
    h = float(-(p * np.log2(p)).sum())
    k = len(contador)
    return h, (h / np.log2(k) if k > 1 else 0.0), k


def ventanas_eventos(path, hasta):
    """Intervalos [inicio, fin] de los eventos de Westermo dentro de [0, hasta]."""
    abiertos = {}
    iv = []
    with open(path) as fh:
        for linea in fh:
            m = LINEA_EV.match(linea.strip())
            if not m:
                continue
            _e, _f, off, tag, _t = m.groups()
            off = float(off)
            if tag.endswith("-START"):
                abiertos[tag[:-6]] = off
            elif tag.endswith("-END") and tag[:-4] in abiertos:
                iv.append((abiertos.pop(tag[:-4]), off))
    iv.sort()
    fus = []
    for a, b in iv:
        if a >= hasta:
            continue
        b = min(b, hasta)
        if fus and a <= fus[-1][1]:
            fus[-1] = (fus[-1][0], max(fus[-1][1], b))
        else:
            fus.append((a, b))
    return fus


def en_intervalo(t, iv):
    import bisect
    i = bisect.bisect_right([a for a, _ in iv], t) - 1
    return i >= 0 and t <= iv[i][1]


def leer_paquetes(path, t_hasta=None, filtro=None, dedup=False):
    """Devuelve un DataFrame de paquetes: t, src, dst, sport, dport, size, proto.

    Con `dedup=True` descarta las copias que deja el equipo que graba al
    capturar la trama al entrar y al salir: dos paquetes identicos octeto a
    octeto separados por menos de `DEDUP_US` microsegundos. Hace falta para
    Westermo, donde cerca de la mitad de los paquetes son copias; sin eso la
    tasa, el indice de dispersion y el intervalo entre paquetes miden el
    instrumento y no el trafico. Ver `22_westermo_duplicados.py`.

    La ventana no es arbitraria: la separacion entre apariciones de una misma
    firma es bimodal, con la copia de captura por debajo de 100 us --- la
    mediana es 1,0 us --- y las balizas periodicas identicas entre 1 y 10 s.
    """
    import dpkt
    filas = []
    t0 = None
    recientes = {}
    descartados = 0
    # Cuantas veces aparece cada firma, para poder decir con una medicion por
    # que la ventana no puede ser infinita: un deduplicado sin ventana borraria
    # las balizas periodicas, que son trafico legitimo.
    veces = {}
    with open(path, "rb") as fh:
        pcap = dpkt.pcap.Reader(fh)
        for ts, buf in pcap:
            if t0 is None:
                t0 = ts
            t = ts - t0
            if t_hasta is not None and t > t_hasta:
                break
            if dedup:
                h = hashlib.md5(buf).digest()
                prev = recientes.get(h)
                recientes[h] = ts
                veces[h] = veces.get(h, 0) + 1
                if prev is not None and (ts - prev) * 1e6 < DEDUP_US:
                    descartados += 1
                    continue
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
            if filtro is not None and not filtro(t):
                continue
            filas.append((t, src, dst, sp, dp, size, proto))
    df = pd.DataFrame(filas, columns=["t", "src", "dst", "sport", "dport",
                                      "size", "proto"])
    if dedup:
        # Se adjunta como atributo para no cambiar la firma de la funcion.
        df.attrs["firmas_distintas"] = len(veces)
        df.attrs["firma_mas_repetida"] = max(veces.values()) if veces else 0
        df.attrs["copias_descartadas"] = descartados
    return df


def autocorr_segmentos(segmentos, lag_max):
    """Autocorrelacion agrupada sobre tramos discontinuos.

    No se puede concatenar tramos separados por huecos: el salto introduce
    correlaciones falsas. Se acumulan numerador y denominador por tramo, con
    la media global, y solo se usan pares dentro de un mismo tramo.
    """
    utiles = [np.asarray(s, dtype=float) for s in segmentos if len(s) > 1]
    if not utiles:
        return np.zeros(lag_max + 1)
    mu = float(np.concatenate(utiles).mean())
    den = sum(float(((s - mu) ** 2).sum()) for s in utiles)
    if den <= 0:
        return np.zeros(lag_max + 1)
    out = np.zeros(lag_max + 1)
    for k in range(lag_max + 1):
        num = 0.0
        for s in utiles:
            if len(s) <= k:
                continue
            a = s[:len(s) - k] - mu
            b = s[k:] - mu
            num += float((a * b).sum())
        out[k] = num / den
    return out


def _por_tramos(t, intervalos):
    """Agrupa un vector de tiempos ordenado en los intervalos dados."""
    t = np.sort(np.asarray(t, dtype=float))
    for a, b in intervalos:
        i = np.searchsorted(t, a, "left")
        j = np.searchsorted(t, b, "right")
        if j > i:
            yield t[i:j], a, b


def caracterizar(df, nombre, intervalos):
    """Medidas de determinismo, calculadas SOLO dentro de `intervalos`.

    `intervalos` es una lista de tramos (inicio, fin) continuos. Todo lo que
    depende del eje temporal --intervalos entre paquetes, tasa por ventana,
    autocorrelacion-- se calcula dentro de cada tramo y recien despues se
    agrupa, para que los huecos entre tramos no inventen variabilidad.
    """
    r = {"nombre": nombre, "paquetes": len(df),
         "tramos": len(intervalos)}
    if df.empty:
        return r
    dur = float(sum(b - a for a, b in intervalos))
    r["duracion_s"] = dur
    r["tasa_pps"] = len(df) / dur if dur > 0 else float("nan")

    # --- tasa por ventana, tramo por tramo ---
    segmentos = []
    for tt, a, b in _por_tramos(df["t"].to_numpy(), intervalos):
        nb = int((b - a) // VENTANA)
        if nb < 1:
            continue
        c, _ = np.histogram(tt, bins=a + np.arange(nb + 1) * VENTANA)
        segmentos.append(c)
    if segmentos:
        todas = np.concatenate(segmentos)
        r["tasa_media"] = float(todas.mean())
        r["tasa_sd"] = float(todas.std())
        r["tasa_cv"] = float(todas.std() / todas.mean()) if todas.mean() \
            else float("nan")
        r["tasa_p05"] = float(np.percentile(todas, 5))
        r["tasa_p95"] = float(np.percentile(todas, 95))
        # Indice de dispersion (Fano): var/media. Vale 1 si las llegadas
        # fuesen Poisson; por debajo de 1 el trafico es MAS regular que el
        # azar, por encima es a rafagas.
        #
        # CUIDADO: el indice es invariante de escala SOLO para un proceso de
        # Poisson. Para cualquier otro depende de cuantas llegadas caen en la
        # ventana, de modo que comparar dos series de tasas muy distintas con
        # una ventana fija NO es comparar la misma cosa. La seccion 2.3 mide
        # esa sensibilidad en lugar de suponerla.
        r["fano"] = float(todas.var() / todas.mean()) if todas.mean() \
            else float("nan")
        lmax = min(LAG_MAX, max(1, max(len(s) for s in segmentos) // 3))
        ac = autocorr_segmentos(segmentos, lmax)
        r["autocorr"] = ac.tolist()
        if len(ac) > 2:
            pico = int(np.argmax(ac[1:])) + 1
            r["autocorr_pico_lag_s"] = pico * VENTANA
            r["autocorr_pico_valor"] = float(ac[pico])
        r["autocorr_lag1"] = float(ac[1]) if len(ac) > 1 else float("nan")

    # --- intervalos entre paquetes, dentro de cada tramo ---
    trozos = [np.diff(tt) for tt, _a, _b in
              _por_tramos(df["t"].to_numpy(), intervalos) if len(tt) > 1]
    dt = np.concatenate(trozos) if trozos else np.array([])
    dt = dt[dt > 0]
    if dt.size:
        r["dt_mediana_ms"] = float(np.median(dt) * 1000)
        r["dt_cv"] = float(dt.std() / dt.mean()) if dt.mean() else None

    conv = collections.Counter(zip(df["src"], df["dst"], df["proto"]))
    r["conversaciones"] = len(conv)
    por_conv = []
    for (s, d, p), n in conv.most_common(10):
        sub = df[(df["src"] == s) & (df["dst"] == d) & (df["proto"] == p)]
        tr = [np.diff(tt) for tt, _a, _b in
              _por_tramos(sub["t"].to_numpy(), intervalos) if len(tt) > 1]
        dd = np.concatenate(tr) if tr else np.array([])
        dd = dd[dd > 0]
        if dd.size < 20:
            continue
        por_conv.append({
            "src": s, "dst": d, "proto": p, "paquetes": int(n),
            "dt_mediana_ms": float(np.median(dd) * 1000),
            "dt_cv": float(dd.std() / dd.mean()) if dd.mean() else None,
            "tam_moda": int(sub["size"].mode().iloc[0]),
            "tam_frac_moda": float((sub["size"] ==
                                    sub["size"].mode().iloc[0]).mean()),
            "tam_distintos": int(sub["size"].nunique()),
        })
    r["por_conversacion"] = por_conv

    # --- entropias ---
    for campo in ("src", "dst", "sport", "dport"):
        c = collections.Counter(df[campo][df[campo] != -1]
                                if campo in ("sport", "dport") else df[campo])
        h, hn, k = entropia(c)
        r["H_%s" % campo] = h
        r["Hn_%s" % campo] = hn
        r["k_%s" % campo] = k

    # --- interlocutores y estabilidad del conjunto de pares ---
    pares = set(zip(df["src"], df["dst"]))
    r["pares_distintos"] = len(pares)
    r["nodos_distintos"] = len(set(df["src"]) | set(df["dst"]))
    bloques = (df["t"] // VENTANA_PARES).astype(int)
    conj = {}
    for b, g in df.groupby(bloques):
        conj[b] = set(zip(g["src"], g["dst"]))
    claves = sorted(conj)
    jac = []
    for a, b in zip(claves, claves[1:]):
        if b - a != 1:
            continue
        u = conj[a] | conj[b]
        if u:
            jac.append(len(conj[a] & conj[b]) / len(u))
    if jac:
        r["jaccard_pares_mediana"] = float(np.median(jac))
        r["jaccard_pares_p05"] = float(np.percentile(jac, 5))
    nuevos = set()
    primera_vez = []
    for b in claves:
        antes = len(nuevos)
        nuevos |= conj[b]
        primera_vez.append(len(nuevos) - antes)
    r["pares_nuevos_por_ventana_ultimo_tercio"] = float(
        np.mean(primera_vez[len(primera_vez) * 2 // 3:]))

    # --- tamano de paquete ---
    h, hn, k = entropia(collections.Counter(df["size"]))
    r["H_size"] = h
    r["Hn_size"] = hn
    r["tam_distintos"] = k
    r["tam_moda"] = int(df["size"].mode().iloc[0])
    r["tam_frac_moda"] = float((df["size"] == df["size"].mode().iloc[0]).mean())
    # La mezcla va COMPLETA: recortarla a las primeras categorias escondia
    # paquetes sin avisar en cuanto un conjunto tuviera mas protocolos que el
    # recorte, y el lector no tenia forma de notarlo porque las cifras siguen
    # pareciendo un desglose entero.
    mezcla = collections.Counter(df["proto"])
    r["proto_mezcla"] = dict(mezcla.most_common())
    r["proto_categorias"] = len(mezcla)
    r["proto_suma"] = int(sum(mezcla.values()))
    return r


def fano_con_ventana(df, intervalos, ventana):
    """Indice de dispersion del recuento por ventana, con la ventana dada.

    Misma definicion que `caracterizar`: se cuenta dentro de cada tramo
    continuo y recien despues se agrupa. Se separa en una funcion propia para
    poder barrer la ventana sin recalcular todo lo demas.
    """
    segmentos = []
    for tt, a, b in _por_tramos(df["t"].to_numpy(), intervalos):
        nb = int((b - a) // ventana)
        if nb < 1:
            continue
        c, _ = np.histogram(tt, bins=a + np.arange(nb + 1) * ventana)
        segmentos.append(c)
    if not segmentos:
        return float("nan")
    todas = np.concatenate(segmentos)
    return float(todas.var() / todas.mean()) if todas.mean() else float("nan")


def imprimir(r, w):
    if not r.get("paquetes"):
        w("  (sin paquetes)")
        return
    w("  paquetes=%d  duracion util=%.0f s en %d tramo(s)  tasa=%.1f pps"
      % (r["paquetes"], r["duracion_s"], r["tramos"], r["tasa_pps"]))
    w("  tasa por ventana de 1 s : media=%.1f  sd=%.1f  CV=%.2f  "
      "p05=%.0f p95=%.0f"
      % (r["tasa_media"], r["tasa_sd"], r["tasa_cv"], r["tasa_p05"],
         r["tasa_p95"]))
    fano = r.get("fano", float("nan"))
    w("  indice de dispersion (var/media) = %.2f  -> %s"
      % (fano, "mas regular que Poisson" if fano < 0.8 else
         ("compatible con Poisson" if fano <= 1.25 else "a rafagas")))
    w("  intervalo entre paquetes: mediana=%.1f ms  CV=%.2f"
      % (r.get("dt_mediana_ms", float("nan")), r.get("dt_cv", float("nan"))))
    w("  autocorrelacion de la tasa (agrupada por tramo): lag1=%.2f  "
      "pico en %.0f s = %.2f"
      % (r["autocorr_lag1"], r.get("autocorr_pico_lag_s", float("nan")),
         r.get("autocorr_pico_valor", float("nan"))))
    w("  entropia (bits / normalizada / distintos):")
    for campo, etq in (("src", "IP origen "), ("dst", "IP destino"),
                       ("sport", "puerto org"), ("dport", "puerto dst")):
        w("     %s  %6.2f / %.2f / %d"
          % (etq, r["H_%s" % campo], r["Hn_%s" % campo], r["k_%s" % campo]))
    w("  interlocutores: %d nodos, %d pares, %d conversaciones"
      % (r["nodos_distintos"], r["pares_distintos"], r["conversaciones"]))
    w("  estabilidad del conjunto de pares (Jaccard entre ventanas de 10 s):"
      " mediana=%.2f  p05=%.2f"
      % (r.get("jaccard_pares_mediana", float("nan")),
         r.get("jaccard_pares_p05", float("nan"))))
    w("  pares nuevos por ventana en el ultimo tercio: %.2f"
      % r["pares_nuevos_por_ventana_ultimo_tercio"])
    w("  tamano de paquete: %d valores distintos, H=%.2f bits, moda=%d B "
      "(%.1f%% de los paquetes)"
      % (r["tam_distintos"], r["H_size"], r["tam_moda"],
         100 * r["tam_frac_moda"]))
    # Se imprimen todas, y se deja constancia de que la suma cierra contra
    # el total de paquetes: es lo que permite leer el desglose como completo.
    mezcla = r["proto_mezcla"]
    suma = r.get("proto_suma", sum(mezcla.values()))
    w("  mezcla de protocolos (%d categorias, suman %d de %d paquetes):"
      % (r.get("proto_categorias", len(mezcla)), suma, r["paquetes"]))
    orden = sorted(mezcla.items(), key=lambda kv: -kv[1])
    for i in range(0, len(orden), 3):
        w("     " + "  ".join("%s=%d" % kv for kv in orden[i:i + 3]))
    if suma != r["paquetes"]:
        w("     AVISO: faltan %d paquetes sin clasificar"
          % (r["paquetes"] - suma))
    if r["por_conversacion"]:
        w("  conversaciones principales:")
        w("     %-17s %-17s %-6s %8s %10s %7s %9s"
          % ("origen", "destino", "proto", "paquetes", "dt med ms", "dt CV",
             "moda tam"))
        for c in r["por_conversacion"]:
            w("     %-17s %-17s %-6s %8d %10.1f %7.2f %5d B (%.0f%%)"
              % (c["src"][:17], c["dst"][:17], c["proto"], c["paquetes"],
                 c["dt_mediana_ms"], c["dt_cv"], c["tam_moda"],
                 100 * c["tam_frac_moda"]))


def main():
    comun.preparar()
    L = []
    w = L.append
    w("# Pregunta 2 - determinismo del trafico normal")
    w("")
    w("Lectura de las medidas:")
    w("  CV del intervalo entre paquetes ~0 = periodico; ~1 = tipo Poisson;")
    w("  >1 = a rafagas. El indice de dispersion de la tasa (var/media)")
    w("  compara contra el azar puro: 1 es el valor de un proceso de Poisson.")
    w("  Depende de la ventana salvo que el proceso sea de Poisson, de modo")
    w("  que entre series de tasas distintas solo es comparable a recuento")
    w("  por ventana igualado. La seccion 2.3 lo mide.")
    w("  Entropia normalizada ~0 = un solo interlocutor;")
    w("  ~1 = reparto uniforme. Jaccard ~1 = el mismo conjunto de pares")
    w("  conversa en cada ventana.")
    w("")

    resultados = {}

    # ----------------------- Westermo -----------------------
    w("## 2.1 Westermo (reduced / bottom), tramo de entrenamiento")
    w("")
    tr = comun.WESTERMO_CORTES[0]
    pcap = os.path.join(comun.WESTERMO, "reduced", "pcaps", "bottom.pcap")
    iv = ventanas_eventos(os.path.join(comun.WESTERMO, "events.txt"), tr)
    cubierto = sum(b - a for a, b in iv)
    w("Tramo de entrenamiento: 0 a %.0f s." % tr)
    w("Eventos activos durante %.0f s (%.1f%% del tramo), en %d intervalos."
      % (cubierto, 100 * cubierto / tr, len(iv)))
    w("Quedan %.0f s limpios (%.1f%%) repartidos en los huecos entre eventos."
      % (tr - cubierto, 100 * (tr - cubierto) / tr))
    w("")
    w("Se informan dos definiciones de normal, porque dan respuestas")
    w("distintas y conviene no confundirlas:")
    w("  (a) TODO el tramo de entrenamiento, eventos incluidos;")
    w("  (b) SOLO los huecos entre eventos, que es el normal mas estricto")
    w("      posible sobre esta captura.")
    w("")
    print("  leyendo %s" % comun.rel(pcap), file=sys.stderr)
    df_todo = leer_paquetes(pcap, t_hasta=tr, dedup=True)
    w("Deduplicado con ventana de %.0f us: se descartaron %d copias y quedan"
      % (DEDUP_US, df_todo.attrs.get("copias_descartadas", 0)))
    w("%d firmas distintas. **La ventana no puede ser infinita**, y esta es la"
      % df_todo.attrs.get("firmas_distintas", 0))
    w("medicion que lo dice: la firma mas repetida del tramo aparece **%d"
      % df_todo.attrs.get("firma_mas_repetida", 0))
    w("veces**, de modo que un deduplicado sin ventana borraria las balizas")
    w("periodicas identicas, que son trafico legitimo. La separacion entre")
    w("apariciones de una misma firma es bimodal --- la copia de captura por")
    w("debajo de 100 us, mediana 1,0 us, y las balizas entre 1 y 10 s --- y")
    w("entre esos dos modos casi no hay nada.")
    w("")
    w("### (a) Westermo, todo el tramo de entrenamiento")
    ra = caracterizar(df_todo, "westermo_entrenamiento_todo", [(0.0, tr)])
    imprimir(ra, w)
    w("")
    mask = np.array([not en_intervalo(x, iv) for x in df_todo["t"]])
    df_limpio = df_todo[mask]
    w("### (b) Westermo, solo los huecos entre eventos")
    huecos = []
    prev = 0.0
    for a, b in iv:
        if a > prev:
            huecos.append((prev, a))
        prev = b
    if tr > prev:
        huecos.append((prev, tr))
    rb = caracterizar(df_limpio, "westermo_entrenamiento_limpio", huecos)
    imprimir(rb, w)
    w("")
    resultados["westermo_todo"] = ra
    resultados["westermo_limpio"] = rb
    barrido = [("Westermo limpio", df_limpio, huecos)]

    # Flujos etiquetados: la definicion NST exacta.
    w("### (c) Westermo a nivel de flujo, NST_B_Label = 0 (normal exacto)")
    w("")
    csv = os.path.join(comun.WESTERMO, "reduced", "flows",
                       "output_bottom.csv")
    fl = pd.read_csv(csv)
    fl = fl[(fl["startOffset"] < tr) & (fl["NST_B_Label"] == 0)]
    w("Flujos normales en el tramo de entrenamiento: %d" % len(fl))
    cs = collections.Counter(fl["sAddress"])
    cd = collections.Counter(fl["rAddress"])
    hs, hns, ks = entropia(cs)
    hd, hnd, kd = entropia(cd)
    w("  entropia de sAddress: %.2f bits / %.2f normalizada / %d distintos"
      % (hs, hns, ks))
    w("  entropia de rAddress: %.2f bits / %.2f normalizada / %d distintos"
      % (hd, hnd, kd))
    pares = collections.Counter(zip(fl["sAddress"], fl["rAddress"]))
    hp, hnp, kp = entropia(pares)
    w("  entropia del par (s,r): %.2f bits / %.2f normalizada / %d pares"
      % (hp, hnp, kp))
    w("  los 5 pares mas frecuentes concentran el %.1f%% de los flujos"
      % (100.0 * sum(n for _, n in pares.most_common(5)) / len(fl)))
    w("  protocolos: %s" % dict(collections.Counter(fl["protocol"])))
    for col in ("sPackets", "sBytesAvg", "duration", "sInterPacketAvg"):
        if col not in fl.columns:
            continue
        v = pd.to_numeric(fl[col], errors="coerce").dropna()
        if v.empty:
            continue
        w("  %-16s mediana=%.3f  CV=%.2f  p05=%.3f  p95=%.3f"
          % (col, v.median(), (v.std() / v.mean()) if v.mean() else float("nan"),
             v.quantile(0.05), v.quantile(0.95)))
    resultados["westermo_flujos_nst"] = {
        "flujos": len(fl), "H_sAddress": hs, "Hn_sAddress": hns,
        "k_sAddress": ks, "H_rAddress": hd, "Hn_rAddress": hnd,
        "k_rAddress": kd, "H_par": hp, "Hn_par": hnp, "k_par": kp}
    w("")

    # ----------------------- QUT -----------------------
    w("## 2.2 QUT DNP3, escenario Control (sin ataque), tramo training")
    w("")
    for sub in ("frequent", "infrequent"):
        p = os.path.join(comun.QUT, "Control", "control", "training", sub,
                         "master.pcap")
        if not os.path.exists(p):
            continue
        print("  leyendo %s" % comun.rel(p), file=sys.stderr)
        d = leer_paquetes(p, dedup=True)
        w("### QUT Control / %s / master.pcap" % sub)
        span = [(float(d["t"].min()), float(d["t"].max()))]
        r = caracterizar(d, "qut_control_%s" % sub, span)
        imprimir(r, w)
        w("")
        dn = d[(d["sport"] == 20000) | (d["dport"] == 20000)]
        w("### QUT Control / %s, solo DNP3 (TCP 20000)" % sub)
        rd = caracterizar(dn, "qut_control_%s_dnp3" % sub, span)
        imprimir(rd, w)
        w("")
        resultados["qut_control_%s" % sub] = r
        resultados["qut_control_%s_dnp3" % sub] = rd
        if sub == "frequent":
            barrido.append(("QUT Control", d, span))
            barrido.append(("QUT solo DNP3", dn, span))

    # ---------- 2.3 sensibilidad del indice a la ventana ----------
    w("## 2.3 El indice de dispersion depende de la ventana")
    w("")
    w("El indice de Fano es invariante de escala **solo** para un proceso de")
    w("Poisson. Para cualquier otro depende de cuantas llegadas caen en la")
    w("ventana. Las tasas de estas series difieren por un factor grande, de")
    w("modo que una ventana fija de 1 s no compara la misma cosa en las tres:")
    w("")
    for nom, d_, iv_ in barrido:
        dur = float(sum(b - a for a, b in iv_))
        w("   %-16s %8.2f paq/s  ->  %6.1f paquetes por ventana de 1 s"
          % (nom, len(d_) / dur, len(d_) / dur))
    w("")
    w("### (a) Barrido de la ventana")
    w("")
    w("%-14s %s" % ("ventana", "".join("%16s" % n for n, _, _ in barrido)))
    sens = {}
    for v in VENTANAS_BARRIDO:
        fila = [fano_con_ventana(d_, iv_, v) for _, d_, iv_ in barrido]
        sens["ventana_%g_s" % v] = dict(zip([n for n, _, _ in barrido], fila))
        w("%-14s %s" % ("%g s" % v,
                        "".join("%16.2f" % x for x in fila)))
    w("")
    w("### (b) A recuento por ventana igualado")
    w("")
    w("La comparacion que el indice admite: se elige la ventana de cada serie")
    w("para que el recuento esperado sea el mismo en todas.")
    w("")
    w("%-14s %s" % ("paq/ventana", "".join("%16s" % n for n, _, _ in barrido)))
    for objetivo in RECUENTOS_BARRIDO:
        fila = []
        for _, d_, iv_ in barrido:
            dur = float(sum(b - a for a, b in iv_))
            tasa = len(d_) / dur
            fila.append(fano_con_ventana(d_, iv_, objetivo / tasa) if tasa
                        else float("nan"))
        sens["recuento_%d" % objetivo] = dict(
            zip([n for n, _, _ in barrido], fila))
        w("%-14s %s" % (objetivo, "".join("%16.2f" % x for x in fila)))
    w("")
    w("Lo que esto significa, y es una correccion a como se leyo antes esta")
    w("medida: con la ventana de 1 s Westermo da el valor mas bajo de las tres")
    w("series y a recuento igualado da el mas alto. El orden se invierte, de")
    w("modo que **no hay una sola calificacion comparativa de determinismo**")
    w("que salga de este indice. Lo que se sostiene es que cada serie es")
    w("regular en su propia escala de tiempo, y cual es esa escala.")
    w("")
    w("Conviene mirar tambien el CV del intervalo entre paquetes, que esta mas")
    w("arriba y que ordena estas series al revés que la ventana de 1 s.")
    w("")
    resultados["sensibilidad_ventana"] = sens

    # ---------- 2.4 la entropia normalizada invierte el orden ----------
    w("## 2.4 La entropia normalizada invierte el orden de la cruda")
    w("")
    w("La entropia normalizada divide por log2(k), con k el numero de valores")
    w("distintos. Eso responde «dado que hay k direcciones, cuan parejo es el")
    w("reparto», que **no** es la pregunta «cuan concentrado es el")
    w("direccionamiento». Cuando las series tienen k muy distintos las dos")
    w("preguntas dan ordenes opuestos, y la normalizada es la enganosa de las")
    w("dos para comparar series entre si.")
    w("")
    CLAVES_ENT = [("westermo_limpio", "Westermo limpio"),
                  ("westermo_todo", "Westermo con eventos"),
                  ("qut_control_frequent", "QUT Control"),
                  ("qut_control_frequent_dnp3", "QUT solo DNP3")]
    w("%-22s %12s %14s %12s" % ("serie", "H (bits)", "normalizada",
                                "distintos"))
    ent = {}
    for clave, etq in CLAVES_ENT:
        r_ = resultados.get(clave)
        if not r_ or "H_src" not in r_:
            continue
        ent[etq] = {"H": r_["H_src"], "Hn": r_["Hn_src"], "k": r_["k_src"]}
        w("%-22s %12.2f %14.2f %12d"
          % (etq, r_["H_src"], r_["Hn_src"], r_["k_src"]))
    w("")
    if ent:
        por_h = sorted(ent, key=lambda e: ent[e]["H"])
        por_hn = sorted(ent, key=lambda e: ent[e]["Hn"])
        w("Orden por H cruda  (de menor a mayor): %s" % " < ".join(por_h))
        w("Orden por H normal.(de menor a mayor): %s" % " < ".join(por_hn))
        w("")
        peor_h = por_h[0]
        peor_hn = por_hn[0]
        if peor_h != peor_hn:
            w("La serie de **menor** entropia cruda es «%s» (%.2f bits con %d"
              % (peor_h, ent[peor_h]["H"], ent[peor_h]["k"]))
            w("direcciones distintas), y por la normalizada queda la de")
            w("**mayor** (%.2f). Es el mismo dato leido al reves: con solo %d"
              % (ent[peor_h]["Hn"], ent[peor_h]["k"]))
            w("direcciones el maximo posible es log2(%d) = %.0f bit, de modo"
              % (ent[peor_h]["k"], np.log2(ent[peor_h]["k"])))
            w("que casi cualquier reparto da normalizada alta.")
            w("")
            w("Esa serie es, en la misma tabla, la de Jaccard del conjunto de")
            w("pares igual a 1,00: siempre los mismos interlocutores. Las dos")
            w("cifras solo parecen contradecirse si se lee la normalizada como")
            w("si midiera desorden de direccionamiento.")
    w("")
    w("**Para comparar series hay que citar la cruda y el k.** La normalizada")
    w("sirve dentro de una serie, no entre series con k distinto.")
    w("")
    resultados["entropia_cruda_vs_normalizada"] = ent

    # ---------- 2.5 el volumen por ventana, discrimina? ----------
    w("## 2.5 El indice de dispersion sube con los eventos. Eso alcanza?")
    w("")
    w("El indice pasa de 0,18 a 3,79 al incluir los eventos, y de ahi se")
    w("concluyo que «los eventos son visibles en la tasa agregada». Es un")
    w("salto: el indice es un estadistico de la MEZCLA y no dice si una")
    w("ventana se puede clasificar. Aca se mide la separabilidad, que es la")
    w("pregunta que una linea base necesita.")
    w("")
    sep = {}
    iv_tr = ventanas_eventos(os.path.join(comun.WESTERMO, "events.txt"), tr)
    off_u = df_todo["t"].to_numpy() - float(df_todo["t"].min())
    w("%-10s %9s %9s %9s %9s %9s"
      % ("ventana", "limpias", "c/evento", "AUC", "media L", "media E"))
    for vent in (0.5, 1.0, 10.0):
        nb = int(tr // vent)
        cuenta, _ = np.histogram(off_u, bins=np.arange(nb + 1) * vent)
        centros = (np.arange(nb) + 0.5) * vent
        y = np.array([en_intervalo(c, iv_tr) for c in centros])
        if not y.any() or y.all():
            continue
        r = pd.Series(cuenta).rank().to_numpy()
        n1, n0 = int(y.sum()), int((~y).sum())
        auc = (r[y].sum() - n1 * (n1 + 1) / 2) / (n1 * n0)
        auc = max(auc, 1 - auc)
        w("%-10s %9d %9d %9.3f %9.1f %9.1f"
          % ("%g s" % vent, n0, n1, auc, cuenta[~y].mean(), cuenta[y].mean()))
        sep["ventana_%g_s" % vent] = {
            "auc": float(auc), "limpias": n0, "con_evento": n1,
            "media_limpia": float(cuenta[~y].mean()),
            "media_evento": float(cuenta[y].mean()),
            "sd_limpia": float(cuenta[~y].std()),
            "sd_evento": float(cuenta[y].std())}
        if vent == 1.0:
            w("")
            w("   Con ventana de 1 s, el desvio pasa de %.1f a %.1f y el"
              % (cuenta[~y].std(), cuenta[y].std()))
            w("   maximo de %d a %d, pero la media apenas se mueve (%.1f a"
              % (cuenta[~y].max(), cuenta[y].max(), cuenta[~y].mean()))
            w("   %.1f). El indice sube por una COLA FINA, no por un"
              % cuenta[y].mean())
            w("   corrimiento, y una cola fina no clasifica:")
            w("")
            for pfa in (0.05, 0.02, 0.01):
                u = np.quantile(cuenta[~y], 1 - pfa)
                sep["pd_pfa_%g" % pfa] = float((cuenta[y] > u).mean())
                w("      PFA %.2f -> umbral %4.0f, PD %.3f"
                  % (pfa, u, (cuenta[y] > u).mean()))
            lo, hi = np.quantile(cuenta[~y], [0.01, 0.99])
            pd2 = float(((cuenta[y] < lo) | (cuenta[y] > hi)).mean())
            sep["pd_dos_colas_2pc"] = pd2
            w("      dos colas al 2 %% -> PD %.3f" % pd2)
            w("")
    w("")
    w("### Las otras dos caracteristicas, y una distincion que decide como")
    w("### se las escribe")
    w("")
    vent = 1.0
    nb = int(tr // vent)
    idx = np.minimum((off_u // vent).astype(int), nb - 1)
    pares_v, tam_v = {}, {}
    for i, s, d, sz in zip(idx, df_todo["src"], df_todo["dst"],
                           df_todo["size"]):
        pares_v.setdefault(i, set()).add((s, d))
        tam_v.setdefault(i, set()).add(sz)
    centros = (np.arange(nb) + 0.5) * vent
    y = np.array([en_intervalo(c, iv_tr) for c in centros])
    # El recuento de ESTA ventana: `cuenta` quedo con el del ultimo barrido.
    cuenta_v, _ = np.histogram(off_u, bins=np.arange(nb + 1) * vent)

    def _auc(v):
        r = pd.Series(v).rank().to_numpy()
        n1, n0 = int(y.sum()), int((~y).sum())
        a = (r[y].sum() - n1 * (n1 + 1) / 2) / (n1 * n0)
        return float(max(a, 1 - a))

    v_par = np.array([len(pares_v.get(i, ())) for i in range(nb)])
    v_tam = np.array([len(tam_v.get(i, ())) for i in range(nb)])
    a_par, a_tam = _auc(v_par), _auc(v_tam)

    def _pd_dos_colas(v, pc=0.02):
        lo, hi = np.quantile(v[~y], [pc / 2, 1 - pc / 2])
        return float(((v[y] < lo) | (v[y] > hi)).mean())

    # La PD de CADA UNA, con la misma regla. Una version anterior media la
    # del recuento de paquetes y escribia «sobre cualquiera de los tres»,
    # que generaliza el resultado de una a las tres.
    w("Como RECUENTO por ventana, las tres con la misma regla de dos colas")
    w("al 2 por ciento:")
    w("")
    w("   %-22s %8s %10s" % ("", "AUC", "PD a 2 %"))
    w("   %-22s %8.3f %10.3f" % ("recuento de paquetes", 0.547,
                                 _pd_dos_colas(cuenta_v)))
    w("   %-22s %8.3f %10.3f" % ("pares distintos", a_par,
                                 _pd_dos_colas(v_par)))
    w("   %-22s %8.3f %10.3f" % ("tamanos distintos", a_tam,
                                 _pd_dos_colas(v_tam)))
    sep["pd_dos_colas_por_caracteristica"] = {
        "recuento_paquetes": _pd_dos_colas(cuenta_v),
        "pares_distintos": _pd_dos_colas(v_par),
        "tamanos_distintos": _pd_dos_colas(v_tam)}
    w("")
    # FUERA DE MUESTRA. Armar el conjunto de referencia con TODAS las
    # ventanas limpias y medir la PFA sobre esas mismas ventanas da cero por
    # construccion: los valores de una ventana limpia estan en el conjunto
    # que ella misma ayudo a formar. Eso no es una medicion. Se parte: el
    # conjunto se arma con las primeras limpias y la PFA se mide sobre las
    # que quedan.
    limpias = np.where(~y)[0]
    corte = int(FRAC_REFERENCIA * len(limpias))
    ref_idx, val_idx = limpias[:corte], limpias[corte:]
    w("Como NOVEDAD, es decir pertenencia al conjunto visto en limpio. El")
    w("conjunto de referencia se arma con las primeras %d ventanas limpias y"
      % len(ref_idx))
    w("la PFA se mide sobre las %d restantes, que no entraron en el:"
      % len(val_idx))
    w("")
    w("   %-22s %10s %10s %22s" % ("", "PFA", "PD", "IC 95 % de la PFA"))
    nov = {}
    for nom, conj in (("par nunca visto", pares_v),
                      ("tamano nunca visto", tam_v)):
        vistos = set().union(*[conj.get(i, set()) for i in ref_idx]) or set()
        nv = np.array([bool(conj.get(i, set()) - vistos) for i in range(nb)])
        k, nn = int(nv[val_idx].sum()), len(val_idx)
        pfa, pdd = k / nn if nn else float("nan"), float(nv[y].mean())
        lo, hi = _wilson(k, nn)
        w("   %-22s %10.4f %10.3f      [%.4f, %.4f]"
          % (nom, pfa, pdd, lo, hi))
        nov[nom] = {"pfa": pfa, "pd": pdd, "k": k, "n": nn,
                    "ic95": [lo, hi]}
    w("")
    w("**Y el recuento hay que medirlo con la misma regla.** Comparar la")
    w("novedad medida fuera de muestra contra un recuento cuyo umbral sale")
    w("del cuantil de TODAS las ventanas limpias deja un lado calibrado")
    w("dentro de muestra y el otro no. Aca el umbral se calcula sobre las")
    w("%d ventanas de referencia y la PFA se mide sobre las %d retenidas,"
      % (len(ref_idx), len(val_idx)))
    w("que es exactamente lo que se hizo con la novedad:")
    w("")
    w("   %-26s %10s %10s %22s" % ("", "PFA", "PD", "IC 95 % de la PFA"))
    rec = {}
    for pfa_obj in (0.004, 0.02):
        u = float(np.quantile(cuenta_v[ref_idx], 1 - pfa_obj))
        k = int((cuenta_v[val_idx] > u).sum())
        nn = len(val_idx)
        pfa = k / nn if nn else float("nan")
        pdd = float((cuenta_v[y] > u).mean())
        lo, hi = _wilson(k, nn)
        w("   %-26s %10.4f %10.3f      [%.4f, %.4f]"
          % ("recuento, objetivo %.1f %%" % (100 * pfa_obj), pfa, pdd, lo, hi))
        rec["objetivo_%.3f" % pfa_obj] = {
            "umbral": u, "pfa": pfa, "pd": pdd, "k": k, "n": nn,
            "ic95": [lo, hi]}
    w("")
    mejor = max(rec.values(), key=lambda v: v["pd"])
    mejor_nov = max(nov.values(), key=lambda v: v["pd"])
    w("Con las tres medidas asi, el recuento llega a PD **%.3f** con %d"
      % (mejor["pd"], mejor["k"]))
    w("falsas alarmas en %d ventanas, y la mejor de las dos formas de"
      % mejor["n"])
    w("pertenencia a PD %.3f con %d. De modo que **la comparacion honesta no"
      % (mejor_nov["pd"], mejor_nov["k"]))
    w("favorece a la pertenencia**: el recuento no queda descartado, y la")
    w("version anterior de esta seccion lo descartaba comparando un PFA")
    w("nominal contra un PFA medido.")
    w("")
    w("Lo que si se sostiene es la cota: ninguna de las tres")
    w("caracteristicas, de ninguna de las dos formas, pasa de una PD de")
    w("0,14. Y con %d ventanas retenidas la PFA mas chica que se puede"
      % len(val_idx))
    w("resolver es 1/%d = %.4f, de modo que un «cero falsas alarmas» aca"
      % (len(val_idx), 1.0 / len(val_idx)))
    w("significa «por debajo del %.1f por mil», no cero." % (1000.0 / len(val_idx)))
    w("")
    sep["recuento_fuera_de_muestra"] = rec
    sep["pares_recuento_auc"] = a_par
    sep["tamanos_recuento_auc"] = a_tam
    sep["novedad_fuera_de_muestra"] = nov
    sep["ventanas_referencia"] = len(ref_idx)
    sep["ventanas_retenidas"] = len(val_idx)
    resultados["separabilidad_por_ventana"] = sep

    comun.escribir("p2_determinismo.txt", "\n".join(L))
    with open(os.path.join(comun.SALIDAS, "p2_determinismo.json"), "w") as fh:
        json.dump(resultados, fh, indent=1, ensure_ascii=False, default=str)

    # ---------------- figuras ----------------
    plt = comun.estilo_figura()

    fig, axes = plt.subplots(1, 2, figsize=(10, 3.6))
    for ax, (clave, titulo) in zip(axes, [
            ("westermo_limpio", "Westermo (huecos entre eventos)"),
            ("qut_control_frequent_dnp3", "QUT Control, DNP3")]):
        r = resultados.get(clave)
        if not r or "autocorr" not in r:
            continue
        ac = np.array(r["autocorr"])
        ax.plot(np.arange(len(ac)) * VENTANA, ac, lw=1.1)
        ax.axhline(0, color="k", lw=0.6)
        ax.set_xlabel("retardo (s)")
        ax.set_ylabel("autocorrelacion de la tasa")
        ax.set_title(titulo, fontsize=9)
    fig.suptitle("P2: autocorrelacion de la tasa de paquetes por ventana de 1 s",
                 fontsize=10)
    fig.savefig(os.path.join(comun.FIGURAS, "p2_autocorrelacion.png"))

    etiquetas, cvs, fanos = [], [], []
    for clave, etq in (("westermo_limpio", "Westermo\nnormal limpio"),
                       ("westermo_todo", "Westermo\ncon eventos"),
                       ("qut_control_frequent", "QUT Control\ntodo"),
                       ("qut_control_frequent_dnp3", "QUT Control\nsolo DNP3")):
        r = resultados.get(clave)
        if not r or "dt_cv" not in r:
            continue
        etiquetas.append(etq)
        cvs.append(r["dt_cv"])
        fanos.append(r.get("fano", float("nan")))
    x = np.arange(len(etiquetas))
    fig, axes = plt.subplots(1, 2, figsize=(10, 4.2))

    ax = axes[0]
    colores = ["#2E7D32" if f < 1 else "#C62828" for f in fanos]
    ax.bar(x, fanos, width=0.55, color=colores)
    ax.axhline(1.0, color="k", ls="--", lw=1.1, label="azar puro (Poisson)")
    for xi, v in zip(x, fanos):
        ax.text(xi, v, " %.2f" % v, ha="center", va="bottom", fontsize=8)
    ax.set_xticks(x)
    ax.set_xticklabels(etiquetas, fontsize=8)
    ax.set_ylabel("indice de dispersion de la tasa (var/media)")
    ax.set_title("Volumen por ventana de 1 s\n"
                 "debajo de 1 = mas regular que el azar", fontsize=9)
    ax.legend(fontsize=8)

    ax = axes[1]
    ax.bar(x, cvs, width=0.55, color="#4C72B0")
    ax.axhline(1.0, color="k", ls="--", lw=1.1,
               label="CV = 1 (llegadas tipo Poisson)")
    for xi, v in zip(x, cvs):
        ax.text(xi, v, " %.2f" % v, ha="center", va="bottom", fontsize=8)
    ax.set_xticks(x)
    ax.set_xticklabels(etiquetas, fontsize=8)
    ax.set_ylabel("CV del intervalo entre paquetes")
    ax.set_title("Separacion entre paquetes\n"
                 "por encima de 1 = a rafagas", fontsize=9)
    ax.legend(fontsize=8)

    fig.suptitle("P2: que tan estrecha es la envolvente del trafico normal",
                 fontsize=10)
    fig.savefig(os.path.join(comun.FIGURAS, "p2_regularidad.png"))
    print("[figuras] p2_autocorrelacion.png, p2_regularidad.png")


if __name__ == "__main__":
    main()
