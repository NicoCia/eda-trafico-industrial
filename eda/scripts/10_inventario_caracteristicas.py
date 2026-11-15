"""Inventario de las caracteristicas que publica cada conjunto.

Responde la pregunta por las caracteristicas de cada conjunto, campo por
campo. Las cinco preguntas del brief original (`eda/INSTRUCCIONES.md`) no
cubren esto --- miden determinismo, etiquetas, tamano de muestra y deriva, no el
esquema --- de modo que el inventario se mide aqui.

Para cada archivo publicado de cada uno de los cinco conjuntos se enumera campo
por campo:

  - el nombre tal como lo publica el archivo;
  - el tipo medido sobre los datos (no el declarado);
  - la unidad y **de donde sale esa unidad**: verificada por una identidad
    numerica que este script comprueba, transcripta de un documento publicado
    del conjunto, o no declarada en ninguna parte --- en ese ultimo caso se da
    el rango medido y nada mas;
  - el nivel de agregacion del registro que lo contiene (paquete, flujo,
    ventana, transaccion, registro de proceso o evento), medido sobre el
    archivo;
  - cobertura (filas con valor), cardinalidad y rango.

**Particiones.** Solo se lee el tramo de entrenamiento de cada conjunto, con
los cortes fijados en `eda/INSTRUCCIONES.md` y, para ICS-Flow, con la misma
regla del 60 / 20 / 20 sobre `start` que usa `06_icsflow_escrituras.py`. De los
archivos de prueba no se lee ninguna fila: solo la cabecera, que es formato y
no distribucion.

Uso:  python eda/scripts/10_inventario_caracteristicas.py
"""

import collections
import csv
import glob
import json
import os
import re
import sys

import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import comun  # noqa: E402

ICSFLOW = os.path.join(comun.DATOS, "ics-flow")

# Tope de valores distintos que se guardan por columna antes de informar
# "mas de N". Acota la memoria en HAI, que son 2,6 GB de entrenamiento.
TOPE_CARDINALIDAD = 2000

# ---------------------------------------------------------------------------
# Unidades de los 64 campos de flujo de Westermo y de ICS-Flow.
#
# Cada entrada declara la unidad y la procedencia de esa unidad. Los codigos de
# procedencia son:
#   ID   la verifica una identidad numerica que este script comprueba y cuyo
#        resultado se imprime en la seccion "identidades verificadas";
#   ID*  se deduce de una identidad verificada sobre un campo de la misma
#        familia (p. ej. sBytesMax es byte porque sBytesAvg lo es y
#        min <= avg <= max se cumple);
#   RNG  no esta declarada en ninguna parte: solo se informa el rango medido;
#   CAT  campo categorico o de identidad, sin unidad.
UNIDAD_FLUJO = {
    "sAddress": ("---", "CAT", "identificador del emisor (IP o MAC)"),
    "rAddress": ("---", "CAT", "identificador del receptor (IP o MAC)"),
    "sMACs": ("---", "CAT", "MAC de origen"),
    "rMACs": ("---", "CAT", "MAC de destino"),
    "sIPs": ("---", "CAT", "IP de origen"),
    "rIPs": ("---", "CAT", "IP de destino"),
    "protocol": ("---", "CAT", "familia de protocolo del flujo"),
    "startDate": ("---", "ID", "fecha y hora de inicio; start == epoch(startDate)"),
    "endDate": ("---", "ID", "fecha y hora de fin; end == epoch(endDate)"),
    "start": ("s", "ID", "epoch Unix de la primera trama"),
    "end": ("s", "ID", "epoch Unix de la ultima trama"),
    "startOffset": ("s", "ID", "start menos el minimo de start del archivo"),
    "endOffset": ("s", "ID", "end menos el minimo de start del archivo"),
    "duration": ("s", "ID", "end - start; acotada por la ventana de flujo"),
    "sPackets": ("paquete", "ID*", "recuento; sBytesAvg = sBytesSum / sPackets"),
    "rPackets": ("paquete", "ID*", "recuento; rBytesAvg = rBytesSum / rPackets"),
    "sBytesSum": ("byte", "ID", "total de octetos de trama del emisor"),
    "rBytesSum": ("byte", "ID", "total de octetos de trama del receptor"),
    "sBytesMax": ("byte", "ID*", "min <= avg <= max verificado"),
    "rBytesMax": ("byte", "ID*", "min <= avg <= max verificado"),
    "sBytesMin": ("byte", "ID*", "min <= avg <= max verificado"),
    "rBytesMin": ("byte", "ID*", "min <= avg <= max verificado"),
    "sBytesAvg": ("byte", "ID", "sBytesSum / sPackets"),
    "rBytesAvg": ("byte", "ID", "rBytesSum / rPackets"),
    "sLoad": ("bit/s", "ID", "8 * sBytesSum / duration"),
    "rLoad": ("bit/s", "ID", "8 * rBytesSum / duration"),
    "sPayloadSum": ("byte", "ID", "sPayloadAvg = sPayloadSum / sPackets"),
    "rPayloadSum": ("byte", "ID", "rPayloadAvg = rPayloadSum / rPackets"),
    "sPayloadMax": ("byte", "ID*", "min <= avg <= max verificado"),
    "rPayloadMax": ("byte", "ID*", "min <= avg <= max verificado"),
    "sPayloadMin": ("byte", "ID*", "min <= avg <= max verificado"),
    "rPayloadMin": ("byte", "ID*", "min <= avg <= max verificado"),
    "sPayloadAvg": ("byte", "ID", "sPayloadSum / sPackets"),
    "rPayloadAvg": ("byte", "ID", "rPayloadSum / rPackets"),
    "sInterPacketAvg": ("s", "ID", "~ duration / (sPackets - 1)"),
    "rInterPacketAvg": ("s", "ID", "~ duration / (rPackets - 1)"),
    "sttl": ("salto", "RNG", "TTL medio del emisor"),
    "rttl": ("salto", "RNG", "TTL medio del receptor"),
    "sAckRate": ("fraccion", "ID", "en [0, 1] verificado"),
    "rAckRate": ("fraccion", "ID", "en [0, 1] verificado"),
    "sUrgRate": ("fraccion", "ID", "en [0, 1] verificado"),
    "rUrgRate": ("fraccion", "ID", "en [0, 1] verificado"),
    "sFinRate": ("fraccion", "ID", "en [0, 1] verificado"),
    "rFinRate": ("fraccion", "ID", "en [0, 1] verificado"),
    "sPshRate": ("fraccion", "ID", "en [0, 1] verificado"),
    "rPshRate": ("fraccion", "ID", "en [0, 1] verificado"),
    "sSynRate": ("fraccion", "ID", "en [0, 1] verificado"),
    "rSynRate": ("fraccion", "ID", "en [0, 1] verificado"),
    "sRstRate": ("fraccion", "ID", "en [0, 1] verificado"),
    "rRstRate": ("fraccion", "ID", "en [0, 1] verificado"),
    "sWinTCP": ("---", "RNG", "ventana TCP media; unidad no declarada"),
    "rWinTCP": ("---", "RNG", "ventana TCP media; unidad no declarada"),
    "sFragmentRate": ("fraccion", "ID", "en [0, 1] verificado"),
    "rFragmentRate": ("fraccion", "ID", "en [0, 1] verificado"),
    "sAckDelayMax": ("s", "ID", "<= duration verificado"),
    "rAckDelayMax": ("s", "ID", "<= duration verificado"),
    "sAckDelayMin": ("s", "ID", "min <= avg <= max verificado"),
    "rAckDelayMin": ("s", "ID", "min <= avg <= max verificado"),
    "sAckDelayAvg": ("s", "ID", "min <= avg <= max verificado"),
    "rAckDelayAvg": ("s", "ID", "min <= avg <= max verificado"),
    "IT_B_Label": ("---", "CAT", "etiqueta binaria, estrategia IT"),
    "IT_M_Label": ("---", "CAT", "etiqueta multiclase, estrategia IT"),
    "NST_B_Label": ("---", "CAT", "etiqueta binaria, estrategia NST"),
    "NST_M_Label": ("---", "CAT", "etiqueta multiclase, estrategia NST"),
}

# Los 20 atributos de Morris. La columna "procedencia" dice de donde sale la
# descripcion: DOC = la pagina del conjunto, transcripta en
# datasets/morris-turnipseed/PROCEDENCIA.md; RNG = no declarada, solo rango.
SEMANTICA_MORRIS = {
    "address": ("---", "DOC", "direccion del dispositivo Modbus"),
    "function": ("---", "DOC", "codigo de funcion Modbus"),
    "length": ("byte", "DOC", "longitud de la trama"),
    "setpoint": ("---", "DOC", "consigna del lazo; unidad no declarada"),
    "gain": ("---", "DOC", "ganancia del PID; unidad no declarada"),
    "reset rate": ("---", "DOC", "accion integral del PID; unidad no declarada"),
    "deadband": ("---", "DOC", "banda muerta; unidad no declarada"),
    "cycle time": ("---", "DOC", "tiempo de ciclo; unidad no declarada"),
    "rate": ("---", "DOC", "accion derivativa del PID; unidad no declarada"),
    "system mode": ("---", "DOC", "modo de sistema (categorico)"),
    "control scheme": ("---", "DOC", "esquema de control (categorico)"),
    "pump": ("---", "DOC", "estado de la bomba (categorico)"),
    "solenoid": ("---", "DOC", "estado de la valvula solenoide (categorico)"),
    "pressure measurement": ("---", "DOC", "presion medida; unidad no declarada"),
    "crc rate": ("---", "RNG", "tasa de error de CRC; unidad no declarada"),
    "command response": ("---", "DOC", "1 = comando, 0 = respuesta (verificado)"),
    "time": ("s", "DOC", "epoch Unix del registro"),
    "binary result": ("---", "CAT", "etiqueta binaria"),
    "categorized result": ("---", "CAT", "etiqueta de familia, 8 clases"),
    "specific result": ("---", "CAT", "etiqueta especifica, 36 clases"),
}

NIVELES = {
    "flujo": "flujo: una conversacion dentro de una ventana de duracion acotada",
    "paquete": "paquete: una trama de la captura",
    "ventana": "ventana: un recuento agregado sobre un intervalo fijo",
    "transaccion": "transaccion: una ADU de protocolo (un comando o una respuesta)",
    "proceso": "registro de proceso: una muestra de todas las variables a la vez",
    "evento": "evento: un episodio con inicio y fin",
}


# ---------------------------------------------------------------------------
# Utilidades de perfilado


def perfil(serie):
    """Perfil de una columna: tipo medido, cobertura, cardinalidad y rango."""
    n = len(serie)
    num = pd.to_numeric(serie, errors="coerce")
    es_num = num.notna().sum() > 0 and num.notna().sum() >= serie.notna().sum()
    no_nulos = int(serie.notna().sum())
    card = serie.nunique(dropna=True)
    out = {
        "filas": int(n),
        "no_nulos": no_nulos,
        "cobertura": (no_nulos / n) if n else float("nan"),
        "cardinalidad": int(card),
    }
    if es_num:
        v = num.dropna()
        entero = bool(len(v)) and bool(np.all(np.equal(np.mod(v, 1), 0)))
        out["tipo"] = "entero" if entero else "real"
        out["min"] = float(v.min()) if len(v) else float("nan")
        out["max"] = float(v.max()) if len(v) else float("nan")
        out["constante"] = bool(len(v)) and bool(v.min() == v.max())
    else:
        out["tipo"] = "texto"
        out["min"] = None
        out["max"] = None
        out["constante"] = bool(card == 1)
    return out


def fmt_rango(p):
    if p["min"] is None:
        return "%d valores" % p["cardinalidad"]
    a, b = p["min"], p["max"]
    if p["tipo"] == "entero" and abs(a) < 1e9 and abs(b) < 1e9:
        return "%g .. %g" % (a, b)
    return "%.4g .. %.4g" % (a, b)


def tabla_campos(w, campos, unidades, nivel):
    """Imprime la tabla de inventario de un archivo."""
    w("%-26s %-7s %-9s %-4s %7s %9s %-24s"
      % ("campo", "tipo", "unidad", "proc", "cobert.", "distintos", "rango medido"))
    for nombre, p in campos.items():
        u, proc, _ = unidades.get(nombre, ("---", "RNG", ""))
        card = ("%d" % p["cardinalidad"]) if p["cardinalidad"] < TOPE_CARDINALIDAD \
            else ">=%d" % TOPE_CARDINALIDAD
        w("%-26s %-7s %-9s %-4s %6.1f%% %9s %-24s"
          % (nombre[:26], p["tipo"], u, proc, 100 * p["cobertura"], card,
             fmt_rango(p)))
    w("")
    w("Nivel de agregacion de todos los campos de este archivo: %s" % NIVELES[nivel])
    w("")


# ---------------------------------------------------------------------------
# Identidades que fijan las unidades de los campos de flujo


def identidades_flujo(d):
    """Comprueba sobre un DataFrame de flujos las identidades que definen las
    unidades. Devuelve {nombre: (se_cumplen, total, detalle)}.

    Las filas con sPackets == 0 o rPackets == 0 se excluyen de las identidades
    que dividen por ese recuento: la division no esta definida y el archivo
    deja el campo vacio.
    """
    res = collections.OrderedDict()

    def chk(nombre, mascara, cumple, nota=""):
        m = mascara & cumple.notna() if hasattr(cumple, "notna") else mascara
        ok = int((cumple & m).sum())
        tot = int(m.sum())
        res[nombre] = {"cumplen": ok, "evaluadas": tot,
                       "fraccion": (ok / tot) if tot else float("nan"),
                       "nota": nota}

    todo = pd.Series(True, index=d.index)
    sp = d["sPackets"] > 0
    rp = d["rPackets"] > 0

    chk("start == epoch(startDate)", todo,
        np.isclose(d["start"], pd.to_datetime(d["startDate"]).astype("int64") / 1e9,
                   atol=1e-5))
    chk("end == epoch(endDate)", todo,
        np.isclose(d["end"], pd.to_datetime(d["endDate"]).astype("int64") / 1e9,
                   atol=1e-5))
    chk("duration == end - start", todo,
        np.isclose(d["duration"], d["end"] - d["start"], atol=2e-6),
        "tolerancia 2e-6 s: el archivo guarda 6 decimales")
    chk("startOffset == start - min(start)", todo,
        np.isclose(d["startOffset"], d["start"] - d["start"].min(), atol=1e-6))
    chk("endOffset == end - min(start)", todo,
        np.isclose(d["endOffset"], d["end"] - d["start"].min(), atol=1e-6))
    chk("sBytesAvg == sBytesSum / sPackets", sp,
        np.isclose(d["sBytesAvg"], d["sBytesSum"] / d["sPackets"].replace(0, np.nan),
                   rtol=0, atol=1e-3),
        "tolerancia 1e-3: el archivo redondea a 3 decimales")
    chk("rBytesAvg == rBytesSum / rPackets", rp,
        np.isclose(d["rBytesAvg"], d["rBytesSum"] / d["rPackets"].replace(0, np.nan),
                   rtol=0, atol=1e-3))
    chk("sPayloadAvg == sPayloadSum / sPackets", sp,
        np.isclose(d["sPayloadAvg"],
                   d["sPayloadSum"] / d["sPackets"].replace(0, np.nan),
                   rtol=0, atol=1e-3))
    chk("rPayloadAvg == rPayloadSum / rPackets", rp,
        np.isclose(d["rPayloadAvg"],
                   d["rPayloadSum"] / d["rPackets"].replace(0, np.nan),
                   rtol=0, atol=1e-3))
    chk("sLoad == 8 * sBytesSum / duration", sp,
        np.isclose(d["sLoad"], 8 * d["sBytesSum"] / d["duration"], rtol=0.05),
        "tolerancia relativa 5 %: `duration` se publica con 6 decimales y en "
        "los flujos de pocos microsegundos esa cuantizacion domina el cociente. "
        "El factor 8 es lo que fija la unidad en bit/s y no en byte/s")
    chk("rLoad == 8 * rBytesSum / duration", rp,
        np.isclose(d["rLoad"], 8 * d["rBytesSum"] / d["duration"], rtol=0.05))
    chk("sBytesMin <= sBytesAvg <= sBytesMax", sp,
        (d["sBytesMin"] <= d["sBytesAvg"] + 1e-3)
        & (d["sBytesAvg"] <= d["sBytesMax"] + 1e-3))
    chk("sPayloadMin <= sPayloadAvg <= sPayloadMax", sp,
        (d["sPayloadMin"] <= d["sPayloadAvg"] + 1e-3)
        & (d["sPayloadAvg"] <= d["sPayloadMax"] + 1e-3))
    chk("sAckDelayMin <= sAckDelayAvg <= sAckDelayMax",
        d["sAckDelayAvg"].notna(),
        (d["sAckDelayMin"] <= d["sAckDelayAvg"] + 5e-4)
        & (d["sAckDelayAvg"] <= d["sAckDelayMax"] + 5e-4),
        "holgura de 5e-4 s: `sAckDelayMin` y `sAckDelayMax` se publican con 3 "
        "decimales y `sAckDelayAvg` con 6, de modo que sin holgura el promedio "
        "supera al maximo por redondeo")
    chk("sAckDelayMax <= duration", d["sAckDelayMax"].notna(),
        d["sAckDelayMax"] <= d["duration"] + 1e-6,
        "fija la unidad de los retardos de ACK en segundos")
    tasas = [c for c in d.columns if c.endswith("Rate")]
    dentro = pd.Series(True, index=d.index)
    for c in tasas:
        v = pd.to_numeric(d[c], errors="coerce")
        dentro &= (v.isna() | ((v >= 0) & (v <= 1)))
    chk("las 14 columnas *Rate caen en [0, 1]", todo, dentro,
        "fija que son fracciones de paquetes y no recuentos")
    m = d["sPackets"] > 1
    chk("sInterPacketAvg ~ duration / (sPackets - 1)", m,
        np.isclose(d["sInterPacketAvg"], d["duration"] / (d["sPackets"] - 1),
                   rtol=0.02),
        "tolerancia relativa 2 %; la ventana de flujo recorta el ultimo intervalo")
    return res


def imprimir_identidades(w, res):
    w("%-46s %10s %11s %8s" % ("identidad", "se cumple", "evaluadas", "fraccion"))
    for k, v in res.items():
        w("%-46s %10d %11d %7.2f%%"
          % (k[:46], v["cumplen"], v["evaluadas"], 100 * v["fraccion"]))
    w("")
    notas = [(k, v["nota"]) for k, v in res.items() if v["nota"]]
    if notas:
        w("Notas:")
        for k, nota in notas:
            w("  - %s: %s" % (k, nota))
        w("")


# ---------------------------------------------------------------------------
# A. Westermo


def westermo(w, J):
    w("## A. Westermo")
    w("")
    corte = comun.WESTERMO_CORTES[0]
    w("Lo que publica: 6 PCAP y 6 CSV de flujos, en dos variantes (`reduced` y")
    w("`extended`) por cada uno de los tres puntos de captura, mas")
    w("`data/events.txt` con el registro de eventos.")
    w("")

    # cabeceras de los seis CSV
    w("### A.1 Las seis cabeceras de flujos")
    w("")
    cabeceras = {}
    for var in ("reduced", "extended"):
        for pto in ("bottom", "left", "right"):
            p = os.path.join(comun.WESTERMO, var, "flows", "output_%s.csv" % pto)
            with open(p) as fh:
                cab = next(csv.reader(fh))
            cabeceras["%s/%s" % (var, pto)] = cab
    base = cabeceras["reduced/bottom"]
    w("Campos por archivo y coincidencia con `reduced/bottom`:")
    w("")
    w("%-22s %8s %12s" % ("archivo", "campos", "identica"))
    for k, v in cabeceras.items():
        w("%-22s %8d %12s" % (k, len(v), "SI" if v == base else "NO"))
    w("")
    w("Los seis archivos publican **%d campos** con los mismos nombres y en el"
      % len(base))
    w("mismo orden. El `README` del conjunto declara 54 columnas (50")
    w("caracteristicas y 4 etiquetas); el archivo trae %d." % len(base))
    w("")

    # inventario sobre el tramo de entrenamiento del punto inferior
    ruta = os.path.join(comun.WESTERMO, "reduced", "flows", "output_bottom.csv")
    d = pd.read_csv(ruta)
    tr = d[d["startOffset"] < corte].copy()
    w("### A.2 Inventario de los %d campos de flujo" % len(base))
    w("")
    w("Medido sobre %s, tramo de entrenamiento" % comun.rel(ruta))
    w("(`startOffset` < %.0f s): %d flujos de los %d del archivo."
      % (corte, len(tr), len(d)))
    w("")
    campos = collections.OrderedDict((c, perfil(tr[c])) for c in base)
    tabla_campos(w, campos, UNIDAD_FLUJO, "flujo")

    w("### A.3 La ventana de flujo, medida")
    w("")
    w("%-30s %12s %12s %12s" % ("", "min", "mediana", "max"))
    w("%-30s %12.6f %12.6f %12.6f"
      % ("duration (s)", tr["duration"].min(), tr["duration"].median(),
         tr["duration"].max()))
    excede = int((tr["duration"] > 0.5 + 1e-6).sum())
    w("")
    w("Flujos con duration > 0,5 s: **%d de %d**. La ventana de agregacion es"
      % (excede, len(tr)))
    w("de **0,5 s como tope**: un 'flujo' de este conjunto no es una conexion")
    w("TCP completa sino el tramo de una conversacion dentro de medio segundo.")
    w("")
    w("Reparto por familia de protocolo:")
    w("")
    for k, v in tr["protocol"].value_counts().items():
        w("  %-12s %8d  (%.1f %% de %d)" % (k, v, 100 * v / len(tr), len(tr)))
    w("")

    w("### A.4 Identidades que fijan las unidades")
    w("")
    ident = identidades_flujo(tr)
    imprimir_identidades(w, ident)

    w("### A.5 `data/events.txt`")
    w("")
    ev = os.path.join(comun.WESTERMO, "events.txt")
    with open(ev) as fh:
        lineas = [l.rstrip("\n") for l in fh if l.strip()]
    w("**No es un CSV: es un registro de texto libre**, %d lineas no vacias, sin"
      % len(lineas))
    w("cabecera y sin esquema fijo. Primeras tres lineas:")
    w("")
    for l in lineas[:3]:
        w("  %s" % l[:100])
    w("")
    cab_re = re.compile(r"^\[(\d+\.\d+)\s+--\s+([\d\-: ]+)\s+--\s+([\d.]+)\]"
                        r"\s+\[([A-Z]+)\]\s+(.*)$")
    con_cab = sum(1 for l in lineas if cab_re.match(l))
    niveles_log = collections.Counter(m.group(4) for l in lineas
                                      if (m := cab_re.match(l)))
    start = sum(1 for l in lineas if " START " in l or l.endswith(" START"))
    end = sum(1 for l in lineas if " END " in l or l.endswith(" END"))
    w("Nivel: %s" % NIVELES["evento"])
    w("")
    w("Los campos que se pueden extraer de la cabecera de cada linea, que")
    w("respeta el patron `[epoch -- fecha y hora -- offset] [NIVEL] mensaje` en")
    w("%d de las %d lineas:" % (con_cab, len(lineas)))
    w("")
    w("%-26s %-7s %-9s %-4s %s"
      % ("campo (sin nombre)", "tipo", "unidad", "proc", "contenido"))
    w("%-26s %-7s %-9s %-4s %s"
      % ("1  epoch", "real", "s", "ID", "epoch Unix del evento"))
    w("%-26s %-7s %-9s %-4s %s"
      % ("2  fecha y hora", "texto", "---", "ID", "la misma marca, legible"))
    w("%-26s %-7s %-9s %-4s %s"
      % ("3  offset", "real", "s", "ID", "segundos desde el inicio de la captura"))
    w("%-26s %-7s %-9s %-4s %s"
      % ("4  nivel", "texto", "---", "CAT",
         "%s" % dict(niveles_log)))
    w("%-26s %-7s %-9s %-4s %s"
      % ("5  mensaje", "texto", "---", "CAT",
         "texto libre; los eventos llevan START o END"))
    w("")
    w("Lineas con START: %d. Lineas con END: %d. El recuento de eventos que sale"
      % (start, end))
    w("de emparejarlos esta en `eda/salidas/p3_p4_westermo.txt` (94 eventos).")
    w("")
    w("Que el inventario de eventos sea texto libre y no una tabla importa para")
    w("la integracion: **la etiqueta por evento de Westermo hay que parsearla**,")
    w("mientras que ICS-Flow la publica como CSV con cabecera.")
    w("")
    campos_ev = 5

    w("### A.6 Los PCAP")
    w("")
    w("Los 6 PCAP son el nivel de paquete y **no publican ningun campo**: son")
    w("tramas Ethernet crudas. Toda caracteristica a ese nivel hay que")
    w("calcularla. Tamanos en disco:")
    w("")
    for var in ("reduced", "extended"):
        for pto in ("bottom", "left", "right"):
            p = os.path.join(comun.WESTERMO, var, "pcaps", "%s.pcap" % pto)
            if os.path.exists(p):
                w("  %-24s %8.1f MB" % ("%s/%s.pcap" % (var, pto),
                                        os.path.getsize(p) / 1e6))
    w("")

    J["westermo"] = {
        "cabeceras": {k: len(v) for k, v in cabeceras.items()},
        "cabeceras_identicas": all(v == base for v in cabeceras.values()),
        "campos_flujo": len(base),
        "nombres_flujo": base,
        "flujos_entrenamiento": int(len(tr)),
        "flujos_archivo": int(len(d)),
        "ventana_flujo_s": 0.5,
        "flujos_que_exceden_ventana": excede,
        "duration": {"min": float(tr["duration"].min()),
                     "mediana": float(tr["duration"].median()),
                     "max": float(tr["duration"].max())},
        "protocolos": {str(k): int(v) for k, v in
                       tr["protocol"].value_counts().items()},
        "identidades": ident,
        "perfil": campos,
        "events_txt_lineas": len(lineas),
        "events_txt_campos": campos_ev,
    }
    return base, tr, ident


# ---------------------------------------------------------------------------
# B. ICS-Flow


def icsflow(w, J, base_westermo):
    w("## B. ICS-Flow")
    w("")
    w("Lo que publica: `Dataset.csv` (flujos etiquetados), `snapshots_PLC1.csv`")
    w("y `snapshots_PLC2.csv` (variables de proceso), `attacker_summary.csv` y")
    w("`attacker_machine_summary.csv` (inventario de eventos) y `traffic.pcap`.")
    w("")

    ruta = os.path.join(ICSFLOW, "Dataset.csv")
    d = pd.read_csv(ruta)
    with open(ruta) as fh:
        cab = next(csv.reader(fh))
    # misma regla de corte que 06_icsflow_escrituras.py
    t0, t1 = float(d["start"].min()), float(d["end"].max())
    span = t1 - t0
    corte60 = t0 + 0.6 * span
    tr = d[d["start"] < corte60].copy()

    w("### B.1 `Dataset.csv`: el esquema es el de Westermo")
    w("")
    w("La cabecera de `Dataset.csv` tiene **%d campos** y es **identica a la de"
      % len(cab))
    w("los seis CSV de Westermo**, nombre por nombre y en el mismo orden:")
    w("coinciden %d de %d. Es el hecho que mas pesa en la pregunta de"
      % (sum(1 for a, b in zip(cab, base_westermo) if a == b), len(cab)))
    w("integracion y se trata aparte en `11_integracion_esquemas.py`.")
    w("")
    w("Medido sobre el tramo de entrenamiento (`start` < %.3f, el 60 %% del" % corte60)
    w("tramo segun la misma regla de `06_icsflow_escrituras.py`): %d flujos de"
      % len(tr))
    w("los %d del archivo." % len(d))
    w("")
    campos = collections.OrderedDict((c, perfil(tr[c])) for c in cab)
    tabla_campos(w, campos, UNIDAD_FLUJO, "flujo")

    w("### B.2 La ventana de flujo, medida")
    w("")
    excede = int((tr["duration"] > 0.5 + 1e-6).sum())
    w("%-30s %12.6f %12.6f %12.6f"
      % ("duration (s): min/med/max", tr["duration"].min(),
         tr["duration"].median(), tr["duration"].max()))
    w("Flujos con duration > 0,5 s: **%d de %d**. **La misma ventana de 0,5 s**"
      % (excede, len(tr)))
    w("que Westermo.")
    w("")
    w("Reparto por familia de protocolo:")
    w("")
    for k, v in tr["protocol"].value_counts().items():
        w("  %-12s %8d  (%.1f %% de %d)" % (k, v, 100 * v / len(tr), len(tr)))
    w("")

    w("### B.3 Identidades que fijan las unidades")
    w("")
    ident = identidades_flujo(tr)
    imprimir_identidades(w, ident)

    w("### B.4 Los dos `snapshots_PLC*.csv`")
    w("")
    w("**Una trampa de formato que hay que resolver antes de usarlos.** La")
    w("columna `time` de estos archivos es hora local **sin marca de zona**,")
    w("mientras que la columna `start` de `Dataset.csv` y las marcas del PCAP")
    w("son epoch Unix. Cortar los snapshots por `time` leido como UTC deja el")
    w("tramo de entrenamiento vacio.")
    w("")
    w("Lo que resuelve el problema es `current_loop`, que **no es un contador de")
    w("ciclo sino el epoch en milisegundos**. Se verifica por identidad:")
    w("")
    snaps = {}
    offsets = {}
    off_dataset = (pd.to_datetime(d["startDate"]).astype("int64") / 1e9
                   - d["start"]).median()
    for arch in ("snapshots_PLC1.csv", "snapshots_PLC2.csv"):
        p = os.path.join(ICSFLOW, arch)
        s = pd.read_csv(p)
        s.columns = [c.strip() for c in s.columns]
        s = s.loc[:, [c for c in s.columns if c]]
        t = pd.to_datetime(s["time"].astype(str).str.strip())
        cl = pd.to_numeric(s["current_loop"], errors="coerce")
        off = (t.astype("int64") / 1e9 - cl / 1000.0)
        offsets[arch] = float(off.median())
    w("%-34s %26s %16s"
      % ("archivo", "columnas comparadas", "desfase (s)"))
    for arch, o in offsets.items():
        w("%-34s %26s %16.3f" % (arch, "time - current_loop/1000", o))
    w("%-34s %26s %16.3f"
      % ("Dataset.csv", "startDate - start", off_dataset))
    w("")
    w("El desfase entre `time` y `current_loop` es de **%.0f s** en los dos"
      % offsets["snapshots_PLC1.csv"])
    w("snapshots, y **el mismo %.0f s** separa `startDate` de `start` en"
      % off_dataset)
    w("`Dataset.csv`. Son dos horas: la zona horaria del banco. De modo que")
    w("`current_loop / 1000` es el epoch, es la unica columna que alinea los")
    w("snapshots con los flujos y con la captura, y es por esa columna que se")
    w("corta aqui el tramo de entrenamiento.")
    w("")
    for arch in ("snapshots_PLC1.csv", "snapshots_PLC2.csv"):
        p = os.path.join(ICSFLOW, arch)
        s = pd.read_csv(p)
        s.columns = [c.strip() for c in s.columns]
        s = s.loc[:, [c for c in s.columns if c]]
        t = pd.to_datetime(s["time"].astype(str).str.strip())
        cl = pd.to_numeric(s["current_loop"], errors="coerce")
        dt = (cl / 1000.0).diff().dropna()
        trs = s[cl / 1000.0 < corte60].copy()
        w("#### %s" % arch)
        w("")
        w("%d filas, %d campos. Rango de `current_loop`: %.3f a %.3f"
          % (len(s), s.shape[1], cl.min() / 1000, cl.max() / 1000))
        w("(hora local %s a %s)." % (t.min(), t.max()))
        w("Intervalo entre muestras: mediana %.4f s, p05 %.4f s, p95 %.4f s."
          % (dt.median(), dt.quantile(0.05), dt.quantile(0.95)))
        w("Tramo de entrenamiento (`current_loop`/1000 < %.1f): %d filas de %d."
          % (corte60, len(trs), len(s)))
        w("")
        uni = {}
        for c in s.columns:
            if c == "time":
                uni[c] = ("---", "ID", "hora local sin zona; desfase de %.0f s"
                          % offsets[arch])
            elif c == "current_loop":
                uni[c] = ("ms", "ID", "epoch en milisegundos, verificado arriba")
            elif c in ("loop_latency", "logic_execution_time"):
                uni[c] = ("---", "RNG", "unidad no declarada; rango medido")
            elif re.search(r"\((\d+)\)$", c):
                uni[c] = ("---", "RNG",
                          "indice de registro entre parentesis; unidad no declarada")
            else:
                uni[c] = ("---", "RNG", "unidad no declarada")
        cs = collections.OrderedDict((c, perfil(trs[c])) for c in s.columns)
        tabla_campos(w, cs, uni, "proceso")
        snaps[arch] = {"filas": int(len(s)), "campos": int(s.shape[1]),
                       "columnas": list(s.columns),
                       "offset_time_vs_current_loop_s": offsets[arch],
                       "dt_mediana_s": float(dt.median()),
                       "dt_p05_s": float(dt.quantile(0.05)),
                       "dt_p95_s": float(dt.quantile(0.95)),
                       "filas_entrenamiento": int(len(trs)),
                       "perfil": cs}
    w("**Las unidades de las variables de proceso no estan declaradas en")
    w("ninguna parte**: ni en la cabecera, ni en un archivo del conjunto. Lo")
    w("unico que se sabe de ellas es el rango medido de la tabla y la")
    w("correspondencia con los registros Modbus del parrafo siguiente. Es la")
    w("diferencia con HAI, que publica un PDF con la unidad de cada punto.")
    w("")
    w("El numero entre parentesis del nombre de cada variable es el **indice de")
    w("registro Modbus dividido por dos**: la direccion 6 corresponde a")
    w("`tank_level_min(3)`. Esa correspondencia esta medida en la seccion 4 de")
    w("INFORME.md y es lo que permite ligar una escritura de la captura con")
    w("la variable de proceso que modifica.")
    w("")

    w("### B.5 El inventario de eventos")
    w("")
    eventos = {}
    for arch in ("attacker_summary.csv", "attacker_machine_summary.csv"):
        p = os.path.join(ICSFLOW, arch)
        e = pd.read_csv(p)
        w("#### %s --- %d filas, %d campos" % (arch, len(e), e.shape[1]))
        w("")
        if not len(e):
            w("**Esta vacio: trae la cabecera y ninguna fila** (%d bytes en"
              % os.path.getsize(p))
            w("disco). El inventario de eventos utilizable es el otro archivo.")
            w("")
        uni = {c: ("---", "CAT", "") for c in e.columns}
        uni["startStamp"] = ("s", "RNG", "epoch Unix de inicio")
        uni["endStamp"] = ("s", "RNG", "epoch Unix de fin")
        ce = collections.OrderedDict((c, perfil(e[c])) for c in e.columns)
        tabla_campos(w, ce, uni, "evento")
        if "attack" in e.columns:
            w("Tipos de evento: %s"
              % ", ".join("%s (%d)" % (k, v)
                          for k, v in e["attack"].value_counts().items()))
            w("")
        eventos[arch] = {"filas": int(len(e)), "campos": int(e.shape[1]),
                         "columnas": list(e.columns), "perfil": ce}

    w("### B.6 `traffic.pcap`")
    w("")
    p = os.path.join(ICSFLOW, "traffic.pcap")
    w("Nivel de paquete, %.1f MB en disco. No publica campos: hay que"
      % (os.path.getsize(p) / 1e6))
    w("calcularlos. La seccion 4 de INFORME.md documenta lo que se")
    w("recupera de su carga util Modbus.")
    w("")

    J["icsflow"] = {
        "campos_flujo": len(cab),
        "nombres_flujo": cab,
        "cabecera_identica_a_westermo": cab == base_westermo,
        "flujos_entrenamiento": int(len(tr)),
        "flujos_archivo": int(len(d)),
        "corte60": corte60,
        "flujos_que_exceden_ventana": excede,
        "duration": {"min": float(tr["duration"].min()),
                     "mediana": float(tr["duration"].median()),
                     "max": float(tr["duration"].max())},
        "protocolos": {str(k): int(v) for k, v in
                       tr["protocol"].value_counts().items()},
        "identidades": ident,
        "perfil": campos,
        "snapshots": snaps,
        "eventos": eventos,
    }
    return cab, tr, ident


# ---------------------------------------------------------------------------
# C. Morris / Turnipseed


ATRIBUTO_ARFF = re.compile(r"^@attribute\s+(?:'([^']*)'|\"([^\"]*)\"|(\S+))\s*(.*)$",
                           re.IGNORECASE)


def leer_arff(path):
    atributos, declarados, filas = [], [], []
    en_datos = False
    with open(path) as fh:
        for linea in fh:
            s = linea.strip()
            if not en_datos:
                low = s.lower()
                if low.startswith("@attribute"):
                    m = ATRIBUTO_ARFF.match(s)
                    atributos.append(next(g for g in m.groups()[:3]
                                          if g is not None))
                    declarados.append(m.group(4).strip())
                elif low.startswith("@data"):
                    en_datos = True
                continue
            if not s or s.startswith("%"):
                continue
            filas.append(s.split(","))
    df = pd.DataFrame(filas, columns=atributos).replace("?", np.nan)
    return df, atributos, declarados


def morris(w, J):
    w("## C. Morris / Turnipseed")
    w("")
    ruta = os.path.join(comun.MORRIS, "IanArffDataset.arff")
    d, atributos, declarados = leer_arff(ruta)
    for c in atributos:
        if c not in ("command response", "binary result", "categorized result",
                     "specific result"):
            d[c] = pd.to_numeric(d[c], errors="coerce")
    t = pd.to_numeric(d["time"], errors="coerce")
    tr = d[t < comun.MORRIS_CORTES[0]].copy()

    w("Lo que publica: **un solo archivo ARFF** con las caracteristicas ya")
    w("extraidas. No hay captura: el archivo con el hexadecimal de las tramas")
    w("no esta archivado (ver `datasets/morris-turnipseed/PROCEDENCIA.md`).")
    w("")
    w("### C.1 Inventario de los %d atributos" % len(atributos))
    w("")
    w("Medido sobre %s, tramo de entrenamiento" % comun.rel(ruta))
    w("(`time` < %d): %d filas de las %d del archivo."
      % (comun.MORRIS_CORTES[0], len(tr), len(d)))
    w("")
    campos = collections.OrderedDict((c, perfil(tr[c])) for c in atributos)
    tabla_campos(w, campos, SEMANTICA_MORRIS, "transaccion")
    w("Tipo declarado en el propio ARFF (`@attribute`), que no es lo mismo que")
    w("el tipo medido:")
    w("")
    w("%-26s %-34s %-8s" % ("atributo", "declarado en el ARFF", "medido"))
    for a, dec in zip(atributos, declarados):
        w("%-26s %-34s %-8s" % (a[:26], dec[:34], campos[a]["tipo"]))
    w("")
    w("Los 15 atributos que **no** son etiqueta estan declarados `real`,")
    w("incluidos los que son categoricos (`function`, `system mode`,")
    w("`control scheme`, `pump`, `solenoid`): el ARFF no distingue. El tipo")
    w("medido tampoco lo resuelve, porque un codigo de funcion es un entero.")
    w("")

    w("### C.2 Granularidad y nivel de agregacion")
    w("")
    tt = pd.to_numeric(tr["time"], errors="coerce").dropna()
    dt = tt.diff().dropna()
    w("Nivel: %s" % NIVELES["transaccion"])
    w("Una fila es un comando **o** una respuesta, no el par: el atributo")
    w("`command response` dice cual (1 = comando, 0 = respuesta, verificado en")
    w("la seccion 1.4 de INFORME.md).")
    w("")
    # resolucion real de `time`: se cuenta sobre el texto del archivo, porque
    # el float ya no distingue cuantos decimales venian escritos
    dec_time = collections.Counter()
    with open(ruta) as fh:
        en_datos = False
        for linea in fh:
            s = linea.strip()
            if not en_datos:
                en_datos = s.lower().startswith("@data")
                continue
            if not s or s.startswith("%"):
                continue
            campos = s.split(",")
            if len(campos) > atributos.index("time"):
                v = campos[atributos.index("time")]
                dec_time[len(v.split(".")[1]) if "." in v else 0] += 1
    w("`time` es epoch Unix y **tiene %d decimales**, es decir resolucion de"
      % max(dec_time))
    w("microsegundo, no de segundo entero. Reparto de decimales sobre el")
    w("archivo completo: %s."
      % ", ".join("%d decimales en %d filas" % (k, v)
                  for k, v in sorted(dec_time.items())))
    w("")
    w("Intervalo entre filas sucesivas del tramo de entrenamiento:")
    w("  mediana %.4f s | p05 %.4f s | p95 %.4f s | min %.4f s | max %.4f s"
      % (dt.median(), dt.quantile(0.05), dt.quantile(0.95), dt.min(), dt.max()))
    w("  filas con intervalo 0 (misma marca de tiempo): %d de %d"
      % (int((dt == 0).sum()), len(dt)))
    w("")
    w("Hay **%d marcas de tiempo distintas** en %d filas del tramo, es decir"
      % (int(tt.nunique()), len(tt)))
    w("%.2f filas por marca: **cada fila tiene su propia marca** y el orden"
      % (len(tt) / tt.nunique()))
    w("temporal es inequivoco. Es mas resolucion de la que el conjunto")
    w("aparenta, y mas de la que sirve: no hay ningun otro conjunto con el que")
    w("alinearlo, porque la captura es de %s y los demas bancos son otros."
      % pd.to_datetime(tt.min(), unit="s").strftime("%Y-%m"))
    w("")

    w("### C.3 Cobertura de los atributos semanticos")
    w("")
    w("Es el dato que decide que se puede usar: la mayoria de los atributos")
    w("vienen vacios en la mayoria de las filas, porque dependen del sentido")
    w("del dialogo y del codigo de funcion.")
    w("")
    w("%-26s %10s %10s %10s" % ("atributo", "cobertura", "en comando", "en resp."))
    cr = tr["command response"]
    cobertura_cr = {}
    for c in atributos:
        if c in ("time", "binary result", "categorized result", "specific result"):
            continue
        v = tr[c]
        a = int((v.notna() & (cr == "1")).sum())
        b = int((v.notna() & (cr == "0")).sum())
        w("%-26s %9.1f%% %10d %10d" % (c[:26], 100 * v.notna().mean(), a, b))
        cobertura_cr[c] = {"en_comando": a, "en_respuesta": b,
                           "cobertura": float(v.notna().mean())}
    w("")
    w("Denominadores del tramo: %d filas, de ellas %d comandos y %d respuestas."
      % (len(tr), int((cr == "1").sum()), int((cr == "0").sum())))
    w("")

    J["morris"] = {
        "atributos": len(atributos),
        "nombres": atributos,
        "tipos_declarados": dict(zip(atributos, declarados)),
        "filas_archivo": int(len(d)),
        "filas_entrenamiento": int(len(tr)),
        "perfil": campos,
        "granularidad": {"dt_mediana_s": float(dt.median()),
                         "dt_p05_s": float(dt.quantile(0.05)),
                         "dt_p95_s": float(dt.quantile(0.95)),
                         "marcas_distintas": int(tt.nunique()),
                         "filas_por_marca": float(len(tt) / tt.nunique())},
        "cobertura_por_sentido": cobertura_cr,
    }


# ---------------------------------------------------------------------------
# D. HAI


HAI_VERSIONES = [
    ("hai-20.07", ";", "time", "train*.csv"),
    ("hai-21.03", ",", "time", "train*.csv"),
    ("hai-22.04", ",", "timestamp", "train*.csv"),
    ("hai-23.05", ",", "timestamp", "hai-train*.csv"),
    ("haiend-23.05", ",", "Timestamp", "end-train*.csv"),
]

# Una fila de la tabla de puntos del PDF tecnico de HAI. Min, Max y Unit
# pueden valer "-": los puntos de logica interna de HAIEnd no declaran rango
# ni unidad, y eso es un dato, no un fallo de lectura.
_NUM = r"(?:-|[-+]?[\d,]+(?:\.\d+)?)"
FILA_PUNTO = re.compile(
    r"^\s*(\d{1,3})\s+"                      # No
    r"([A-Za-z0-9][A-Za-z0-9_.\-]*)\s+"      # Name
    r"(" + _NUM + r")\s+"                    # Min
    r"(" + _NUM + r")\s+"                    # Max
    r"(\S+)\s+"                              # Unit
    r"(.+?)\s*$")                            # Description + presencia
# Linea de continuacion que solo trae el punto equivalente entre parentesis.
SOLO_PARENTESIS = re.compile(r"^\(([A-Za-z0-9_]+)\)$")

# Paginas del PDF (indice base 0) que ocupan las dos tablas de puntos. La
# segunda empieza en la misma pagina en que termina la primera, de modo que no
# se separan por pagina sino por el reinicio de la numeracion de la columna
# "No": la tabla de HAI va de 1 a 87 y la de HAIEnd vuelve a empezar en 1.
PAG_PUNTOS = range(12, 24)


def _filas_punto(pagina_texto):
    """Devuelve [(indice de linea, grupos)] de las filas de tabla de una
    pagina, mas la lista de lineas, para poder mirar las continuaciones."""
    lineas = pagina_texto.splitlines()
    out = []
    for i, linea in enumerate(lineas):
        m = FILA_PUNTO.match(linea)
        if not m:
            continue
        if m.group(2).lower() in ("name", "range", "min", "max", "unit"):
            continue
        out.append((i, m.groups()))
    return lineas, out


def _leer_pdf():
    try:
        from pypdf import PdfReader
    except ImportError:
        return None, "pypdf no esta instalado en eda/.venv"
    p = os.path.join(comun.HAI, "hai_dataset_technical_details.pdf")
    if not os.path.exists(p):
        return None, "falta %s" % comun.rel(p)
    return PdfReader(p), None


def tabla_puntos_hai():
    """Lee del PDF tecnico del conjunto la tabla de puntos de datos.

    `datasets/hai/hai_dataset_technical_details.pdf`, secciones "HAI DATA
    POINTS" y "HAIEND DATA POINTS". Es la **unica** fuente que declara la
    unidad de cada variable de HAI: ni los CSV ni el README la traen.

    Devuelve ademas el control de lectura: cuantas filas numeradas tiene cada
    tabla y cuantas se pudieron leer, para que quede visible si el parseo
    perdio alguna.
    """
    r, err = _leer_pdf()
    if err:
        return None, err, {}
    puntos = {}
    control = collections.Counter()
    etiqueta = "HAI"
    previo = 0
    for i in PAG_PUNTOS:
        _, filas = _filas_punto(
            r.pages[i].extract_text(extraction_mode="layout"))
        for _, (no, nombre, mn, mx, unidad, resto) in filas:
            no = int(no)
            if no < previo:                 # la numeracion reinicia: otra tabla
                etiqueta = "HAIEnd"
            previo = no
            control[etiqueta] += 1
            puntos.setdefault(nombre, {
                "no": no,
                "tabla": etiqueta,
                "min": mn.replace(",", ""),
                "max": mx.replace(",", ""),
                "unidad": unidad,
                "descripcion": re.sub(r"\s*[√✓]\s*", " ",
                                      resto).strip(),
                "marcas": resto.count("√") + resto.count("✓"),
            })
    return puntos, None, dict(control)


def equivalencias_entre_nombres():
    """Nombres alternativos que el PDF declara para un mismo punto de datos.

    El PDF los pone en una linea de continuacion que lleva **solo** el otro
    nombre entre parentesis, debajo de la fila. Se acepta esa linea unicamente
    si aparece despues de una fila de tabla y antes de la fila siguiente,
    dentro de la misma pagina: de otro modo el parseo arrastra la ultima fila
    vista y produce equivalencias que el documento no declara.

    Aparecen en los dos sentidos y conviene no confundirlos, porque significan
    cosas distintas:

      - en la tabla de HAIEnd, el parentesis da el punto de HAI equivalente,
        es decir la misma variable publicada con otro nombre en otra familia
        de archivos;
      - en la tabla de HAI, el parentesis da el nombre que el mismo punto
        tenia en una **version anterior**, es decir un cambio de nombre entre
        versiones del mismo conjunto.

    Devuelve {nombre: (otro nombre, tabla en que aparecio la fila)}.
    """
    r, err = _leer_pdf()
    if err:
        return {}
    equiv = {}
    etiqueta = "HAI"
    previo = 0
    for i in PAG_PUNTOS:
        lineas, filas = _filas_punto(
            r.pages[i].extract_text(extraction_mode="layout"))
        for k, (idx, grupos) in enumerate(filas):
            no = int(grupos[0])
            if no < previo:
                etiqueta = "HAIEnd"
            previo = no
            fin = filas[k + 1][0] if k + 1 < len(filas) else len(lineas)
            for linea in lineas[idx + 1:fin]:
                m = SOLO_PARENTESIS.match(linea.strip())
                if m:
                    equiv[grupos[1]] = (m.group(1), etiqueta)
                    break
    return equiv


FILA_ATAQUE = re.compile(r"^\s*(\d{1,3})\s+(A\d{3})\b(.*)$")
ENCABEZADO_VERSION = re.compile(r"^(HAI(?:/HAIEnd)?\s+\d{2}\.\d{2})", re.I)
COD_ESCENARIO = re.compile(r"\b(A[PE]\d{1,2})\b")


def tabla_ataques_hai():
    """Lee del PDF tecnico la tabla de ataques de cada version.

    Son las secciones "ATTACK OPERATION". Publican, por ataque: numero,
    identificador, codigo de escenario, controlador atacado, **punto de proceso
    atacado**, hora de inicio y duracion. Nada de eso esta en los CSV, y es la
    unica informacion de tipo de anomalia que el conjunto trae.

    La version se toma del encabezado de pagina, no de un rango fijo.
    """
    r, err = _leer_pdf()
    if err:
        return {}
    por_version = collections.OrderedDict()
    actual = None
    for i in range(len(r.pages)):
        lineas = r.pages[i].extract_text(extraction_mode="layout").splitlines()
        texto = "\n".join(lineas)
        for linea in lineas:
            m = ENCABEZADO_VERSION.match(linea.strip())
            if m:
                actual = re.sub(r"\s+", " ", m.group(1))
                break
        if actual is None or "ATTACK OPERATION" not in texto \
                and actual not in por_version:
            if actual is None:
                continue
        filas = [FILA_ATAQUE.match(l) for l in lineas]
        filas = [m for m in filas if m]
        if not filas:
            continue
        reg = por_version.setdefault(actual, {"ataques": [], "paginas": []})
        reg["paginas"].append(i)
        for m in filas:
            resto = m.group(3)
            esc = COD_ESCENARIO.search(resto)
            dur = re.findall(r"(\d[\d,]*)\s*$", resto.rstrip())
            reg["ataques"].append({
                "id": m.group(2),
                "escenario": esc.group(1) if esc else None,
                "duracion_s": int(dur[0].replace(",", "")) if dur else None,
                "con_punto_atacado": bool(re.search(r"P\d_[A-Za-z0-9_]+|"
                                                    r"\d{4}[-.]\d{2}", resto)),
            })
    return por_version


def hai(w, J):
    w("## D. HAI")
    w("")
    w("Lo que publica: cinco versiones de CSV de variables de proceso, mas")
    w("`hai_dataset_technical_details.pdf`, que es el **unico** lugar donde")
    w("estan declaradas las unidades: ni los CSV ni el `README` las traen.")
    w("")

    puntos, err, control = tabla_puntos_hai()
    if err:
        w("ADVERTENCIA: no se pudo leer la tabla de puntos del PDF (%s)." % err)
        w("")
        puntos = {}
    else:
        w("### D.1 La tabla de puntos del PDF tecnico")
        w("")
        w("Se leyeron **%d puntos de datos** de las tablas 'HAI DATA POINTS' y"
          % len(puntos))
        w("'HAIEND DATA POINTS' del PDF: %d filas de la primera y %d de la"
          % (control.get("HAI", 0), control.get("HAIEnd", 0)))
        w("segunda. Cada fila trae nombre, minimo, maximo, unidad, descripcion y")
        w("en que versiones aparece el punto.")
        w("")
        sin_unidad = sum(1 for v in puntos.values() if v["unidad"] == "-")
        unidades = collections.Counter(v["unidad"] for v in puntos.values())
        w("Unidades declaradas, con su recuento:")
        w("")
        for u, n in unidades.most_common():
            w("  %-12s %4d puntos%s"
              % (u, n, "   <-- sin unidad declarada" if u == "-" else ""))
        w("")
        w("**Ninguna es una unidad de red.** Las %d entradas distintas son todas"
          % len(unidades))
        w("magnitudes de proceso, estados binarios o el guion que indica que el")
        w("punto no declara unidad. HAI no publica una sola caracteristica de")
        w("trafico.")
        w("")
        w("Los **%d puntos sin unidad ni rango declarados** son, casi todos, los"
          % sin_unidad)
        w("de logica interna del DCS de `haiend-23.05` (`1001.02-OUT` y")
        w("similares), que el PDF describe solo como 'Output of 1001.02'. De esa")
        w("version se publican 226 columnas y la mayor parte no tiene")
        w("documentacion de contenido.")
        w("")

    # cabeceras de los archivos de entrenamiento: hacen falta para validar la
    # correspondencia del PDF contra las columnas que los CSV traen de verdad.
    cabeceras = {}
    for version, sep, _, patron in HAI_VERSIONES:
        cols = set()
        for a in sorted(glob.glob(os.path.join(comun.HAI, version, patron))):
            with open(a) as fh:
                cols.update(c.strip() for c in next(csv.reader(fh,
                                                               delimiter=sep)))
        cabeceras[version] = cols

    equiv = equivalencias_entre_nombres()
    cruce_haiend, renombres, equiv_invalidas, correccion = {}, {}, {}, {}
    if equiv:
        w("### D.2 Los nombres alternativos que declara el PDF")
        w("")
        w("El PDF declara, en una linea de continuacion y entre parentesis, otro")
        w("nombre para el mismo punto de datos. Se leyeron **%d**, y cada uno se"
          % len(equiv))
        w("valida contra las cabeceras reales de los `train*.csv`: los dos")
        w("nombres tienen que ser columnas de alguna version. Hay dos clases, y")
        w("conviene no confundirlas.")
        w("")

        # El PDF no siempre escribe el nombre como lo escriben los CSV: a veces
        # cambia la caja (`P2_AutoGo` por `P2_AutoGO`) y a veces omite el
        # prefijo de proceso (`Auto` por `P2_Auto`). Se resuelve en tres pasos
        # y se deja constancia de cual se aplico, para no corregir en silencio.
        indice = {}
        real = {}
        for ver, cols in cabeceras.items():
            for c in cols:
                indice.setdefault(c.lower(), set()).add(ver)
                real[c.lower()] = c

        def resolver(nombre, prefijo=None):
            """Devuelve (nombre tal como lo escriben los CSV, versiones, regla)."""
            if nombre.lower() in indice:
                regla = "exacto" if real[nombre.lower()] == nombre else "caja"
                return real[nombre.lower()], sorted(indice[nombre.lower()]), regla
            if prefijo:
                cand = "%s_%s" % (prefijo, nombre)
                if cand.lower() in indice:
                    return (real[cand.lower()], sorted(indice[cand.lower()]),
                            "prefijo")
            return None, [], "sin resolver"

        for k, (v, tabla) in sorted(equiv.items()):
            pref = k.split("_")[0] if re.match(r"^P\d_", k) else None
            rk, cols_k, regla_k = resolver(k)
            rv, cols_v, regla_v = resolver(v, prefijo=pref)
            if not cols_k or not cols_v:
                equiv_invalidas[k] = (v, tabla, cols_k, cols_v)
            elif tabla == "HAIEnd":
                cruce_haiend[k] = (rk, rv, cols_k, cols_v, regla_v)
            else:
                renombres[k] = (rk, rv, cols_k, cols_v, regla_v)

        w("#### D.2.a `haiend-23.05` contra el resto: %d pares validados"
          % len(cruce_haiend))
        w("")
        w("%-22s %-22s %-20s %s"
          % ("punto de HAIEnd", "punto de HAI", "el de HAI esta en", "regla"))
        for k, (rk, rv, ck, cv, regla) in sorted(cruce_haiend.items()):
            w("%-22s %-22s %-20s %s" % (rk, rv, ",".join(cv), regla))
        w("")
        w("Importa porque la matriz de columnas comunes de INFORME.md da")
        w("**cero** columnas compartidas entre `haiend-23.05` y las otras cuatro")
        w("versiones. Eso es cierto **por nombre**: por contenido, el PDF declara")
        w("%d pares que son la misma variable con otro nombre, sobre %d columnas"
          % (len(cruce_haiend), len(cabeceras.get("haiend-23.05", ()))))
        w("de esa version. El %.1f %% restante sigue sin contraparte."
          % (100 * (1 - len(cruce_haiend)
                    / max(1, len(cabeceras.get("haiend-23.05", ()))))))
        w("")
        w("Una salvedad de transcripcion: el PDF declara `DM-TIT02 -> P1_TIT03`")
        w("aunque describe `DM-TIT02` como la temperatura del tanque de agua")
        w("caliente, que es lo que describe `P1_TIT02`. Se transcribe lo que dice")
        w("el documento y se deja asentada la discrepancia, sin corregirla: no")
        w("hay fuente para decidir cual de los dos nombres es el correcto.")
        w("")

        w("#### D.2.b Cambios de nombre entre versiones de HAI: %d pares"
          % len(renombres))
        w("")
        w("Estos salen de la tabla de HAI, no de la de HAIEnd, y el parentesis")
        w("da el nombre que el **mismo punto** llevaba en una version anterior.")
        w("El PDF los escribe sin el prefijo de proceso (`Auto` por `P2_Auto`),")
        w("de modo que la columna `regla` dice como se resolvio cada uno contra")
        w("las cabeceras reales.")
        w("")
        w("%-22s %-22s %-24s %-24s %s"
          % ("nombre", "nombre anterior", "el nuevo esta en",
             "el anterior esta en", "regla"))
        for k, (rk, rv, ck, cv, regla) in sorted(renombres.items()):
            w("%-22s %-22s %-24s %-24s %s"
              % (rk, rv, ",".join(ck), ",".join(cv), regla))
        w("")
        w("**Es una correccion a la matriz de columnas comunes de")
        w("INFORME.md**, que cuenta coincidencias por nombre exacto y por lo tanto")
        w("subestima en estos %d puntos la continuidad entre versiones de HAI."
          % len(renombres))
        w("No cambia la conclusion --- entre 20.07 y 23.05 siguen faltando")
        w("decenas de columnas --- pero si el numero. Correccion por par de")
        w("versiones, contando los renombres que afectan a cada uno:")
        w("")
        w("%-28s %12s %12s" % ("par de versiones", "renombres",
                               "matriz del EDA"))
        matriz_eda = {("hai-20.07", "hai-21.03"): 58,
                      ("hai-20.07", "hai-22.04"): 46,
                      ("hai-20.07", "hai-23.05"): 38,
                      ("hai-21.03", "hai-22.04"): 67,
                      ("hai-21.03", "hai-23.05"): 59,
                      ("hai-22.04", "hai-23.05"): 79}
        correccion = {}
        for (a, b), n in sorted(matriz_eda.items()):
            extra = sum(1 for _, (_, _, ck, cv, _) in renombres.items()
                        if {a, b} <= set(ck) | set(cv)
                        and not ({a, b} <= set(ck) or {a, b} <= set(cv)))
            correccion["%s|%s" % (a, b)] = {"matriz_eda": n, "renombres": extra,
                                            "corregido": n + extra}
            w("%-28s %12d %7d -> %-4d"
              % ("%s / %s" % (a, b), extra, n, n + extra))
        w("")
        w("Los valores de la columna `matriz del EDA` se transcriben de la tabla")
        w("de la pregunta 5 de `eda/INFORME.md`; los renombres salen de este")
        w("analisis.")
        w("")

        if equiv_invalidas:
            w("#### D.2.c Pares que no se pudieron validar: %d"
              % len(equiv_invalidas))
            w("")
            for k, (v, tabla, ck, cv) in sorted(equiv_invalidas.items()):
                w("  %-22s -> %-22s (%s: %s / %s)"
                  % (k, v, tabla, ",".join(ck) or "en ninguna",
                     ",".join(cv) or "en ninguna"))
            w("")
            w("Son nombres que el PDF usa y las cabeceras no, de modo que la")
            w("correspondencia existe en el documento pero no se puede aplicar")
            w("sobre los archivos.")
            w("")

    w("### D.3 Inventario por version")
    w("")
    resumen = {}
    for version, sep, col_t, patron in HAI_VERSIONES:
        carpeta = os.path.join(comun.HAI, version)
        archivos = sorted(glob.glob(os.path.join(carpeta, patron)))
        if not archivos:
            w("ADVERTENCIA: no hay archivos de entrenamiento en %s." % version)
            continue
        w("#### %s --- %d archivos de entrenamiento" % (version, len(archivos)))
        w("")
        acum = {}
        total = 0
        rango_t = [None, None]
        dts = []
        for a in archivos:
            d = pd.read_csv(a, sep=sep, low_memory=False)
            d.columns = [c.strip() for c in d.columns]
            total += len(d)
            t = pd.to_datetime(d[col_t].astype(str).str.strip())
            rango_t[0] = t.min() if rango_t[0] is None else min(rango_t[0], t.min())
            rango_t[1] = t.max() if rango_t[1] is None else max(rango_t[1], t.max())
            dts.append(t.diff().dt.total_seconds().dropna())
            for c in d.columns:
                e = acum.setdefault(c, {"filas": 0, "no_nulos": 0, "min": None,
                                        "max": None, "valores": set(),
                                        "tope": False, "entero": True})
                s = d[c]
                e["filas"] += len(s)
                e["no_nulos"] += int(s.notna().sum())
                v = pd.to_numeric(s, errors="coerce").dropna()
                if len(v):
                    e["min"] = float(v.min()) if e["min"] is None \
                        else min(e["min"], float(v.min()))
                    e["max"] = float(v.max()) if e["max"] is None \
                        else max(e["max"], float(v.max()))
                    if not np.all(np.equal(np.mod(v, 1), 0)):
                        e["entero"] = False
                if not e["tope"]:
                    e["valores"].update(s.dropna().unique().tolist())
                    if len(e["valores"]) >= TOPE_CARDINALIDAD:
                        e["tope"] = True
                        e["valores"] = set()
            del d
        dt = pd.concat(dts)
        cols = sorted(acum)
        etiquetas = [c for c in cols
                     if c.lower().startswith("attack") or c.lower() == "label"]
        proceso = [c for c in cols if c not in etiquetas and c != col_t]
        w("%d filas, %d columnas. Columna de tiempo: `%s`." % (total, len(cols), col_t))
        w("Rango: %s a %s." % (rango_t[0], rango_t[1]))
        w("Intervalo entre filas: moda %s s, min %s s, max %s s."
          % (dt.mode().iloc[0], dt.min(), dt.max()))
        w("Columnas de etiqueta: %s."
          % (", ".join("`%s`" % c for c in etiquetas) if etiquetas
             else "**ninguna** (las etiquetas vienen en `label-test*.csv`)"))
        w("Columnas de proceso: %d." % len(proceso))
        w("")
        w("%-24s %-7s %-9s %-4s %7s %9s %-22s %s"
          % ("campo", "tipo", "unidad", "proc", "cobert.", "distintos",
             "rango medido", "rango declarado"))
        perf = {}
        for c in cols:
            e = acum[c]
            if c == col_t:
                tipo, uni, proc = "texto", "---", "ID"
            elif c in etiquetas:
                tipo, uni, proc = "entero", "---", "CAT"
            else:
                tipo = "entero" if e["entero"] else "real"
                pt = puntos.get(c)
                uni = pt["unidad"] if pt else "---"
                proc = "PDF" if pt else "RNG"
            card = len(e["valores"]) if not e["tope"] else TOPE_CARDINALIDAD
            cards = ("%d" % card) if not e["tope"] else ">=%d" % TOPE_CARDINALIDAD
            rng = "%.4g .. %.4g" % (e["min"], e["max"]) \
                if e["min"] is not None else "---"
            pt = puntos.get(c)
            dec = "%s .. %s" % (pt["min"], pt["max"]) if pt else "no declarado"
            w("%-24s %-7s %-9s %-4s %6.1f%% %9s %-22s %s"
              % (c[:24], tipo, uni, proc,
                 100 * e["no_nulos"] / e["filas"] if e["filas"] else 0,
                 cards, rng, dec))
            perf[c] = {"tipo": tipo, "unidad": uni, "procedencia": proc,
                       "cobertura": e["no_nulos"] / e["filas"] if e["filas"] else 0,
                       "cardinalidad": card, "tope_cardinalidad": e["tope"],
                       "min": e["min"], "max": e["max"],
                       "declarado_pdf": dec if pt else None}
        w("")
        w("Nivel de agregacion: %s" % NIVELES["proceso"])
        w("")
        sin_unidad = [c for c in proceso if c not in puntos]
        w("Columnas de proceso **sin unidad declarada en el PDF**: %d de %d."
          % (len(sin_unidad), len(proceso)))
        if sin_unidad:
            w("  %s" % ", ".join(sin_unidad[:20]))
            if len(sin_unidad) > 20:
                w("  ... y %d mas." % (len(sin_unidad) - 20))
        w("")
        resumen[version] = {
            "archivos_entrenamiento": len(archivos),
            "filas": total, "columnas": len(cols), "nombres": cols,
            "columna_tiempo": col_t,
            "columnas_etiqueta": etiquetas,
            "columnas_proceso": len(proceso),
            "dt_moda_s": float(dt.mode().iloc[0]),
            "dt_min_s": float(dt.min()), "dt_max_s": float(dt.max()),
            "rango": [str(rango_t[0]), str(rango_t[1])],
            "sin_unidad_declarada": sin_unidad,
            "perfil": perf,
        }

    w("### D.4 La tabla de ataques del PDF: la etiqueta de tipo que los CSV no traen")
    w("")
    ataques = tabla_ataques_hai()
    # recuento de eventos que ya midio 04_hai.py sobre los archivos de prueba
    p = os.path.join(comun.SALIDAS, "p3_p4_p5_hai.json")
    eventos_medidos = {}
    if os.path.exists(p):
        with open(p) as fh:
            eventos_medidos = json.load(fh).get("eventos_prueba", {})
    if ataques:
        w("Las secciones 'ATTACK OPERATION' del PDF publican, **por ataque**:")
        w("identificador, codigo de escenario, controlador atacado, punto de")
        w("proceso atacado, hora de inicio y duracion. **Nada de eso esta en los")
        w("CSV**, donde la etiqueta es binaria.")
        w("")
        w("%-20s %8s %10s %12s %14s %12s"
          % ("version del PDF", "paginas", "ataques", "escenarios",
             "con punto", "eventos medidos"))
        for ver, reg in ataques.items():
            escen = {a["escenario"] for a in reg["ataques"] if a["escenario"]}
            con_punto = sum(1 for a in reg["ataques"] if a["con_punto_atacado"])
            # el recuento medido sobre los archivos lo da 04_hai.py: se cruza
            # por el numero de version, que es lo unico comun a las dos formas
            # de nombrarla ("HAI/HAIEnd 23.05" contra "hai-23.05")
            num = re.search(r"\d{2}\.\d{2}", ver)
            clave = [k for k in eventos_medidos
                     if num and k.endswith(num.group(0))]
            med = ", ".join("%s=%s" % (k, eventos_medidos[k]) for k in clave)
            w("%-20s %8s %10d %12d %14d %12s"
              % (ver, "%d-%d" % (min(reg["paginas"]), max(reg["paginas"])),
                 len(reg["ataques"]), len(escen), con_punto, med or "---"))
        w("")
        w("El recuento del PDF y el que `04_hai.py` midio contando rachas de")
        w("etiqueta sobre los archivos de prueba **coinciden en tres de las")
        w("cuatro versiones**. Es un control cruzado util: la tabla del documento")
        w("describe los mismos ataques que estan etiquetados en los datos.")
        w("")
        w("Lo que esto habilita, y conviene no exagerarlo: se **podria**")
        w("construir una etiqueta por tipo para HAI cruzando la hora de inicio y")
        w("la duracion de esta tabla con las marcas de tiempo de los archivos de")
        w("prueba. No se hace aqui --- seria tocar el tramo de prueba mas alla")
        w("del conteo que el brief admite --- y tiene dos obstaculos: la tabla da")
        w("la hora sin la fecha completa en varias filas, y los codigos de")
        w("escenario (`AP01`, `AE03`) nombran el punto atacado, no una familia de")
        w("anomalia comparable con la taxonomia de Morris.")
        w("")
    else:
        w("No se pudo leer la tabla de ataques del PDF.")
        w("")

    # cabeceras de los archivos de prueba: solo formato, ninguna fila
    w("### D.5 Cabeceras de los archivos de prueba")
    w("")
    w("De los archivos de prueba se lee **solo la cabecera**: es formato, no")
    w("distribucion. Ninguna fila se abrio.")
    w("")
    cab_test = {}
    for version, sep, _, _ in HAI_VERSIONES:
        for p in sorted(glob.glob(os.path.join(comun.HAI, version, "*test*.csv"))):
            with open(p) as fh:
                cab = next(csv.reader(fh, delimiter=sep))
            cab_test[os.path.join(version, os.path.basename(p))] = len(cab)
    w("%-40s %8s" % ("archivo", "campos"))
    for k, v in cab_test.items():
        w("%-40s %8d" % (k, v))
    w("")

    J["hai"] = {"puntos_pdf": puntos,
                "nombres_alternativos_pdf": equiv,
                "cruce_haiend_hai": cruce_haiend,
                "renombres_entre_versiones": renombres,
                "correccion_matriz_hai": correccion,
                "no_validados": equiv_invalidas,
                "tabla_ataques_pdf": ataques,
                "versiones": resumen, "cabeceras_prueba": cab_test}


# ---------------------------------------------------------------------------
# E. QUT DNP3


def qut(w, J):
    w("## E. QUT DNP3")
    w("")
    w("Lo que publica, por escenario y por particion: tres PCAP (`master`,")
    w("`slave`, `attacker`), un `master.csv` y un `slave.csv` con etiquetas por")
    w("paquete, y un directorio `tshark/` con recuentos por segundo y por")
    w("protocolo. Es el unico de los cinco que **no publica ninguna tabla de")
    w("caracteristicas de flujo**.")
    w("")

    # E.1 inventario de archivos del tramo de entrenamiento
    base = comun.QUT
    pcaps = sorted(glob.glob(os.path.join(base, "*", "*", "training", "*",
                                          "*.pcap")))
    etiq = sorted(glob.glob(os.path.join(base, "*", "*", "training", "*",
                                         "master.csv"))
                  + glob.glob(os.path.join(base, "*", "*", "training", "*",
                                           "slave.csv")))
    tsh = sorted(glob.glob(os.path.join(base, "*", "*", "training", "*",
                                        "tshark", "*.csv")))
    w("### E.1 Archivos del tramo de entrenamiento")
    w("")
    w("%-34s %8s %12s" % ("tipo de archivo", "archivos", "MB en disco"))
    for nombre, lista in (("PCAP", pcaps),
                          ("master.csv / slave.csv", etiq),
                          ("tshark/*.csv", tsh)):
        mb = sum(os.path.getsize(p) for p in lista) / 1e6
        w("%-34s %8d %12.1f" % (nombre, len(lista), mb))
    w("")

    w("### E.2 Los PCAP: cero campos publicados")
    w("")
    w("Nivel: %s" % NIVELES["paquete"])
    w("No traen cabecera ni esquema. Todo lo que el proyecto usa de ellos lo")
    w("calcula su propio lector (`eda/scripts/dnp3.py`). Los campos que ese")
    w("lector recupera estan documentados en la pregunta 1 de INFORME.md")
    w("y en `eda/salidas/p1_qut_payload.txt`; **no se vuelven a medir aqui**,")
    w("porque no son campos publicados sino calculados por el proyecto.")
    w("")

    w("### E.3 `master.csv` y `slave.csv`: etiquetas por paquete")
    w("")
    w("Son CSV **sin cabecera**, de tres campos. Medido sobre los %d archivos"
      % len(etiq))
    w("del tramo de entrenamiento:")
    w("")
    vocab = collections.Counter()
    filas = 0
    campos_vistos = collections.Counter()
    idx_min, idx_max = None, None
    for p in etiq:
        with open(p, newline="") as fh:
            for fila in csv.reader(fh):
                campos_vistos[len(fila)] += 1
                if len(fila) != 3:
                    continue
                filas += 1
                vocab[fila[2]] += 1
                try:
                    i = int(fila[0])
                except ValueError:
                    continue
                idx_min = i if idx_min is None else min(idx_min, i)
                idx_max = i if idx_max is None else max(idx_max, i)
    w("%-26s %-7s %-9s %-4s %s"
      % ("campo (posicion)", "tipo", "unidad", "proc", "contenido"))
    w("%-26s %-7s %-9s %-4s %s"
      % ("1  (sin nombre)", "entero", "indice", "RNG",
         "numero de paquete dentro del PCAP, %d .. %d" % (idx_min, idx_max)))
    w("%-26s %-7s %-9s %-4s %s"
      % ("2  (sin nombre)", "texto", "---", "CAT",
         "resumen de la trama en notacion de Scapy"))
    w("%-26s %-7s %-9s %-4s %s"
      % ("3  (sin nombre)", "texto", "---", "CAT",
         "nombre del ataque; %d valores distintos" % len(vocab)))
    w("")
    w("Nivel: %s" % NIVELES["paquete"])
    w("Pero **solo de los paquetes de ataque**: %d filas en total, frente a los"
      % filas)
    w("millones de paquetes de los PCAP. El escenario `Control`, que es la linea")
    w("base sin ataque, **no tiene estos archivos**.")
    w("")
    w("Numero de campos por fila: %s."
      % ", ".join("%d campos en %d filas" % (k, v)
                  for k, v in sorted(campos_vistos.items())))
    w("")
    w("Las %d etiquetas distintas del tramo de entrenamiento:" % len(vocab))
    w("")
    for k, v in vocab.most_common():
        w("  %-44s %8d" % (k, v))
    w("")
    w("Es un vocabulario **mucho mas fino** que el de las siete carpetas de")
    w("escenario: nombra el mecanismo (`MITM_modification_BinaryStatus`,")
    w("`injection_WarmRestart`) y no solo la familia.")
    w("")

    w("### E.4 `tshark/*.csv`: recuentos por ventana de 1 s")
    w("")
    por_nombre = collections.defaultdict(list)
    for p in tsh:
        por_nombre[os.path.basename(p)].append(p)
    ejemplo = None
    for nombre in sorted(por_nombre):
        if "DNP" in nombre and "master" in nombre:
            ejemplo = por_nombre[nombre][0]
            break
    w("%d archivos, %d nombres distintos:" % (len(tsh), len(por_nombre)))
    w("")
    for nombre in sorted(por_nombre):
        w("  %-34s %3d archivos" % (nombre, len(por_nombre[nombre])))
    w("")
    if ejemplo:
        with open(ejemplo) as fh:
            lineas = [l.split() for l in fh if l.strip()]
        n = len(lineas)
        total = sum(int(x[1]) for x in lineas if len(x) == 2)
        w("Medido sobre %s:" % comun.rel(ejemplo))
        w("")
        w("%-26s %-7s %-9s %-4s %s"
          % ("campo (posicion)", "tipo", "unidad", "proc", "contenido"))
        w("%-26s %-7s %-9s %-4s %s"
          % ("1  (sin nombre)", "entero", "s", "ID",
             "segundo desde el inicio, 0 .. %d" % (n - 1)))
        w("%-26s %-7s %-9s %-4s %s"
          % ("2  (sin nombre)", "entero", "paquete", "ID",
             "paquetes de ese protocolo en ese segundo; suma %d" % total))
        w("")
        w("Sin cabecera, separados por espacio. %d lineas = **%d ventanas de 1 s**,"
          % (n, n))
        w("es decir %.2f horas, que es lo que dura el escenario." % (n / 3600.0))
        w("")
        w("Nivel: %s" % NIVELES["ventana"])
        w("")
        w("**Es la unica caracteristica agregada que QUT publica**: una tasa de")
        w("paquetes por segundo, separada por protocolo. La genera `plot_data.sh`")
        w("del propio repositorio para dibujar graficos con gnuplot, de modo que")
        w("es un subproducto, no un conjunto de caracteristicas pensado para")
        w("aprendizaje automatico.")
        w("")

    J["qut"] = {
        "pcaps_entrenamiento": len(pcaps),
        "pcaps_MB": sum(os.path.getsize(p) for p in pcaps) / 1e6,
        "archivos_etiqueta": len(etiq),
        "filas_etiqueta": filas,
        "campos_por_fila_etiqueta": dict(campos_vistos),
        "indice_min": idx_min, "indice_max": idx_max,
        "vocabulario_etiquetas": dict(vocab),
        "etiquetas_distintas": len(vocab),
        "archivos_tshark": len(tsh),
        "nombres_tshark": {k: len(v) for k, v in por_nombre.items()},
        "ventanas_tshark": n if ejemplo else None,
        "ventana_s": 1,
        "publica_tabla_de_flujos": False,
    }


# ---------------------------------------------------------------------------


def main():
    comun.preparar()
    L = []
    w = L.append
    J = {}

    w("# Inventario de las caracteristicas publicadas por cada conjunto")
    w("")
    w("Generado por `eda/scripts/10_inventario_caracteristicas.py`.")
    w("")
    w("Responde la pregunta por las caracteristicas publicadas de")
    w("cada conjunto. Para cada archivo publicado se enumera campo por campo el")
    w("nombre, el tipo medido, la unidad **con su procedencia**, el nivel de")
    w("agregacion, la cobertura, la cardinalidad y el rango.")
    w("")
    w("Codigos de la columna `proc` (procedencia de la unidad):")
    w("")
    w("  ID   la fija una identidad numerica verificada en este analisis")
    w("  ID*  se deduce de una identidad verificada sobre un campo hermano")
    w("  PDF  esta declarada en un documento publicado del conjunto")
    w("  DOC  esta declarada en la pagina del conjunto, transcripta en el repo")
    w("  RNG  **no esta declarada en ninguna parte**: solo hay rango medido")
    w("  CAT  campo categorico o de identidad, sin unidad")
    w("")
    w("Particiones: solo tramo de entrenamiento, con los cortes de")
    w("`eda/INSTRUCCIONES.md`. De los archivos de prueba se lee solo la")
    w("cabecera.")
    w("")
    w("---")
    w("")

    base_w, _, _ = westermo(w, J)
    w("---")
    w("")
    icsflow(w, J, base_w)
    w("---")
    w("")
    morris(w, J)
    w("---")
    w("")
    hai(w, J)
    w("---")
    w("")
    qut(w, J)

    comun.escribir("p10_inventario.txt", "\n".join(L))
    with open(os.path.join(comun.SALIDAS, "p10_inventario.json"), "w") as fh:
        json.dump(J, fh, indent=1, ensure_ascii=False, default=str)
    print("\n[escrito] %s"
          % comun.rel(os.path.join(comun.SALIDAS, "p10_inventario.json")))


if __name__ == "__main__":
    main()
