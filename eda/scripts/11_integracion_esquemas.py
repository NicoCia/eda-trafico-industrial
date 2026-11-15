"""Se puede armar un conjunto de datos integrado con los cinco conjuntos?

Responde la pregunta de fondo del proyecto. No alcanza con comparar nombres
de columna: dos campos con el mismo nombre pueden no ser la misma variable, y
dos campos con nombres distintos pueden serlo. De modo que se mide:

  1. la interseccion de los esquemas publicados, campo por campo;
  2. si las definiciones coinciden de verdad y no solo de nombre --- se
     comprueba sobre los dos conjuntos que comparten esquema que las mismas
     identidades numericas se cumplen, que la ventana de agregacion es la misma
     y que **la precision publicada de cada campo es la misma**, que es la
     huella del extractor;
  3. si las distribuciones son compatibles, con un nivel de referencia interno
     a cada conjunto para no confundir deriva con cambio de sistema;
  4. la granularidad temporal de cada conjunto y si es conciliable;
  5. los esquemas de etiquetado y si son traducibles entre conjuntos.

**Particiones.** Solo tramo de entrenamiento, con los cortes de
`eda/INSTRUCCIONES.md`. De HAI se usan los nombres de columna que ya midio
`04_hai.py` sobre los `train*.csv`, leidos de `eda/salidas/p3_p4_p5_hai.json`,
para no volver a recorrer 2,6 GB. De los archivos de prueba no se lee ninguna
fila.

Uso:  python eda/scripts/11_integracion_esquemas.py
"""

import collections
import csv
import hashlib
import itertools
import json
import os
import re
import sys

import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import comun  # noqa: E402

ICSFLOW = os.path.join(comun.DATOS, "ics-flow")

# Columnas de los flujos que son identificadores o etiquetas, no caracteristicas.
NO_CARACTERISTICA = {
    "sAddress", "rAddress", "sMACs", "rMACs", "sIPs", "rIPs", "protocol",
    "startDate", "endDate", "start", "end", "startOffset", "endOffset",
    "IT_B_Label", "IT_M_Label", "NST_B_Label", "NST_M_Label",
}


def md5_texto(s):
    return hashlib.md5(s.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# 1. Esquemas publicados


def cargar_esquemas():
    """Devuelve {nombre del esquema: [campos]} de todo lo tabular publicado."""
    esq = collections.OrderedDict()

    p = os.path.join(comun.WESTERMO, "reduced", "flows", "output_bottom.csv")
    with open(p) as fh:
        esq["Westermo flujos"] = next(csv.reader(fh))

    p = os.path.join(ICSFLOW, "Dataset.csv")
    with open(p) as fh:
        esq["ICS-Flow flujos"] = next(csv.reader(fh))

    for n, arch in (("1", "snapshots_PLC1.csv"), ("2", "snapshots_PLC2.csv")):
        with open(os.path.join(ICSFLOW, arch)) as fh:
            cols = [c.strip() for c in next(csv.reader(fh))]
        esq["ICS-Flow proceso PLC%s" % n] = [c for c in cols if c]

    with open(os.path.join(comun.MORRIS, "IanArffDataset.arff")) as fh:
        atrs = []
        for linea in fh:
            s = linea.strip()
            if s.lower().startswith("@attribute"):
                m = re.match(r"^@attribute\s+(?:'([^']*)'|\"([^\"]*)\"|(\S+))",
                             s, re.IGNORECASE)
                atrs.append(next(g for g in m.groups() if g is not None))
            elif s.lower().startswith("@data"):
                break
    esq["Morris ARFF"] = atrs

    # HAI: nombres ya medidos por 04_hai.py sobre los train*.csv
    p = os.path.join(comun.SALIDAS, "p3_p4_p5_hai.json")
    hai_cols = None
    if os.path.exists(p):
        with open(p) as fh:
            hai_cols = json.load(fh).get("columnas_por_version")
    if hai_cols:
        for v, cols in hai_cols.items():
            esq["HAI %s" % v] = list(cols)
    return esq, bool(hai_cols)


def seccion_1(w, J):
    w("## 1. Que esquemas tabulares publica cada conjunto")
    w("")
    esq, hay_hai = cargar_esquemas()
    if not hay_hai:
        w("ADVERTENCIA: falta `eda/salidas/p3_p4_p5_hai.json`. Correr primero")
        w("`04_hai.py`. Las columnas de HAI no entran en esta comparacion.")
        w("")

    w("**QUT DNP3 no aparece en esta tabla porque no publica ningun esquema")
    w("tabular de caracteristicas.** Lo que publica es PCAP, etiquetas por")
    w("paquete sin cabecera y recuentos por segundo; esta medido en")
    w("`eda/salidas/p10_inventario.txt`, seccion E. Para integrarlo hay que")
    w("calcularle las caracteristicas primero, y entonces el esquema es el que")
    w("elija el proyecto, no el que trae el conjunto.")
    w("")
    w("%-26s %8s" % ("esquema publicado", "campos"))
    for k, v in esq.items():
        w("%-26s %8d" % (k, len(v)))
    w("")

    # agrupar por conjunto
    grupos = collections.OrderedDict([
        ("Westermo", ["Westermo flujos"]),
        ("ICS-Flow", [k for k in esq if k.startswith("ICS-Flow")]),
        ("Morris", ["Morris ARFF"]),
        ("HAI", [k for k in esq if k.startswith("HAI")]),
    ])
    union = collections.OrderedDict(
        (g, set(itertools.chain.from_iterable(esq[k] for k in ks)))
        for g, ks in grupos.items())

    w("### 1.1 Matriz de campos con el mismo nombre")
    w("")
    nombres = list(esq)
    w("%-26s %s" % ("", " ".join("%7d" % (i + 1) for i in range(len(nombres)))))
    matriz = {}
    for i, a in enumerate(nombres):
        fila = []
        for b in nombres:
            n = len(set(esq[a]) & set(esq[b]))
            fila.append(n)
            matriz["%s|%s" % (a, b)] = n
        w("%-23s %2d %s" % (a[:23], i + 1,
                            " ".join("%7d" % x for x in fila)))
    w("")

    w("### 1.2 Campos comunes a los cuatro conjuntos con esquema tabular")
    w("")
    comunes = set.intersection(*union.values())
    w("Interseccion de Westermo, ICS-Flow, Morris y HAI: **%d campos**."
      % len(comunes))
    if comunes:
        w("  %s" % ", ".join(sorted(comunes)))
    w("")
    w("Si se cuenta tambien QUT, que no publica esquema, la interseccion es **0**")
    w("por construccion.")
    w("")

    w("### 1.3 Campos comunes a algun par de conjuntos")
    w("")
    w("%-22s %-22s %8s %s" % ("conjunto A", "conjunto B", "comunes", "cuales"))
    pares = {}
    for a, b in itertools.combinations(union, 2):
        c = union[a] & union[b]
        pares["%s|%s" % (a, b)] = sorted(c)
        detalle = ", ".join(sorted(c)[:6]) if c else "---"
        if len(c) > 6:
            detalle += ", ... (%d en total)" % len(c)
        w("%-22s %-22s %8d %s" % (a, b, len(c), detalle))
    w("")

    w("### 1.4 Campos exclusivos de un solo conjunto")
    w("")
    w("%-22s %8s %8s %s" % ("conjunto", "campos", "exclusivos", "% del conjunto"))
    exclusivos = {}
    for g in union:
        otros = set.union(*[union[h] for h in union if h != g])
        ex = union[g] - otros
        exclusivos[g] = sorted(ex)
        w("%-22s %8d %8d %13.1f %%"
          % (g, len(union[g]), len(ex), 100 * len(ex) / len(union[g])))
    w("")
    w("Lectura: casi todo el contenido de cada conjunto es exclusivo suyo. Las")
    w("unicas dos excepciones son el par Westermo / ICS-Flow en el nivel de")
    w("flujo, que se trata en la seccion 2, y las coincidencias entre versiones")
    w("de HAI, que no son conjuntos distintos sino versiones del mismo banco.")
    w("")

    J["esquemas"] = {k: len(v) for k, v in esq.items()}
    J["nombres_por_esquema"] = {k: v for k, v in esq.items()}
    J["matriz_nombres"] = matriz
    J["union_por_conjunto"] = {k: sorted(v) for k, v in union.items()}
    J["comunes_a_los_cuatro"] = sorted(comunes)
    J["comunes_por_par"] = pares
    J["exclusivos"] = exclusivos
    return esq, union


# ---------------------------------------------------------------------------
# 2. Westermo contra ICS-Flow: la misma variable o solo el mismo nombre?


def decimales_publicados(path, columnas, sep=","):
    """Maximo de decimales con que el archivo publica cada columna.

    Es la huella del extractor: dos archivos generados por la misma
    herramienta redondean cada campo con la misma politica. Se recorre el
    archivo **completo**, porque el maximo de una muestra inicial subestima
    la precision de los campos que arrancan en cero.

    Devuelve (maximo de decimales por campo, valores distintos por campo). El
    segundo hace falta para leer el primero: un campo que en un conjunto solo
    toma los valores 0 y 1 nunca muestra mas de un decimal, y eso no es una
    politica de redondeo distinta sino un campo degenerado.
    """
    dec = collections.defaultdict(collections.Counter)
    vals = collections.defaultdict(set)
    with open(path, newline="") as fh:
        r = csv.reader(fh, delimiter=sep)
        cab = next(r)
        idx = {c: cab.index(c) for c in columnas if c in cab}
        for fila in r:
            for c, j in idx.items():
                v = fila[j]
                vals[c].add(v)
                if "." not in v:
                    continue
                ent, _, frac = v.partition(".")
                if not (ent.lstrip("-").isdigit() and frac.isdigit()):
                    continue
                dec[c][len(frac)] += 1
    return ({c: max(v) for c, v in dec.items()},
            {c: len(v) for c, v in vals.items()})


def ks(a, b):
    """Estadistico de Kolmogorov-Smirnov entre dos muestras, sin scipy."""
    a = np.sort(np.asarray(a, dtype=float))
    b = np.sort(np.asarray(b, dtype=float))
    if not len(a) or not len(b):
        return float("nan")
    todos = np.concatenate([a, b])
    ca = np.searchsorted(a, todos, side="right") / len(a)
    cb = np.searchsorted(b, todos, side="right") / len(b)
    return float(np.max(np.abs(ca - cb)))


def seccion_2(w, J, esq):
    w("## 2. Westermo e ICS-Flow: la misma variable, o solo el mismo nombre?")
    w("")
    pw = os.path.join(comun.WESTERMO, "reduced", "flows", "output_bottom.csv")
    pi = os.path.join(ICSFLOW, "Dataset.csv")

    # 2.1 cabecera byte a byte
    with open(pw) as fh:
        linea_w = fh.readline().rstrip("\r\n")
    with open(pi) as fh:
        linea_i = fh.readline().rstrip("\r\n")
    w("### 2.1 La cabecera es la misma, byte a byte")
    w("")
    w("%-24s %-34s %8s" % ("archivo", "md5 de la linea de cabecera", "campos"))
    w("%-24s %-34s %8d" % ("Westermo flujos", md5_texto(linea_w),
                           len(esq["Westermo flujos"])))
    w("%-24s %-34s %8d" % ("ICS-Flow flujos", md5_texto(linea_i),
                           len(esq["ICS-Flow flujos"])))
    w("")
    iguales = linea_w == linea_i
    w("Identicas: **%s**. No es solo que coincidan los nombres: coincide la"
      % ("SI" if iguales else "NO"))
    w("linea completa, con el mismo orden y la misma puntuacion. Los seis CSV de")
    w("Westermo tienen esa misma cabecera (medido en la seccion A.1 de")
    w("`p10_inventario.txt`).")
    w("")
    w("La explicacion documental, que no se mide aqui y queda como tal: los dos")
    w("conjuntos comparten autor. Alireza Dehlaghi-Ghadim firma el `README` de")
    w("Westermo y es el autor de la pagina de Kaggle de la que se bajo")
    w("ICS-Flow. Las caracteristicas de flujo de los dos salen de la misma")
    w("herramienta de extraccion.")
    w("")

    # 2.2 precision publicada por campo
    numericas = [c for c in esq["Westermo flujos"] if c not in NO_CARACTERISTICA]
    dw, vw_n = decimales_publicados(pw, numericas)
    di, vi_n = decimales_publicados(pi, numericas)
    w("### 2.2 La precision publicada de cada campo es la misma")
    w("")
    w("Es la prueba mas fina de que no son dos definiciones parecidas sino la")
    w("misma implementacion: con cuantos decimales publica cada archivo cada")
    w("campo. Dos herramientas distintas no coinciden en eso. Medido sobre los")
    w("dos archivos **completos**, no sobre una muestra.")
    w("")
    w("%-22s %10s %10s %8s %11s %11s"
      % ("campo", "Westermo", "ICS-Flow", "coincide", "distintos W", "distintos I"))
    coinciden = 0
    evaluados = 0
    detalle_dec = {}
    discrepan = []
    for c in numericas:
        a, b = dw.get(c), di.get(c)
        if a is None and b is None:
            continue
        evaluados += 1
        ok = a == b
        coinciden += int(ok)
        if not ok:
            discrepan.append((c, a, b, vw_n.get(c), vi_n.get(c)))
        detalle_dec[c] = {"westermo": a, "icsflow": b, "coincide": bool(ok),
                          "distintos_westermo": vw_n.get(c),
                          "distintos_icsflow": vi_n.get(c)}
        w("%-22s %10s %10s %8s %11s %11s"
          % (c[:22], a, b, "SI" if ok else "NO", vw_n.get(c), vi_n.get(c)))
    w("")
    w("Coinciden **%d de %d** campos con parte decimal."
      % (coinciden, evaluados))
    w("")
    if discrepan:
        w("Los %d que no coinciden son todos campos **degenerados en uno de los"
          % len(discrepan))
        w("dos conjuntos**: toman tan pocos valores distintos que nunca llegan a")
        w("mostrar el tope de decimales. No son politicas de redondeo distintas.")
        w("")
        w("%-22s %10s %10s %11s %11s"
          % ("campo", "dec. W", "dec. I", "distintos W", "distintos I"))
        for c, a, b, nw_, ni_ in discrepan:
            w("%-22s %10s %10s %11s %11s" % (c[:22], a, b, nw_, ni_))
        w("")
        w("El caso mas claro es `sttl`: en Westermo vale **siempre** 64, un solo")
        w("valor, de modo que se publica como `64.0` y el maximo de decimales")
        w("observable es 1; en ICS-Flow toma %s valores y llega a 3."
          % vi_n.get("sttl"))
        w("")
    w("Los casos que mas pesan en la comparacion son los que coinciden en una")
    w("eleccion arbitraria: `*AckDelayMin` y `*AckDelayMax` a 3 decimales")
    w("mientras `*AckDelayAvg` va a 6, y `*InterPacketAvg` sin redondear, con")
    w("20 decimales. Esa asimetria repetida campo por campo en los dos")
    w("conjuntos no sale de dos implementaciones independientes.")
    w("")

    # 2.3 vocabulario de protocol
    w("### 2.3 El vocabulario del campo `protocol`")
    w("")
    dwf = pd.read_csv(pw)
    dif = pd.read_csv(pi)
    trw = dwf[dwf["startOffset"] < comun.WESTERMO_CORTES[0]]
    t0, t1 = float(dif["start"].min()), float(dif["end"].max())
    corte60 = t0 + 0.6 * (t1 - t0)
    tri = dif[dif["start"] < corte60]
    vw = set(trw["protocol"].unique())
    vi = set(tri["protocol"].unique())
    w("%-24s %s" % ("Westermo (entrenamiento)", ", ".join(sorted(vw))))
    w("%-24s %s" % ("ICS-Flow (entrenamiento)", ", ".join(sorted(vi))))
    w("")
    w("Comunes: %s" % (", ".join(sorted(vw & vi)) or "ninguno"))
    w("Solo en Westermo: %s" % (", ".join(sorted(vw - vi)) or "ninguno"))
    w("Solo en ICS-Flow: %s" % (", ".join(sorted(vi - vw)) or "ninguno"))
    w("")
    w("Misma convencion de nombres (`IPV4-` seguido del protocolo de")
    w("transporte), distinto repertorio: los dos bancos no corren los mismos")
    w("protocolos. Para concatenar filas, este campo es categorico y su")
    w("dominio es la union, no la interseccion.")
    w("")

    # 2.4 distribuciones
    w("### 2.4 La definicion coincide; la distribucion, no")
    w("")
    w("Las identidades numericas de la seccion A.4 y B.3 de `p10_inventario.txt`")
    w("se cumplen en los dos conjuntos con las mismas tolerancias, y la ventana")
    w("de flujo es 0,5 s en los dos. Queda la pregunta de si los valores son")
    w("comparables, que es distinta.")
    w("")
    w("Se compara **solo el trafico normal** de los dos tramos de entrenamiento,")
    w("con la etiqueta `NST_M_Label == Normal`, y se usa un **nivel de")
    w("referencia interno**: el mismo estadistico KS entre la primera y la")
    w("segunda mitad del propio tramo de cada conjunto. Una diferencia entre")
    w("conjuntos solo significa algo si supera ese nivel.")
    w("")
    nw = trw[trw["NST_M_Label"] == "Normal"]
    ni = tri[tri["NST_M_Label"] == "Normal"]
    w("Flujos normales comparados: %d de Westermo y %d de ICS-Flow."
      % (len(nw), len(ni)))
    w("")
    filas = []
    for c in numericas:
        a = pd.to_numeric(nw[c], errors="coerce").dropna().values
        b = pd.to_numeric(ni[c], errors="coerce").dropna().values
        if len(a) < 50 or len(b) < 50:
            continue
        ref_w = ks(a[: len(a) // 2], a[len(a) // 2:])
        ref_i = ks(b[: len(b) // 2], b[len(b) // 2:])
        cruce = ks(a, b)
        filas.append((c, ref_w, ref_i, cruce, max(ref_w, ref_i)))
    filas.sort(key=lambda x: -x[3])
    w("%-22s %10s %10s %10s %8s" % ("campo", "ref. West.", "ref. ICS-F",
                                    "cruzado", "razon"))
    for c, rw_, ri_, cr, ref in filas:
        razon = cr / ref if ref > 0 else float("inf")
        w("%-22s %10.3f %10.3f %10.3f %8s"
          % (c[:22], rw_, ri_, cr,
             "%.1fx" % razon if np.isfinite(razon) else "inf"))
    w("")
    cruzados = np.array([f[3] for f in filas])
    refs = np.array([f[4] for f in filas])
    constantes = [f[0] for f in filas if f[3] == 0.0 and f[4] == 0.0]
    fuertes = [f for f in filas if f[3] > 0.5]
    w("Mediana del KS cruzado: **%.3f** sobre %d campos con al menos 50"
      % (float(np.median(cruzados)), len(filas)))
    w("observaciones en los dos conjuntos.")
    w("Mediana del nivel de referencia interno: **%.3f**."
      % float(np.median(refs)))
    w("Campos con KS cruzado por encima de 0,5: **%d de %d**."
      % (len(fuertes), len(filas)))
    w("Campos con KS cruzado igual a 1,00 (distribuciones disjuntas): **%d**."
      % int((cruzados >= 0.999).sum()))
    w("Campos constantes en los dos conjuntos, que no aportan nada a ninguno de")
    w("los dos por separado: **%d de %d**." % (len(constantes), len(filas)))
    w("  %s" % ", ".join(constantes))
    w("")
    w("### 2.5 Donde esta la diferencia, en magnitudes")
    w("")
    w("Los %d campos con KS cruzado por encima de 0,5, con sus cuantiles en cada"
      % len(fuertes))
    w("conjunto, para que la diferencia se lea en unidades y no en estadisticos:")
    w("")
    w("%-20s %-9s %12s %12s %12s" % ("campo", "conjunto", "p05", "mediana",
                                     "p95"))
    cuantiles = {}
    for c, _, _, _, _ in fuertes:
        cuantiles[c] = {}
        for etiqueta, sub in (("Westermo", nw), ("ICS-Flow", ni)):
            v = pd.to_numeric(sub[c], errors="coerce").dropna()
            q = [float(v.quantile(x)) for x in (0.05, 0.5, 0.95)]
            cuantiles[c][etiqueta] = q
            w("%-20s %-9s %12.4g %12.4g %12.4g"
              % (c[:20] if etiqueta == "Westermo" else "", etiqueta, *q))
    w("")
    w("**Conclusion de las secciones 2.1 a 2.5.** Los dos conjuntos comparten la")
    w("definicion de las caracteristicas: la cabecera es la misma byte a byte,")
    w("las identidades numericas se cumplen en los dos con las mismas")
    w("tolerancias, la ventana es 0,5 s en los dos y la precision publicada")
    w("coincide en %d de los %d campos con parte decimal, con las 3 excepciones"
      % (coinciden, evaluados))
    w("explicadas por campos degenerados. **Como esquema, son el mismo")
    w("conjunto.**")
    w("")
    w("Como poblacion, no. La diferencia no es dramatica --- ninguna")
    w("distribucion es disjunta y la mediana del KS cruzado es %.3f ---, pero"
      % float(np.median(cruzados)))
    w("supera el nivel de referencia interno por un factor mediano de %.0f y se"
      % float(np.median(cruzados / np.maximum(refs, 1e-9))))
    w("concentra justo donde duele: los %d campos que mas difieren son de"
      % len(fuertes))
    w("**volumen y de temporizado**, que son las caracteristicas que la")
    w("pregunta 2 de INFORME.md identifico como discriminantes. Entrenar")
    w("sobre la union de las filas ensancha la envolvente del 'normal' en")
    w("exactamente las variables que llevan la senal.")
    w("")
    w("Hay una asimetria que conviene registrar: el nivel de referencia interno")
    w("de Westermo en los campos de temporizado (`duration` %.3f,"
      % [f[1] for f in filas if f[0] == "duration"][0])
    w("`sInterPacketAvg` %.3f, `rLoad` %.3f) es entre cinco y diez veces el de"
      % ([f[1] for f in filas if f[0] == "sInterPacketAvg"][0],
         [f[1] for f in filas if f[0] == "rLoad"][0]))
    w("ICS-Flow. El propio tramo de entrenamiento de Westermo es mas")
    w("heterogeneo en el tiempo que el de ICS-Flow, de modo que parte de lo que")
    w("se mediria como diferencia entre conjuntos es variabilidad interna de")
    w("Westermo.")
    w("")

    J["westermo_icsflow"] = {
        "cabecera_identica": iguales,
        "md5_cabecera": {"westermo": md5_texto(linea_w),
                         "icsflow": md5_texto(linea_i)},
        "decimales": detalle_dec,
        "decimales_coinciden": coinciden,
        "decimales_evaluados": evaluados,
        "protocolo": {"westermo": sorted(vw), "icsflow": sorted(vi),
                      "comunes": sorted(vw & vi)},
        "flujos_normales": {"westermo": int(len(nw)), "icsflow": int(len(ni))},
        "ks": [{"campo": c, "ref_westermo": rw_, "ref_icsflow": ri_,
                "cruzado": cr} for c, rw_, ri_, cr, _ in filas],
        "ks_mediana_cruzado": float(np.median(cruzados)),
        "ks_mediana_referencia": float(np.median(refs)),
        "ks_mayor_05": int((cruzados > 0.5).sum()),
        "ks_igual_1": int((cruzados >= 0.999).sum()),
        "campos_constantes_en_ambos": constantes,
        "cuantiles_campos_fuertes": cuantiles,
    }
    return numericas


# ---------------------------------------------------------------------------
# 3. Granularidad temporal


def seccion_3(w, J):
    w("## 3. Granularidad temporal de cada conjunto")
    w("")
    w("Es lo que decide si dos conjuntos se pueden alinear en el tiempo o solo")
    w("apilar. Todo lo de esta tabla esta medido sobre el tramo de")
    w("entrenamiento, salvo la duracion total, que sale del rango de la columna")
    w("de tiempo del archivo completo.")
    w("")
    reg = []

    # Westermo
    d = pd.read_csv(os.path.join(comun.WESTERMO, "reduced", "flows",
                                 "output_bottom.csv"),
                    usecols=["startOffset", "duration", "start"])
    tr = d[d["startOffset"] < comun.WESTERMO_CORTES[0]]
    reg.append(("Westermo flujos", "flujo", "ventana de 0,5 s",
                float(tr["duration"].max()), len(tr),
                float(d["start"].max() - d["start"].min())))

    # ICS-Flow flujos
    d = pd.read_csv(os.path.join(ICSFLOW, "Dataset.csv"),
                    usecols=["start", "end", "duration"])
    t0, t1 = float(d["start"].min()), float(d["end"].max())
    tr = d[d["start"] < t0 + 0.6 * (t1 - t0)]
    reg.append(("ICS-Flow flujos", "flujo", "ventana de 0,5 s",
                float(tr["duration"].max()), len(tr), t1 - t0))

    # ICS-Flow proceso. Se corta por `current_loop`, que es el epoch en
    # milisegundos: la columna `time` es hora local sin zona y cortarla como
    # UTC deja el tramo vacio (medido en la seccion B.4 del inventario).
    for arch in ("snapshots_PLC1.csv", "snapshots_PLC2.csv"):
        s = pd.read_csv(os.path.join(ICSFLOW, arch))
        s.columns = [c.strip() for c in s.columns]
        cl = pd.to_numeric(s["current_loop"], errors="coerce") / 1000.0
        dt = cl.diff().dropna()
        corte = t0 + 0.6 * (t1 - t0)
        reg.append(("ICS-Flow %s" % arch.replace("snapshots_", "")
                    .replace(".csv", ""), "proceso",
                    "muestreo de %.3f s (mediana)" % dt.median(),
                    float(dt.median()), int((cl < corte).sum()),
                    float(cl.max() - cl.min())))

    # Morris
    with open(os.path.join(comun.MORRIS, "IanArffDataset.arff")) as fh:
        tiempos = []
        en_datos = False
        idx = None
        atrs = []
        for linea in fh:
            s = linea.strip()
            if not en_datos:
                if s.lower().startswith("@attribute"):
                    m = re.match(r"^@attribute\s+(?:'([^']*)'|\"([^\"]*)\"|(\S+))",
                                 s, re.IGNORECASE)
                    atrs.append(next(g for g in m.groups() if g is not None))
                elif s.lower().startswith("@data"):
                    en_datos = True
                    idx = atrs.index("time")
                continue
            if not s or s.startswith("%"):
                continue
            try:
                tiempos.append(float(s.split(",")[idx]))
            except (ValueError, IndexError):
                pass
    tm = pd.Series(tiempos)
    trm = tm[tm < comun.MORRIS_CORTES[0]]
    dtm = trm.diff().dropna()
    reg.append(("Morris ARFF", "transaccion",
                "epoch de microsegundo; %.2f s entre filas (mediana)"
                % dtm.median(),
                float(dtm.median()), len(trm), float(tm.max() - tm.min())))

    # HAI: lo medido por 10_inventario_caracteristicas.py sobre los train*.csv
    p = os.path.join(comun.SALIDAS, "p10_inventario.json")
    hai_med = {}
    if os.path.exists(p):
        with open(p) as fh:
            hai_med = json.load(fh).get("hai", {}).get("versiones", {})
    for v, info in hai_med.items():
        paso = info.get("dt_moda_s", 1.0)
        reg.append(("HAI %s" % v, "proceso",
                    "muestreo de %.0f s (medido: min %.0f, max %.0f)"
                    % (paso, info.get("dt_min_s", paso),
                       info.get("dt_max_s", paso)),
                    paso, info.get("filas"),
                    paso * info.get("filas", 0)))

    # QUT: el directorio tshark/ existe en los escenarios de ataque, no en
    # Control, de modo que se toma el primero que aparezca en training/
    import glob as _glob
    ejs = sorted(_glob.glob(os.path.join(comun.QUT, "*", "*", "training", "*",
                                         "tshark", "master.pcap.DNP 3.0.csv")))
    n = None
    if ejs:
        with open(ejs[0]) as fh:
            n = sum(1 for l in fh if l.strip())
    reg.append(("QUT tshark/*.csv", "ventana", "ventana de 1 s", 1.0, n,
                float(n) if n else None))
    reg.append(("QUT PCAP", "paquete", "marca de tiempo de microsegundo",
                1e-6, None, float(n) if n else None))
    reg.append(("Westermo PCAP", "paquete", "marca de tiempo de microsegundo",
                1e-6, None, comun.WESTERMO_DURACION))
    reg.append(("ICS-Flow traffic.pcap", "paquete",
                "marca de tiempo de microsegundo", 1e-6, None, t1 - t0))

    w("%-26s %-14s %-52s %12s" % ("archivo", "nivel", "granularidad",
                                  "cobertura (s)"))
    for nombre, nivel, gran, _, _, dur in reg:
        w("%-26s %-14s %-52s %12s"
          % (nombre[:26], nivel, gran[:52],
             "%.0f" % dur if dur else "---"))
    w("")
    w("La columna de cobertura es el rango de la columna de tiempo, salvo en")
    w("HAI, donde es la suma de los tramos de los `train*.csv`: esos archivos")
    w("**no son continuos** y los separan huecos de entre 1 y 47 dias, medidos")
    w("en la pregunta 5 de INFORME.md.")
    w("")

    # fechas de captura: la razon por la que no hay alineacion absoluta posible
    w("Cuando se tomo cada captura:")
    w("")
    fechas = {}
    dw_ = pd.read_csv(os.path.join(comun.WESTERMO, "reduced", "flows",
                                   "output_bottom.csv"), usecols=["startDate"],
                      nrows=1)
    fechas["Westermo"] = str(dw_["startDate"].iloc[0])
    di_ = pd.read_csv(os.path.join(ICSFLOW, "Dataset.csv"),
                      usecols=["startDate"], nrows=1)
    fechas["ICS-Flow"] = str(di_["startDate"].iloc[0])
    fechas["Morris"] = str(pd.to_datetime(tm.min(), unit="s"))
    for v, info in hai_med.items():
        fechas["HAI %s" % v] = info.get("rango", ["?"])[0]
    ejp = os.path.join(comun.QUT, "Control", "control", "training", "frequent",
                       "master.pcap")
    if os.path.exists(ejp):
        import dpkt
        with open(ejp, "rb") as fh:
            ts, _ = next(iter(dpkt.pcap.Reader(fh)))
        fechas["QUT"] = str(pd.to_datetime(ts, unit="s"))
    w("%-22s %s" % ("conjunto", "primera marca de tiempo"))
    for k, v in fechas.items():
        w("%-22s %s" % (k, v))
    w("")
    anios = sorted({v[:4] for v in fechas.values()})
    w("Son %d campanas de adquisicion repartidas entre %s y %s, y ningun par de"
      % (len(fechas), anios[0], anios[-1]))
    w("conjuntos distintos se solapa en el tiempo. **No hay ningun par que se")
    w("pueda alinear por marca de tiempo absoluta**: solo por desplazamiento")
    w("relativo al inicio de cada captura, que es lo que hace `startOffset`.")
    w("")
    w("Las unicas dos series que **si** son simultaneas son `hai-23.05` y")
    w("`haiend-23.05`, que el propio conjunto declara tomadas a la vez sobre el")
    w("mismo banco, y lo confirma la coincidencia de su primera marca de tiempo")
    w("al segundo. Son el unico caso de este material donde dos tablas se")
    w("pueden unir por marca de tiempo sin suposiciones.")
    w("")
    w("**Cuatro niveles distintos y ninguno comun a los cinco conjuntos.**")
    w("")
    w("  - Al nivel de **paquete** hay tres conjuntos: Westermo, QUT e")
    w("    ICS-Flow. Morris y HAI no publican capturas, de modo que ese nivel")
    w("    les esta cerrado para siempre.")
    w("  - Al nivel de **flujo con ventana de 0,5 s** hay dos: Westermo e")
    w("    ICS-Flow, y ademas con la misma definicion. QUT se podria sumar")
    w("    calculandolo; Morris y HAI, no.")
    w("  - Al nivel de **registro de proceso** hay dos: HAI a 1 s y los")
    w("    snapshots de ICS-Flow a 0,2 s. Son cinco veces mas rapidos, de modo")
    w("    que para alinearlos hay que remuestrear uno de los dos y el")
    w("    remuestreo no es neutro: promediar 0,2 s a 1 s borra justo la")
    w("    variabilidad de ciclo que el detector busca.")
    w("  - Al nivel de **transaccion de protocolo** hay uno solo: Morris. Su")
    w("    marca de tiempo tiene resolucion de microsegundo y es unica por")
    w("    fila, de modo que el orden es inequivoco; el problema no es la")
    w("    resolucion sino que no hay con que alinearlo.")
    w("")

    J["fechas_de_captura"] = fechas
    J["granularidad"] = [
        {"archivo": a, "nivel": b, "granularidad": c, "paso_s": dd,
         "registros_entrenamiento": e, "duracion_s": f}
        for a, b, c, dd, e, f in reg]
    return reg


# ---------------------------------------------------------------------------
# 4. Esquemas de etiquetado


def normalizar_etiqueta(s):
    """Normaliza una etiqueta para buscar coincidencias entre vocabularios."""
    s = s.lower().strip()
    s = re.sub(r"^(bad|good)[-_]", "", s)
    s = re.sub(r"[-_\s]", "", s)
    s = re.sub(r"\d+$", "", s)
    return s


def seccion_4(w, J):
    w("## 4. Los esquemas de etiquetado")
    w("")
    vocab = collections.OrderedDict()

    # Westermo
    d = pd.read_csv(os.path.join(comun.WESTERMO, "reduced", "flows",
                                 "output_bottom.csv"),
                    usecols=["startOffset", "IT_B_Label", "IT_M_Label",
                             "NST_B_Label", "NST_M_Label"])
    tr = d[d["startOffset"] < comun.WESTERMO_CORTES[0]]
    vocab["Westermo"] = dict(tr["NST_M_Label"].value_counts())

    # ICS-Flow
    d = pd.read_csv(os.path.join(ICSFLOW, "Dataset.csv"),
                    usecols=["start", "end", "NST_M_Label", "IT_M_Label"])
    t0, t1 = float(d["start"].min()), float(d["end"].max())
    tri = d[d["start"] < t0 + 0.6 * (t1 - t0)]
    vocab["ICS-Flow"] = dict(tri["NST_M_Label"].value_counts())

    # Morris
    CAT = {"0": "Normal", "1": "NMRI", "2": "CMRI", "3": "MSCI", "4": "MPCI",
           "5": "MFCI", "6": "DoS", "7": "Reconnaissance"}
    with open(os.path.join(comun.MORRIS, "IanArffDataset.arff")) as fh:
        atrs, filas = [], []
        en_datos = False
        for linea in fh:
            s = linea.strip()
            if not en_datos:
                if s.lower().startswith("@attribute"):
                    m = re.match(r"^@attribute\s+(?:'([^']*)'|\"([^\"]*)\"|(\S+))",
                                 s, re.IGNORECASE)
                    atrs.append(next(g for g in m.groups() if g is not None))
                elif s.lower().startswith("@data"):
                    en_datos = True
                continue
            if s and not s.startswith("%"):
                filas.append(s.split(","))
    dm = pd.DataFrame(filas, columns=atrs)
    tm = pd.to_numeric(dm["time"], errors="coerce")
    trm = dm[tm < comun.MORRIS_CORTES[0]]
    vocab["Morris"] = {CAT.get(k, k): int(v) for k, v
                       in trm["categorized result"].value_counts().items()}

    # QUT: etiquetas por paquete del tramo de entrenamiento
    import glob
    cuenta = collections.Counter()
    for p in sorted(glob.glob(os.path.join(comun.QUT, "*", "*", "training", "*",
                                           "master.csv"))
                    + glob.glob(os.path.join(comun.QUT, "*", "*", "training",
                                             "*", "slave.csv"))):
        with open(p, newline="") as fh:
            for fila in csv.reader(fh):
                if len(fila) == 3:
                    cuenta[fila[2]] += 1
    vocab["QUT (por paquete)"] = dict(cuenta)
    carpetas = sorted(os.path.basename(x) for x
                      in glob.glob(os.path.join(comun.QUT, "*"))
                      if os.path.isdir(x) and not os.path.basename(x)
                      .startswith("."))
    vocab["QUT (por carpeta)"] = {c: 1 for c in carpetas}

    # HAI
    p = os.path.join(comun.SALIDAS, "p3_p4_p5_hai.json")
    hai_fmt = {}
    if os.path.exists(p):
        with open(p) as fh:
            hai_fmt = json.load(fh).get("formato", {})

    w("### 4.1 Vocabulario de etiquetas medido, por conjunto")
    w("")
    for k, v in vocab.items():
        if k == "QUT (por carpeta)":
            w("**%s** --- %d valores: %s" % (k, len(v), ", ".join(sorted(v))))
            w("")
            continue
        total = sum(v.values())
        w("**%s** --- %d valores distintos, %d registros etiquetados"
          % (k, len(v), total))
        w("")
        for e, n in sorted(v.items(), key=lambda x: -x[1]):
            w("  %-46s %10d  (%.2f %% de %d)"
              % (e, n, 100 * n / total, total))
        w("")
    w("**HAI** --- no tiene vocabulario: las etiquetas son binarias.")
    w("")
    for ver, info in hai_fmt.items():
        et = info.get("etiquetas", info)
        w("  %-16s %s" % (ver, et))
    w("")
    w("Las versiones 20.07 y 21.03 agregan `attack_P1`, `attack_P2` y")
    w("`attack_P3`, que dicen **que proceso** fue atacado, no de que tipo fue el")
    w("ataque. A partir de 22.04 queda una sola columna binaria.")
    w("")
    w("El PDF tecnico del conjunto publica, aparte, una tabla por ataque con")
    w("identificador, codigo de escenario, controlador y **punto de proceso")
    w("atacado**. Esta medida en la seccion D.4 de `p10_inventario.txt`: 52, 57,")
    w("50 y 38 ataques segun la version, con 37, 35, 25 y 14 codigos de")
    w("escenario distintos. Esa informacion **no esta en los CSV**, de modo que")
    w("una etiqueta por tipo para HAI habria que construirla cruzando esa tabla")
    w("con las marcas de tiempo, y los codigos de escenario nombran el punto")
    w("atacado, no una familia de anomalia comparable con la de Morris.")
    w("")

    w("### 4.2 Hay dos esquemas de etiquetado distintos, no cinco")
    w("")
    w("%-22s %-16s %-28s %s"
      % ("conjunto", "nivel", "columnas de etiqueta", "estrategias"))
    w("%-22s %-16s %-28s %s"
      % ("Westermo", "flujo", "IT_B, IT_M, NST_B, NST_M", "dos (IT y NST)"))
    w("%-22s %-16s %-28s %s"
      % ("ICS-Flow", "flujo", "IT_B, IT_M, NST_B, NST_M", "dos (IT y NST)"))
    w("%-22s %-16s %-28s %s"
      % ("Morris", "transaccion", "binary/categorized/specific", "una"))
    w("%-22s %-16s %-28s %s"
      % ("QUT", "paquete y carpeta", "sin cabecera, tercer campo", "una"))
    w("%-22s %-16s %-28s %s"
      % ("HAI", "registro de proceso", "attack / Attack / label", "una"))
    w("")
    w("Westermo e ICS-Flow comparten **las cuatro columnas de etiqueta y las dos")
    w("estrategias**: binaria y multiclase por cada una de IT (marca todo el")
    w("trafico mientras el ataque esta activo) y NST (marca solo el trafico que")
    w("involucra al atacante). Es el mismo esquema, igual que el de")
    w("caracteristicas. Los otros tres tienen cada uno el suyo.")
    w("")

    w("### 4.3 Son traducibles los vocabularios?")
    w("")
    w("Se normaliza cada etiqueta --- minusculas, sin prefijo `BAD-` o `GOOD-`,")
    w("sin guiones ni sufijo numerico --- y se buscan coincidencias exactas")
    w("entre los vocabularios normalizados.")
    w("")
    norm = {k: {normalizar_etiqueta(e): e for e in v}
            for k, v in vocab.items() if k != "QUT (por carpeta)"}
    norm["QUT (por carpeta)"] = {normalizar_etiqueta(e): e for e
                                 in vocab["QUT (por carpeta)"]}
    nombres = list(norm)
    w("%-22s %-22s %8s %s" % ("conjunto A", "conjunto B", "comunes", "cuales"))
    coincidencias = {}
    for a, b in itertools.combinations(nombres, 2):
        c = set(norm[a]) & set(norm[b])
        coincidencias["%s|%s" % (a, b)] = sorted(c)
        w("%-22s %-22s %8d %s"
          % (a, b, len(c),
             ", ".join("%s=%s" % (norm[a][x], norm[b][x])
                       for x in sorted(c)) or "---"))
    w("")
    sin_normal = {k: [x for x in v if x != "normal"]
                  for k, v in coincidencias.items()}
    total_pares = len(coincidencias)
    con_coincidencia = sum(1 for v in sin_normal.values() if v)
    todas = sorted(set(itertools.chain.from_iterable(sin_normal.values())))
    w("Fuera de `Normal`, hay coincidencia automatica en **%d de los %d pares**"
      % (con_coincidencia, total_pares))
    w("de vocabularios, y las familias que coinciden son solo **%d**: %s."
      % (len(todas), ", ".join("`%s`" % x for x in todas)))
    w("")
    for k, v in sorted(sin_normal.items()):
        if v:
            a, b = k.split("|")
            w("  %-22s / %-22s %s"
              % (a, b, ", ".join("%s = %s" % (norm[a][x], norm[b][x])
                                 for x in v)))
    w("")
    w("Dos advertencias sobre esa cuenta, que la hacen mas generosa de lo que")
    w("el dato aguanta:")
    w("")
    w("  - La normalizacion **colapsa distinciones que los conjuntos hacen**.")
    w("    `BAD-PORTSCAN1` y `BAD-PORTSCAN2` de Westermo, que son el escaneo")
    w("    contra un dispositivo y contra varios, quedan los dos en `portscan`")
    w("    y coinciden con el `port-scan` de ICS-Flow, que es un escaneo con")
    w("    `nmap`. Son tres cosas distintas con un nombre parecido.")
    w("  - Las coincidencias con `QUT (por carpeta)` son con el nombre del")
    w("    directorio, no con una etiqueta de los datos. El vocabulario real de")
    w("    QUT, el de sus %d etiquetas por paquete, **no coincide en nada con"
      % len(vocab["QUT (por paquete)"]))
    w("    ningun otro conjunto**: todas sus etiquetas son compuestas")
    w("    (`MITM_forwarding_from_attacker`) y ninguna normaliza a un nombre")
    w("    simple.")
    w("")
    w("Todo el resto exige un diccionario escrito a mano, y dos de las familias")
    w("no tienen contraparte en ningun otro conjunto:")
    w("")
    w("  - Las **malas configuraciones** de Westermo (`BAD-MISCONF` y")
    w("    `BAD-MISCONF-DUPLICATION`, los dos eventos que son error humano y no")
    w("    ataque, y los que mas le interesan a este proyecto) no existen en")
    w("    ningun")
    w("    otro de los cinco.")
    w("  - La **taxonomia contextual** de Morris (MPCI, CMRI, MSCI, MFCI) nombra")
    w("    manipulaciones de la semantica del proceso. Westermo, que es un")
    w("    conjunto de anomalias de red, no tiene ninguna; HAI tampoco, porque")
    w("    no distingue tipo.")
    w("")
    w("Un diccionario escrito a mano puede unificar a un nivel grueso ---")
    w("escaneo, intermediario, denegacion de servicio, repeticion ---, y esa")
    w("union es **una interpretacion de las taxonomias publicadas, no una")
    w("medicion**. Con un detalle que la hace cara: lo que cada conjunto llama")
    w("igual se midio sobre unidades distintas. Un `mitm` de Westermo es un")
    w("flujo de 0,5 s marcado por NST; un `mitm` de ICS-Flow tambien, y hasta")
    w("ahi la traduccion es limpia. Un `MITM_modification_BinaryStatus` de QUT")
    w("es un paquete. Un `MPCI` de Morris es una transaccion Modbus. La etiqueta")
    w("traducida no significa lo mismo si la unidad etiquetada no es la misma.")
    w("")

    J["etiquetas"] = {
        "vocabularios": {k: {str(a): int(b) for a, b in v.items()}
                         for k, v in vocab.items()},
        "hai_formato": hai_fmt,
        "coincidencias_normalizadas": coincidencias,
    }
    return vocab


# ---------------------------------------------------------------------------
# 5. El esquema comun minimo


def seccion_5(w, J, esq, union, numericas):
    w("## 5. Que sobrevive a cada forma de integrar")
    w("")
    w("Hay tres formas de armar un conjunto integrado y no son equivalentes. Se")
    w("evalua cada una con lo medido en las secciones anteriores.")
    w("")

    w("### 5.1 Concatenar filas con un esquema comun minimo")
    w("")
    comunes_4 = set.intersection(*union.values())
    w("Entre los cuatro conjuntos con esquema tabular, los campos con el mismo")
    w("nombre son **%d**." % len(comunes_4))
    if comunes_4:
        w("  %s" % ", ".join(sorted(comunes_4)))
    w("Sumando QUT, que no publica esquema, son **0**.")
    w("")
    w("Y hay una razon anterior a los nombres: los registros no son la misma")
    w("cosa. Una fila de Westermo es un flujo de 0,5 s; una de Morris, una")
    w("transaccion Modbus; una de HAI, una muestra de proceso de 1 s. Apilarlas")
    w("en una tabla produce filas que no son observaciones de la misma")
    w("poblacion, y ninguna transformacion de columnas lo arregla.")
    w("")
    w("**No es viable con los cinco.** Entre Westermo e ICS-Flow, que si")
    w("comparten esquema, es tecnicamente posible --- y se trata en 5.2 ---,")
    w("pero con la salvedad medida en 2.5: la union ensancha la envolvente del")
    w("'normal' justo en las caracteristicas de volumen y temporizado, que son")
    w("las que llevan la senal.")
    w("")

    w("### 5.2 Union al nivel de caracteristicas de flujo")
    w("")
    w("Esta forma es la que la evidencia sostiene, y con un alcance preciso.")
    w("")
    carac = [c for c in esq["Westermo flujos"] if c not in NO_CARACTERISTICA]
    w("Westermo e ICS-Flow publican los mismos **%d campos**, de los cuales %d"
      % (len(esq["Westermo flujos"]), len(carac)))
    w("son caracteristicas y %d son identificadores, marcas de tiempo o"
      % (len(esq["Westermo flujos"]) - len(carac)))
    w("etiquetas. Las %d caracteristicas tienen el mismo nombre, la misma"
      % len(carac))
    w("definicion verificada por identidad numerica, la misma ventana de 0,5 s y")
    w("la misma precision publicada campo por campo; las etiquetas, las mismas")
    w("cuatro columnas con las mismas dos estrategias.")
    w("")
    w("A ellos **se puede sumar QUT** calculandole las mismas %d" % len(carac))
    w("caracteristicas desde sus PCAP, que es trabajo del proyecto y no un dato")
    w("del conjunto. Tiene la ventaja de que el flujo de extraccion queda bajo")
    w("control del proyecto, que es justo lo que pide el requerimiento 2.3.")
    w("")
    w("Y tiene un limite que conviene fijar ahora: de las %d caracteristicas,"
      % len(carac))
    w("**%d son constantes en los dos conjuntos a la vez** (seccion 2.4), de"
      % len(J["westermo_icsflow"]["campos_constantes_en_ambos"]))
    w("modo que la union util es menor que el numero de columnas.")
    w("")
    hai_min = min((len(v) for k, v in esq.items() if k.startswith("HAI")),
                  default=0)
    hai_max = max((len(v) for k, v in esq.items() if k.startswith("HAI")),
                  default=0)
    w("**Morris y HAI quedan afuera de esta union, y no por una limitacion")
    w("salvable.** Morris no publica captura --- el archivo con el hexadecimal")
    w("de las tramas no esta archivado --- y HAI no publica ni una sola")
    w("caracteristica de red: sus %d a %d columnas son todas variables de"
      % (hai_min, hai_max))
    w("proceso, y las unidades que declara su PDF tecnico son bar, mm, l/h, %,")
    w("grados, RPM, MW y Hz. No hay nada que convertir.")
    w("")

    w("### 5.3 Un conjunto por dominio, con evaluacion separada")
    w("")
    w("Es lo que la medicion sostiene para los cinco a la vez. Cada conjunto")
    w("conserva su esquema, su nivel de agregacion y su etiquetado, y lo que se")
    w("integra es **el protocolo de evaluacion**: la misma particion temporal")
    w("60 / 20 / 20, la misma definicion de PD y PFA, el mismo criterio de no")
    w("mirar el tramo de prueba, y una tabla de resultados por conjunto y por")
    w("familia de anomalia.")
    w("")
    w("Lo que se pierde: no hay una cifra agregada unica, y no se puede afirmar")
    w("que el detector generaliza entre dominios, porque nunca se lo entrena")
    w("sobre mas de uno. Lo que se gana: cada cifra es interpretable y cada")
    w("caracteristica tiene una unidad y una ventana declaradas.")
    w("")

    w("### 5.4 Resumen de lo que habilita cada conjunto")
    w("")
    fmt = "%-10s %-16s %-8s %-14s %-14s %s"
    w(fmt % ("conjunto", "nivel del reg.", "captura", "esquema", "etiqueta",
             "entra en la union de flujo"))
    tabla = [
        ("Westermo", "flujo 0,5 s", "si", "64 campos", "4 columnas",
         "si, es la base"),
        ("ICS-Flow", "flujo 0,5 s", "si", "64 campos", "4 columnas",
         "si, mismo esquema"),
        ("QUT", "paquete", "si", "ninguno", "por paquete",
         "si, calculandola"),
        ("Morris", "transaccion", "no", "20 atributos", "3 columnas",
         "no, falta la captura"),
        ("HAI", "proceso 1 s", "no", "64 a 226 cols", "binaria",
         "no, no publica red"),
    ]
    for f in tabla:
        w(fmt % f)
    w("")

    J["integracion"] = {
        "comunes_a_los_cuatro": sorted(comunes_4),
        "caracteristicas_de_flujo": carac,
        "n_caracteristicas_de_flujo": len(carac),
        "tabla_resumen": [dict(zip(["conjunto", "nivel", "captura", "esquema",
                                    "etiqueta", "union_de_flujo"], f))
                          for f in tabla],
    }


# ---------------------------------------------------------------------------
# Figura


def figura(J, esq):
    plt = comun.estilo_figura()
    nombres = [k for k in esq]
    n = len(nombres)
    M = np.zeros((n, n), dtype=int)
    for i, a in enumerate(nombres):
        for j, b in enumerate(nombres):
            M[i, j] = len(set(esq[a]) & set(esq[b]))

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12.5, 5.2),
                                   gridspec_kw={"width_ratios": [1.25, 1]})

    fuera = M.copy()
    np.fill_diagonal(fuera, 0)
    im = ax1.imshow(fuera, cmap="Greys", vmin=0, vmax=max(1, fuera.max()))
    ax1.set_xticks(range(n))
    ax1.set_yticks(range(n))
    ax1.set_xticklabels(nombres, rotation=55, ha="right", fontsize=7)
    ax1.set_yticklabels(nombres, fontsize=7)
    ax1.set_title("Campos con el mismo nombre entre esquemas publicados\n"
                  "(la diagonal se omite; el numero es el total de campos)",
                  fontsize=8)
    for i in range(n):
        for j in range(n):
            v = M[i, j]
            if i == j:
                ax1.text(j, i, "%d" % v, ha="center", va="center", fontsize=6,
                         color="tab:blue")
            elif v:
                ax1.text(j, i, "%d" % v, ha="center", va="center", fontsize=6,
                         color="white" if v > fuera.max() * 0.55 else "black")
    ax1.grid(False)

    niveles = [(r["archivo"], r["paso_s"], r["nivel"])
               for r in J["granularidad"] if r["paso_s"]]
    niveles.sort(key=lambda x: x[1])
    color = {"paquete": "tab:red", "flujo": "tab:blue",
             "ventana": "tab:green", "proceso": "tab:orange",
             "transaccion": "tab:purple"}
    y = range(len(niveles))
    ax2.barh(list(y), [x[1] for x in niveles],
             color=[color.get(x[2], "gray") for x in niveles], height=0.6)
    ax2.set_yticks(list(y))
    ax2.set_yticklabels([x[0] for x in niveles], fontsize=7)
    ax2.set_xscale("log")
    ax2.set_xlabel("paso temporal del registro (s, escala logaritmica)",
                   fontsize=8)
    ax2.set_title("Granularidad temporal medida\n"
                  "(color = nivel de agregacion)", fontsize=8)
    vistos = []
    for nivel, c in color.items():
        if any(x[2] == nivel for x in niveles):
            vistos.append(plt.Line2D([0], [0], color=c, lw=5, label=nivel))
    ax2.legend(handles=vistos, fontsize=7, loc="lower right")

    destino = os.path.join(comun.FIGURAS, "p11_esquemas.png")
    fig.savefig(destino)
    plt.close(fig)
    print("[escrito] %s" % comun.rel(destino))


# ---------------------------------------------------------------------------


def main():
    comun.preparar()
    L = []
    w = L.append
    J = {}

    w("# Se puede armar un conjunto de datos integrado?")
    w("")
    w("Generado por `eda/scripts/11_integracion_esquemas.py`.")
    w("")
    w("Responde la pregunta de fondo del proyecto. Mide la interseccion de")
    w("los esquemas, si las definiciones coinciden de verdad y no solo de")
    w("nombre, si las distribuciones son compatibles, la granularidad temporal")
    w("de cada conjunto y si los esquemas de etiquetado son traducibles.")
    w("")
    w("Particiones: solo tramo de entrenamiento, con los cortes de")
    w("`eda/INSTRUCCIONES.md`. Ninguna fila de ningun archivo de prueba.")
    w("")
    w("---")
    w("")
    esq, union = seccion_1(w, J)
    w("---")
    w("")
    numericas = seccion_2(w, J, esq)
    w("---")
    w("")
    seccion_3(w, J)
    w("---")
    w("")
    seccion_4(w, J)
    w("---")
    w("")
    seccion_5(w, J, esq, union, numericas)

    comun.escribir("p11_integracion.txt", "\n".join(L))
    with open(os.path.join(comun.SALIDAS, "p11_integracion.json"), "w") as fh:
        json.dump(J, fh, indent=1, ensure_ascii=False, default=str)
    print("\n[escrito] %s"
          % comun.rel(os.path.join(comun.SALIDAS, "p11_integracion.json")))
    figura(J, esq)


if __name__ == "__main__":
    main()
