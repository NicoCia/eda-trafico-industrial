"""Preguntas 3 y 4 --- Morris / Turnipseed.

Pregunta 3: confirma contra el archivo las cifras que se daban por buenas
(274.628 filas, 214.580 normales, siete categorias de ataque con conteos
conocidos, y el atributo `command response` con 137.013 / 137.615). Sirve de
control del propio analisis. Verifica ademas **que valor de `command response`
es el comando y cual la respuesta**, que es lo que sostiene el criterio D3.

Pregunta 4: instancias y eventos distintos por categoria de ataque, con la
particion temporal 60/20/20 sobre `time` fijada en el brief.

Uso:  python eda/scripts/03_morris.py
"""

import collections
import re
import json
import os
import sys

import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import comun  # noqa: E402

# Nombres de las categorias segun la taxonomia del laboratorio de Morris.
CATEGORIA = {
    "0": "Normal",
    "1": "NMRI  (inyeccion simple de respuesta maliciosa)",
    "2": "CMRI  (inyeccion compleja de respuesta maliciosa)",
    "3": "MSCI  (inyeccion de estado malicioso)",
    "4": "MPCI  (inyeccion de parametros de comando)",
    "5": "MFCI  (inyeccion de codigo de funcion malicioso)",
    "6": "DoS   (denegacion de servicio)",
    "7": "Reconnaissance (reconocimiento)",
}

CONTEOS_INFORME = [7753, 13035, 7900, 20412, 4898, 2176, 3874]


ATRIBUTO = re.compile(r"^@attribute\s+(?:'([^']*)'|\"([^\"]*)\"|(\S+))",
                      re.IGNORECASE)


def leer_arff(path):
    """Lee un ARFF simple (sin comillas con comas) a un DataFrame."""
    atributos = []
    filas = []
    en_datos = False
    with open(path) as fh:
        for linea in fh:
            s = linea.strip()
            if not en_datos:
                low = s.lower()
                if low.startswith("@attribute"):
                    m = ATRIBUTO.match(s)
                    nombre = next(g for g in m.groups() if g is not None)
                    atributos.append(nombre)
                elif low.startswith("@data"):
                    en_datos = True
                continue
            if not s or s.startswith("%"):
                continue
            filas.append(s.split(","))
    df = pd.DataFrame(filas, columns=atributos)
    return df.replace("?", np.nan)


def rachas(etiquetas):
    """Cuenta rachas contiguas por etiqueta sobre una secuencia ya ordenada."""
    out = collections.Counter()
    largos = collections.defaultdict(list)
    actual = None
    n = 0
    for e in etiquetas:
        if e == actual:
            n += 1
            continue
        if actual is not None:
            out[actual] += 1
            largos[actual].append(n)
        actual, n = e, 1
    if actual is not None:
        out[actual] += 1
        largos[actual].append(n)
    return out, largos


def main():
    comun.preparar()
    ruta = os.path.join(comun.MORRIS, "IanArffDataset.arff")
    df = leer_arff(ruta)

    for c in ("time", "length", "function", "address", "setpoint",
              "pressure measurement", "gain", "crc rate"):
        if c in df.columns:
            df[c] = pd.to_numeric(df[c], errors="coerce")

    L = []
    w = L.append
    w("# Preguntas 3 y 4 - Morris / Turnipseed")
    w("")
    w("Archivo: %s" % comun.rel(ruta))
    w("")

    # ---- P3: control de cifras -------------------------------------
    w("## P3.a Control de las cifras que se daban por verificadas")
    w("")
    w("%-46s %12s %12s %8s" % ("comprobacion", "declarado", "medido", "coincide"))

    def chk(nombre, esperado, medido):
        ok = "SI" if esperado == medido else "NO"
        w("%-46s %12s %12s %8s" % (nombre, esperado, medido, ok))
        return esperado == medido

    todo_ok = []
    todo_ok.append(chk("filas", 274628, len(df)))
    todo_ok.append(chk("atributos", 20, df.shape[1]))
    vc_cat = df["categorized result"].value_counts()
    todo_ok.append(chk("normales (categorized result = 0)", 214580,
                       int(vc_cat.get("0", 0))))
    ataques = int(len(df) - vc_cat.get("0", 0))
    todo_ok.append(chk("ataques (total)", 60048, ataques))
    for i, esperado in enumerate(CONTEOS_INFORME, start=1):
        todo_ok.append(chk("categoria %d  %s" % (i, CATEGORIA[str(i)][:28]),
                           esperado, int(vc_cat.get(str(i), 0))))
    vc_cr = df["command response"].value_counts()
    todo_ok.append(chk("command response = 0", 137013, int(vc_cr.get("0", 0))))
    todo_ok.append(chk("command response = 1", 137615, int(vc_cr.get("1", 0))))
    w("")
    w("Comprobaciones correctas: %d de %d" % (sum(todo_ok), len(todo_ok)))
    w("")
    w("Etiqueta `binary result`: %s"
      % dict(df["binary result"].value_counts()))
    w("Etiqueta `specific result`: %d clases distintas"
      % df["specific result"].nunique())
    w("")

    # ---- P3.b: polaridad de command response ------------------------
    w("## P3.b Que valor de `command response` es el comando")
    w("")
    w("`datasets/morris-turnipseed/PROCEDENCIA.md` dice: 0 = comando,")
    w("1 = respuesta. Se contrasta contra el contenido de las filas.")
    w("")
    w("Tabla cruzada con el codigo de funcion Modbus:")
    w("")
    tab = pd.crosstab(df["function"], df["command response"])
    w("%-10s %12s %12s" % ("function", "cr=0", "cr=1"))
    for f, fila in tab.iterrows():
        w("%-10s %12d %12d" % (int(f), fila.get("0", 0), fila.get("1", 0)))
    w("")
    w("Longitud de trama (`length`) segun el valor:")
    w("")
    w("%-10s %-6s %10s %10s %10s" % ("function", "cr", "n", "length med",
                                     "length max"))
    for f in sorted(df["function"].dropna().unique()):
        for cr in ("0", "1"):
            sub = df[(df["function"] == f) & (df["command response"] == cr)]
            if not len(sub):
                continue
            w("%-10d %-6s %10d %10.0f %10.0f"
              % (int(f), cr, len(sub), sub["length"].median(),
                 sub["length"].max()))
    w("")
    exc = df[df["function"] >= 128]
    exc0 = int((exc["command response"] == "0").sum())
    exc1 = int((exc["command response"] == "1").sum())
    w("Codigos de excepcion Modbus (`function` >= 128), que por definicion solo")
    w("pueden aparecer en una respuesta:")
    w("")
    w("  filas con function >= 128 : %d" % len(exc))
    w("  de ellas con cr=0         : %d" % exc0)
    w("  de ellas con cr=1         : %d" % exc1)
    w("  codigos presentes         : %s"
      % sorted(int(x) for x in exc["function"].dropna().unique()))
    w("")
    w("Presencia de campos que solo puede traer uno de los dos sentidos:")
    w("")
    w("%-26s %10s %12s %12s" % ("campo", "criterio", "cr=0", "cr=1"))
    presencia = {}
    for campo in ("setpoint", "gain", "pressure measurement"):
        if campo not in df.columns:
            continue
        v = pd.to_numeric(df[campo], errors="coerce")
        for etiqueta, mask in (("con valor", v.notna()),
                               ("no nulo", v.notna() & (v != 0))):
            a = int((mask & (df["command response"] == "0")).sum())
            b = int((mask & (df["command response"] == "1")).sum())
            w("%-26s %10s %12d %12d" % (campo if etiqueta == "con valor"
                                        else "", etiqueta, a, b))
            presencia["%s/%s" % (campo, etiqueta)] = {"cr0": a, "cr1": b}
    w("")
    w("Lectura: en Modbus la peticion de funcion 16 (escribir registros) es la")
    w("que lleva los parametros del lazo (`setpoint`, `gain`), y la respuesta")
    w("es un acuse corto. La peticion de funcion 3 (leer registros) es corta y")
    w("la respuesta es la que trae la medicion (`pressure measurement`).")
    w("")

    # ---- P4: eventos por categoria ----------------------------------
    w("## P4 Instancias y eventos distintos por categoria")
    w("")
    df = df.sort_values("time", kind="mergesort").reset_index(drop=True)
    t = df["time"]
    w("Rango de `time`: %.3f a %.3f  (%.0f s = %.1f h)"
      % (t.min(), t.max(), t.max() - t.min(), (t.max() - t.min()) / 3600.0))
    w("Monotona creciente tras ordenar: %s | ya venia ordenada: %s"
      % (bool(t.is_monotonic_increasing),
         bool(pd.to_numeric(leer_arff(ruta)["time"],
                            errors="coerce").is_monotonic_increasing)))
    c0, c1 = comun.MORRIS_CORTES
    w("Cortes de la particion (brief): %.0f y %.0f" % (c0, c1))
    w("")
    part = pd.cut(t, [-np.inf, c0, c1, np.inf],
                  labels=["entrenamiento", "calibracion", "prueba"])
    df["particion"] = part

    cuenta, largos = rachas(df["categorized result"].tolist())
    w("Un 'evento' es una racha contigua de filas de la misma categoria en")
    w("orden temporal.")
    w("")
    w("%-46s %10s %8s %9s %9s" % ("categoria", "instancias", "eventos",
                                  "med/ev", "max/ev"))
    eventos_info = {}
    for k in sorted(CATEGORIA):
        n = int(vc_cat.get(k, 0))
        if not n:
            continue
        ls = sorted(largos.get(k, []))
        w("%-46s %10d %8d %9d %9d"
          % (CATEGORIA[k], n, cuenta.get(k, 0),
             ls[len(ls) // 2] if ls else 0, ls[-1] if ls else 0))
        eventos_info[k] = {"instancias": n, "eventos": cuenta.get(k, 0)}
    w("")
    w("Reparto por particion (solo conteos; es la excepcion admitida por el")
    w("brief para dimensionar el experimento):")
    w("")
    tab = pd.crosstab(df["categorized result"], df["particion"])
    for col in ("entrenamiento", "calibracion", "prueba"):
        if col not in tab.columns:
            tab[col] = 0
    w("%-46s %14s %12s %10s" % ("categoria", "entrenamiento", "calibracion",
                                "prueba"))
    for k in sorted(CATEGORIA):
        if k not in tab.index:
            continue
        f = tab.loc[k]
        w("%-46s %14d %12d %10d" % (CATEGORIA[k], f["entrenamiento"],
                                    f["calibracion"], f["prueba"]))
    w("")
    w("Eventos por particion (rachas contadas dentro de cada tramo):")
    w("")
    w("%-46s %14s %12s %10s" % ("categoria", "entrenamiento", "calibracion",
                                "prueba"))
    ev_part = {}
    for nombre in ("entrenamiento", "calibracion", "prueba"):
        sub = df[df["particion"] == nombre]
        c, _ = rachas(sub["categorized result"].tolist())
        ev_part[nombre] = c
    for k in sorted(CATEGORIA):
        if k not in vc_cat.index:
            continue
        w("%-46s %14d %12d %10d"
          % (CATEGORIA[k], ev_part["entrenamiento"].get(k, 0),
             ev_part["calibracion"].get(k, 0), ev_part["prueba"].get(k, 0)))
        eventos_info[k]["por_particion"] = {
            n: ev_part[n].get(k, 0) for n in ev_part}
    w("")

    comun.escribir("p3_p4_morris.txt", "\n".join(L))
    with open(os.path.join(comun.SALIDAS, "p3_p4_morris.json"), "w") as fh:
        json.dump({"comprobaciones_ok": int(sum(todo_ok)),
                   "comprobaciones_total": len(todo_ok),
                   "excepciones_modbus": {"filas": len(exc), "cr0": exc0,
                                          "cr1": exc1},
                   "presencia_campos": presencia,
                   "por_categoria": eventos_info}, fh, indent=1,
                  ensure_ascii=False)


if __name__ == "__main__":
    main()
