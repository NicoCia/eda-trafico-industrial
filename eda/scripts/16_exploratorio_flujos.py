"""Estudio exploratorio de los dos conjuntos de flujos: Westermo e ICS-Flow.

Alimenta `eda/EXPLORATORIO.md`. Es la capa descriptiva que `eda/INFORME.md`
no tiene: que trae cada conjunto, de que tipo, que falta y por que, como se
relacionan las caracteristicas entre si y como esta el balance de clases.

Complementa al reporte generico que produce el script de la materia
(`scripts/eda_report.py` del skill `analisis-de-datos`), guardado en
`eda/derivados/reporte_*.md`. Lo que agrega este script es lo que el reporte
generico no puede saber sin el dominio:

  1. que los faltantes son **estructurales** y no aleatorios, con la prueba;
  2. los grupos de redundancia entre caracteristicas, no solo los pares;
  3. las caracteristicas degeneradas, que no aportan nada a ningun modelo;
  4. el balance de clases por las cuatro columnas de etiqueta a la vez.

Particion: solo el tramo de entrenamiento, con los cortes de
`eda/INSTRUCCIONES.md`. Ninguna fila de calibracion ni de prueba.

Uso:  python eda/scripts/16_exploratorio_flujos.py
"""

import json
import os
import sys

import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import comun  # noqa: E402

# Los 64 campos del esquema de ICSFlowGenerator se reparten en tres bloques
# fijos: identificadores, caracteristicas y etiquetas. El corte esta medido en
# la seccion 5 de eda/INFORME.md.
N_IDENT = 13
N_FEATS = 47

UMBRAL_CORR = 0.8        # el de la materia para redundancia
UMBRAL_ASIM = (0.5, 1.0)  # simetrica / moderada / alta


def cargar():
    """Devuelve los dos tramos de entrenamiento, con su nombre.

    Deja cada tramo escrito en `eda/derivados/`, porque es lo que consume el
    reporte generico de la materia, que toma un archivo y no un DataFrame.
    """
    W = pd.read_csv(os.path.join(comun.WESTERMO, "reduced", "flows",
                                 "output_bottom.csv"))
    W.columns = [c.strip() for c in W.columns]
    W = W[W["startOffset"] < comun.WESTERMO_CORTES[0]].reset_index(drop=True)

    F = pd.read_csv(os.path.join(comun.DATOS, "ics-flow", "Dataset.csv"))
    F.columns = [c.strip() for c in F.columns]
    t0 = F["start"].min()
    corte = t0 + 0.6 * (F["end"].max() - t0)
    F = F[F["start"] < corte].reset_index(drop=True)

    salida = [("Westermo", W, "westermo_bottom_entrenamiento.csv"),
              ("ICS-Flow", F, "icsflow_entrenamiento.csv")]
    for _n, df, archivo in salida:
        df.to_csv(os.path.join(comun.DERIVADOS, archivo), index=False)
    return [(n, df) for n, df, _a in salida]


def clasificar_asimetria(s):
    a = abs(s)
    if a < UMBRAL_ASIM[0]:
        return "simetrica"
    return "moderada" if a < UMBRAL_ASIM[1] else "alta"


def grupos_redundancia(df, cols, umbral=UMBRAL_CORR):
    """Agrupa caracteristicas por correlacion de Spearman, con union-find.

    Los pares sueltos no alcanzan: si A se correlaciona con B y B con C, las
    tres son el mismo eje y hay que verlas juntas para decidir cual conservar.
    """
    sub = df[cols].apply(pd.to_numeric, errors="coerce")
    sub = sub.loc[:, sub.nunique(dropna=True) > 1]
    if sub.shape[1] < 2:
        return [], pd.DataFrame()
    corr = sub.corr(method="spearman")
    padre = {c: c for c in sub.columns}

    def raiz(x):
        while padre[x] != x:
            padre[x] = padre[padre[x]]
            x = padre[x]
        return x

    pares = []
    for i, a in enumerate(sub.columns):
        for b in sub.columns[i + 1:]:
            r = corr.loc[a, b]
            if pd.notna(r) and abs(r) >= umbral:
                pares.append((a, b, float(r)))
                ra, rb = raiz(a), raiz(b)
                if ra != rb:
                    padre[ra] = rb
    gr = {}
    for c in sub.columns:
        gr.setdefault(raiz(c), []).append(c)
    return [sorted(v) for v in gr.values() if len(v) > 1], pd.DataFrame(
        pares, columns=["a", "b", "spearman"])


def analizar(nombre, df, w):
    cols = list(df.columns)
    ident, feats, etq = cols[:N_IDENT], cols[N_IDENT:N_IDENT + N_FEATS], cols[-4:]
    res = {"filas": len(df), "columnas": len(cols)}

    w("## %s" % nombre)
    w("")
    w("### Panorama")
    w("")
    w("- Observaciones: **%d** · Variables: **%d** (%d identificadores, "
      "%d características, %d etiquetas)"
      % (len(df), len(cols), len(ident), len(feats), len(etq)))
    dup = int(df.duplicated().sum())
    dup_f = int(df[feats].duplicated().sum())
    w("- Filas duplicadas exactas: **%d**; duplicadas en las %d "
      "características: **%d** (%.1f %%)"
      % (dup, len(feats), dup_f, 100.0 * dup_f / len(df)))
    res["duplicadas"] = dup
    res["duplicadas_features"] = dup_f
    nul = df.isna().mean().mean() * 100
    w("- Celdas faltantes: %.1f %% del total; filas con al menos un nulo: "
      "%.1f %%" % (nul, 100.0 * df.isna().any(axis=1).mean()))
    w("- Protocolos: %s"
      % ", ".join("%s %d" % kv for kv in df["protocol"].value_counts().items()))
    w("")

    # ---------------- faltantes ----------------
    w("### Faltantes: son estructurales")
    w("")
    nulos = df[feats].isna().mean().sort_values(ascending=False)
    con_nulos = nulos[nulos > 0]
    if con_nulos.empty:
        w("Ninguna característica tiene faltantes.")
        res["faltantes"] = {}
    else:
        w("%d de las %d características tienen faltantes, entre %.1f %% y "
          "%.1f %%." % (len(con_nulos), len(feats), 100 * con_nulos.min(),
                        100 * con_nulos.max()))
        w("")
        w("La hipótesis del dominio es que no faltan al azar: un flujo que no")
        w("es TCP no tiene banderas ni ventana, y una dirección sin paquetes")
        w("no tiene TTL que informar. Se comprueba por identidad exacta.")
        w("")
        no_tcp = df["protocol"] != "IPV4-TCP"
        pruebas = []
        for c in ("sttl", "rttl", "sWinTCP", "rWinTCP", "sAckRate",
                  "rAckRate"):
            if c not in df.columns:
                continue
            lado = df["sPackets"] if c.startswith("s") else df["rPackets"]
            ident_exacta = (df[c].isna() == (no_tcp | (lado == 0))).all()
            pruebas.append((c, "no TCP, o sin paquetes de ese lado",
                            bool(ident_exacta)))
        # Que protocolos carecen de direccion IPv4 no se puede codificar: el
        # repertorio cambia de un conjunto a otro. Se deriva de los datos y
        # despues se comprueba que la identidad sea exacta.
        for c in ("sIPs", "rIPs"):
            if c not in df.columns:
                continue
            frac = df.groupby("protocol")[c].apply(lambda g: g.isna().mean())
            sin_v4 = sorted(frac[frac == 1.0].index)
            m = df["protocol"].isin(sin_v4)
            pruebas.append((c, "protocolo sin IPv4 (%s)" % ", ".join(sin_v4),
                            bool((df[c].isna() == m).all())))
        w("%-12s %-46s %s" % ("campo", "el nulo equivale a", "exacto"))
        for c, regla, okk in pruebas:
            w("%-12s %-46s %s" % (c, regla, "sí" if okk else "NO"))
        res["faltantes_estructurales"] = {c: o for c, _r, o in pruebas}
        w("")
        tcp = df[~no_tcp]
        if "sAckDelayAvg" in df.columns and len(tcp):
            w("El retardo de ACK necesita además al menos dos paquetes del")
            w("lado medido, de modo que su falta crece al achicarse el flujo:")
            w("")
            w("%-14s %8s %14s" % ("sPackets", "flujos", "sin el dato"))
            for k in (0, 1, 2, 3):
                s = tcp[tcp["sPackets"] == k]
                if len(s):
                    w("%-14d %8d %13.0f %%"
                      % (k, len(s), 100 * s["sAckDelayAvg"].isna().mean()))
            resto = tcp[tcp["sPackets"] > 3]
            if len(resto):
                w("%-14s %8d %13.0f %%"
                  % ("más de 3", len(resto),
                     100 * resto["sAckDelayAvg"].isna().mean()))
        w("")
        w("**Consecuencia para la preparación.** No corresponde imputar: el")
        w("valor no existe, no está perdido. Un reporte automático propone")
        w("imputación simple para estas columnas, y sería un error — pondría")
        w("un número donde el protocolo no define ninguno. Lo que corresponde")
        w("es una bandera de ausencia, o separar el modelo por protocolo.")
    w("")

    # ---------------- degeneradas ----------------
    w("### Características degeneradas")
    w("")
    num = df[feats].apply(pd.to_numeric, errors="coerce")
    nun = num.nunique(dropna=True)
    constantes = sorted(nun[nun <= 1].index)
    casi = sorted([c for c in nun[nun > 1].index
                   if num[c].value_counts(normalize=True, dropna=True).iloc[0]
                   >= 0.99])
    w("- Constantes (un solo valor): **%d** — %s"
      % (len(constantes), ", ".join("`%s`" % c for c in constantes) or "ninguna"))
    w("- Casi constantes (un valor en ≥ 99 %%): **%d** — %s"
      % (len(casi), ", ".join("`%s`" % c for c in casi) or "ninguna"))
    w("")
    w("Ninguna de las dos aporta a un modelo y conviene descartarlas antes de")
    w("cualquier cálculo que escale con el número de columnas.")
    res["constantes"] = constantes
    res["casi_constantes"] = casi
    w("")

    # ---------------- descriptivos ----------------
    w("### Forma de las distribuciones")
    w("")
    utiles = [c for c in feats if c not in constantes]
    filas = []
    for c in utiles:
        v = num[c].dropna()
        if len(v) < 50:
            continue
        q1, q3 = v.quantile(.25), v.quantile(.75)
        iqr = q3 - q1
        out = ((v < q1 - 1.5 * iqr) | (v > q3 + 1.5 * iqr)).mean() if iqr > 0 \
            else 0.0
        filas.append((c, float(v.skew()), float(v.kurt()), 100 * out))
    d = pd.DataFrame(filas, columns=["campo", "asim", "curt", "out"])
    cl = d["asim"].map(clasificar_asimetria).value_counts()
    w("Sobre las %d características no constantes:" % len(d))
    w("")
    for k in ("simetrica", "moderada", "alta"):
        w("- asimetría %-10s %2d" % (k, int(cl.get(k, 0))))
    w("")
    w("Las %d de asimetría alta son las de volumen y temporizado, donde la"
      % int(cl.get("alta", 0)))
    w("media no representa el centro: ahí corresponde mediana y, si se")
    w("escala, escala logarítmica.")
    w("")
    w("Las diez con más valores fuera del rango intercuartílico:")
    w("")
    w("%-20s %8s %9s %10s" % ("campo", "asim.", "curtosis", "fuera RIQ"))
    for _, r in d.sort_values("out", ascending=False).head(10).iterrows():
        w("%-20s %8.2f %9.1f %9.1f %%" % (r.campo, r.asim, r.curt, r.out))
    w("")
    w("En un conjunto de tráfico el valor extremo rara vez es un error de")
    w("carga: suele ser la ráfaga o el evento. No se eliminan.")
    res["asimetria"] = {k: int(cl.get(k, 0))
                        for k in ("simetrica", "moderada", "alta")}
    w("")

    # ---------------- redundancia ----------------
    w("### Redundancia entre características")
    w("")
    grupos, pares = grupos_redundancia(df, utiles)
    w("Pares con |Spearman| ≥ %.1f: **%d**. Agrupados por transitividad, "
      "quedan **%d** grupos de redundancia:" % (UMBRAL_CORR, len(pares),
                                                len(grupos)))
    w("")
    for g in sorted(grupos, key=len, reverse=True):
        w("- %s" % ", ".join("`%s`" % c for c in g))
    w("")
    n_red = sum(len(g) for g in grupos)
    w("Son %d características dentro de algún grupo. Conservando una por"
      % n_red)
    w("grupo, las %d no constantes se reducen a **%d ejes independientes**."
      % (len(utiles), len(utiles) - n_red + len(grupos)))
    res["grupos_redundancia"] = grupos
    res["pares_fuertes"] = len(pares)
    w("")

    # ---------------- balance ----------------
    w("### Balance de clases")
    w("")
    w("%-14s %10s %10s %9s" % ("etiqueta", "normal", "anómalo", "razón"))
    bal = {}
    for c in ("IT_B_Label", "NST_B_Label"):
        if c not in df.columns:
            continue
        v = pd.to_numeric(df[c], errors="coerce")
        n0, n1 = int((v == 0).sum()), int((v == 1).sum())
        w("%-14s %10d %10d %8.1f:1"
          % (c, n0, n1, max(n0, n1) / max(1, min(n0, n1))))
        bal[c] = {"normal": n0, "anomalo": n1}
    w("")
    for c in ("IT_M_Label", "NST_M_Label"):
        if c not in df.columns:
            continue
        vc = df[c].value_counts()
        w("%s: %s" % (c, ", ".join("%s %d" % kv for kv in vc.items())))
        bal[c] = {str(k): int(v) for k, v in vc.items()}
    w("")
    w("La estrategia de etiquetado cambia el problema: no es la misma tarea")
    w("con una u otra, y eso se decide antes de partir los datos.")
    res["balance"] = bal
    w("")
    w("**Sobre la fuga.** Las cuatro columnas de etiqueta describen el mismo")
    w("evento con dos estrategias. Usar una como característica para predecir")
    w("otra es fuga por construcción, y un reporte automático lo marca como")
    w("hallazgo. No lo es: son todas la variable a predecir, y la elección")
    w("entre IT y NST es una decisión de diseño, no una característica.")
    w("")
    return res


def main():
    comun.preparar()
    L = []
    w = L.append
    w("# Exploración de los dos conjuntos de flujos")
    w("")
    w("Generado por `eda/scripts/16_exploratorio_flujos.py`.")
    w("Solo tramo de entrenamiento.")
    w("")
    res = {}
    for nombre, df in cargar():
        res[nombre] = analizar(nombre, df, w)
        w("---")
        w("")
    comun.escribir("p16_exploratorio_flujos.txt", "\n".join(L))
    with open(os.path.join(comun.SALIDAS,
                           "p16_exploratorio_flujos.json"), "w") as fh:
        json.dump(res, fh, indent=1, ensure_ascii=False, default=str)


if __name__ == "__main__":
    main()
