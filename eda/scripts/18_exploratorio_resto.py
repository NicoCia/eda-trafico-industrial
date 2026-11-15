"""Estudio exploratorio de Morris y de HAI, con la ficha de los de flujo.

Completa `eda/EXPLORATORIO.md`. Sigue el mismo guion que
`16_exploratorio_flujos.py` y `17_discriminante_estructura.py` --que falta,
que variables hay, como se distribuyen, cuanto discriminan, que estructura
temporal tienen y si conviene reducir-- para que las fichas se puedan leer una
al lado de la otra.

Los dos conjuntos obligan a apartarse del guion en un punto cada uno, y eso es
parte del resultado:

  * Morris no es trafico de red sino transacciones Modbus, y su atributo mas
    informativo falta en tres de cada cuatro filas.
  * HAI **no trae anomalias en el tramo de entrenamiento**, de modo que el
    poder discriminante no se puede medir sin abrir el de prueba.

QUT no se mide aqui: no publica ninguna tabla de caracteristicas, y lo que
hay esta inventariado en `eda/salidas/p10_inventario.txt`, seccion E.

Particion: solo entrenamiento. Morris con el corte temporal de
`eda/INSTRUCCIONES.md`; HAI con sus archivos `train`.

Uso:  python eda/scripts/18_exploratorio_resto.py
"""

import glob
import json
import os
import sys
import warnings

import numpy as np
import pandas as pd
from sklearn.decomposition import PCA
from sklearn.metrics import roc_auc_score
from sklearn.preprocessing import StandardScaler

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import comun  # noqa: E402

LAGS = (1, 2, 5, 10)
HAI_VERSIONES = [("hai-20.07", ";", "train*.csv", "time"),
                 ("hai-21.03", ",", "train*.csv", "time"),
                 ("hai-22.04", ",", "train*.csv", "timestamp"),
                 ("hai-23.05", ",", "hai-train*.csv", "timestamp"),
                 ("haiend-23.05", ",", "end-train*.csv", "Timestamp")]
HAI_FICHA = "hai-20.07"   # la version con linea base publicada


def autocorr_serie(v, lag):
    v = np.asarray(v, float)
    v = v[np.isfinite(v)]
    if len(v) <= lag or v.std() == 0:
        return np.nan
    z = v - v.mean()
    return float((z[:-lag] * z[lag:]).sum() / (z * z).sum())


def resumen_forma(num, cols):
    filas = []
    for c in cols:
        v = num[c].dropna()
        if len(v) < 50:
            continue
        q1, q3 = v.quantile(.25), v.quantile(.75)
        iqr = q3 - q1
        out = ((v < q1 - 1.5 * iqr) | (v > q3 + 1.5 * iqr)).mean() if iqr > 0 \
            else 0.0
        filas.append((c, float(v.skew()), float(v.kurt()), 100 * out))
    return pd.DataFrame(filas, columns=["campo", "asim", "curt", "out"])


def clase_asim(s):
    a = abs(s)
    return "simetrica" if a < 0.5 else ("moderada" if a < 1 else "alta")


# ------------------------------------------------------------------ Morris
FIG = {}


def morris(w):
    mod = __import__("03_morris")
    ruta = os.path.join(comun.MORRIS, "IanArffDataset.arff")
    df = mod.leer_arff(ruta)
    for c in df.columns:
        if c not in ("command response", "binary result",
                     "categorized result", "specific result"):
            df[c] = pd.to_numeric(df[c], errors="coerce")
    df = df.sort_values("time", kind="mergesort").reset_index(drop=True)
    tr = df[df["time"] < comun.MORRIS_CORTES[0]].reset_index(drop=True)
    etiquetas = ["binary result", "categorized result", "specific result"]
    feats = [c for c in df.columns if c not in etiquetas + ["time"]]
    r = {"filas": len(tr), "de": len(df)}

    w("## Morris / Turnipseed")
    w("")
    w("### Qué es")
    w("")
    w("Registros de un gasoducto de laboratorio del Mississippi State SCADA")
    w("Lab, en su versión corregida. **No es tráfico de red**: cada fila es")
    w("una transacción Modbus con sus campos ya extraídos, de modo que no hay")
    w("captura ni posibilidad de recalcular las características.")
    w("")
    w("- %d transacciones en el tramo de entrenamiento, de %d en total"
      % (len(tr), len(df)))
    w("- 20 atributos: 1 de tiempo, %d características y 3 etiquetas"
      % len(feats))
    w("- Sin licencia declarada; recuperado del Internet Archive")
    w("")
    w("### Qué falta, y por qué")
    w("")
    nul = tr[feats].isna().mean().sort_values(ascending=False) * 100
    w("%-24s %8s" % ("atributo", "% nulos"))
    for c, v in nul[nul > 0].items():
        w("%-24s %7.1f %%" % (c, v))
    w("")
    cr = tr["command response"]
    w("La falta es estructural y la explica el sentido de la transacción: una")
    w("petición no trae medición y una respuesta no trae consigna. Medido:")
    w("")
    w("%-24s %14s %14s" % ("atributo", "nulos si cr=1", "nulos si cr=0"))
    for c in ("pressure measurement", "setpoint", "gain"):
        if c not in tr.columns:
            continue
        w("%-24s %13.0f %% %13.0f %%"
          % (c, 100 * tr.loc[cr == "1", c].isna().mean(),
             100 * tr.loc[cr == "0", c].isna().mean()))
    w("")
    w("`pressure measurement` falta en el %.1f %% de las filas del tramo,"
      % nul.get("pressure measurement", 0))
    w("y es el atributo con el que la literatura discute la fuga del conjunto")
    w("original. No corresponde imputarlo: en una petición no existe.")
    r["nulos"] = {k: float(v) for k, v in nul[nul > 0].items()}
    # Para la figura: nulos por atributo y por sentido de la transaccion.
    FIG["morris_nulos"] = pd.DataFrame({
        "comando (cr=1)": tr.loc[cr == "1", feats].isna().mean() * 100,
        "respuesta (cr=0)": tr.loc[cr == "0", feats].isna().mean() * 100,
    })
    w("")

    num = tr[feats].apply(pd.to_numeric, errors="coerce")
    nun = num.nunique(dropna=True)
    cte = sorted(nun[nun <= 1].index)
    w("### Qué variables hay en realidad")
    w("")
    w("- Constantes: **%d** — %s" % (len(cte), ", ".join(cte) or "ninguna"))
    utiles = [c for c in feats if c not in cte]
    sub = num[utiles]
    corr = sub.corr(method="spearman").abs()
    pares = [(a, b, corr.loc[a, b]) for i, a in enumerate(utiles)
             for b in utiles[i + 1:] if corr.loc[a, b] >= 0.8]
    w("- Pares con |Spearman| ≥ 0,8: **%d**" % len(pares))
    for a, b, v in sorted(pares, key=lambda x: -x[2])[:6]:
        w("    `%s` y `%s`: %.2f" % (a, b, v))
    w("")
    w("Hay mucha menos redundancia que en los conjuntos de flujo, donde un")
    w("solo grupo reunía veinte columnas. Acá los atributos son de naturaleza")
    w("distinta —consigna, ganancia, modo, código de función— y se mueven por")
    w("separado.")
    r["constantes"] = cte
    r["pares_fuertes"] = len(pares)
    w("")

    d = resumen_forma(num, utiles)
    cl = d["asim"].map(clase_asim).value_counts()
    w("### Cómo se distribuyen")
    w("")
    for k in ("simetrica", "moderada", "alta"):
        w("- asimetría %-10s %2d" % (k, int(cl.get(k, 0))))
    w("")
    r["asimetria"] = {k: int(cl.get(k, 0))
                      for k in ("simetrica", "moderada", "alta")}

    w("### Poder discriminante")
    w("")
    y = (tr["binary result"] == "1").astype(int)
    filas = []
    for c in utiles:
        x = num[c]
        m = x.notna()
        if m.sum() < 200 or x[m].nunique() <= 1 or y[m].nunique() < 2:
            continue
        auc = roc_auc_score(y[m], x[m])
        filas.append((c, float(auc), float(abs(auc - 0.5) + 0.5),
                      int(m.sum())))
    dd = pd.DataFrame(filas, columns=["campo", "auc", "auc_abs", "n"])
    dd = dd.sort_values("auc_abs", ascending=False)
    w("AUC de cada atributo frente a `binary result`, sobre las filas en que")
    w("el atributo existe:")
    w("")
    w("%-24s %8s %10s %10s" % ("atributo", "AUC", "AUC pleg.", "n"))
    for _, x in dd.head(8).iterrows():
        w("%-24s %8.3f %10.3f %10d" % (x.campo, x.auc, x.auc_abs, x.n))
    w("")
    mejor = dd.iloc[0]
    # La comparacion con los otros dos conjuntos se calcula, no se afirma:
    # el orden depende del dato y ya cambio una vez al medirlo.
    otros = {"Westermo": 0.563, "ICS-Flow": 0.669}
    peor_que = [k for k, v in otros.items() if mejor.auc_abs <= v]
    w("El mejor es `%s` con AUC plegado **%.3f**, frente a %s."
      % (mejor.campo, mejor.auc_abs,
         " y ".join("%.3f de %s" % (v, k) for k, v in otros.items())))
    w("")
    if not peor_que and mejor.auc_abs < 0.75:
        w("Es el más alto de los tres conjuntos con etiqueta, pero por poco y")
        w("sin llegar a separar bien: **en ninguno de los tres hay un atributo")
        w("que alcance solo.** Que Morris quede algo por encima es esperable,")
        w("porque sus atributos son semánticos y la anomalía los manipula de")
        w("forma directa, mientras que en los de flujo la anomalía aparece")
        w("recién al agregar paquetes. Pero la diferencia es de centésimas y")
        w("no cambia la conclusión.")
    elif peor_que:
        w("Queda por debajo de %s, de modo que no es el conjunto más separable"
          % " y ".join(peor_que))
        w("pese a tener atributos semánticos.")
    else:
        w("Es el único de los tres donde un atributo solo separa bien.")
    r["discriminante"] = {"mejor": mejor.campo,
                          "auc": float(mejor.auc_abs),
                          "evaluados": len(dd)}
    w("")

    w("### Estructura temporal")
    w("")
    w("Es una sola secuencia de transacciones, no varias conversaciones en")
    w("paralelo, de modo que la autocorrelación se mide sobre la serie")
    w("ordenada por `time`.")
    w("")
    w("%-8s %12s %14s" % ("retardo", "mediana", "con |ac|>0,3"))
    ac1 = None
    for lag in LAGS:
        v = np.array([autocorr_serie(num[c].values, lag) for c in utiles])
        v = v[np.isfinite(v)]
        if lag == 1:
            ac1 = float(np.median(v))
        w("%-8d %12.2f %14d" % (lag, np.median(v), int((np.abs(v) > 0.3).sum())))
    n = len(tr)
    n_eff = n * (1 - ac1) / (1 + ac1)
    w("")
    w("Con %.2f a retardo 1, las %d transacciones valen como **%d**, el %.0f %%."
      % (ac1, n, round(n_eff), 100 * n_eff / n))
    w("Las transacciones consecutivas se parecen porque el lazo de control")
    w("repite el mismo ciclo, así que vale la misma advertencia que en")
    w("ICS-Flow: validación por bloques y no al azar.")
    r["autocorrelacion"] = {"rho_lag1": ac1, "n": n, "n_efectivo": float(n_eff)}
    FIG["ac_Morris"] = (num[utiles], None)
    w("")

    w("### ¿Conviene reducir la dimensión?")
    w("")
    comp = num[utiles].dropna()
    w("Solo **%d** de las %d filas tienen los %d atributos a la vez (%.1f %%),"
      % (len(comp), len(tr), len(utiles), 100 * len(comp) / len(tr)))
    w("porque los faltantes estructurales se excluyen entre sí: una fila es")
    w("petición o respuesta, nunca las dos. Un PCA sobre esas filas describe")
    w("un subconjunto muy particular y no el conjunto, de modo que **no se")
    w("calcula**: la reducción, si se hiciera, tendría que ser por separado")
    w("para peticiones y para respuestas.")
    r["filas_completas"] = int(len(comp))
    w("")

    w("### Balance de clases")
    w("")
    vc = tr["categorized result"].value_counts().sort_index()
    nb = int((tr["binary result"] == "0").sum())
    na = int((tr["binary result"] == "1").sum())
    w("Binario: %d normales y %d ataques, razón %.1f : 1."
      % (nb, na, nb / max(1, na)))
    w("")
    w("Por categoría: %s" % ", ".join("%s %d" % kv for kv in vc.items()))
    w("")
    w("Es el único de los cinco con una taxonomía de anomalías contextuales")
    w("etiquetada, y por eso sostiene el compromiso de PD por tipo.")
    r["balance"] = {"normal": nb, "ataque": na,
                    "por_categoria": {str(k): int(v) for k, v in vc.items()}}
    w("")
    w("---")
    w("")
    return r


# --------------------------------------------------------------------- HAI
def hai(w):
    r = {}
    w("## HAI")
    w("")
    w("### Qué es")
    w("")
    w("Series de proceso de un banco de pruebas de generación térmica e")
    w("hidráulica, muestreadas a 1 Hz. **No trae ni una característica de")
    w("red**: todas sus columnas son variables físicas, en bar, mm, l/h, %,")
    w("grados, RPM, MW y Hz.")
    w("")
    w("Son cinco versiones que no comparten esquema entre sí:")
    w("")
    w("%-14s %9s %9s %10s %12s"
      % ("versión", "archivos", "columnas", "filas", "horas"))
    tot = {}
    for ver, sep, pat, tcol in HAI_VERSIONES:
        arch = sorted(glob.glob(os.path.join(comun.HAI, ver, pat)))
        filas, horas, ncol = 0, 0.0, 0
        for a in arch:
            x = pd.read_csv(a, sep=sep, usecols=lambda c: c.strip() == tcol)
            x.columns = [c.strip() for c in x.columns]
            t = pd.to_datetime(x[tcol])
            filas += len(x)
            horas += (t.max() - t.min()).total_seconds() / 3600.0
            ncol = pd.read_csv(a, sep=sep, nrows=2).shape[1]
        w("%-14s %9d %9d %10d %12.0f" % (ver, len(arch), ncol, filas, horas))
        tot[ver] = {"archivos": len(arch), "columnas": ncol, "filas": filas,
                    "horas": round(horas)}
    r["versiones"] = tot
    w("")
    w("La ficha que sigue se hace sobre **%s**, que es la versión con línea"
      % HAI_FICHA)
    w("base publicada y la que el relevamiento usa de referencia.")
    w("")

    ver, sep, pat, tcol = [v for v in HAI_VERSIONES if v[0] == HAI_FICHA][0]
    arch = sorted(glob.glob(os.path.join(comun.HAI, ver, pat)))
    df = pd.concat([pd.read_csv(a, sep=sep) for a in arch], ignore_index=True)
    df.columns = [c.strip() for c in df.columns]
    etq = [c for c in df.columns if c.lower().startswith("attack")]
    feats = [c for c in df.columns if c not in etq + [tcol]]
    num = df[feats].apply(pd.to_numeric, errors="coerce")

    w("### Qué falta, y por qué")
    w("")
    nul = num.isna().mean().max() * 100
    w("No falta nada: el máximo de nulos en cualquier columna es %.2f %%."
      % nul)
    w("Es lo esperable en un registro de proceso, que muestrea a intervalo")
    w("fijo y escribe el valor del instante.")
    r["nulos_max"] = float(nul)
    w("")

    nun = num.nunique(dropna=True)
    cte = sorted(nun[nun <= 1].index)
    casi = sorted([c for c in nun[nun > 1].index
                   if num[c].value_counts(normalize=True).iloc[0] >= 0.99])
    utiles = [c for c in feats if c not in cte]
    w("### Qué variables hay en realidad")
    w("")
    w("- Columnas de proceso: %d" % len(feats))
    w("- Constantes en el tramo de entrenamiento: **%d**" % len(cte))
    w("- Casi constantes (un valor en ≥ 99 %%): **%d**" % len(casi))
    corr = num[utiles].corr(method="spearman").abs()
    pares = sum(1 for i, a in enumerate(utiles) for b in utiles[i + 1:]
                if corr.loc[a, b] >= 0.8)
    w("- Pares con |Spearman| ≥ 0,8 entre las no constantes: **%d**" % pares)
    w("")
    w("")
    w("El %.0f %% de las columnas no varía en todo el tramo. Es la firma de un"
      % (100.0 * len(cte) / len(feats)))
    w("banco de pruebas donde parte de los lazos queda en reposo.")
    r["columnas"] = len(feats)
    r["constantes"] = len(cte)
    r["casi_constantes"] = len(casi)
    r["pares_fuertes"] = pares
    w("")

    d = resumen_forma(num, utiles)
    cl = d["asim"].map(clase_asim).value_counts()
    w("### Cómo se distribuyen")
    w("")
    for k in ("simetrica", "moderada", "alta"):
        w("- asimetría %-10s %2d" % (k, int(cl.get(k, 0))))
    w("")
    r["asimetria"] = {k: int(cl.get(k, 0))
                      for k in ("simetrica", "moderada", "alta")}

    w("### Poder discriminante: no se puede medir")
    w("")
    pos = int(sum((pd.to_numeric(df[c], errors="coerce").fillna(0) != 0).sum()
                  for c in etq[:1]))
    w("**Los archivos de entrenamiento de HAI no traen anomalías.** En esta")
    w("versión hay %d filas con etiqueta distinta de cero sobre %d, y son los"
      % (pos, len(df)))
    w("dos ataques que se colaron en `train2` y que INFORME.md ya")
    w("había detectado. Con una clase positiva de ese tamaño no se puede")
    w("estimar el poder discriminante de nada.")
    w("")
    w("Es una diferencia de diseño respecto de Westermo, ICS-Flow y Morris,")
    w("que sí traen anomalías etiquetadas dentro del tramo de entrenamiento.")
    w("Medirlo sobre el tramo de prueba daría el número, pero rompería el")
    w("protocolo, de modo que **queda sin medir y se deja dicho**.")
    r["positivos_en_train"] = pos
    w("")

    w("### Estructura temporal")
    w("")
    w("%-8s %12s %14s" % ("retardo", "mediana", "con |ac|>0,3"))
    ac1 = None
    for lag in LAGS:
        v = np.array([autocorr_serie(num[c].values, lag) for c in utiles])
        v = v[np.isfinite(v)]
        if lag == 1:
            ac1 = float(np.median(v))
        w("%-8d %12.2f %14d" % (lag, np.median(v), int((np.abs(v) > 0.3).sum())))
    n = len(df)
    # Con rho tan cerca de 1 la correccion AR(1) se vuelve inestable --- da un
    # numero enorme o ridiculo segun la cuarta cifra de rho --- asi que se usa
    # el tiempo de decorrelacion, que es el retardo en que la autocorrelacion
    # cae por debajo de 1/e y no depende de suponer un AR(1).
    taus = []
    for c in utiles:
        v = num[c].values
        for lag in (1, 2, 5, 10, 30, 60, 300, 600, 1800, 3600):
            a_ = autocorr_serie(v, lag)
            if a_ is not None and np.isfinite(a_) and a_ < 1 / np.e:
                taus.append(lag)
                break
        else:
            taus.append(3600)
    tau = float(np.median(taus))
    w("")
    w("Con %.2f a retardo 1 es **el valor más alto de los cuatro conjuntos**."
      % ac1)
    w("Tan cerca de 1 la corrección AR(1) deja de ser fiable, porque su")
    w("resultado cambia de orden con la cuarta cifra de la autocorrelación.")
    w("Se usa en su lugar el tiempo de decorrelación, el retardo en que la")
    w("autocorrelación cae por debajo de 1/e:")
    w("")
    w("- Tiempo de decorrelación mediano: **%.0f s**" % tau)
    w("- Muestras independientes equivalentes: **≈ %d** sobre %d"
      % (round(n / tau), n))
    w("")
    w("A 1 Hz cada fila es casi idéntica a la anterior. El conjunto tiene")
    w("órdenes de magnitud menos observaciones independientes de las que")
    w("aparenta, y esa es la cifra que hay que usar para cualquier intervalo.")
    r["autocorrelacion"] = {"rho_lag1": ac1, "n": n,
                            "tau_decorrelacion_s": tau,
                            "independientes": float(n / tau)}
    FIG["ac_HAI"] = (num[utiles], None)
    w("")

    w("### ¿Conviene reducir la dimensión?")
    w("")
    comp = num[utiles].dropna()
    X = StandardScaler().fit_transform(comp.to_numpy(float))
    p = PCA(random_state=comun.SEMILLA).fit(X)
    acum = np.cumsum(p.explained_variance_ratio_)
    n90 = int(np.searchsorted(acum, 0.90) + 1)
    n95 = int(np.searchsorted(acum, 0.95) + 1)
    w("PCA sobre las %d columnas no constantes, con las %d filas completas."
      % (len(utiles), len(comp)))
    w("")
    w("- **%d componentes** para el 90 %% de la varianza, **%d** para el 95 %%"
      % (n90, n95))
    w("- La primera explica el %.1f %%" % (100 * acum[0]))
    w("")
    w("Es la reducción más fuerte de los cuatro conjuntos medidos: %d de %d"
      % (n90, len(utiles)))
    w("columnas bastan para el 90 % de la varianza.")
    r["pca"] = {"no_constantes": len(utiles), "n_90": n90, "n_95": n95,
                "primera": float(acum[0])}
    w("")
    w("### Balance de clases")
    w("")
    w("No aplica en el tramo de entrenamiento, por lo dicho más arriba: no")
    w("hay clase positiva. El recuento de ataques por versión, sobre los")
    w("archivos de prueba y solo como conteo, está en la pregunta 4 de")
    w("INFORME.md.")
    w("")
    w("---")
    w("")
    return r


def figuras():
    """Dos figuras: los faltantes de Morris y la caida de la autocorrelacion.

    La segunda incluye a Westermo y a ICS-Flow, que se leen de los derivados
    que deja `16_exploratorio_flujos.py`, para que los cuatro conjuntos
    medibles se vean en el mismo eje. Es la evidencia de que el tamano
    nominal no dice cuantas observaciones independientes hay.
    """
    plt = comun.estilo_figura()

    # --- 1. faltantes de Morris por sentido de la transaccion ---
    d = FIG["morris_nulos"]
    d = d[(d > 0).any(axis=1)].sort_values("respuesta (cr=0)")
    fig, ax = plt.subplots(figsize=(7.5, 4.6))
    y = np.arange(len(d))
    ax.barh(y - 0.2, d["comando (cr=1)"], height=0.4, label="comando (cr=1)",
            color="#4C72B0")
    ax.barh(y + 0.2, d["respuesta (cr=0)"], height=0.4,
            label="respuesta (cr=0)", color="#DD8452")
    ax.set_yticks(y)
    ax.set_yticklabels(d.index, fontsize=8)
    ax.set_xlabel("% de valores ausentes")
    ax.set_xlim(0, 100)
    ax.set_title("Morris: el atributo falta según el sentido de la "
                 "transacción\nninguna fila tiene los dieciséis a la vez",
                 fontsize=9)
    ax.legend(fontsize=8, loc="lower right")
    fig.savefig(os.path.join(comun.FIGURAS, "p18_morris_faltantes.png"))

    # --- 2. caida de la autocorrelacion, los cuatro medibles ---
    # Westermo e ICS-Flow son varias conversaciones en paralelo, de modo que
    # la autocorrelacion se calcula DENTRO de cada una y se pondera por su
    # largo, igual que en el script 17. Mezclarlas diluye el valor y daria
    # una curva que no coincide con la cifra de INFORME.md.
    series = {}
    for nom, arch, tcol in (
            ("Westermo", "westermo_bottom_entrenamiento.csv", "startOffset"),
            ("ICS-Flow", "icsflow_entrenamiento.csv", "start")):
        ruta = os.path.join(comun.DERIVADOS, arch)
        if not os.path.exists(ruta):
            continue
        x = pd.read_csv(ruta).sort_values(tcol)
        cols = list(x.columns)[13:60]
        n = x[cols].apply(pd.to_numeric, errors="coerce")
        grupos = [g for _k, g in n.groupby([x["sAddress"], x["rAddress"]])
                  if len(g) >= 200]
        series[nom] = ("grupos", grupos,
                       [c for c in cols if n[c].nunique(dropna=True) > 1])
    for nom in ("Morris", "HAI"):
        if "ac_" + nom in FIG:
            X = FIG["ac_" + nom][0]
            series[nom] = ("unica", [X], list(X.columns))

    lags = [1, 2, 3, 5, 10, 20, 50, 100, 300, 1000, 3000]
    fig, ax = plt.subplots(figsize=(7.5, 4.4))
    for nom, (_tipo, grupos, cols) in series.items():
        med = []
        for lag in lags:
            por_campo = []
            for c in cols:
                num_, den_ = 0.0, 0.0
                for g in grupos:
                    a_ = autocorr_serie(g[c].values, lag)
                    if a_ is not None and np.isfinite(a_):
                        num_ += a_ * len(g)
                        den_ += len(g)
                if den_:
                    por_campo.append(num_ / den_)
            med.append(np.median(por_campo) if por_campo else np.nan)
        ax.plot(lags, med, marker="o", ms=3.5, label=nom)
    ax.axhline(1 / np.e, color="crimson", ls="--", lw=1.1,
               label="1/e: límite de decorrelación")
    ax.axhline(0, color="k", lw=0.7)
    ax.set_xscale("log")
    ax.set_xlabel("retardo, en registros del propio conjunto")
    ax.set_ylabel("autocorrelación mediana entre variables")
    ax.set_title("Cuánto tarda cada conjunto en decorrelacionarse\n"
                 "cuanto más tarda, menos observaciones independientes tiene",
                 fontsize=9)
    ax.legend(fontsize=8)
    fig.savefig(os.path.join(comun.FIGURAS, "p18_decorrelacion.png"))
    print("[figuras] p18_morris_faltantes.png, p18_decorrelacion.png")


def main():
    comun.preparar()
    warnings.filterwarnings("ignore", category=RuntimeWarning,
                            message=".*encountered in matmul.*")
    L = []
    w = L.append
    w("# Exploración de Morris y de HAI")
    w("")
    w("Generado por `eda/scripts/18_exploratorio_resto.py`.")
    w("Solo tramo de entrenamiento.")
    w("")
    res = {"Morris": morris(w), "HAI": hai(w)}
    figuras()
    comun.escribir("p18_exploratorio_resto.txt", "\n".join(L))
    with open(os.path.join(comun.SALIDAS,
                           "p18_exploratorio_resto.json"), "w") as fh:
        json.dump(res, fh, indent=1, ensure_ascii=False, default=str)


if __name__ == "__main__":
    main()
