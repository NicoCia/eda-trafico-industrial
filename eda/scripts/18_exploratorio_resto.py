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


def autocorr_segmentos(segmentos, lag):
    """Autocorrelacion agrupada sobre tramos discontinuos.

    Misma regla que `05_determinismo.py`: no se puede concatenar tramos
    separados por huecos, porque el salto introduce correlaciones falsas. Se
    acumulan numerador y denominador por tramo, con la media global, y solo se
    usan pares dentro de un mismo tramo.

    Los `train` de HAI son campanas de adquisicion separadas por dias --- en
    `hai-20.07` el hueco entre `train1` y `train2` es de 47,4 dias ---, de modo
    que la serie es segmentada y no continua. Una version anterior de este
    script las concatenaba antes de medir, que es justo lo que el script 05
    prohibe por escrito y evita para Westermo.
    """
    ss = [np.asarray(s, dtype=float) for s in segmentos]
    ss = [s[np.isfinite(s)] for s in ss]
    ss = [s for s in ss if len(s) > lag]
    if not ss:
        return np.nan
    todo = np.concatenate(ss)
    mu = todo.mean()
    den = float(((todo - mu) ** 2).sum())
    if den == 0:
        return np.nan
    num = 0.0
    for s in ss:
        z = s - mu
        num += float((z[:-lag] * z[lag:]).sum())
    return num / den


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
    # Dos cantidades que no son la misma y conviene no mezclar: la TASA POR
    # COLUMNA de las columnas afectadas, y la FRACCION DE CELDAS del conjunto.
    # La segunda depende del denominador, asi que se informa con los tres que
    # tienen sentido.
    afect = nul[nul > 0]
    etiq = [c for c in tr.columns if c in ("binary result", "categorized result",
                                           "specific result")]
    sin_etiq = [c for c in tr.columns if c not in etiq]
    w("Las dos cantidades que no hay que confundir:")
    w("")
    w("  tasa por columna de las %d columnas afectadas: %.1f a %.1f %%"
      % (len(afect), afect.min(), afect.max()))
    for nom, cols in (("las %d caracteristicas" % len(feats), list(feats)),
                      ("las %d columnas sin etiqueta" % len(sin_etiq), sin_etiq),
                      ("las %d columnas" % len(tr.columns), list(tr.columns))):
        w("  fraccion de celdas faltantes sobre %-28s %5.1f %%"
          % (nom + ":", 100 * tr[cols].isna().mean().mean()))
    w("")
    w("La tasa por columna es alta porque la falta es estructural y parte el")
    w("conjunto en dos mitades; la fraccion de celdas es la que se puede")
    w("comparar contra otro conjunto, y solo si se declara el denominador.")
    w("")
    res_falt = {"tasa_por_columna_min": float(afect.min()),
                "tasa_por_columna_max": float(afect.max()),
                "columnas_afectadas": int(len(afect)),
                "celdas_sobre_caracteristicas":
                    float(100 * tr[list(feats)].isna().mean().mean()),
                "celdas_sobre_sin_etiqueta":
                    float(100 * tr[sin_etiq].isna().mean().mean()),
                "celdas_sobre_todas":
                    float(100 * tr[list(tr.columns)].isna().mean().mean())}
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
    dd["cobertura"] = 100.0 * dd["n"] / len(tr)
    # Prevalencia de la clase positiva en la subpoblacion de cada atributo: si
    # cambia, el AUC no esta midiendo sobre la misma poblacion que los demas.
    dd["prev"] = [100.0 * y[num[c].notna()].mean() for c in dd["campo"]]
    dd = dd.sort_values("auc_abs", ascending=False)
    w("AUC de cada atributo frente a `binary result`, sobre las filas en que")
    w("el atributo existe. **La columna de cobertura decide si dos AUC son")
    w("comparables**: un atributo que falta en tres de cada cuatro filas se")
    w("evalua sobre otra poblacion, y con otra prevalencia de la clase")
    w("positiva, que uno presente en todas.")
    w("")
    w("%-24s %8s %10s %10s %7s %7s"
      % ("atributo", "AUC", "AUC pleg.", "n", "cob.%", "pos.%"))
    for _, x in dd.head(8).iterrows():
        w("%-24s %8.3f %10.3f %10d %7.1f %7.1f"
          % (x.campo, x.auc, x.auc_abs, x.n, x.cobertura, x.prev))
    w("")
    mejor = dd.iloc[0]
    # Las cifras de los otros dos conjuntos son de poblacion completa, de modo
    # que lo comparable es el mejor atributo COMPLETO, no el mejor absoluto.
    COB_MIN = 99.0
    completos = dd[dd["cobertura"] >= COB_MIN]
    mejor_comp = completos.iloc[0] if len(completos) else None
    # Se LEEN de la salida del script 17, no se escriben a mano. Una version
    # anterior las traia fijas --- 0,563 y 0,669 --- con un comentario que
    # afirmaba que eran de poblacion completa. No lo son: son los maximos
    # absolutos, medidos sobre el 83,8 % y el 99,0 % de las filas. Comparar
    # el mejor COMPLETO de Morris contra el maximo ABSOLUTO de los otros dos
    # es el mismo error de base que esta seccion corrige.
    otros = {}
    p17 = os.path.join(comun.SALIDAS, "p17_discriminante_estructura.json")
    if os.path.exists(p17):
        with open(p17, encoding="utf-8") as fh:
            d17 = json.load(fh)
        for k, v in d17.items():
            a = (v.get("discriminante") or {}).get("auc_max_poblacion_completa")
            if a is not None:
                otros[k] = float(a)
    if not otros:
        w("**Falta `p17_discriminante_estructura.json`**, de modo que la")
        w("comparación entre conjuntos no se hace: las cifras de los otros")
        w("dos se leen de esa salida y no se escriben a mano.")
        w("")
    w("Sobre **todo el tramo** (cobertura >= %.0f %%) el mejor es `%s` con AUC"
      % (COB_MIN, mejor_comp.campo if mejor_comp is not None else "-"))
    w("plegado **%.3f**. Esa es la cifra comparable con %s,"
      % (mejor_comp.auc_abs if mejor_comp is not None else float("nan"),
         " y ".join("%.3f de %s" % (v, k) for k, v in otros.items())))
    w("que son de población completa.")
    w("")
    if mejor.campo != (mejor_comp.campo if mejor_comp is not None else None):
        w("El mejor absoluto es otro: `%s`, con **%.3f**, pero medido sobre"
          % (mejor.campo, mejor.auc_abs))
        w("%d filas, el %.1f %% del tramo, donde la clase positiva pesa"
          % (mejor.n, mejor.cobertura))
        w("%.1f %% en lugar del %.1f %% del tramo entero. Es un AUC"
          % (mejor.prev, 100.0 * y.mean()))
        w("**condicional** a que el atributo exista, y no se puede poner al")
        w("lado de los otros dos conjuntos como si fuera lo mismo.")
        w("")
    base = mejor_comp.auc_abs if mejor_comp is not None else mejor.auc_abs
    peor_que = [k for k, v in otros.items() if base <= v]
    if not peor_que and base < 0.75:
        w("Con esa base Morris queda el más alto de los tres conjuntos con")
        w("etiqueta, por poco y sin llegar a separar bien.")
    elif peor_que:
        w("Con esa base Morris **queda por debajo de %s**, de modo que no es"
          % " y ".join(peor_que))
        w("el conjunto más separable pese a tener atributos semánticos. Lo")
        w("que sí se sostiene, y es la conclusión que importa, es que **en")
        w("ninguno de los tres hay un atributo que alcance solo**: los tres")
        w("mejores quedan entre 0,56 y 0,67.")
    else:
        w("Es el único de los tres donde un atributo solo separa bien.")
    r["discriminante"] = {
        "mejor_absoluto": mejor.campo,
        "auc_absoluto": float(mejor.auc_abs),
        "cobertura_del_mejor_absoluto": float(mejor.cobertura),
        "prevalencia_en_esa_subpoblacion": float(mejor.prev),
        "prevalencia_en_el_tramo": float(100.0 * y.mean()),
        "mejor_en_poblacion_completa": (mejor_comp.campo
                                        if mejor_comp is not None else None),
        "auc_en_poblacion_completa": (float(mejor_comp.auc_abs)
                                      if mejor_comp is not None else None),
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
    w("**Pero el retardo 1 de la mayoría de estas columnas no es medible, y")
    w("el número de arriba no es lo que parece.** El cálculo quita los")
    w("ausentes y recién después empareja posiciones contiguas del arreglo")
    w("compacto, de modo que para una columna presente en un cuarto de las")
    w("filas «retardo 1» empareja filas que están a cuatro de distancia:")
    w("")
    w("   %-24s %7s %9s %10s %12s"
      % ("columna", "cob.%", "rho", "n propio", "pares contig."))
    det, nefs = [], []
    for c in utiles:
        v = pd.to_numeric(num[c], errors="coerce").to_numpy(float)
        ok = np.isfinite(v)
        if ok.sum() < 2 or v[ok].std() == 0:
            continue
        rr = autocorr_serie(v, 1)
        nc = int(ok.sum())
        par = int((ok[:-1] & ok[1:]).sum())
        ne = nc * (1 - rr) / (1 + rr) if rr > -1 else float(nc)
        det.append({"columna": c, "cobertura": float(ok.mean()), "rho": rr,
                    "n_propio": nc, "pares_contiguos": par,
                    "n_efectivo_propio": float(ne)})
        nefs.append(ne)
    for d_ in sorted(det, key=lambda x: x["cobertura"]):
        w("   %-24s %7.1f %9.3f %10d %12d"
          % (d_["columna"][:24], 100 * d_["cobertura"], d_["rho"],
             d_["n_propio"], d_["pares_contiguos"]))
    sin_par = [d_ for d_ in det if d_["pares_contiguos"] == 0]
    med_ne = float(np.median(nefs)) if nefs else float("nan")
    w("")
    w("**%d de las %d columnas no tienen ni un par de filas contiguas con los"
      % (len(sin_par), len(det)))
    w("dos valores presentes**: los atributos de proceso vienen solo en las")
    w("respuestas. Para ellas el retardo 1 entre filas no es estimable, y lo")
    w("que se calcula es la autocorrelación de la subsecuencia, con un")
    w("retardo efectivo de unas cuatro filas y sobre %d filas de un solo"
      % (sin_par[0]["n_propio"] if sin_par else 0))
    w("tipo de transacción. Las completas dan rho entre %.3f y %.3f."
      % (min(d_["rho"] for d_ in det if d_["pares_contiguos"] > 0),
         max(d_["rho"] for d_ in det if d_["pares_contiguos"] > 0)))
    w("")
    w("Encima el n efectivo de arriba usa las %d filas para todas. Con el n" % n)
    w("propio de cada columna, la mediana del n efectivo es **%d**, no %d."
      % (round(med_ne), round(n_eff)))
    w("Las transacciones consecutivas se parecen porque el lazo de control")
    w("repite el mismo ciclo, así que vale la advertencia de siempre")
    w("—validación por bloques y no al azar— pero la magnitud de la")
    w("corrección no es la que publicaba este cuadro.")
    r["autocorrelacion"] = {
        "rho_lag1": ac1, "n": n, "n_efectivo": float(n_eff),
        "n_efectivo_mediana_por_columna": med_ne,
        "columnas_sin_pares_contiguos": len(sin_par),
        "por_columna": det}
    w("")

    # La autocorrelacion de la ETIQUETA es otra pregunta, y es la que decide
    # si un corte al azar filtra. La tabla comparativa de EXPLORATORIO.md
    # traia en esa fila, para Morris, la cifra de las CARACTERISTICAS ---
    # 0,86 y 12.060 ---, que es justo la confusion que el hallazgo 5 de ese
    # documento levanta como hallazgo. Se mide aparte.
    y = (pd.to_numeric(tr["binary result"], errors="coerce") != 0).to_numpy()
    ye = y.astype(float)
    z = ye - ye.mean()
    rho_y = float((z[:-1] * z[1:]).sum() / (z * z).sum()) if z.var() else 0.0
    n_eff_y = n * (1 - rho_y) / (1 + rho_y)
    cambios = int((y[1:] != y[:-1]).sum())
    rachas = cambios + 1
    mejor = act = 0
    for v in y:
        act = act + 1 if v else 0
        mejor = max(mejor, act)
    w("La autocorrelación de la **etiqueta**, que es otra pregunta y la que")
    w("decide si un corte al azar filtra:")
    w("")
    ind_y = comun.observaciones_independientes(ye)
    w("- a retardo 1: **%.3f** (contra %.3f de las características)"
      % (rho_y, ac1))
    w("- rachas: %d ; racha anómala más larga: %d filas" % (rachas, mejor))
    w("")
    w("**Y acá el retardo 1 es justo donde no está la estructura.** La")
    w("etiqueta alterna comando y respuesta, lo que fuerza los retardos 1 y 2")
    w("hacia abajo y pone la dependencia en los múltiplos de 4:")
    w("")
    w("   %-10s %10s" % ("retardo", "rho"))
    for lag in (1, 2, 3, 4, 8, 16, 32):
        w("   %-10d %10.4f" % (lag, autocorr_serie(ye, lag)))
    w("")
    if ind_y:
        _lags = (1, 2, 3, 4, 8, 16, 32)
        _pico = max(_lags[1:], key=lambda k: autocorr_serie(ye, k))
        w("De modo que la corrección AR(1) con rho(1) no corresponde: con")
        w("rho(1) = %.3f un AR(1) predeciría rho(%d) = %.4f, y lo medido en"
          % (ind_y["rho1"], _pico, ind_y["rho1"] ** _pico))
        w("ese retardo es **%.4f**. Los dos estimadores dan:"
          % autocorr_serie(ye, _pico))
        w("")
        w("- AR(1) con rho(1): %d de %d" % (round(ind_y["n_ar1"]), n))
        w("- tiempo de decorrelación (último retardo con rho >= 1/e): "
          "tau = %s filas -> **%d de %d**"
          % ((">=%d" % ind_y["tau"]) if ind_y["tau_censurado"]
             else "%d" % ind_y["tau"], round(ind_y["n_tau"]), n))
        w("")
        w("El segundo no supone ningún modelo y es el criterio que este")
        w("trabajo ya usa para HAI, de modo que es el que hace comparable la")
        w("fila entre los cuatro conjuntos. La lectura de fondo no cambia —la")
        w("etiqueta de Morris es mucho menos dependiente que sus")
        w("características— pero la ventaja es de un orden y no de tres.")
    w("")
    r["autocorrelacion_objetivo"] = {
        "rho_lag1": rho_y, "n": n, "n_efectivo": float(n_eff_y),
        "independientes": ind_y,
        "por_lag": {str(k): float(autocorr_serie(ye, k))
                    for k in (1, 2, 3, 4, 8, 16, 32)},
        "rachas": rachas, "racha_mas_larga": mejor}
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
    r["faltantes"] = res_falt
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
    # Los archivos se guardan POR SEPARADO, no solo concatenados: lo que es
    # legitimo calcular sobre la union (que falta, que varia, como se
    # distribuye, cuanto se correlacionan dos columnas) no lo es para nada
    # que mire el orden temporal, porque entre un archivo y el siguiente hay
    # dias de hueco. La seccion de estructura temporal usa `piezas`.
    piezas = []
    for a in arch:
        x = pd.read_csv(a, sep=sep)
        x.columns = [c.strip() for c in x.columns]
        piezas.append(x)
    df = pd.concat(piezas, ignore_index=True)
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
    w("Los %d archivos `train` de %s son campañas separadas por días, de modo"
      % (len(piezas), HAI_FICHA))
    w("que la serie es **segmentada**. Se mide con pares dentro de un mismo")
    w("archivo, como hace `05_determinismo.py` para Westermo: concatenar")
    w("tramos separados por huecos introduce correlaciones falsas.")
    w("")
    segs = {c: [pd.to_numeric(p[c], errors="coerce").to_numpy(float)
                for p in piezas if c in p.columns] for c in utiles}
    w("%-8s %12s %14s %16s" % ("retardo", "mediana", "con |ac|>0,3",
                               "si se concatena"))
    ac1 = None
    for lag in LAGS:
        v = np.array([autocorr_segmentos(segs[c], lag) for c in utiles])
        v = v[np.isfinite(v)]
        vc = np.array([autocorr_serie(num[c].values, lag) for c in utiles])
        vc = vc[np.isfinite(vc)]
        if lag == 1:
            ac1 = float(np.median(v))
        w("%-8d %12.2f %14d %16.2f"
          % (lag, np.median(v), int((np.abs(v) > 0.3).sum()), np.median(vc)))
    n = len(df)
    # Con rho tan cerca de 1 la correccion AR(1) se vuelve inestable --- da un
    # numero enorme o ridiculo segun la cuarta cifra de rho --- asi que se usa
    # el tiempo de decorrelacion, que es el retardo en que la autocorrelacion
    # cae por debajo de 1/e y no depende de suponer un AR(1).
    LAGS_TAU = (1, 2, 5, 10, 30, 60, 300, 600, 1800, 3600)
    taus, taus_conc = [], []
    for c in utiles:
        for lag in LAGS_TAU:
            a_ = autocorr_segmentos(segs[c], lag)
            if a_ is not None and np.isfinite(a_) and a_ < 1 / np.e:
                taus.append(lag)
                break
        else:
            taus.append(3600)
        v = num[c].values
        for lag in LAGS_TAU:
            a_ = autocorr_serie(v, lag)
            if a_ is not None and np.isfinite(a_) and a_ < 1 / np.e:
                taus_conc.append(lag)
                break
        else:
            taus_conc.append(3600)
    tau = float(np.median(taus))
    tau_conc = float(np.median(taus_conc))
    cambian = sum(1 for a_, b_ in zip(taus, taus_conc) if a_ != b_)
    w("")
    w("La última columna es la medida mal hecha, a propósito, para saber")
    w("cuánto costaba el atajo: con un solo hueco entre %d filas el sesgo"
      % n)
    w("no se ve. Tiempo de decorrelación mediano **%.0f s** por tramos y"
      % tau)
    w("%.0f s concatenando, y de las %d columnas no constantes cambian **%d**."
      % (tau_conc, len(utiles), cambian))
    w("De modo que las cifras publicadas no dependían del error; lo que se")
    w("corrige es el método, que contradecía la regla del propio script 05.")
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
    r["autocorrelacion_concatenando"] = {"tau_s": tau_conc,
                                         "columnas_que_cambian": cambian}
    r["autocorrelacion"] = {"rho_lag1": ac1, "n": n, "segmentos": len(piezas),
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
