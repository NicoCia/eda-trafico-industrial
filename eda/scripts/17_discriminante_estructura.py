"""Poder discriminante, estructura temporal y reduccion, en Westermo e ICS-Flow.

Cierra los huecos que quedaban en `eda/EXPLORATORIO.md`:

  1. **Poder discriminante por caracteristica**, que el requerimiento 2.8 pide
     junto con las distribuciones y la periodicidad, y que no estaba medido.
  2. **Estructura temporal**: autocorrelacion de las caracteristicas dentro de
     cada conversacion y el tamano de muestra efectivo que implica. Decide si
     las filas se pueden tratar como independientes, que es un supuesto que
     atraviesa todo lo demas.
  3. **Reduccion de dimension**: PCA y LDA, con los numeros que justifican
     usarlas o no.
  4. **Datos sensibles**: que identificadores de red publica cada conjunto.

Criterios de la materia Analisis de Datos (CEIA, FIUBA). Se usa scikit-learn
en lugar de implementaciones propias para que un revisor audite un parametro y
no un calculo.

Particion: solo el tramo de entrenamiento. Todo lo que aprende de los datos
--el escalado del PCA, el ajuste del LDA-- se ajusta aqui y nunca con prueba.

Uso:  python eda/scripts/17_discriminante_estructura.py
"""

import importlib
import json
import os
import sys
import warnings

import numpy as np
import pandas as pd
from sklearn.decomposition import PCA
from sklearn.discriminant_analysis import LinearDiscriminantAnalysis
from sklearn.feature_selection import f_classif, mutual_info_classif
from sklearn.metrics import roc_auc_score
from sklearn.preprocessing import StandardScaler

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import comun  # noqa: E402

N_IDENT, N_FEATS = 13, 47
OBJETIVO = "NST_B_Label"       # el etiquetado de referencia del proyecto
PARALELO = "IT_B_Label"        # se informa al lado, como cota
LAGS = (1, 2, 5, 10)


def cargar():
    W = pd.read_csv(os.path.join(comun.DERIVADOS,
                                 "westermo_bottom_entrenamiento.csv"))
    F = pd.read_csv(os.path.join(comun.DERIVADOS,
                                 "icsflow_entrenamiento.csv"))
    return [("Westermo", W, "startOffset"), ("ICS-Flow", F, "start")]


def discriminante(df, feats, objetivo):
    """AUC, eta cuadrado e informacion mutua de cada caracteristica."""
    y = pd.to_numeric(df[objetivo], errors="coerce")
    filas = []
    for c in feats:
        x = pd.to_numeric(df[c], errors="coerce")
        m = x.notna() & y.notna()
        if m.sum() < 100 or x[m].nunique() <= 1 or y[m].nunique() < 2:
            continue
        xi, yi = x[m].to_numpy(float), y[m].to_numpy(int)
        auc = roc_auc_score(yi, xi)
        # El AUC por debajo de 0,5 discrimina igual, con el signo invertido.
        filas.append({"campo": c, "n": int(m.sum()),
                      "auc": float(auc), "auc_abs": float(abs(auc - 0.5) + 0.5),
                      "F": float(f_classif(xi.reshape(-1, 1), yi)[0][0])})
    if not filas:
        return pd.DataFrame()
    d = pd.DataFrame(filas)
    # Informacion mutua de una sola vez, sobre las filas completas: captura
    # relaciones no monotonas que el AUC se pierde.
    cols = list(d["campo"])
    sub = df[cols + [objetivo]].apply(pd.to_numeric, errors="coerce").dropna()
    if len(sub) > 200:
        mi = mutual_info_classif(sub[cols].to_numpy(float),
                                 sub[objetivo].to_numpy(int),
                                 random_state=comun.SEMILLA)
        d["mi"] = mi
    else:
        d["mi"] = np.nan
    return d.sort_values("auc_abs", ascending=False).reset_index(drop=True)


def autocorrelacion(df, feats, tcol):
    """Autocorrelacion por conversacion, ponderada por su largo.

    Una fila no es una observacion suelta: pertenece a una conversacion que
    avanza en el tiempo. Mezclar conversaciones al calcular el retardo
    inventaria una correlacion que no existe, asi que se calcula dentro de
    cada una y recien despues se promedia.
    """
    d = df.sort_values(tcol)
    grupos = [g for _k, g in d.groupby(["sAddress", "rAddress"])
              if len(g) >= 200]
    out = {}
    for lag in LAGS:
        por_campo = {}
        for c in feats:
            num, den = 0.0, 0.0
            for g in grupos:
                v = pd.to_numeric(g[c], errors="coerce").dropna().to_numpy(float)
                if len(v) <= lag or v.std() == 0:
                    continue
                z = v - v.mean()
                r = float((z[:-lag] * z[lag:]).sum() / (z * z).sum())
                num += r * len(v)
                den += len(v)
            if den:
                por_campo[c] = num / den
        out[lag] = por_campo
    return out, len(grupos)


def main():
    comun.preparar()
    # numpy compilado contra Accelerate (macOS) emite avisos de desbordamiento
    # en `matmul` que no afectan al resultado: se comprobo que el PCA da lo
    # mismo por tres caminos --sklearn, autovalores de la covarianza y SVD--
    # con una diferencia maxima de 1e-15. Se silencian para no ensuciar la
    # salida; la comprobacion esta en la seccion de reduccion de
    # EXPLORATORIO.md.
    warnings.filterwarnings("ignore", category=RuntimeWarning,
                            message=".*encountered in matmul.*")
    plt = comun.estilo_figura()
    L, res = [], {}
    w = L.append
    w("# Poder discriminante, estructura temporal y reduccion")
    w("")
    w("Generado por `eda/scripts/17_discriminante_estructura.py`.")
    w("Solo tramo de entrenamiento. Objetivo: `%s`." % OBJETIVO)
    w("")

    datos = cargar()
    disc, auto, pcas = {}, {}, {}

    for nombre, df, tcol in datos:
        feats = list(df.columns)[N_IDENT:N_IDENT + N_FEATS]
        r = {}
        w("## %s" % nombre)
        w("")

        # ---------- 1. poder discriminante ----------
        d = discriminante(df, feats, OBJETIVO)
        d2 = discriminante(df, feats, PARALELO)
        disc[nombre] = d
        w("### Poder discriminante por característica")
        w("")
        w("AUC de cada característica tomada sola frente a `%s`. Un AUC de"
          % OBJETIVO)
        w("0,5 es no discriminar; se informa además el valor plegado, que trata")
        w("igual a las que discriminan con el signo invertido.")
        w("")
        w("%-20s %7s %9s %10s %9s" % ("campo", "AUC", "AUC pleg.", "F de ANOVA",
                                      "inf. mutua"))
        for _, x in d.head(12).iterrows():
            w("%-20s %7.3f %9.3f %10.0f %9.3f"
              % (x.campo, x.auc, x.auc_abs, x.F, x.mi))
        w("")
        fuertes = int((d["auc_abs"] >= 0.70).sum())
        nulas = int((d["auc_abs"] < 0.55).sum())
        w("De las %d características evaluadas: **%d** alcanzan AUC plegado"
          % (len(d), fuertes))
        w("≥ 0,70 y **%d** quedan por debajo de 0,55, es decir que no" % nulas)
        w("discriminan por sí solas.")
        w("")
        if len(d2):
            w("Con el etiquetado `%s` como objetivo, el mejor AUC plegado pasa"
              % PARALELO)
            w("de %.3f a %.3f: la estrategia de etiquetado cambia también qué"
              % (d["auc_abs"].max(), d2["auc_abs"].max()))
            w("tan separable es el problema, no solo su balance.")
        r["discriminante"] = {
            "evaluadas": len(d), "auc_max": float(d["auc_abs"].max()),
            "fuertes_070": fuertes, "nulas_055": nulas,
            "top": d.head(12)[["campo", "auc", "auc_abs", "mi"]]
                    .to_dict("records")}
        w("")

        # ---------- 2. estructura temporal ----------
        ac, n_conv = autocorrelacion(df, feats, tcol)
        auto[nombre] = ac
        w("### Estructura temporal")
        w("")
        w("Autocorrelación dentro de cada conversación, ponderada por su largo")
        w("(%d conversaciones con al menos 200 flujos)." % n_conv)
        w("")
        w("%-8s %10s %10s %12s" % ("retardo", "mediana", "p90", "con |ac|>0,3"))
        for lag in LAGS:
            v = np.array(list(ac[lag].values()))
            w("%-8d %10.2f %10.2f %12d"
              % (lag, np.median(v), np.percentile(v, 90),
                 int((np.abs(v) > 0.3).sum())))
        rho = float(np.median(list(ac[1].values())))
        n = len(df)
        # Correccion AR(1) del tamano de muestra: n_eff = n (1-rho)/(1+rho).
        n_eff = n * (1 - rho) / (1 + rho) if rho > -1 else n
        w("")
        if rho > 0.05:
            w("Con una autocorrelación mediana a retardo 1 de **%.2f**, la"
              % rho)
            w("corrección AR(1) del tamaño de muestra da")
            w("**n_efectivo ≈ %d** sobre %d filas, el %.0f %%."
              % (round(n_eff), n, 100 * n_eff / n))
        else:
            w("La autocorrelación mediana a retardo 1 es **%.2f**, de modo"
              % rho)
            w("que la corrección AR(1) del tamaño de muestra es inmaterial:")
            w("las %d filas valen como %d." % (n, round(n_eff)))
        w("")
        if rho >= 0.3:
            w("Las filas **no** se pueden tratar como independientes. Toda")
            w("validación cruzada tiene que ser por bloques temporales, nunca")
            w("al azar, y los intervalos de confianza calculados como si")
            w("fueran independientes salen demasiado angostos.")
        else:
            w("Las filas sucesivas son casi independientes, de modo que los")
            w("estadísticos habituales se pueden usar sin corrección.")
        r["autocorrelacion"] = {"rho_lag1": rho, "n": n,
                                "n_efectivo": float(n_eff),
                                "conversaciones": n_conv,
                                "por_lag": {str(k): float(np.median(
                                    list(v.values()))) for k, v in ac.items()}}
        w("")

        # ---------- 3. reduccion ----------
        comp = df[feats].apply(pd.to_numeric, errors="coerce").dropna()
        y = pd.to_numeric(df.loc[comp.index, OBJETIVO], errors="coerce")
        util = comp.loc[:, comp.nunique() > 1]
        X = StandardScaler().fit_transform(util.to_numpy(float))
        p = PCA(random_state=comun.SEMILLA).fit(X)
        acum = np.cumsum(p.explained_variance_ratio_)
        n90 = int(np.searchsorted(acum, 0.90) + 1)
        n95 = int(np.searchsorted(acum, 0.95) + 1)
        pcas[nombre] = acum
        w("### Reducción de dimensión")
        w("")
        w("PCA sobre las %d características no constantes, estandarizadas,"
          % util.shape[1])
        w("con las %d filas completas (%.0f %% del tramo; no se imputa, porque"
          % (len(util), 100 * len(util) / len(df)))
        w("los faltantes son estructurales).")
        w("")
        w("- Componentes para el 90 %% de la varianza: **%d** de %d"
          % (n90, util.shape[1]))
        w("- Componentes para el 95 %% de la varianza: **%d**" % n95)
        w("- La primera componente explica el %.1f %%"
          % (100 * (acum[0])))
        w("")
        lda = LinearDiscriminantAnalysis()
        lda.fit(X, y.to_numpy(int))
        w("LDA con dos clases da una sola dirección discriminante, que separa")
        w("con AUC %.3f sobre los mismos datos con los que se ajustó, de modo"
          % roc_auc_score(y.to_numpy(int), lda.decision_function(X)))
        w("que es una cota superior y no una estimación honesta.")
        r["pca"] = {"caracteristicas": int(util.shape[1]),
                    "filas_completas": int(len(util)),
                    "n_90": n90, "n_95": n95,
                    "primera": float(acum[0])}
        w("")

        # ---------- 4. identificadores sensibles ----------
        w("### Identificadores de red publicados")
        w("")
        ident = list(df.columns)[:N_IDENT]
        sens = [c for c in ident
                if any(k in c.lower() for k in ("address", "mac", "ip"))]
        w("El conjunto publica %d columnas con identificadores de red: %s."
          % (len(sens), ", ".join("`%s`" % c for c in sens)))
        for c in sens:
            w("  - `%-9s` %d valores distintos" % (c, df[c].nunique()))
        r["identificadores"] = {c: int(df[c].nunique()) for c in sens}
        w("")
        w("Son direcciones de un banco de pruebas, no de personas, y el rango")
        w("no es enrutable en Internet. No hay datos personales, pero sí")
        w("topología: conviene no publicarlas en un anexo sin pensarlo.")
        w("")
        res[nombre] = r
        w("---")
        w("")

    # ---------------- figuras ----------------
    fig, axes = plt.subplots(1, 2, figsize=(11, 4.4))
    for ax, (nombre, _df, _t) in zip(axes, datos):
        d = disc[nombre].head(12).iloc[::-1]
        ax.barh(range(len(d)), d["auc_abs"], color="#4C72B0")
        ax.axvline(0.5, color="k", lw=1, ls="--")
        ax.set_yticks(range(len(d)))
        ax.set_yticklabels(d["campo"], fontsize=7)
        ax.set_xlim(0.5, 1.0)
        ax.set_xlabel("AUC plegado")
        ax.set_title("%s" % nombre, fontsize=9)
    fig.suptitle("Poder discriminante de cada característica, tomada sola\n"
                 "frente a %s (0,5 = no discrimina)" % OBJETIVO, fontsize=10)
    fig.savefig(os.path.join(comun.FIGURAS, "p17_discriminante.png"))

    # Mapa de correlacion con los grupos de redundancia contiguos: es lo que
    # hace visible que las 47 columnas sean una docena de ejes. El agrupado se
    # toma del script 16 para no tener dos implementaciones del mismo criterio.
    ex = importlib.import_module("16_exploratorio_flujos")
    fig, axes = plt.subplots(1, 2, figsize=(11.5, 5.0))
    fig.subplots_adjust(right=0.88, wspace=0.08)
    for ax, (nombre, df, _t) in zip(axes, datos):
        feats = list(df.columns)[N_IDENT:N_IDENT + N_FEATS]
        num = df[feats].apply(pd.to_numeric, errors="coerce")
        util = [c for c in feats if num[c].nunique(dropna=True) > 1]
        grupos, _pares = ex.grupos_redundancia(df, util)
        engrupo = [c for g in sorted(grupos, key=len, reverse=True) for c in g]
        orden = engrupo + [c for c in util if c not in engrupo]
        M = num[orden].corr(method="spearman").abs().to_numpy()
        im = ax.imshow(M, cmap="magma", vmin=0, vmax=1)
        # Lineas en los limites de cada grupo.
        corte = 0
        for g in sorted(grupos, key=len, reverse=True):
            corte += len(g)
            ax.axhline(corte - 0.5, color="#4FC3F7", lw=0.9)
            ax.axvline(corte - 0.5, color="#4FC3F7", lw=0.9)
        ax.set_xticks([])
        ax.set_yticks([])
        ax.set_title("%s — %d características, %d grupos"
                     % (nombre, len(orden), len(grupos)), fontsize=9)
    cax = fig.add_axes([0.90, 0.17, 0.018, 0.62])
    fig.colorbar(im, cax=cax, label="|Spearman|")
    fig.suptitle("Redundancia: las características ordenadas por grupo\n"
                 "cada bloque sobre la diagonal es un solo eje", fontsize=10)
    fig.savefig(os.path.join(comun.FIGURAS, "p17_redundancia.png"))

    fig, ax = plt.subplots(figsize=(7, 4.2))
    for nombre, acum in pcas.items():
        ax.plot(range(1, len(acum) + 1), 100 * acum, marker="o", ms=3,
                label=nombre)
    for nivel in (90, 95):
        ax.axhline(nivel, color="k", lw=0.8, ls=":")
    ax.set_xlabel("componentes principales")
    ax.set_ylabel("varianza explicada acumulada (%)")
    ax.set_title("¿Conviene reducir? Varianza explicada por el PCA",
                 fontsize=9)
    ax.legend(fontsize=8)
    fig.savefig(os.path.join(comun.FIGURAS, "p17_pca.png"))

    fig, ax = plt.subplots(figsize=(7, 4.2))
    for nombre in auto:
        v = np.array(list(auto[nombre][1].values()))
        ax.hist(v, bins=20, alpha=0.6, label="%s (mediana %.2f)"
                % (nombre, np.median(v)))
    ax.axvline(0.3, color="crimson", ls="--", lw=1.1,
               label="0,3: límite de independencia práctica")
    ax.set_xlabel("autocorrelación a retardo 1, por característica")
    ax.set_ylabel("características")
    ax.set_title("¿Se pueden tratar las filas como independientes?",
                 fontsize=9)
    ax.legend(fontsize=8)
    fig.savefig(os.path.join(comun.FIGURAS, "p17_autocorrelacion.png"))
    print("[figuras] p17_discriminante.png, p17_redundancia.png, "
          "p17_pca.png, p17_autocorrelacion.png")

    comun.escribir("p17_discriminante_estructura.txt", "\n".join(L))
    with open(os.path.join(comun.SALIDAS,
                           "p17_discriminante_estructura.json"), "w") as fh:
        json.dump(res, fh, indent=1, ensure_ascii=False, default=str)


if __name__ == "__main__":
    main()
