"""Preguntas 3, 4 y 5 --- HAI.

Pregunta 3: verifica el formato de cada version contra lo que declara
`datasets/LEEME.md` (separador, numero de columnas, donde estan las etiquetas)
y que anomalias quedan etiquetadas en cada una.

Pregunta 4: cuenta ataques por version contando **rachas** de la columna de
etiqueta en los archivos de prueba. Se leen unicamente las columnas de
etiqueta: es la excepcion de dimensionamiento que admite el brief.

Pregunta 5: mide deriva. Distingue dos niveles:
  - dentro de una version, entre `train` sucesivos (deriva temporal real);
  - entre versiones, que es cambio de banco de pruebas y no deriva.

Para que las cifras signifiquen algo hacen falta DOS varas, no una, y
confundirlas cambia como se lee toda la seccion:

  - el **ruido del estimador**: la misma medida entre dos mitades de un mismo
    archivo tomadas AL AZAR. Es lo que dos muestras de la misma distribucion
    dan por tamano finito, y nada mas.
  - la **deriva dentro del archivo**: la misma medida entre la primera y la
    segunda mitad del archivo EN ORDEN TEMPORAL. Esto no es ruido: es cuanto
    se mueve el proceso en las horas que dura una sola campana.

Una version anterior calculaba solo la segunda y la llamaba «ruido de fondo
del estimador». No lo es: sobre `hai-20.07/train1.csv` la mitad contra mitad
en orden da KS mediano 0,093 y al azar 0,002, cuarenta y siete veces menos,
con el umbral de significacion al 95 % en 0,005. De modo que el cociente
«entre archivos / mitad contra mitad» no es una razon senal-ruido sino la
comparacion entre deriva entre campanas y deriva dentro de una campana, que
es una pregunta distinta y una vara mucho mas exigente.

Uso:  python eda/scripts/04_hai.py
"""

import glob
import json
import os
import sys

import numpy as np
import pandas as pd
from scipy import stats

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import comun  # noqa: E402

VERSIONES = [
    ("hai-20.07", ";", "time", ["attack", "attack_P1", "attack_P2",
                                "attack_P3"]),
    ("hai-21.03", ",", "time", ["attack", "attack_P1", "attack_P2",
                                "attack_P3"]),
    ("hai-22.04", ",", "timestamp", ["Attack"]),
    ("hai-23.05", ",", "timestamp", []),
    ("haiend-23.05", ",", "Timestamp", []),
]

N_BINS = 50


def archivos(version, patron):
    d = os.path.join(comun.HAI, version)
    return sorted(glob.glob(os.path.join(d, patron)))


def trains(version):
    for patron in ("train*.csv", "hai-train*.csv", "end-train*.csv"):
        f = archivos(version, patron)
        if f:
            return f
    return []


def tests(version):
    for patron in ("test*.csv", "hai-test*.csv", "end-test*.csv"):
        f = [x for x in archivos(version, patron)
             if not os.path.basename(x).startswith("label-")]
        if f:
            return f
    return []


def rachas_positivas(serie):
    """Numero de rachas de valor distinto de cero y su largo total."""
    v = (pd.to_numeric(serie, errors="coerce").fillna(0) != 0).to_numpy()
    if not v.any():
        return 0, 0
    bordes = np.diff(v.astype(np.int8))
    return int((bordes == 1).sum() + (1 if v[0] else 0)), int(v.sum())


def divergencia(a, b, lo, hi):
    """Distancia de Jensen-Shannon y estadistico KS entre dos muestras.

    Las dos medidas NO se calculan igual, y la diferencia importa:

    * La de Jensen-Shannon es una divergencia entre distribuciones discretas,
      de modo que **necesita** una discretizacion: se usan los intervalos
      comunes de `N_BINS`. El valor depende de esa eleccion y se informa como
      lo que es.
    * El de Kolmogorov-Smirnov se calcula sobre las acumuladas empiricas
      **exactas**, con `scipy.stats.ks_2samp`. Una version anterior de este
      script lo calculaba sobre las acumuladas de esos mismos intervalos y
      lo llamaba igual: eso es una cota inferior del estadistico, porque mira
      la diferencia solo en los bordes de los intervalos y no en todos los
      puntos de la muestra. Sobre `hai-20.07/train1.csv` la mediana entre
      columnas apenas se movia (0,0930 contra 0,0967), pero en una columna
      la subestimacion llegaba a 0,14, que es del tamano de los efectos que
      esta seccion discute.
    """
    a = a[np.isfinite(a)]
    b = b[np.isfinite(b)]
    if len(a) < 100 or len(b) < 100 or not np.isfinite(lo) or hi <= lo:
        return None, None
    bordes = np.linspace(lo, hi, N_BINS + 1)
    pa, _ = np.histogram(a, bins=bordes)
    pb, _ = np.histogram(b, bins=bordes)
    pa = pa / pa.sum()
    pb = pb / pb.sum()
    m = 0.5 * (pa + pb)
    with np.errstate(divide="ignore", invalid="ignore"):
        kl_a = np.nansum(np.where(pa > 0, pa * np.log2(pa / m), 0.0))
        kl_b = np.nansum(np.where(pb > 0, pb * np.log2(pb / m), 0.0))
    js = float(np.sqrt(max(0.0, 0.5 * (kl_a + kl_b))))
    ks = float(stats.ks_2samp(a, b).statistic)
    return js, ks


def comparar(d1, d2, columnas):
    """Resume la divergencia columna a columna entre dos DataFrames."""
    js_list, ks_list, detalle = [], [], {}
    for c in columnas:
        a = pd.to_numeric(d1[c], errors="coerce").to_numpy(dtype=float)
        b = pd.to_numeric(d2[c], errors="coerce").to_numpy(dtype=float)
        todo = np.concatenate([a[np.isfinite(a)], b[np.isfinite(b)]])
        if todo.size < 200:
            continue
        lo, hi = float(np.min(todo)), float(np.max(todo))
        if hi <= lo:
            continue          # constante: no aporta
        js, ks = divergencia(a, b, lo, hi)
        if js is None:
            continue
        js_list.append(js)
        ks_list.append(ks)
        detalle[c] = {"js": js, "ks": ks}
    if not js_list:
        return None
    js_arr = np.array(js_list)
    ks_arr = np.array(ks_list)
    return {
        "columnas": len(js_list),
        "js_mediana": float(np.median(js_arr)),
        "js_p90": float(np.percentile(js_arr, 90)),
        "ks_mediana": float(np.median(ks_arr)),
        "ks_p90": float(np.percentile(ks_arr, 90)),
        "n_ks_mayor_02": int((ks_arr > 0.2).sum()),
        "detalle": detalle,
    }


def main():
    comun.preparar()
    L = []
    w = L.append
    w("# Preguntas 3, 4 y 5 - HAI")
    w("")

    # ---------------- P3: formato por version ----------------
    w("## P3 Formato de cada version, contra lo declarado en datasets/LEEME.md")
    w("")
    w("%-14s %-4s %-10s %6s %9s %9s %-28s"
      % ("version", "sep", "col.tiempo", "cols", "train", "test",
         "columnas de etiqueta"))
    formato = {}
    for ver, sep, coltime, etiquetas in VERSIONES:
        tr, te = trains(ver), tests(ver)
        if not tr:
            w("%-14s  (sin archivos)" % ver)
            continue
        cab = pd.read_csv(tr[0], sep=sep, nrows=5)
        cab_test = pd.read_csv(te[0], sep=sep, nrows=5) if te else None
        etq_train = [c for c in cab.columns
                     if c.lower().startswith("attack") or
                     c.lower() == "label"]
        etq_test = ([c for c in cab_test.columns
                     if c.lower().startswith("attack") or c.lower() == "label"]
                    if cab_test is not None else [])
        aparte = sorted(os.path.basename(p) for p in
                        archivos(ver, "label-*.csv"))
        w("%-14s %-4s %-10s %6d %9d %9d %-28s"
          % (ver, repr(sep).strip("'"), coltime, cab.shape[1], len(tr),
             len(te), ",".join(etq_test) or ("aparte: %d archivos"
                                             % len(aparte))))
        formato[ver] = {
            "separador": sep, "columna_tiempo": coltime,
            "columnas_train": int(cab.shape[1]),
            "columnas_test": int(cab_test.shape[1]) if cab_test is not None
            else None,
            "n_train": len(tr), "n_test": len(te),
            "etiquetas_en_train": etq_train,
            "etiquetas_en_test": etq_test,
            "archivos_label_aparte": aparte,
            "declarado_LEEME": etiquetas,
        }
        if etq_train:
            w("%-14s   AVISO: el archivo de entrenamiento trae columnas de "
              "etiqueta: %s" % ("", etq_train))
    w("")
    w("Observacion: el nombre de la columna de tiempo cambia entre versiones")
    w("(`time`, `timestamp`, `Timestamp`), ademas del separador y del numero")
    w("de columnas. Cualquier lector comun tiene que contemplar las tres.")
    w("")

    # ---- P3.b: los archivos de entrenamiento, estan limpios? ----------
    w("## P3.b Los archivos de entrenamiento, vienen libres de ataque?")
    w("")
    w("El plan entrena solo con trafico normal. Se comprueba, version por")
    w("version, si las columnas de etiqueta de los `train` son todas cero y")
    w("que tramo temporal cubre cada archivo.")
    w("")
    w("%-14s %-16s %9s %-21s %-21s %7s %9s"
      % ("version", "archivo", "filas", "desde", "hasta", "horas",
         "etiq != 0"))
    contaminacion = {}
    for ver, sep, coltime, _e in VERSIONES:
        info = formato.get(ver)
        if not info:
            continue
        etq = info["etiquetas_en_train"]
        anterior = None
        for ruta in trains(ver):
            cols = [coltime] + etq
            x = pd.read_csv(ruta, sep=sep,
                            usecols=lambda c: c.strip() in cols)
            x.columns = [c.strip() for c in x.columns]
            t = pd.to_datetime(x[coltime])
            n_pos = 0
            n_ev = 0
            if etq:
                col = etq[0]          # `attack` / `Attack`: la global
                n_ev, n_pos = rachas_positivas(x[col])
            w("%-14s %-16s %9d %-21s %-21s %7.0f %9s"
              % (ver, os.path.basename(ruta), len(x), str(t.min()),
                 str(t.max()), (t.max() - t.min()).total_seconds() / 3600.0,
                 ("%d filas / %d ev" % (n_pos, n_ev)) if etq else "sin col."))
            if n_pos:
                contaminacion.setdefault(ver, []).append(
                    {"archivo": os.path.basename(ruta), "filas": int(n_pos),
                     "eventos": int(n_ev)})
            if anterior is not None:
                hueco = (t.min() - anterior).total_seconds() / 86400.0
                w("%-14s %-16s   (hueco respecto del archivo anterior: "
                  "%.1f dias)" % ("", "", hueco))
            anterior = t.max()
    w("")
    if contaminacion:
        w("AVISO. Hay ataques etiquetados dentro de archivos de")
        w("ENTRENAMIENTO: %s" % json.dumps(contaminacion, ensure_ascii=False))
        w("Entrenar sobre esos archivos sin filtrar mete ataques en el")
        w("conjunto de trafico normal.")
    else:
        w("Ningun archivo de entrenamiento trae etiquetas distintas de cero.")
    w("")
    w("Los huecos entre archivos sucesivos importan para leer la pregunta 5:")
    w("lo que se mide entre `train` consecutivos no es deriva continua sino")
    w("la diferencia entre campanas de adquisicion separadas en el tiempo.")
    w("")

    # ---------------- P4: ataques en los conjuntos de prueba ----------
    w("## P4 Ataques etiquetados por version (solo conteos)")
    w("")
    w("Se cuentan rachas de etiqueta distinta de cero. Se leen unicamente las")
    w("columnas de etiqueta de los archivos de prueba.")
    w("")
    w("%-14s %-20s %10s %10s %12s"
      % ("version", "archivo", "eventos", "filas pos.", "dur.med.s"))
    p4 = {}
    for ver, sep, coltime, _e in VERSIONES:
        total_ev = 0
        for ruta in tests(ver):
            base = os.path.basename(ruta)
            cab = pd.read_csv(ruta, sep=sep, nrows=2)
            cols = [c for c in cab.columns
                    if c.lower() == "attack" or c.lower() == "label"]
            if cols:
                s = pd.read_csv(ruta, sep=sep, usecols=cols)[cols[0]]
            else:
                lab = os.path.join(os.path.dirname(ruta),
                                   "label-" + base.split("-")[-1])
                if not os.path.exists(lab):
                    w("%-14s %-20s  (sin etiquetas localizables)"
                      % (ver, base))
                    continue
                s = pd.read_csv(lab, sep=sep)["label"]
            n_ev, n_pos = rachas_positivas(s)
            total_ev += n_ev
            w("%-14s %-20s %10d %10d %12.0f"
              % (ver, base, n_ev, n_pos, (n_pos / n_ev) if n_ev else 0))
        p4[ver] = total_ev
        w("%-14s %-20s %10d" % (ver, "TOTAL", total_ev))
    w("")
    w("Las etiquetas son por segundo, de modo que `filas pos.` son segundos de")
    w("ataque y la duracion media sale de dividir.")
    w("")

    # ---------------- P5: deriva ----------------
    w("## P5 Deriva")
    w("")
    w("Medida: distancia de Jensen-Shannon por columna numerica no constante,")
    w("sobre %d intervalos comunes, y estadistico de Kolmogorov-Smirnov sobre" % N_BINS)
    w("las acumuladas empiricas exactas (`scipy.stats.ks_2samp`). Se resume la")
    w("mediana y el percentil 90 entre columnas.")
    w("")
    w("### P5.a Las DOS varas, que no son la misma")
    w("")
    w("Hacen falta dos niveles de comparacion, y confundirlos cambia la")
    w("lectura de toda la seccion:")
    w("")
    w("  - **ruido del estimador**: mitad contra mitad del mismo archivo")
    w("    partido AL AZAR. Es lo que dan dos muestras de la misma")
    w("    distribucion por tamano finito, y nada mas.")
    w("  - **deriva dentro del archivo**: mitad contra mitad del mismo")
    w("    archivo EN ORDEN TEMPORAL. No es ruido: es cuanto se mueve el")
    w("    proceso en las horas que dura una sola campana.")
    w("")
    w("Se informa, por archivo, el umbral de significacion del KS al 95 %,")
    w("que es 1,36*raiz(2/n) con n el tamano de cada mitad.")
    w("")
    w("%-14s %-16s %7s %9s %8s %9s %8s %9s %9s"
      % ("version", "archivo", "cols", "JS med", "JS p90", "KS med",
         "KS p90", "KS azar", "umbral95"))
    referencia = {}
    ruido = {}
    cache = {}
    rng = np.random.default_rng(comun.SEMILLA)
    for ver, sep, coltime, _e in VERSIONES:
        tr = trains(ver)
        if not tr:
            continue
        d = pd.read_csv(tr[0], sep=sep)
        d.columns = [c.strip() for c in d.columns]
        num = [c for c in d.columns
               if c.lower() not in ("time", "timestamp") and
               not c.lower().startswith("attack") and c.lower() != "label"]
        cache[(ver, tr[0])] = (d, num)
        mitad = len(d) // 2
        # La vara de ruido: la misma particion por tamano, pero al azar, de
        # modo que las dos partes vienen de la misma distribucion por
        # construccion y lo unico que queda es el tamano finito.
        perm = rng.permutation(len(d))
        rz = comparar(d.iloc[perm[:mitad]], d.iloc[perm[mitad:]], num)
        if rz:
            # El umbral de significacion viaja CON la medicion: si queda solo
            # impreso en el .txt, cualquier guarda que diga compararse contra
            # el tiene que inventarse una constante.
            rz["umbral95"] = (1.36 * np.sqrt(2.0 / mitad) if mitad
                              else float("nan"))
            rz["n_por_mitad"] = int(mitad)
            ruido[ver] = rz
        r = comparar(d.iloc[:mitad], d.iloc[mitad:], num)
        if r:
            referencia[ver] = r
            umbral = 1.36 * np.sqrt(2.0 / mitad) if mitad else float("nan")
            w("%-14s %-16s %7d %9.4f %8.4f %9.4f %8.4f %9.4f %9.5f"
              % (ver, os.path.basename(tr[0]), r["columnas"],
                 r["js_mediana"], r["js_p90"], r["ks_mediana"], r["ks_p90"],
                 ruido.get(ver, {}).get("ks_mediana", float("nan")), umbral))
    w("")
    w("Las dos ultimas columnas son la vara honesta. Donde «KS med» supera a")
    w("«KS azar» por un factor grande, la mitad contra mitad en orden **no es**")
    w("ruido del estimador sino deriva dentro de la propia campana:")
    w("")
    for ver in referencia:
        kz = ruido.get(ver, {}).get("ks_mediana")
        km = referencia[ver]["ks_mediana"]
        if kz:
            w("   %-14s en orden %.4f / al azar %.4f = %.0f veces"
              % (ver, km, kz, km / kz))
    w("")
    w("De modo que el cociente de P5.b contra P5.a **no es una razon**")
    w("senal-ruido. Compara deriva entre campanas contra deriva dentro de una")
    w("campana, que es una vara mucho mas exigente y una pregunta distinta.")
    w("")
    w("### P5.b Deriva temporal dentro de una version (train sucesivos)")
    w("")
    w("%-14s %-28s %7s %9s %8s %9s %8s %7s"
      % ("version", "comparacion", "cols", "JS med", "JS p90", "KS med",
         "KS p90", "KS>0,2"))
    dentro = {}
    for ver, sep, coltime, _e in VERSIONES:
        tr = trains(ver)
        if len(tr) < 2:
            continue
        dentro[ver] = {}
        for i in range(len(tr) - 1):
            a, b = tr[i], tr[i + 1]
            if (ver, a) in cache:
                d1, num = cache[(ver, a)]
            else:
                d1 = pd.read_csv(a, sep=sep)
                d1.columns = [c.strip() for c in d1.columns]
                num = [c for c in d1.columns
                       if c.lower() not in ("time", "timestamp") and
                       not c.lower().startswith("attack") and
                       c.lower() != "label"]
            d2 = pd.read_csv(b, sep=sep)
            d2.columns = [c.strip() for c in d2.columns]
            comunes = [c for c in num if c in d2.columns]
            r = comparar(d1, d2, comunes)
            if not r:
                continue
            nombre = "%s -> %s" % (os.path.basename(a).replace(".csv", ""),
                                   os.path.basename(b).replace(".csv", ""))
            dentro[ver][nombre] = {k: v for k, v in r.items()
                                   if k != "detalle"}
            peores = sorted(r["detalle"].items(), key=lambda kv: -kv[1]["ks"])
            dentro[ver][nombre]["peores"] = [
                {"columna": c, "ks": v["ks"], "js": v["js"]}
                for c, v in peores[:5]]
            w("%-14s %-28s %7d %9.4f %8.4f %9.4f %8.4f %7d"
              % (ver, nombre, r["columnas"], r["js_mediana"], r["js_p90"],
                 r["ks_mediana"], r["ks_p90"], r["n_ks_mayor_02"]))
            del d2
    w("")
    w("Columnas con mayor KS en cada comparacion:")
    for ver, comps in dentro.items():
        for nombre, r in comps.items():
            top = ", ".join("%s=%.2f" % (p["columna"], p["ks"])
                            for p in r["peores"])
            w("  %-14s %-28s %s" % (ver, nombre, top))
    w("")
    w("### P5.c Entre versiones: cambio de banco, no deriva")
    w("")
    w("Las versiones no comparten el mismo conjunto de columnas ni el mismo")
    w("banco de pruebas. Se reporta cuantas columnas comparten, que es el")
    w("limite de lo comparable, y no se calcula una divergencia que se leeria")
    w("como deriva temporal.")
    w("")
    juegos = {}
    for ver, sep, coltime, _e in VERSIONES:
        tr = trains(ver)
        if not tr:
            continue
        cab = pd.read_csv(tr[0], sep=sep, nrows=2)
        juegos[ver] = set(c.strip() for c in cab.columns)
    nombres = list(juegos)
    w("%-14s %7s %s" % ("version", "cols", "   ".join("%-14s" % v
                                                      for v in nombres)))
    for a in nombres:
        fila = []
        for b in nombres:
            fila.append("%-14d" % len(juegos[a] & juegos[b]))
        w("%-14s %7d %s" % (a, len(juegos[a]), "   ".join(fila)))
    w("")
    w("Columnas comunes a las cinco versiones: %d"
      % len(set.intersection(*juegos.values())))
    w("Columnas comunes a 20.07, 21.03 y 22.04: %d"
      % len(juegos["hai-20.07"] & juegos["hai-21.03"] & juegos["hai-22.04"]))
    w("")

    comun.escribir("p3_p4_p5_hai.txt", "\n".join(L))
    with open(os.path.join(comun.SALIDAS, "p3_p4_p5_hai.json"), "w") as fh:
        json.dump({"formato": formato, "eventos_prueba": p4,
                   "ataques_en_entrenamiento": contaminacion,
                   "referencia_intra_archivo": {
                       k: {kk: vv for kk, vv in v.items() if kk != "detalle"}
                       for k, v in referencia.items()},
                   "ruido_estimador_particion_al_azar": {
                       k: {kk: vv for kk, vv in v.items() if kk != "detalle"}
                       for k, v in ruido.items()},
                   "deriva_intra_version": dentro,
                   "columnas_por_version": {k: sorted(v)
                                            for k, v in juegos.items()}},
                  fh, indent=1, ensure_ascii=False)

    # Figura: deriva medida contra el nivel de referencia.
    plt = comun.estilo_figura()
    etiquetas, valores, refs, ruidos = [], [], [], []
    for ver, comps in dentro.items():
        for nombre, r in comps.items():
            etiquetas.append("%s\n%s" % (ver.replace("hai-", ""),
                                         nombre.replace("train", "t")
                                         .replace("hai-", "")
                                         .replace("end-", "")))
            valores.append(r["ks_mediana"])
            refs.append(referencia.get(ver, {}).get("ks_mediana", np.nan))
            ruidos.append(ruido.get(ver, {}).get("ks_mediana", np.nan))
    if etiquetas:
        x = np.arange(len(etiquetas))
        fig, ax = plt.subplots(figsize=(max(7, 0.8 * len(x)), 4.0))
        ax.bar(x - 0.26, valores, width=0.26,
               label="entre campanas sucesivas")
        ax.bar(x, refs, width=0.26,
               label="deriva dentro de una campana (mitades en orden)")
        ax.bar(x + 0.26, ruidos, width=0.26,
               label="ruido del estimador (mitades al azar)")
        ax.set_xticks(x)
        ax.set_xticklabels(etiquetas, fontsize=7)
        ax.set_ylabel("KS mediano entre columnas")
        ax.set_title("HAI: deriva entre campanas de entrenamiento, contra la\n"
                     "deriva dentro de una campana y contra el ruido del "
                     "estimador", fontsize=9)
        ax.legend(fontsize=7)
        fig.savefig(os.path.join(comun.FIGURAS, "p5_hai_deriva.png"))
        print("[figura] %s" % comun.rel(
            os.path.join(comun.FIGURAS, "p5_hai_deriva.png")))


if __name__ == "__main__":
    main()
