"""Pregunta 7 --- se reproduce en Morris / Turnipseed la fuga de presion?

Los autores del conjunto documentaron una fuga de informacion en el Dataset 3
(gasoducto): parte de los ataques se ejecuto con la presion de gas en un valor
y la operacion normal en otro, de modo que la medicion de presion separaba las
clases por un umbral trivial y cualquier detector daba metricas altas sin
aprender nada. El Dataset 4 (Turnipseed, `IanArffDataset.arff`) es la version
corregida, y es la que usa este proyecto.

Importa porque la propuesta de linea base adopta como referencia los valores
por tipo de anomalia que publica Shirazi et al. 2016 sobre este conjunto: si la
fuga se reprodujera, esas cifras estarian infladas.

Lo que mide, con los denominadores declarados en cada caso:

  7.0  totales e instancias por clase, que fijan los denominadores
  7.1  distribucion de `pressure measurement` por clase (mediana, RIQ, rango)
  7.2  mejor exactitud alcanzable por un umbral unico sobre ese solo atributo
  7.3  ataques que caen fuera del rango de valores de las normales
  7.4  lo mismo, tipo de anomalia por tipo de anomalia
  7.5  control positivo: las mismas medidas sobre el Dataset 3, que tiene la
       fuga documentada, para comprobar que el procedimiento la detecta donde
       se sabe que esta

La carga del ARFF se reusa de `03_morris.py` para no tener dos lectores.

Uso:  eda/.venv/bin/python -I eda/scripts/07_morris_fuga_presion.py
"""

import importlib
import json
import os
import sys

import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import comun  # noqa: E402

# `03_morris` no es un identificador valido, asi que se importa por nombre.
# Ese modulo solo corre su analisis bajo `__main__`, de modo que importarlo no
# recalcula nada: se le toma unicamente el lector de ARFF.
_morris = importlib.import_module("03_morris")
leer_arff = _morris.leer_arff
CATEGORIA = _morris.CATEGORIA


def mejor_umbral(x, es_ataque):
    """Mejor exactitud alcanzable por un umbral unico sobre `x`.

    Evalua de forma exacta las dos reglas posibles --- `ataque si x > t` y
    `ataque si x <= t` --- en todas las fronteras utiles, que son los puntos
    donde el valor ordenado cambia. Los extremos estan incluidos, de modo que
    el resultado nunca queda por debajo del clasificador que asigna todo a la
    clase mayoritaria.

    Devuelve (exactitud, regla, umbral, aciertos, n).
    """
    x = np.asarray(x, dtype=float)
    y = np.asarray(es_ataque, dtype=bool)
    orden = np.argsort(x, kind="mergesort")
    xs = x[orden]
    ys = y[orden].astype(np.int64)
    n = len(xs)
    if n == 0:
        return float("nan"), "n/d", float("nan"), 0, 0
    pos = int(ys.sum())
    neg = n - pos
    acum = np.concatenate(([0], np.cumsum(ys)))
    # Fronteras validas: final de cada bloque de valores iguales.
    bordes = np.concatenate((np.nonzero(np.diff(xs))[0] + 1, [n]))
    izq_ataque = acum[bordes]
    izq_normal = bordes - izq_ataque
    # Regla A: todo lo que esta a la derecha del umbral es ataque.
    ac_a = izq_normal + (pos - izq_ataque)
    # Regla B: todo lo que esta a la izquierda del umbral (inclusive) es ataque.
    ac_b = izq_ataque + (neg - izq_normal)
    i_a = int(np.argmax(ac_a))
    i_b = int(np.argmax(ac_b))
    if ac_a[i_a] >= ac_b[i_b]:
        aciertos = int(ac_a[i_a])
        regla, t = "ataque si x > t", float(xs[bordes[i_a] - 1])
    else:
        aciertos = int(ac_b[i_b])
        regla, t = "ataque si x <= t", float(xs[bordes[i_b] - 1])
    return aciertos / n, regla, t, aciertos, n


def mayoria(es_ataque):
    """Exactitud del clasificador que asigna todo a la clase mayoritaria."""
    y = np.asarray(es_ataque, dtype=bool)
    if len(y) == 0:
        return float("nan")
    return max(float(y.mean()), float(1.0 - y.mean()))


def auc(x, es_ataque):
    """AUC por el estadistico de Mann-Whitney, con empates promediados.

    Un valor de 0,5 significa que el atributo no ordena las clases. Por debajo
    de 0,5 el atributo ordena en sentido inverso (los ataques toman valores mas
    bajos); la separabilidad es |AUC - 0,5|, no AUC.
    """
    from scipy.stats import rankdata

    x = np.asarray(x, dtype=float)
    y = np.asarray(es_ataque, dtype=bool)
    pos, neg = int(y.sum()), int((~y).sum())
    if pos == 0 or neg == 0:
        return float("nan")
    r = rankdata(x)
    return float((r[y].sum() - pos * (pos + 1) / 2.0) / (pos * neg))


def resumen(v):
    """Mediana, cuartiles, RIQ y extremos de un vector."""
    v = np.asarray(v, dtype=float)
    if len(v) == 0:
        return None
    q1, med, q3 = (float(z) for z in np.percentile(v, [25, 50, 75]))
    return {"n": int(len(v)), "min": float(v.min()), "q1": q1, "mediana": med,
            "q3": q3, "max": float(v.max()), "riq": q3 - q1}


def solapan(a, b):
    """Dos intervalos [min, max] se solapan?"""
    if a is None or b is None:
        return None
    return bool(a[0] <= b[1] and b[0] <= a[1])


def linea_resumen(etiqueta, r):
    if r is None:
        return "%-10s %38s" % (etiqueta, "sin filas con valor numerico")
    return ("%-10s %8d %12.6g %12.6g %12.6g %12.6g %12.6g %12.6g"
            % (etiqueta, r["n"], r["min"], r["q1"], r["mediana"], r["q3"],
               r["max"], r["riq"]))


CAB_RESUMEN = ("%-10s %8s %12s %12s %12s %12s %12s %12s"
               % ("clase", "n", "min", "Q1", "mediana", "Q3", "max", "RIQ"))


def main():
    comun.preparar()
    L = []
    w = L.append
    J = {}

    ruta4 = os.path.join(comun.MORRIS, "IanArffDataset.arff")
    ruta3 = os.path.join(comun.MORRIS, "gas_final_DATASET3_CON_FUGA.arff")

    w("# Pregunta 7 - Morris / Turnipseed: se reproduce la fuga de presion?")
    w("")
    w("Archivo medido : %s   (Dataset 4, version corregida)" % comun.rel(ruta4))
    w("Control positivo: %s" % comun.rel(ruta3))
    w("")
    w("Todo porcentaje de este informe lleva su denominador escrito al lado.")
    w("")

    df = leer_arff(ruta4)
    p = pd.to_numeric(df["pressure measurement"], errors="coerce").to_numpy()
    cat = df["categorized result"].to_numpy()
    y = (df["binary result"] == "1").to_numpy()
    con_valor = ~np.isnan(p)

    # ---- 7.0 denominadores ------------------------------------------
    n_tot = int(len(df))
    n_norm = int((~y).sum())
    n_atk = int(y.sum())
    w("## 7.0 Denominadores")
    w("")
    w("%-54s %10s %9s" % ("subconjunto", "instancias", "% del total"))
    for nombre, n in (("total del conjunto", n_tot),
                      ("normales (`binary result` = 0)", n_norm),
                      ("ataques (`binary result` = 1)", n_atk),
                      ("con `pressure measurement` numerico", int(con_valor.sum())),
                      ("  de ellas normales", int((con_valor & ~y).sum())),
                      ("  de ellas ataques", int((con_valor & y).sum())),
                      ("con valor numerico y distinto de cero",
                       int((con_valor & (p != 0)).sum())),
                      ("sin valor (`?` en el ARFF)", int((~con_valor).sum())),
                      ("  de ellas normales", int((~con_valor & ~y).sum())),
                      ("  de ellas ataques", int((~con_valor & y).sum()))):
        w("%-54s %10d %8.2f %%" % (nombre, n, 100.0 * n / n_tot))
    w("")
    w("`binary result` y `categorized result` coinciden: %s"
      % bool(((cat != "0") == y).all()))
    w("")
    w("Dato estructural que condiciona todo lo que sigue: en esta version la")
    w("presion solo viene informada en las respuestas Modbus (funcion 3), que")
    w("son %d de las %d filas, el %.2f %% del total. Las %d filas restantes"
      % (int(con_valor.sum()), n_tot, 100.0 * con_valor.sum() / n_tot,
         int((~con_valor).sum())))
    w("traen `?`: no hay valor que umbralizar.")
    w("")
    J["denominadores"] = {
        "total": n_tot, "normales": n_norm, "ataques": n_atk,
        "con_valor": int(con_valor.sum()),
        "con_valor_normales": int((con_valor & ~y).sum()),
        "con_valor_ataques": int((con_valor & y).sum()),
        "con_valor_no_nulo": int((con_valor & (p != 0)).sum()),
        "sin_valor": int((~con_valor).sum()),
        "sin_valor_normales": int((~con_valor & ~y).sum()),
        "sin_valor_ataques": int((~con_valor & y).sum())}

    # ---- 7.1 distribucion por clase ---------------------------------
    w("## 7.1 Distribucion de `pressure measurement` por clase")
    w("")
    w("Sobre las %d filas con valor numerico (denominador de esta seccion)."
      % int(con_valor.sum()))
    w("")
    w(CAB_RESUMEN)
    r_norm = resumen(p[con_valor & ~y])
    r_atk = resumen(p[con_valor & y])
    w(linea_resumen("normal", r_norm))
    w(linea_resumen("ataque", r_atk))
    w("")
    riq_n = (r_norm["q1"], r_norm["q3"])
    riq_a = (r_atk["q1"], r_atk["q3"])
    rg_n = (r_norm["min"], r_norm["max"])
    rg_a = (r_atk["min"], r_atk["max"])
    w("Se solapan los rangos intercuartilicos? %s"
      % ("SI" if solapan(riq_n, riq_a) else "NO"))
    w("  normal [%.6g, %.6g]  ataque [%.6g, %.6g]  interseccion [%.6g, %.6g]"
      % (riq_n[0], riq_n[1], riq_a[0], riq_a[1],
         max(riq_n[0], riq_a[0]), min(riq_n[1], riq_a[1])))
    w("Se solapan los rangos completos? %s"
      % ("SI" if solapan(rg_n, rg_a) else "NO"))
    w("")
    w("Misma tabla restringida a los valores distintos de cero, porque los")
    w("ceros explicitos se tratan aparte en 7.3:")
    w("")
    w(CAB_RESUMEN)
    nz = con_valor & (p != 0)
    r_norm_nz = resumen(p[nz & ~y])
    r_atk_nz = resumen(p[nz & y])
    w(linea_resumen("normal", r_norm_nz))
    w(linea_resumen("ataque", r_atk_nz))
    w("")
    w("Los ataques alcanzan 3,36e+38 y 8,44e-42, que son valores de coma")
    w("flotante sin sentido fisico: son la inyeccion de respuesta en si misma,")
    w("no un artefacto del montaje experimental.")
    w("")
    J["distribucion"] = {"con_valor": {"normal": r_norm, "ataque": r_atk},
                         "no_nulos": {"normal": r_norm_nz, "ataque": r_atk_nz},
                         "riq_solapan": solapan(riq_n, riq_a),
                         "rangos_solapan": solapan(rg_n, rg_a)}

    # ---- 7.2 mejor umbral unico -------------------------------------
    w("## 7.2 Mejor exactitud alcanzable por un umbral unico")
    w("")
    w("Prueba directa de la fuga. Se evaluan de forma exacta las dos reglas")
    w("posibles en todas las fronteras utiles; el optimo que se reporta es el")
    w("mejor caso, medido sobre los mismos datos con los que se eligio el")
    w("umbral, de modo que es una cota superior, no una estimacion honesta.")
    w("")
    ex_sub, regla_sub, t_sub, ac_sub, n_sub = mejor_umbral(p[con_valor],
                                                           y[con_valor])
    base_sub = mayoria(y[con_valor])
    a_sub = auc(p[con_valor], y[con_valor])

    # Sobre el total hay que fijar que se hace con las filas sin valor. Un
    # umbral no las puede clasificar, asi que se les asigna una clase fija y se
    # declara cual: se prueban las dos y se reporta la mejor.
    sin_valor_norm = int((~con_valor & ~y).sum())
    sin_valor_atk = int((~con_valor & y).sum())
    ac_mejor_sub = max(ac_sub, 0)
    ex_tot_norm = (ac_mejor_sub + sin_valor_norm) / n_tot
    ex_tot_atk = (ac_mejor_sub + sin_valor_atk) / n_tot
    base_tot = mayoria(y)

    w("%-56s %10s %10s %9s" % ("alcance", "exactitud", "mayoria", "ganancia"))
    w("%-56s %9.4f %10.4f %7.2f pp"
      % ("subconjunto con valor numerico (n = %d)" % n_sub, ex_sub, base_sub,
         100.0 * (ex_sub - base_sub)))
    w("%-56s %9.4f %10.4f %7.2f pp"
      % ("total, filas sin valor asignadas a normal (n = %d)" % n_tot,
         ex_tot_norm, base_tot, 100.0 * (ex_tot_norm - base_tot)))
    w("%-56s %9.4f %10.4f %7.2f pp"
      % ("total, filas sin valor asignadas a ataque (n = %d)" % n_tot,
         ex_tot_atk, base_tot, 100.0 * (ex_tot_atk - base_tot)))
    w("")
    w("Umbral optimo sobre el subconjunto: %s, con t = %.6g."
      % (regla_sub, t_sub))
    pred = con_valor & (p <= t_sub) if "x <= t" in regla_sub \
        else con_valor & (p > t_sub)
    tp = int((pred & y).sum())
    fp = int((pred & ~y).sum())
    fn = int((con_valor & y).sum()) - tp
    tn = int((con_valor & ~y).sum()) - fp
    w("")
    w("  VP = %6d   FN = %6d   tasa de deteccion = %.4f  (sobre %d ataques"
      % (tp, fn, tp / (con_valor & y).sum(), int((con_valor & y).sum())))
    w("                                                       con valor)")
    w("  FP = %6d   VN = %6d   tasa de falsa alarma = %.4f  (sobre %d"
      % (fp, tn, fp / (con_valor & ~y).sum(), int((con_valor & ~y).sum())))
    w("                                                       normales con valor)")
    w("")
    w("AUC sobre el subconjunto con valor: %.4f. Esta por debajo de 0,5, es" % a_sub)
    w("decir que los ataques toman valores mas bajos que las normales; la")
    w("separabilidad efectiva es |AUC - 0,5| = %.4f, equivalente a un AUC de"
      % abs(a_sub - 0.5))
    w("%.4f con la regla invertida. Lejos del 1,0 que daria una fuga."
      % (1.0 - a_sub))
    w("")
    J["umbral_unico"] = {
        "subconjunto": {"n": n_sub, "exactitud": ex_sub, "mayoria": base_sub,
                        "regla": regla_sub, "umbral": t_sub, "auc": a_sub,
                        "vp": tp, "fn": fn, "fp": fp, "vn": tn},
        "total_sin_valor_a_normal": {"n": n_tot, "exactitud": ex_tot_norm,
                                     "mayoria": base_tot},
        "total_sin_valor_a_ataque": {"n": n_tot, "exactitud": ex_tot_atk,
                                     "mayoria": base_tot}}

    # ---- 7.3 ataques fuera del rango normal -------------------------
    w("## 7.3 Ataques fuera del rango de valores de las normales")
    w("")
    w("Tres definiciones del rango normal, porque el resultado depende de la")
    w("definicion. Las tres se calculan sobre las %d normales con valor."
      % int((con_valor & ~y).sum()))
    w("")
    vn = p[con_valor & ~y]
    q1n, q3n = (float(z) for z in np.percentile(vn, [25, 75]))
    iqr = q3n - q1n
    p01, p999 = (float(z) for z in np.percentile(vn, [0.1, 99.9]))
    rangos = (("min-max de las normales", float(vn.min()), float(vn.max())),
              ("vallas de Tukey, 1,5 RIQ", q1n - 1.5 * iqr, q3n + 1.5 * iqr),
              ("percentiles 0,1 y 99,9", p01, p999))
    w("%-26s %24s %9s %9s %9s %9s %9s"
      % ("definicion del rango", "intervalo", "ataques", "% del", "% de",
         "% de atk", "normales"))
    w("%-26s %24s %9s %9s %9s %9s %9s"
      % ("", "", "fuera", "total", "ataques", "con valor", "fuera"))
    J["fuera_de_rango"] = {}
    for nombre, a, b in rangos:
        fuera = con_valor & y & ((p < a) | (p > b))
        fuera_n = con_valor & ~y & ((p < a) | (p > b))
        nf = int(fuera.sum())
        w("%-26s %24s %9d %8.3f %8.3f %9.3f %9d"
          % (nombre, "[%.4g, %.4g]" % (a, b), nf, 100.0 * nf / n_tot,
             100.0 * nf / n_atk, 100.0 * nf / (con_valor & y).sum(),
             int(fuera_n.sum())))
        J["fuera_de_rango"][nombre] = {
            "intervalo": [a, b], "ataques_fuera": nf,
            "pct_del_total_274628": 100.0 * nf / n_tot,
            "pct_de_ataques_60048": 100.0 * nf / n_atk,
            "pct_de_ataques_con_valor_20828": 100.0 * nf / (con_valor & y).sum(),
            "normales_fuera": int(fuera_n.sum())}
    w("")
    w("Denominadores de esas columnas: total = %d, ataques = %d, ataques con"
      % (n_tot, n_atk))
    w("valor numerico = %d." % int((con_valor & y).sum()))
    w("")
    w("### El cero explicito")
    w("")
    z = con_valor & (p == 0)
    w("Hay un artefacto puntual que conviene aislar: `pressure measurement`")
    w("vale exactamente cero en %d filas, y las %d son ataques."
      % (int(z.sum()), int((z & y).sum())))
    w("")
    w("El `-0` que aparece como minimo de los ataques en 7.1 es un cero con")
    w("signo, no una presion negativa: de los %d ceros, %d estan escritos con"
      % (int(z.sum()), int((z & np.signbit(p)).sum())))
    w("signo menos. En el conjunto no hay ningun valor estrictamente menor")
    w("que cero (%d filas)." % int((con_valor & (p < 0)).sum()))
    w("")
    w("  precision de la regla `presion == 0 -> ataque` : %.4f"
      % ((z & y).sum() / z.sum()))
    w("  cobertura sobre los %d ataques del conjunto     : %.4f"
      % (n_atk, (z & y).sum() / n_atk))
    w("  cobertura sobre los %d ataques con valor        : %.4f"
      % (int((con_valor & y).sum()), (z & y).sum() / (con_valor & y).sum()))
    w("")
    w("Es una regla de precision perfecta, pero de cobertura baja: identifica")
    w("el %.2f %% de los ataques del conjunto (denominador %d) y deja el resto"
      % (100.0 * (z & y).sum() / n_atk, n_atk))
    w("sin tocar. No alcanza para el nivel de exactitud que daria una fuga.")
    w("")
    J["cero_explicito"] = {
        "filas": int(z.sum()), "normales": int((z & ~y).sum()),
        "ataques": int((z & y).sum()),
        "precision": float((z & y).sum() / z.sum()),
        "cobertura_de_ataques_60048": float((z & y).sum() / n_atk),
        "cobertura_de_ataques_con_valor_20828":
            float((z & y).sum() / (con_valor & y).sum())}

    # ---- 7.4 por tipo de anomalia -----------------------------------
    w("## 7.4 Por tipo de anomalia")
    w("")
    w("Es el corte que importa, porque los valores de referencia que se")
    w("adoptan son por tipo. Cada fila enfrenta las normales contra un solo")
    w("tipo, sobre las filas de ese subconjunto que tienen valor numerico.")
    w("")
    w("%-50s %8s %8s %9s %9s %8s"
      % ("tipo", "filas", "con", "mayoria", "mejor", "ganancia"))
    w("%-50s %8s %8s %9s %9s %8s"
      % ("", "del tipo", "valor", "", "umbral", ""))
    J["por_tipo"] = {}
    for k in "1234567":
        del_tipo = cat == k
        sel = con_valor & (del_tipo | (cat == "0"))
        n_con = int((con_valor & del_tipo).sum())
        if n_con == 0:
            w("%-50s %8d %8d %9s %9s %8s"
              % (CATEGORIA[k], int(del_tipo.sum()), 0, "n/d", "n/d", "n/d"))
            J["por_tipo"][k] = {"nombre": CATEGORIA[k],
                                "instancias": int(del_tipo.sum()),
                                "con_valor": 0, "medible": False}
            continue
        yy = cat[sel] == k
        ex, regla, t, _, n = mejor_umbral(p[sel], yy)
        base = mayoria(yy)
        w("%-50s %8d %8d %9.4f %9.4f %6.2f pp"
          % (CATEGORIA[k], int(del_tipo.sum()), n_con, base, ex,
             100.0 * (ex - base)))
        J["por_tipo"][k] = {"nombre": CATEGORIA[k],
                            "instancias": int(del_tipo.sum()),
                            "con_valor": n_con, "medible": True,
                            "n_comparacion": n, "mayoria": base,
                            "mejor_umbral": ex, "regla": regla, "umbral": t,
                            "ganancia_pp": 100.0 * (ex - base)}
    w("")
    w("`n/d` no es un cero medido: son tipos para los que **ninguna** fila")
    w("trae valor de presion, porque son ataques del lado del comando y la")
    w("presion solo viaja en la respuesta. Para MSCI, MPCI, MFCI y DoS el")
    w("atributo no puede ser un atajo, porque no existe.")
    w("")
    w("Donde queda senal es en NMRI y CMRI, que son precisamente las dos")
    w("familias de inyeccion de respuesta: ahi el valor de presion falseado")
    w("**es** la anomalia, no una pista espuria del montaje. Que un umbral")
    w("sobre la medicion las detecte es el comportamiento esperado de la")
    w("tarea, no una fuga.")
    w("")
    w("Reconnaissance aparece con exactitud 1,0000, y hay que leerlo con")
    w("cuidado: solo %d de sus %d instancias traen valor de presion, y las %d"
      % (int((con_valor & (cat == '7')).sum()), int((cat == '7').sum()),
         int((con_valor & (cat == '7')).sum())))
    w("traen un cero explicito. La ganancia sobre la mayoria es de %.2f pp"
      % J["por_tipo"]["7"]["ganancia_pp"])
    w("sobre un subconjunto de %d filas, de las cuales %d son del tipo."
      % (J["por_tipo"]["7"]["n_comparacion"],
         int((con_valor & (cat == '7')).sum())))
    w("")

    # ---- 7.5 control positivo: Dataset 3 ----------------------------
    w("## 7.5 Control positivo: el Dataset 3, con fuga documentada")
    w("")
    w("Sin este control no se puede afirmar que el procedimiento detectaria la")
    w("fuga si estuviera. Se repite la medida sobre el Dataset 3, que es el")
    w("conjunto sobre el que pesa la advertencia de los autores. Ahi el")
    w("atributo se llama `measurement` y la etiqueta `result`.")
    w("")
    d3 = leer_arff(ruta3)
    p3 = pd.to_numeric(d3["measurement"], errors="coerce").to_numpy()
    r3 = d3["result"].to_numpy()
    y3 = r3 != "0"
    ok3 = ~np.isnan(p3)
    w("Filas: %d. Normales: %d. Ataques: %d. Con valor numerico: %d."
      % (len(d3), int((~y3).sum()), int(y3.sum()), int(ok3.sum())))
    w("")
    ex3, regla3, t3, _, n3 = mejor_umbral(p3[ok3], y3[ok3])
    base3 = mayoria(y3[ok3])
    w("Umbral unico, clase binaria: mayoria %.4f, mejor umbral %.4f"
      % (base3, ex3))
    w("(%s, t = %.6g), ganancia de %.2f pp sobre %d filas."
      % (regla3, t3, 100.0 * (ex3 - base3), n3))
    w("")
    w("Por tipo, que es como la describieron los autores:")
    w("")
    w("%-10s %10s %10s %9s %9s %8s"
      % ("tipo", "instancias", "n compar.", "mayoria", "mejor", "ganancia"))
    J["dataset3"] = {"filas": int(len(d3)), "normales": int((~y3).sum()),
                     "ataques": int(y3.sum()), "con_valor": int(ok3.sum()),
                     "binario": {"mayoria": base3, "mejor_umbral": ex3,
                                 "regla": regla3, "umbral": t3, "n": n3},
                     "por_tipo": {}}
    for k in "1234567":
        sel = ok3 & ((r3 == "0") | (r3 == k))
        if int((ok3 & (r3 == k)).sum()) == 0:
            continue
        yy = r3[sel] == k
        ex, regla, t, _, n = mejor_umbral(p3[sel], yy)
        base = mayoria(yy)
        w("%-10s %10d %10d %9.4f %9.4f %6.2f pp"
          % (k, int((r3 == k).sum()), n, base, ex, 100.0 * (ex - base)))
        J["dataset3"]["por_tipo"][k] = {
            "instancias": int((r3 == k).sum()), "n_comparacion": n,
            "mayoria": base, "mejor_umbral": ex, "regla": regla, "umbral": t,
            "ganancia_pp": 100.0 * (ex - base)}
    w("")
    w("Asi se ve la fuga documentada: en el Dataset 3 los tipos 1, 2 y 7")
    w("llegan a 0,9957, 0,9004 y 0,9889 de exactitud con un solo umbral, y los")
    w("tipos 3 a 6 se quedan exactamente en la mayoria. Es decir que la fuga")
    w("del Dataset 3 **tambien es por tipo**, concentrada en tres de los")
    w("siete, y es ahi donde el procedimiento la encuentra.")
    w("")
    w("Diferencia de fondo entre las dos versiones, en el atributo mismo: en")
    w("el Dataset 3 la presion esta informada en las %d filas (el 100 %%), y"
      % int(ok3.sum()))
    w("en el Dataset 4 en %d de %d (el %.2f %%), solo en las respuestas."
      % (int(con_valor.sum()), n_tot, 100.0 * con_valor.sum() / n_tot))
    w("")

    # ---- 7.6 conclusion ---------------------------------------------
    w("## 7.6 Conclusion")
    w("")
    w("**La fuga no se reproduce en la version corregida.** El mejor umbral")
    w("unico sobre `pressure measurement` alcanza %.4f de exactitud sobre las"
      % ex_sub)
    w("%d filas que tienen valor, contra %.4f del clasificador que asigna"
      % (n_sub, base_sub))
    w("todo a la clase mayoritaria: %.2f pp de ganancia, con una tasa de"
      % (100.0 * (ex_sub - base_sub)))
    w("deteccion de %.4f. Sobre el total de %d filas la exactitud es de %.4f"
      % (tp / (con_valor & y).sum(), n_tot, ex_tot_norm))
    w("contra %.4f de la mayoria. Los rangos intercuartilicos de las dos"
      % base_tot)
    w("clases se solapan y el AUC es de %.4f. En el Dataset 3 el mismo"
      % a_sub)
    w("procedimiento encuentra tres tipos por encima de 0,90.")
    w("")
    w("Cuatro de los siete tipos --- MSCI, MPCI, MFCI y DoS --- no tienen")
    w("ninguna fila con valor de presion, de modo que para ellos el atributo")
    w("no puede inflar nada. La senal que queda esta en NMRI y CMRI, donde la")
    w("medicion falseada es la anomalia por definicion.")
    w("")
    w("**Los valores de referencia por tipo son utilizables.** Queda una")
    w("salvedad que no es una fuga pero conviene dejar anotada: el cero")
    w("explicito de presion identifica ataque con precision 1,0000 en %d"
      % int(z.sum()))
    w("filas, el %.2f %% de los %d ataques. Conviene no construir la linea"
      % (100.0 * (z & y).sum() / n_atk, n_atk))
    w("base sobre ese cero como caracteristica aislada.")
    w("")
    w("Reproducible con:")
    w("  eda/.venv/bin/python -I eda/scripts/07_morris_fuga_presion.py")
    w("")

    J["conclusion"] = {
        "fuga_se_reproduce": False,
        "mejor_umbral_subconjunto": ex_sub,
        "mayoria_subconjunto": base_sub,
        "ganancia_pp_subconjunto": 100.0 * (ex_sub - base_sub),
        "mejor_umbral_total": ex_tot_norm,
        "mayoria_total": base_tot,
        "auc_subconjunto": a_sub,
        "tipos_sin_valor_de_presion": ["3", "4", "5", "6"],
        "referencias_por_tipo_utilizables": True}

    comun.escribir("p7_morris_fuga_presion.txt", "\n".join(L))
    with open(os.path.join(comun.SALIDAS,
                           "p7_morris_fuga_presion.json"), "w") as fh:
        json.dump(J, fh, indent=1, ensure_ascii=False)


if __name__ == "__main__":
    main()
