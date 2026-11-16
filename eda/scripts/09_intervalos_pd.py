"""Pregunta 9 --- los cuatro intervalos de PD, con un solo estadistico.

Los informes presentan como comparables cuatro cifras de precision que no
estan calculadas con el mismo estadistico:

  conjunto                              n eventos   publicado   estadistico
  Morris, DoS (prueba)                        281   +-0,03      error estandar
  Morris, MPCI (prueba)                     1.808   +-0,023     IC 95 % (Wald)
  ICS-Flow, escrituras bajo MITM (prueba)      51   +-0,137     IC 95 % (Wald)
  Westermo, tipo con 3 eventos (prueba)         3   +-0,55      IC 95 % (Wald)

El error estandar y el IC 95 % difieren en un factor 1,96, de modo que la
primera fila no es comparable con las otras tres.

Este script recalcula las cuatro con **un solo estadistico** y deja la salida
citable. El estadistico elegido y el motivo estan en la seccion 9.1.

Los `n` se leen de las salidas ya medidas del propio EDA, no se escriben a
mano, salvo el de Westermo, que se recalcula desde `events.txt` reusando el
lector de `02_westermo_etiquetas.py`.

Uso:  eda/.venv/bin/python -I eda/scripts/09_intervalos_pd.py
"""

import collections
import importlib
import json
import math
import os
import sys

import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import comun  # noqa: E402

_west = importlib.import_module("02_westermo_etiquetas")

Z95 = 1.959963984540054  # cuantil 0,975 de la normal estandar
ALFA = 0.05

# Premisa de los informes: la PD que se quiere acotar esta cerca de 0,5, que es
# donde la varianza de una proporcion es maxima y el intervalo mas ancho.
P_PREMISA = 0.5


def wald(n, p=P_PREMISA, z=Z95):
    """Error estandar y semiancho de Wald. Se incluye solo para reproducir las
    cifras publicadas y mostrar donde falla."""
    se = math.sqrt(p * (1.0 - p) / n)
    return se, z * se, p - z * se, p + z * se


def wilson(k, n, z=Z95):
    """Intervalo de Wilson (score) para una proporcion.

    Devuelve (centro, inferior, superior, semiancho). El intervalo es
    asimetrico respecto de k/n en general, pero con k/n = 0,5 queda centrado en
    0,5 y el semiancho es un `+-` legitimo.
    """
    den = n + z * z
    centro = (k + z * z / 2.0) / den
    semi = (z / den) * math.sqrt(k * (n - k) / float(n) + z * z / 4.0)
    return centro, max(0.0, centro - semi), min(1.0, centro + semi), semi


def clopper_pearson(k, n, alfa=ALFA):
    """Intervalo exacto de Clopper-Pearson. Requiere k entero."""
    from scipy.stats import beta
    inf = 0.0 if k == 0 else float(beta.ppf(alfa / 2.0, k, n - k + 1))
    sup = 1.0 if k == n else float(beta.ppf(1.0 - alfa / 2.0, k + 1, n - k))
    return inf, sup


def k_cercanos(n, p=P_PREMISA):
    """Los k enteros alcanzables mas cercanos a p*n, y si p*n es alcanzable."""
    exacto = p * n
    if abs(exacto - round(exacto)) < 1e-12:
        return [int(round(exacto))], True
    return sorted({math.floor(exacto), math.ceil(exacto)}), False


def peor_wilson(n, z=Z95):
    """Semiancho de Wilson mas grande entre todos los k alcanzables (0..n).

    No supone ningun valor de PD: es una cota que vale cualquiera sea el
    resultado del experimento.
    """
    peor = (-1.0, None)
    for k in range(n + 1):
        _c, _i, _s, semi = wilson(k, n, z)
        if semi > peor[0]:
            peor = (semi, k)
    return peor


UMBRALES_EPISODIO = (5.0, 10.0, 30.0, 60.0, 300.0)


def episodios_morris():
    """Rachas contra EPISODIOS de ataque, por categoria, en el tramo de prueba.

    Un evento definido como racha contigua de la misma categoria cuenta una
    transaccion Modbus, no un episodio de ataque: el atacante inyecta sobre
    transacciones consecutivas con una normal en medio, de modo que una sola
    inyeccion se parte en muchas rachas. Aca se agrupan las rachas separadas
    por menos de `u` segundos y se barre `u`, para que la eleccion quede a la
    vista en lugar de escondida en el codigo.

    Devuelve None si no se puede leer el ARFF.
    """
    try:
        mor = importlib.import_module("03_morris")
    except Exception:
        return None
    ruta = os.path.join(comun.MORRIS, "IanArffDataset.arff")
    if not os.path.exists(ruta):
        return None
    df = mor.leer_arff(ruta)
    df["time"] = pd.to_numeric(df["time"], errors="coerce")
    df = df.sort_values("time", kind="mergesort").reset_index(drop=True)
    pr = df[df["time"] >= comun.MORRIS_CORTES[1]].reset_index(drop=True)
    if len(pr) < 10:
        return None
    cat = pr["categorized result"].astype(str).str.strip().to_numpy()
    t = pr["time"].to_numpy(float)
    filas = []
    for k in sorted(set(cat)):
        if k == "0":
            continue
        idx = np.flatnonzero(cat == k)
        if len(idx) < 2:
            continue
        cortes = np.flatnonzero(np.diff(idx) > 1)
        ini = np.concatenate(([0], cortes + 1))
        fin = np.concatenate((cortes, [len(idx) - 1]))
        rachas = [(idx[a], idx[b]) for a, b in zip(ini, fin)]
        sep = [t[rachas[i][0]] - t[rachas[i - 1][1]]
               for i in range(1, len(rachas))]
        huecos = [rachas[i][0] - rachas[i - 1][1]
                  for i in range(1, len(rachas))]
        por_u = {}
        for u in UMBRALES_EPISODIO:
            g = 1
            for i in range(1, len(rachas)):
                if t[rachas[i][0]] - t[rachas[i - 1][1]] > u:
                    g += 1
            por_u["%g" % u] = g
        nombre = mor.CATEGORIA.get(k, k).split("(")[0].strip() or k
        filas.append({"categoria": nombre, "codigo": k,
                      "rachas": len(rachas),
                      "separacion_mediana_s": float(np.median(sep)) if sep else None,
                      "filas_entre_rachas_mediana": float(np.median(huecos)) if huecos else None,
                      "episodios": por_u})
    filas.sort(key=lambda f: -f["rachas"])
    return filas


def autocorr_eventos_morris():
    """Autocorrelacion a retardo 1 del indicador de categoria, POR EVENTO.

    La dependencia que invalida un intervalo binomial es entre los ensayos ---
    los eventos ---, no entre las filas del conjunto. Morris tiene 0,86 de
    autocorrelacion entre filas, pero el conteo por rachas ya la absorbe: un
    evento ES una racha. Lo que hay que medir es si los eventos de una misma
    categoria se agrupan entre si, y eso se mide sobre la secuencia de
    eventos del tramo de PRUEBA, que es donde se mediria la PD.

    Devuelve None si no se puede leer el ARFF.
    """
    try:
        mor = importlib.import_module("03_morris")
    except Exception:
        return None
    ruta = os.path.join(comun.MORRIS, "IanArffDataset.arff")
    if not os.path.exists(ruta):
        return None
    df = mor.leer_arff(ruta)
    df["time"] = pd.to_numeric(df["time"], errors="coerce")
    df = df.sort_values("time", kind="mergesort").reset_index(drop=True)
    pr = df[df["time"] >= comun.MORRIS_CORTES[1]]
    cat = pr["categorized result"].astype(str).to_numpy()
    if len(cat) < 10:
        return None
    # Un evento es una racha contigua de la misma categoria, igual que en
    # la pregunta 4. La secuencia de eventos es la de sus categorias.
    seq = [cat[0]] + [cat[i] for i in range(1, len(cat)) if cat[i] != cat[i - 1]]
    filas = []
    for k in sorted(set(seq)):
        if k == "0":
            continue          # la clase normal no es una familia de anomalia
        ind = np.array([1.0 if s == k else 0.0 for s in seq])
        n = int(ind.sum())
        if ind.std() == 0 or n < 2:
            continue
        z = ind - ind.mean()
        rho = float((z[:-1] * z[1:]).sum() / (z * z).sum())
        nef = n * (1 - rho) / (1 + rho) if rho > -1 else float(n)
        nombre = mor.CATEGORIA.get(k, k).split("(")[0].strip() or k
        filas.append({"categoria": nombre, "codigo": k,
                      "eventos": n, "rho": rho,
                      "n_efectivo": float(nef),
                      "ic95": float(wilson(0.5 * max(1.0, nef),
                                           max(1.0, nef))[3])})
    return sorted(filas, key=lambda f: -f["eventos"]) or None


def eventos_westermo():
    """Eventos de Westermo por tipo y particion, recalculados desde events.txt."""
    ruta = os.path.join(comun.WESTERMO, "events.txt")
    if not os.path.exists(ruta):
        return None, None, ruta
    eventos, _sin_cerrar, _otras = _west.leer_eventos(ruta)
    tabla = collections.defaultdict(collections.Counter)
    for e in eventos:
        tabla[e["tipo"]][_west.particion(e["inicio"])] += 1
    return tabla, len(eventos), ruta


def main():
    comun.preparar()
    L = []
    w = L.append
    J = {}

    w("# Pregunta 9 - los cuatro intervalos de PD, con un solo estadistico")
    w("")
    w("Nivel de confianza: 95 %%. Cuantil normal z = %.6f." % Z95)
    w("Premisa de los informes: la PD a acotar esta cerca de %.1f, que es donde"
      % P_PREMISA)
    w("la varianza de una proporcion es maxima y el intervalo mas ancho.")
    w("")

    # ---- 9.0 de donde sale cada n -----------------------------------
    w("## 9.0 De donde sale cada n")
    w("")
    casos = []

    pm = os.path.join(comun.SALIDAS, "p3_p4_morris.json")
    pi = os.path.join(comun.SALIDAS, "p6_icsflow.json")
    faltan = [p for p in (pm, pi) if not os.path.exists(p)]
    if faltan:
        w("Faltan salidas previas: %s"
          % ", ".join(comun.rel(p) for p in faltan))
        w("Correr antes `make -C eda morris` y `make -C eda icsflow`.")
        comun.escribir("p9_intervalos_pd.txt", "\n".join(L))
        return 1

    with open(pm) as fh:
        morris = json.load(fh)
    with open(pi) as fh:
        icsflow = json.load(fh)

    n_dos = int(morris["por_categoria"]["6"]["por_particion"]["prueba"])
    n_mpci = int(morris["por_categoria"]["4"]["por_particion"]["prueba"])
    n_ics = int(icsflow["conteo_por_particion"]["prueba"]["escrituras_en_mitm"])
    n_ics_ev = int(icsflow["eventos_por_particion"]["prueba"]["mitm"])

    tabla_w, total_w, ruta_w = eventos_westermo()
    if tabla_w is None:
        w("No esta %s: el caso de Westermo no se puede recalcular."
          % comun.rel(ruta_w))
        n_west = None
        n_west_min = None
        tipo_min = None
    else:
        prueba = {t: c.get("prueba", 0) for t, c in tabla_w.items()}
        tipo_min = min(prueba, key=lambda t: prueba[t])
        n_west_min = prueba[tipo_min]
        # El caso que citan los informes es un tipo con 3 eventos en prueba.
        con_tres = sorted(t for t, v in prueba.items() if v == 3)
        n_west = 3 if con_tres else None

    w("%-44s %7s  %s" % ("caso", "n", "fuente"))
    w("%-44s %7d  %s" % ("Morris, DoS (prueba)", n_dos,
                         "salidas/p3_p4_morris.json"))
    w("%-44s %7d  %s" % ("Morris, MPCI (prueba)", n_mpci,
                         "salidas/p3_p4_morris.json"))
    w("%-44s %7d  %s" % ("ICS-Flow, escrituras bajo MITM (prueba)", n_ics,
                         "salidas/p6_icsflow.json"))
    if n_west is not None:
        w("%-44s %7d  %s" % ("Westermo, tipo con 3 eventos (prueba)", n_west,
                             "datasets/westermo/data/events.txt"))
    w("")
    if tabla_w is not None:
        w("Eventos de Westermo en el tramo de prueba, recalculados desde")
        w("`events.txt` (%d eventos en total):" % total_w)
        w("")
        w("%-28s %8s" % ("tipo", "prueba"))
        for t in sorted(prueba, key=lambda x: (prueba[x], x)):
            w("%-28s %8d" % (t, prueba[t]))
        w("")
        w("Los tipos con 3 eventos en prueba son: %s." % ", ".join(con_tres))
        w("")
        w("**Correccion al caso citado.** El peor caso de Westermo no es 3 sino")
        w("%d evento(s), en %s. El intervalo de +-0,55 que publican los"
          % (n_west_min, tipo_min))
        w("informes corresponde al tipo con 3, que no es el tipo mas pobre.")
        w("")

    casos.append(("Morris, DoS (prueba)", n_dos, "+-0,03 (error estandar)"))
    casos.append(("Morris, MPCI (prueba)", n_mpci, "+-0,023 (IC 95 %)"))
    casos.append(("ICS-Flow, escrituras bajo MITM (prueba)", n_ics,
                  "+-0,137 (IC 95 %)"))
    if n_west is not None:
        casos.append(("Westermo, tipo con 3 eventos (prueba)", n_west,
                      "+-0,55 (IC 95 %)"))
    if n_west_min is not None and n_west_min != n_west:
        casos.append(("Westermo, peor tipo: %s (prueba)" % tipo_min,
                      n_west_min, "no publicado"))
    casos.append(("ICS-Flow, eventos de MITM (prueba)", n_ics_ev,
                  "+-0,438 (IC 95 %)"))
    # Caso hipotetico, y marcado como tal: la seccion 4.5 de INFORME.md
    # razona que pasaria si la proporcion de escrituras ALTERADAS entre las
    # que caen bajo ventana de intermediario --- medida en entrenamiento ---
    # se mantuviera en el tramo de prueba. No esta medido y no puede estarlo
    # sin abrir ese tramo; entra aca para que la cifra que el documento cita
    # salga del mismo estadistico que las demas y no de una cuenta a mano.
    man = icsflow.get("manipulacion") or {}
    n_alt = man.get("alteradas_en_entrenamiento")
    n_ics_tr = int(icsflow["conteo_por_particion"]["entrenamiento"]
                   ["escrituras_en_mitm"])
    if n_alt and n_ics_tr:
        frac = n_alt / float(n_ics_tr)
        n_hip = int(round(n_ics * frac))
        casos.append(("ICS-Flow, escritura ALTERADA (hipotetico, no medido)",
                      n_hip, "no publicado"))
        w("Caso hipotetico que se agrega, y marcado como tal: de las %d"
          % n_ics_tr)
        w("escrituras bajo ventana de intermediario del tramo de")
        w("ENTRENAMIENTO, las que llevan el valor alterado son **%d**, el"
          % n_alt)
        w("%.0f %%. Si esa proporcion se mantuviera en prueba, las alteradas"
          % (100 * frac))
        w("serian del orden de %d. **No esta medido** y no puede estarlo sin"
          % n_hip)
        w("abrir el tramo de prueba; entra en la tabla para que la cifra que")
        w("cita la seccion 4.5 de INFORME.md salga del mismo estadistico que")
        w("las demas y no de una cuenta a mano.")
        w("")

    # ---- 9.1 que estadistico ----------------------------------------
    w("## 9.1 Que estadistico corresponde, y por que")
    w("")
    w("**Se propone el intervalo de Wilson (score) al 95 % como el estadistico")
    w("unico para las cuatro cifras.** Motivos:")
    w("")
    w("- La aproximacion normal (Wald), que es la que usan tres de las cuatro")
    w("  cifras publicadas, **no sirve con n chico**. Con n = 3 y PD = 0,5 el")
    w("  intervalo de Wald es [%.3f, %.3f], que se sale del [0, 1]: no es un"
      % (wald(3)[2], wald(3)[3]))
    w("  intervalo de una proporcion.")
    w("- Wilson no se sale nunca de [0, 1], tiene mejor cobertura que Wald en")
    w("  n chico y no se degrada en n grande, de modo que sirve para las cuatro")
    w("  filas sin cambiar de criterio a mitad de tabla.")
    w("- Se agrega Clopper-Pearson como control conservador. Es exacto en el")
    w("  sentido de que su cobertura nunca baja del 95 %, a costa de ser mas")
    w("  ancho. Si una conclusion se sostiene con Wilson y con Clopper-Pearson,")
    w("  no depende del estadistico.")
    w("")
    w("El error estandar **no** es un intervalo y no se usa aca. Se lo deja en")
    w("la tabla de 9.3 solo para mostrar el factor 1,96 que separa la fila de")
    w("Morris/DoS de las otras tres.")
    w("")
    w("Con PD = 0,5 el intervalo de Wilson queda centrado en 0,5 y es simetrico,")
    w("asi que el `+-` es legitimo. Fuera de 0,5 Wilson es asimetrico y hay que")
    w("citar los dos extremos, no un `+-`.")
    w("")

    # ---- 9.2 el calculo ---------------------------------------------
    w("## 9.2 Las cuatro cifras con el mismo estadistico")
    w("")
    w("Wilson al 95 %, con PD = 0,5 en las cuatro filas, de modo que son")
    w("comparables entre si. La formula de Wilson no necesita que k sea entero")
    w("--- solo entra por k(n-k)/n ---, asi que se evalua en k = 0,5 n y el")
    w("intervalo queda centrado en 0,5 y simetrico. Clopper-Pearson si necesita")
    w("k entero, y se trata en la columna correspondiente de 9.5.")
    w("")
    w("%-44s %6s %10s %22s %9s"
      % ("caso", "n", "semiancho", "intervalo Wilson 95 %", "1/n"))
    J["casos"] = []
    for nombre, n, publicado in casos:
        k_cont = P_PREMISA * n
        c, i, s, semi = wilson(k_cont, n)
        w("%-44s %6d %10.4f %22s %9.4f"
          % (nombre, n, semi, "[%.4f, %.4f]" % (i, s), 1.0 / n))
        wil = {"k_continuo": k_cont, "centro": c, "inferior": i,
               "superior": s, "semiancho": semi}

        se, semi_wald, inf_wald, sup_wald = wald(n)
        peor_semi, peor_k = peor_wilson(n)

        # Clopper-Pearson exige k entero. Si 0,5 n no lo es, se informan los
        # dos enteros vecinos, que son los resultados realmente alcanzables.
        ks, exacto = k_cercanos(n)
        cp = []
        for k in ks:
            inf, sup = clopper_pearson(k, n)
            cp.append({"k": k, "p_estimada": k / float(n), "inferior": inf,
                       "superior": sup,
                       "semiancho_equivalente": (sup - inf) / 2.0})
        cp_semi = max(d["semiancho_equivalente"] for d in cp)

        J["casos"].append({
            "caso": nombre, "n": n, "publicado": publicado,
            "wilson_95": wil,
            "clopper_pearson_95": {"k_exacto_alcanzable": exacto,
                                   "por_k": cp,
                                   "semiancho_equivalente": cp_semi},
            "wald": {"error_estandar": se, "semiancho_95": semi_wald,
                     "inferior": inf_wald, "superior": sup_wald,
                     "se_sale_de_0_1": bool(inf_wald < 0.0 or sup_wald > 1.0)},
            "wilson_peor_caso": {"semiancho": peor_semi, "k": peor_k},
            "granularidad_1_sobre_n": 1.0 / n})
    w("")

    # ---- 9.3 contra lo publicado ------------------------------------
    w("## 9.3 Contra las cifras publicadas")
    w("")
    w("Las dos ultimas columnas muestran por que las cuatro no eran")
    w("comparables: el error estandar y el semiancho de Wald difieren en el")
    w("factor %.2f." % Z95)
    w("")
    w("%-44s %6s %12s %10s %10s %10s"
      % ("caso", "n", "publicado", "err.est.", "Wald 95%", "Wilson 95%"))
    for d in J["casos"]:
        w("%-44s %6d %12s %10.4f %10.4f %10.4f"
          % (d["caso"], d["n"], d["publicado"].split(" ")[0],
             d["wald"]["error_estandar"], d["wald"]["semiancho_95"],
             d["wilson_95"]["semiancho"]))
    w("")
    w("Lectura fila por fila:")
    w("")
    for d in J["casos"]:
        if d["publicado"] == "no publicado":
            continue
        w("- **%s**, n = %d. Lo publicado, %s, reproduce"
          % (d["caso"], d["n"], d["publicado"]))
        if "error estandar" in d["publicado"]:
            w("  el error estandar (%.4f), no un intervalo. Con el mismo"
              % d["wald"]["error_estandar"])
            w("  criterio que las otras tres filas la cifra es %.4f, y con"
              % d["wald"]["semiancho_95"])
            w("  Wilson %.4f." % d["wilson_95"]["semiancho"])
        else:
            w("  el semiancho de Wald (%.4f). Con Wilson es %.4f."
              % (d["wald"]["semiancho_95"], d["wilson_95"]["semiancho"]))
        if d["wald"]["se_sale_de_0_1"]:
            w("  El intervalo de Wald es [%.3f, %.3f]: **se sale de [0, 1]**."
              % (d["wald"]["inferior"], d["wald"]["superior"]))
    w("")
    tres = [d for d in J["casos"] if d["n"] == 3]
    if tres:
        d = tres[0]
        w("Una nota sobre el +-0,55 de Westermo: no reproduce exactamente con")
        w("ninguno de los tres estadisticos. Wald da %.4f, Wilson %.4f y"
          % (d["wald"]["semiancho_95"], d["wilson_95"]["semiancho"]))
        w("Clopper-Pearson %.4f. El %.4f de Wald es el mas cercano, de modo que"
          % (d["clopper_pearson_95"]["semiancho_equivalente"],
             d["wald"]["semiancho_95"]))
        w("la cifra publicada parece un Wald redondeado hacia abajo.")
        w("")

    # ---- 9.4 la granularidad ----------------------------------------
    w("## 9.4 El limite que el intervalo no muestra")
    w("")
    w("Con n chico el intervalo no es la unica limitacion: el estimador solo")
    w("puede tomar n + 1 valores, espaciados 1/n. Conviene decirlo porque")
    w("cambia la lectura del caso de Westermo.")
    w("")
    w("%-44s %6s %10s %11s  %s"
      % ("caso", "n", "1/n", "PD = 0,5?", "valores alcanzables de PD"))
    for d in J["casos"]:
        n = d["n"]
        alcanzable = "SI" if n % 2 == 0 else "NO"
        if n <= 6:
            vals = ", ".join("%.3f" % (k / float(n)) for k in range(n + 1))
        else:
            vals = "0, 1/%d, 2/%d, ... , 1" % (n, n)
        w("%-44s %6d %10.4f %11s  %s" % (d["caso"], n, 1.0 / n, alcanzable,
                                         vals))
    w("")
    w("**Con 3 eventos la PD solo puede valer 0; 0,333; 0,667 o 1.** El 0,5 que")
    w("suponen los informes para calcular el +-0,55 no es un resultado posible")
    w("del experimento. Citar un intervalo alrededor de un valor inalcanzable")
    w("sugiere una precision que no existe: con n = 3 lo correcto es decir que")
    w("la PD de ese tipo **no es estimable**, no acotarla.")
    w("")
    w("Cota que no supone ningun valor de PD. Es el semiancho de Wilson mas")
    w("ancho entre todos los k posibles, de modo que vale cualquiera sea el")
    w("resultado:")
    w("")
    w("%-44s %6s %12s %10s" % ("caso", "n", "peor k", "semiancho"))
    for d in J["casos"]:
        w("%-44s %6d %12d %10.4f"
          % (d["caso"], d["n"], d["wilson_peor_caso"]["k"],
             d["wilson_peor_caso"]["semiancho"]))
    w("")

    # ---- 9.5 tabla citable ------------------------------------------
    w("## 9.5 Tabla citable")
    w("")
    w("Las cuatro cifras con un solo estadistico --- Wilson al 95 %, PD = 0,5")
    w("--- y el control conservador al lado. Es la tabla que hay que citar en")
    w("lugar de convertir ningun numero a mano.")
    w("")
    w("%-44s %6s %12s %14s %10s"
      % ("caso", "n", "Wilson 95%", "Clopper-P. 95%", "k entero"))
    for d in J["casos"]:
        w("%-44s %6d %11.3f %13.3f %10s"
          % (d["caso"], d["n"], d["wilson_95"]["semiancho"],
             d["clopper_pearson_95"]["semiancho_equivalente"],
             "si" if d["clopper_pearson_95"]["k_exacto_alcanzable"] else "no"))
    w("")
    w("Los semianchos de Clopper-Pearson son equivalentes: la mitad del ancho")
    w("del intervalo exacto, que en general es asimetrico. Cuando `k entero` es")
    w("`no`, PD = 0,5 no es alcanzable con ese n y el valor de la columna es el")
    w("mas ancho de los dos k vecinos. Los extremos de cada intervalo, k por k,")
    w("estan en `salidas/p9_intervalos_pd.json`.")
    w("")
    w("Conclusion: el orden de magnitud de las tres filas con n >= 51 no cambia")
    w("al unificar el estadistico --- Morris sigue sosteniendo el compromiso y")
    w("ICS-Flow sigue siendo grueso pero utilizable --- pero la fila de Morris")
    w("DoS pasa de +-0,03 a +-%.3f, que es la cifra comparable con las otras,"
      % J["casos"][0]["wilson_95"]["semiancho"])
    w("y la de Westermo no deberia presentarse como un intervalo.")
    w("")
    # ---- 9.6 la independencia que el intervalo supone ---------------
    w("## 9.6 La independencia que el intervalo supone, medida")
    w("")
    w("Cualquiera de estos intervalos supone que los n eventos son ensayos")
    w("independientes. Eso **no** se deduce de que las filas del conjunto")
    w("sean autocorrelacionadas: Morris tiene 0,86 a retardo 1 ENTRE FILAS, y")
    w("el conteo por rachas ya absorbe esa dependencia, de modo que aplicarla")
    w("otra vez a los eventos seria descontar dos veces lo mismo. La pregunta")
    w("correcta es si los EVENTOS estan agrupados entre si, y se mide sobre la")
    w("secuencia de eventos, no sobre las filas.")
    w("")
    ac_ev = autocorr_eventos_morris()
    if ac_ev is None:
        w("No se pudo leer el ARFF de Morris: queda sin medir.")
        w("")
    else:
        w("%-14s %9s %11s %12s %14s"
          % ("categoria", "eventos", "rho(ev,1)", "n efectivo", "IC95 PD=0,5"))
        for fila in ac_ev:
            w("%-14s %9d %11.3f %12.0f %14s"
              % (fila["categoria"], fila["eventos"], fila["rho"],
                 fila["n_efectivo"], "+-%.3f" % fila["ic95"]))
        w("")
        w("**Todas negativas, y no es un dato: es una identidad.** Un evento")
        w("se define como racha maxima de la misma categoria, de modo que dos")
        w("eventos consecutivos NUNCA comparten categoria por construccion.")
        w("Eso fuerza la suma de productos cruzados a cero y la")
        w("autocorrelacion a -p/(1-p), que es negativa siempre. Despejando el")
        w("largo de la secuencia, las %d categorias dan el mismo numero:"
          % len(ac_ev))
        largos = []
        for f in ac_ev:
            r = f["rho"]
            pp = -r / (1.0 - r) if r < 0 else float("nan")
            largos.append(f["eventos"] / pp if pp and pp == pp else float("nan"))
        w("   %s" % ", ".join("%.0f" % x for x in largos))
        w("De modo que esta columna **no mide agrupamiento** y no habilita la")
        w("conclusion de que suponer independencia sea conservador. Queda")
        w("informada para que no se la lea como medicion.")
        w("")
        J["autocorrelacion_entre_eventos"] = ac_ev
        J["autocorrelacion_entre_eventos_es_identidad"] = {
            "formula": "rho = -p/(1-p) con p = eventos/largo de la secuencia",
            "largo_despejado": [float(x) for x in largos]}

    w("### 9.6.b Lo que si se puede medir: rachas contra episodios")
    w("")
    w("La pregunta que importa es cuantos episodios de ataque **distintos**")
    w("hay, porque es sobre episodios que se promedia una PD por familia. Y")
    w("ahi la definicion por rachas sobreestima: en Morris las rachas")
    w("sucesivas de una misma categoria estan separadas por tres o cuatro")
    w("FILAS, es decir una o dos transacciones normales en medio, de modo que")
    w("una sola inyeccion se parte en decenas de rachas.")
    w("")
    eps = episodios_morris()
    if eps is None:
        w("No se pudo leer el ARFF de Morris: queda sin medir.")
        w("")
    else:
        cab = "".join("%8s" % ("u=%gs" % u) for u in UMBRALES_EPISODIO)
        w("%-14s %8s %10s %12s%s"
          % ("categoria", "rachas", "sep.med.s", "filas entre", cab))
        for f in eps:
            celdas = "".join("%8d" % f["episodios"]["%g" % u]
                             for u in UMBRALES_EPISODIO)
            w("%-14s %8d %10.2f %12.0f%s"
              % (f["categoria"], f["rachas"],
                 f["separacion_mediana_s"] or float("nan"),
                 f["filas_entre_rachas_mediana"] or float("nan"), celdas))
        w("")
        w("El umbral no cambia la lectura en el peor caso: con cualquier `u`")
        w("entre 5 s y 60 s, un rango de doce veces, DoS da el mismo numero")
        w("de episodios. Y el procedimiento discrimina en lugar de colapsar")
        w("todo: a 5 s hay categorias cuyas rachas no se funden, porque su")
        w("separacion mediana pasa de 11 s. Para esas dos la columna de 10 s")
        w("es una cota superior: se agrupan recien por encima de su propia")
        w("separacion, y a 30 s dan 29 y 25 episodios.")
        w("")
        w("Lo que esto le hace al intervalo, al umbral de 10 s:")
        w("")
        w("%-14s %9s %10s %11s %10s %12s"
          % ("categoria", "rachas", "semi", "episodios", "semi", "rejilla 1/n"))
        peor = None
        for f in eps:
            nr, ne = f["rachas"], f["episodios"]["10"]
            sr = wilson(nr / 2.0, nr)[3]
            se = wilson(ne / 2.0, ne)[3]
            w("%-14s %9d %10.3f %11d %10.3f %12.4f"
              % (f["categoria"], nr, sr, ne, se, 1.0 / ne))
            if peor is None or ne < peor[1]:
                peor = (f["categoria"], ne, se)
            f["semi_rachas"] = sr
            f["semi_episodios"] = se
        w("")
        w("**El peor tipo es %s, con %d episodios y un semiancho de +-%.2f.**"
          % (peor[0], peor[1], peor[2]))
        w("Con %d episodios la PD solo puede tomar %d valores espaciados"
          % (peor[1], peor[1] + 1))
        w("1/%d = %.3f, de modo que 0,5 no es alcanzable: los dos valores mas"
          % (peor[1], 1.0 / peor[1]))
        w("cercanos son %.4f y %.4f. Es la misma objecion que la pregunta 4"
          % ((peor[1] // 2) / peor[1], (peor[1] // 2 + 1) / peor[1]))
        w("levanta contra los tipos de Westermo con pocos eventos.")
        w("")
        w("De modo que **la afirmacion de que Morris sostiene un punto de")
        w("operacion por familia vale contando rachas y no contando")
        w("episodios**. Sigue siendo el mejor de los cinco conjuntos, y por")
        w("lejos, pero el compromiso por familia no se sostiene para los")
        w("tipos con pocos episodios.")
        w("")
        J["episodios_morris"] = {"umbrales": list(UMBRALES_EPISODIO),
                                 "por_categoria": eps}

    w("Reproducible con:")
    w("  eda/.venv/bin/python -I eda/scripts/09_intervalos_pd.py")
    w("")

    J["estadistico"] = {
        "elegido": "Wilson score, 95 %",
        "control": "Clopper-Pearson, 95 %",
        "z": Z95, "alfa": ALFA, "pd_premisa": P_PREMISA,
        "motivo": ("Wald no sirve con n chico: con n = 3 su intervalo se sale "
                   "de [0, 1]. Wilson no se sale nunca, tiene mejor cobertura "
                   "en n chico y no se degrada en n grande.")}

    comun.escribir("p9_intervalos_pd.txt", "\n".join(L))
    with open(os.path.join(comun.SALIDAS, "p9_intervalos_pd.json"), "w") as fh:
        json.dump(J, fh, indent=1, ensure_ascii=False)
    return 0


if __name__ == "__main__":
    sys.exit(main())
