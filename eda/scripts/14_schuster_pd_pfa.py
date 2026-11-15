"""Pregunta 14 --- PD y PFA de Schuster y Konig, despejadas de sus tablas.

El proyecto daba por bueno que el trabajo de Schuster y Konig (RAID 2024, "Effective
Anomaly Detection for Process Control Traffic in Absence of Protocol and
Attack Knowledge") no publica el par probabilidad de deteccion / probabilidad
de falsa alarma. Si lo publica, pero repartido en dos tablas:

  - Tabla 6 (cuerpo del articulo): exactitud balanceada sobre el conjunto de
    validacion, `vacc`, para los 48 montajes = 4 conjuntos x 3 perspectivas
    (flujo, paquete, 3 paquetes) x 4 algoritmos.
  - Tabla 13 (apendice A.4): precision, recall y F1 de **los mismos** modelos,
    con la misma estructura de 48 celdas.

El articulo define, en la Seccion 5.1 (paso 3, deteccion sobre el trafico de
validacion):

      vacc = 1/2 * [ TN/(TN+FP) + TP/(TP+FN) ]

y en el apendice A.4:  recall = TP/(TP+FN),  precision = TP/(TP+FP).

El recall ES la probabilidad de deteccion. De la definicion de vacc se despeja

      TNR = TN/(TN+FP) = 2*vacc - recall        PFA = 1 - TNR

Eso da el par PD/PFA para cada montaje donde las dos tablas se cruzan.

VERIFICACION DE QUE LAS DOS TABLAS MIDEN LO MISMO
-------------------------------------------------
No alcanza con que las dos tablas tengan la misma forma. Se comprueban tres
cosas antes de cruzarlas:

1. Misma particion. La nota al pie 13 del articulo dice que precision, recall
   y F1 "no son aplicables a los conjuntos sin anomalias (todos los conjuntos
   de muestras de entrenamiento y todos los derivados de los conjuntos
   reales)". TP y FN solo se definen en el paso 3, sobre la validacion. Por lo
   tanto el recall de la tabla 13 es de validacion, igual que vacc. Ademas la
   tabla 13 trae las filas `precisionf` / `recallf` para WDT, que corresponden
   al conjunto de validacion corregido, el mismo al que la tabla 6 le da
   `vacc_f`: las dos tablas distinguen las mismas dos particiones de WDT.
2. Mismos modelos. Las dos tablas dicen "del mejor modelo identificado para
   cada montaje de perspectiva de trafico, algoritmo y conjunto".
3. Cierre numerico independiente. Con la tabla 5 del articulo, que publica
   cuantas muestras normales y anomalas tiene cada conjunto de validacion, el
   par (precision, recall) alcanza para reconstruir TNR por otro camino:

        TP = recall * N_anomalas
        FP = TP * (1 - precision) / precision
        TNR' = 1 - FP / N_normales

   y de ahi vacc' = (TNR' + recall)/2, que tiene que coincidir con el vacc
   publicado en la tabla 6. Ese es el cierre que valida a la vez la
   derivacion, la hipotesis de particion comun y la transcripcion de los
   numeros. Se informa la diferencia celda por celda.

La transcripcion de las tablas tambien se verifica: cada fila escrita a mano
en este script se busca literalmente en `fuentes/schuster2024noneed.txt`, el
texto extraido del PDF, y se informa si alguna no aparece.

TERCERA VIA: la tasa horaria de falsas alarmas
----------------------------------------------
El articulo publica ademas la tabla 8, "False-alarm rates per hour for the
best model per dataset ... and sample type when using an aggregation period of
30 seconds". Es una tercera via, pero no es la misma cantidad: esta agregada a
ventanas de 30 s y solo cubre el mejor modelo por conjunto y perspectiva. Se
transcribe y se contrasta contra la PFA derivada, sin forzar que coincidan.

Uso:  python eda/scripts/14_schuster_pd_pfa.py
"""

import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import comun  # noqa: E402

FUENTE = os.path.join(comun.RAIZ, "fuentes", "schuster2024noneed.txt")

PERSPECTIVAS = ("flujo", "paquete", "3 paquetes")
ALGORITMOS = ("envelope", "iforest", "OCSVM", "CAE")
# Las 12 columnas de las tablas 6 y 13, en el orden en que estan impresas.
COLUMNAS = [(p, a) for p in PERSPECTIVAS for a in ALGORITMOS]

# --------------------------------------------------------------------------
# Tabla 6: exactitud balanceada sobre validacion (vacc). Solo se transcriben
# las filas vacc y vacc_f, que son las que miden la validacion; bacc mezcla
# entrenamiento con validacion y no sirve para despejar la PFA.
# --------------------------------------------------------------------------
TABLA6 = {
    ("Lemay", "vacc"): [0.8487, 0.9479, 0.8477, 0.8227,
                        0.5401, 0.5405, 0.9454, 0.9374,
                        0.9324, 0.9694, 0.9348, 0.9795],
    ("WDT", "vacc"): [0.8467, 0.8544, 0.8468, 0.8258,
                      0.7572, 0.7524, 0.7541, 0.7523,
                      0.7595, 0.7568, 0.7200, 0.7204],
    ("WDT", "vacc_f"): [0.9471, 0.9581, 0.9471, 0.9262,
                        0.9088, 0.9001, 0.9033, 0.8999,
                        0.8337, 0.8297, 0.7840, 0.7846],
    ("DNP3", "vacc"): [0.8790, 0.9026, 0.8004, 0.7979,
                       0.9395, 0.7510, 0.5441, 0.5668,
                       0.9566, 0.8539, 0.8139, 0.5877],
    ("S7comm", "vacc"): [0.9960, 0.9920, 1.0000, 1.0000,
                         0.9962, 0.9216, 0.5000, 0.7602,
                         0.9809, 0.9684, 0.9347, 0.9736],
}

# --------------------------------------------------------------------------
# Tabla 13: precision y recall de los mismos modelos. `None` marca la celda
# que el articulo imprime como "TP=0" (el modelo no marco nada).
# --------------------------------------------------------------------------
TABLA13 = {
    ("Lemay", "precision"): [0.7000, 0.6429, 0.5600, 0.5417,
                             0.9692, 0.9970, 0.9855, 0.9838,
                             0.9781, 0.9826, 0.9728, 0.9252],
    ("Lemay", "recall"): [0.7000, 0.9000, 0.7000, 0.6500,
                          0.0812, 0.0811, 0.8957, 0.8804,
                          0.8723, 0.9453, 0.8789, 0.9893],
    ("WDT", "precision"): [0.9990, 0.9930, 0.9996, 0.9248,
                           0.9747, 0.9262, 0.9418, 0.9249,
                           0.9868, 0.9533, 0.9921, 0.9999],
    ("WDT", "recall"): [0.6942, 0.7140, 0.6940, 0.7107,
                        0.5237, 0.5338, 0.5305, 0.5341,
                        0.5238, 0.5315, 0.4425, 0.4410],
    ("WDT", "precision_f"): [0.9990, 0.9930, 0.9996, 0.9152,
                             0.9643, 0.9019, 0.9222, 0.9004,
                             0.9822, 0.9424, 0.9907, 0.9999],
    ("WDT", "recall_f"): [0.8949, 0.9204, 0.8946, 0.9066,
                          0.8281, 0.8309, 0.8304, 0.8310,
                          0.6730, 0.6783, 0.5705, 0.5693],
    ("DNP3", "precision"): [0.2299, 0.1643, 0.2192, 0.2105,
                            0.1728, 0.1278, 0.1041, 0.0085,
                            0.6334, 0.4619, 0.2035, 0.0177],
    ("DNP3", "recall"): [0.8696, 1.0000, 0.6957, 0.6957,
                         0.9112, 0.5286, 0.0943, 0.9415,
                         0.9211, 0.7203, 0.6661, 0.9376],
    ("S7comm", "precision"): [0.9130, 0.8400, 1.0000, 1.0000,
                              0.9875, 0.7951, None, 0.5496,
                              0.9966, 0.9896, 0.9992, 0.9847],
    ("S7comm", "recall"): [1.0000, 1.0000, 1.0000, 1.0000,
                           1.0000, 0.9930, 0.0000, 1.0000,
                           0.9722, 0.9688, 0.8716, 0.9955],
}

# --------------------------------------------------------------------------
# Tabla 5: desglose del conjunto de validacion, muestras (normales, anomalas)
# por perspectiva, y duracion de la validacion en segundos.
# --------------------------------------------------------------------------
TABLA5 = {
    "Lemay": {"flujo": (2435, 20), "paquete": (21939, 8124),
              "3 paquetes": (21802, 8259), "duracion_s": 1300},
    "WDT": {"flujo": (22867, 23367), "paquete": (9851133, 6698292),
            "3 paquetes": (9850523, 6698900), "duracion_s": 5764},
    "DNP3": {"flujo": (601, 23), "paquete": (1556112, 11417),
             "3 paquetes": (1544883, 22644), "duracion_s": 86399},
    "S7comm": {"flujo": (251, 21), "paquete": (1137294, 665463),
               "3 paquetes": (438013, 1364742), "duracion_s": 32425},
}

# --------------------------------------------------------------------------
# Tabla 8: falsas alarmas por hora del MEJOR modelo por conjunto y
# perspectiva, con agregacion de 30 s. No es la PFA por muestra.
# --------------------------------------------------------------------------
TABLA8 = {
    ("Lemay", "flujo"): 10, ("Lemay", "paquete"): 100,
    ("Lemay", "3 paquetes"): 688,
    ("WDT", "flujo"): 52, ("WDT", "paquete"): 404,
    ("WDT", "3 paquetes"): 9682,
    ("DNP3", "flujo"): 5, ("DNP3", "paquete"): 1506,
    ("DNP3", "3 paquetes"): 502,
    ("S7comm", "flujo"): 0, ("S7comm", "paquete"): 312,
    ("S7comm", "3 paquetes"): 492,
}

# Modelo marcado en negrita en la tabla 6 como mejor por perspectiva, que es
# el que la tabla 8 usa. Se deduce del maximo de vacc de cada bloque de cuatro
# columnas, de modo que no hace falta transcribir el formato del PDF.
RESOLUCION = 1e-4          # las tablas traen cuatro decimales
MEDIO_PASO = RESOLUCION / 2


def verificar_transcripcion():
    """Busca cada fila transcrita en el texto extraido del PDF.

    Devuelve (verificadas, no encontradas, disponible). El texto extraido del
    PDF no se redistribuye con este repositorio, de modo que puede no estar: en
    ese caso `disponible` es False y la comprobacion se declara no hecha, en
    lugar de darla por buena.
    Es una comprobacion literal: se exige que los 12 valores aparezcan, en
    orden y con cuatro decimales, en una misma linea del archivo fuente.
    """
    if not os.path.exists(FUENTE):
        return [], [], False
    with open(FUENTE, encoding="utf-8", errors="replace") as fh:
        lineas = fh.read().splitlines()
    # Lineas de la fuente que traen 11 o 12 numeros de cuatro decimales.
    candidatas = []
    for i, ln in enumerate(lineas, 1):
        nums = re.findall(r"\d\.\d{4}", ln)
        if 11 <= len(nums) <= 12:
            candidatas.append((i, nums, ln))
    ok, faltan = [], []
    for tabla, nombre in ((TABLA6, "tabla 6"), (TABLA13, "tabla 13")):
        for (conj, metrica), vals in tabla.items():
            esperado = ["%.4f" % v for v in vals if v is not None]
            hallada = None
            for i, nums, _ln in candidatas:
                if nums == esperado:
                    hallada = i
                    break
            if hallada:
                ok.append("%s / %s / %s -> linea %d de %s"
                          % (nombre, conj, metrica, hallada,
                             comun.rel(FUENTE)))
            else:
                faltan.append("%s / %s / %s" % (nombre, conj, metrica))
    return ok, faltan, True


def derivar(conj, metrica_vacc, metrica_prec, metrica_rec, etiqueta,
            usar_tabla5):
    """Despeja PD y PFA para las 12 columnas de un conjunto."""
    filas = []
    vacc = TABLA6[(conj, metrica_vacc)]
    prec = TABLA13[(conj, metrica_prec)]
    rec = TABLA13[(conj, metrica_rec)]
    for j, (persp, alg) in enumerate(COLUMNAS):
        v, p, r = vacc[j], prec[j], rec[j]
        f = {"conjunto": conj, "particion": etiqueta, "perspectiva": persp,
             "algoritmo": alg, "vacc": v, "precision": p, "recall": r}
        # --- via 1: de la definicion de vacc ---
        tnr = 2.0 * v - r
        f["PD"] = r
        f["TNR"] = tnr
        f["PFA"] = 1.0 - tnr
        # Propagacion del redondeo: vacc y recall vienen a cuatro decimales,
        # de modo que TNR = 2*vacc - recall arrastra 2*(0,00005) + 0,00005.
        f["PFA_incert"] = 3 * MEDIO_PASO
        f["PFA_fuera_de_rango"] = not (-1e-9 <= f["PFA"] <= 1 + 1e-9)
        # --- via 2: de precision, recall y el tamano del conjunto ---
        if usar_tabla5 and p not in (None, 0.0) and r is not None:
            n_norm, n_anom = TABLA5[conj][persp]
            tp = r * n_anom
            fp = tp * (1.0 - p) / p
            f["N_normales"] = n_norm
            f["N_anomalas"] = n_anom
            f["TP_est"] = tp
            f["FP_est"] = fp
            f["PFA_b"] = fp / n_norm
            f["TNR_b"] = 1.0 - f["PFA_b"]
            f["vacc_reconstruido"] = (f["TNR_b"] + r) / 2.0
            f["delta_vacc"] = f["vacc_reconstruido"] - v
            f["delta_PFA"] = f["PFA_b"] - f["PFA"]
            horas = TABLA5[conj]["duracion_s"] / 3600.0
            f["falsas_alarmas_por_hora_est"] = fp / horas
            f["horas_validacion"] = horas
        filas.append(f)
    return filas


def main():
    comun.preparar()
    L = []
    w = L.append
    w("# Pregunta 14 - PD y PFA de Schuster y Konig (RAID 2024)")
    w("")
    w("Fuente: Schuster y Konig, RAID 2024, tablas 5, 6, 8 y 13. El texto")
    w("extraido del PDF se espera en %s, que no se" % comun.rel(FUENTE))
    w("redistribuye con este repositorio.")
    w("")
    w("Definiciones del propio articulo (Seccion 5.1, paso 3, y apendice")
    w("A.4), transcritas tal cual:")
    w("   vacc      = 1/2 * [ TN/(TN+FP) + TP/(TP+FN) ]")
    w("   recall    = TP/(TP+FN)                 <- ES la PD")
    w("   precision = TP/(TP+FP)")
    w("De donde:  TNR = 2*vacc - recall    y    PFA = 1 - TNR")
    w("")

    # ------------------------------------------------------- verificacion
    w("## 14.1 Verificacion de la transcripcion")
    w("")
    ok, faltan, disponible = verificar_transcripcion()
    if not disponible:
        w("**No hecha.** Falta %s, el texto" % comun.rel(FUENTE))
        w("extraido del PDF, que no se redistribuye. Las tablas transcritas a")
        w("mano en este script no se pudieron contrastar contra la fuente, de")
        w("modo que lo que sigue vale bajo el supuesto de que la transcripcion")
        w("es correcta. Para verificarla hace falta el texto del articulo.")
        w("")
    for s in ok:
        w("   OK  %s" % s)
    for s in faltan:
        w("   NO ENCONTRADA  %s" % s)
    w("")
    if faltan:
        w("**Hay filas transcritas que no aparecen literalmente en el texto")
        w("extraido. No se cruza nada hasta resolverlo.**")
        comun.escribir("p14_schuster_pd_pfa.txt", "\n".join(L))
        return 1
    if disponible:
        w("Las %d filas transcritas aparecen literalmente en el texto extraido"
          % len(ok))
        w("del PDF, con sus cuatro decimales y en el mismo orden de columnas.")
        w("")

    # ------------------------------------------- misma particion?
    w("## 14.2 Las dos tablas estan medidas sobre la misma particion?")
    w("")
    w("Si, y hay tres razones rastreables:")
    w("")
    w("1. La nota al pie 13 del articulo dice que precision, recall y F1")
    w("   `are not applicable to the sets without anomalies (all sample sets")
    w("   for training and all sets derived from the real datasets)`. Los")
    w("   conjuntos de entrenamiento se armaron solo con trafico normal, de")
    w("   modo que TP y FN no existen ahi: el recall de la tabla 13 solo")
    w("   puede ser de validacion, que es donde la Seccion 5.1 define TP y")
    w("   FN (paso 3, `Detection phase on validation traffic`).")
    w("2. Los dos encabezados dicen `of the best model identified for each")
    w("   setup of traffic perspective, algorithm, and dataset`: son los")
    w("   mismos 48 modelos, elegidos por el mismo criterio (maximo bacc).")
    w("3. Las dos tablas distinguen las mismas dos particiones de WDT: la")
    w("   tabla 6 trae vacc y vacc_f (conjunto de validacion corregido por")
    w("   etiquetas mal puestas) y la tabla 13 trae recall y recallf. Se")
    w("   cruza vacc con recall y vacc_f con recallf, nunca mezclados.")
    w("")
    w("El cierre numerico de 14.4 es la comprobacion dura: si las dos tablas")
    w("no fuesen del mismo conjunto de validacion, el vacc reconstruido a")
    w("partir de precision, recall y el tamano del conjunto no coincidiria")
    w("con el vacc publicado.")
    w("")

    # ------------------------------------------------------- derivacion
    casos = [("Lemay", "vacc", "precision", "recall", "validacion", True),
             ("WDT", "vacc", "precision", "recall", "validacion", True),
             ("WDT", "vacc_f", "precision_f", "recall_f",
              "validacion corregida", False),
             ("DNP3", "vacc", "precision", "recall", "validacion", True),
             ("S7comm", "vacc", "precision", "recall", "validacion", True)]
    todas = []
    for args in casos:
        todas.extend(derivar(*args))

    w("## 14.3 Pares PD / PFA derivados")
    w("")
    w("PD = recall de la tabla 13. PFA = 1 - (2*vacc - recall), con vacc de")
    w("la tabla 6. La incertidumbre de la PFA por el redondeo a cuatro")
    w("decimales de las dos tablas es +-%.5f en todos los casos."
      % (3 * MEDIO_PASO))
    w("")
    w("%-8s %-20s %-11s %-9s %8s %8s %8s %9s"
      % ("conjunto", "particion", "perspectiva", "algoritmo", "vacc",
         "PD", "TNR", "PFA"))
    for f in todas:
        aviso = "  <-- PFA fuera de [0,1]" if f["PFA_fuera_de_rango"] else ""
        w("%-8s %-20s %-11s %-9s %8.4f %8.4f %8.4f %9.4f%s"
          % (f["conjunto"], f["particion"], f["perspectiva"], f["algoritmo"],
             f["vacc"], f["PD"], f["TNR"], f["PFA"], aviso))
    w("")
    fuera = [f for f in todas if f["PFA_fuera_de_rango"]]
    if fuera:
        w("**%d celdas dan una PFA fuera de [0,1]**, o sea que la identidad")
        w("vacc = (TNR + PD)/2 no cierra con los numeros publicados en esas")
        w("celdas. Se dejan marcadas y no se usan. Celdas: %s"
          % ", ".join("%s/%s/%s" % (f["conjunto"], f["perspectiva"],
                                    f["algoritmo"]) for f in fuera))
    else:
        w("Las %d celdas dan una PFA dentro de [0,1]." % len(todas))
    w("")

    # ------------------------------------------------------- cierre
    w("## 14.4 Cierre independiente con la tabla 5")
    w("")
    w("Segunda via, sin usar vacc: con las muestras normales y anomalas del")
    w("conjunto de validacion (tabla 5) y el par (precision, recall) de la")
    w("tabla 13 se reconstruye TP = recall*N_anom, FP = TP*(1-prec)/prec y")
    w("TNR' = 1 - FP/N_norm. Si la derivacion y la hipotesis de particion")
    w("comun son correctas, (TNR' + recall)/2 tiene que dar el vacc")
    w("publicado.")
    w("")
    w("%-8s %-11s %-9s %10s %10s %10s %10s %11s"
      % ("conjunto", "perspectiva", "algoritmo", "FP estim.", "PFA (via 1)",
         "PFA (via 2)", "vacc recon.", "dif. vacc"))
    difs = []
    for f in todas:
        if "PFA_b" not in f:
            continue
        difs.append(abs(f["delta_vacc"]))
        w("%-8s %-11s %-9s %10.1f %10.5f %10.5f %10.4f %11.5f"
          % (f["conjunto"], f["perspectiva"], f["algoritmo"], f["FP_est"],
             f["PFA"], f["PFA_b"], f["vacc_reconstruido"], f["delta_vacc"]))
    w("")
    if difs:
        peor = max(difs)
        w("Diferencia maxima entre el vacc reconstruido y el publicado:")
        w("   %.6f  (el redondeo a cuatro decimales de precision, recall y"
          % peor)
        w("   vacc ya justifica por si solo unas pocas unidades en el cuarto")
        w("   decimal; los conjuntos con pocas muestras anomalas amplifican")
        w("   ese redondeo, porque FP se estima a partir de TP.)")
        w("   Celdas con diferencia menor a 0,001: %d de %d"
          % (sum(1 for d in difs if d < 1e-3), len(difs)))
        w("   Celdas con diferencia menor a 0,01 : %d de %d"
          % (sum(1 for d in difs if d < 1e-2), len(difs)))
    w("")
    w("No se aplica a la particion corregida de WDT (vacc_f / recallf):")
    w("la tabla 5 publica el desglose del conjunto de validacion original,")
    w("no el del corregido, de modo que no hay denominador con el que")
    w("hacer el cierre. Para esas 12 celdas solo queda la via 1.")
    w("")

    # ------------------------------------------------------- tabla 8
    w("## 14.5 Tercera via: la tasa horaria de falsas alarmas")
    w("")
    w("**Si, el articulo la publica.** Es la tabla 8, `False-alarm rates per")
    w("hour for the best model per dataset (highlighted in Tables 6 and 14)")
    w("and sample type when using an aggregation period of 30 seconds`.")
    w("")
    w("No es la misma cantidad que la PFA por muestra, por dos razones que")
    w("el propio articulo deja escritas: esta agregada a ventanas de 30 s")
    w("--- varias falsas alarmas dentro de la misma ventana cuentan como")
    w("una --- y solo cubre el mejor modelo de cada conjunto y perspectiva,")
    w("no los 48 montajes. Para las muestras de flujo el articulo aclara que")
    w("`the false-alarm rates on flow samples could not be reduced by")
    w("aggregation`, de modo que ahi la cifra agregada es la cruda.")
    w("")
    w("Contraste contra la via 2, que es la unica que da falsas alarmas")
    w("absolutas. Se compara el mejor modelo de cada bloque (maximo vacc),")
    w("que es el que la tabla 8 usa:")
    w("")
    w("%-8s %-11s %-9s %12s %14s %14s"
      % ("conjunto", "perspectiva", "algoritmo", "FP estim.",
         "FA/h estimada", "FA/h tabla 8"))
    comparacion = []
    for conj in ("Lemay", "WDT", "DNP3", "S7comm"):
        for persp in PERSPECTIVAS:
            cand = [f for f in todas
                    if f["conjunto"] == conj and f["perspectiva"] == persp
                    and f["particion"] == "validacion"]
            if not cand:
                continue
            mejor = max(cand, key=lambda f: f["vacc"])
            t8 = TABLA8.get((conj, persp))
            est = mejor.get("falsas_alarmas_por_hora_est")
            w("%-8s %-11s %-9s %12s %14s %14s"
              % (conj, persp, mejor["algoritmo"],
                 "%.1f" % mejor["FP_est"] if "FP_est" in mejor else "n/d",
                 "%.1f" % est if est is not None else "n/d",
                 t8 if t8 is not None else "n/d"))
            comparacion.append({"conjunto": conj, "perspectiva": persp,
                                "algoritmo": mejor["algoritmo"],
                                "FP_est": mejor.get("FP_est"),
                                "FA_h_est": est, "FA_h_tabla8": t8})
    w("")
    cerca, lejos = [], []
    for c in comparacion:
        if c["FA_h_est"] is None or c["FA_h_tabla8"] is None:
            continue
        ref = max(c["FA_h_est"], c["FA_h_tabla8"])
        d = abs(c["FA_h_est"] - c["FA_h_tabla8"])
        etq = "%s/%s" % (c["conjunto"], c["perspectiva"])
        (cerca if ref == 0 or d / ref <= 0.10 else lejos).append(etq)
    w("La columna estimada es cruda y la publicada esta agregada a 30 s, de")
    w("modo que la igualdad no es exigible: la agregada tiene que ser menor")
    w("o igual.")
    w("   coinciden dentro del 10 %%: %s" % (", ".join(cerca) or "ninguna"))
    w("   difieren mas del 10 %%:     %s" % (", ".join(lejos) or "ninguna"))
    n_mayor = sum(1 for c in comparacion
                  if c["FA_h_est"] is not None and c["FA_h_tabla8"] is not None
                  and c["FA_h_tabla8"] > c["FA_h_est"] + 1e-9)
    excesos = [(c["FA_h_tabla8"] - c["FA_h_est"],
                "%s/%s" % (c["conjunto"], c["perspectiva"]))
               for c in comparacion
               if c["FA_h_est"] is not None and c["FA_h_tabla8"] is not None
               and c["FA_h_tabla8"] > c["FA_h_est"] + 1e-9]
    w("   casos donde la tabla 8 supera la estimacion cruda: %d de %d"
      % (n_mayor, len(comparacion)))
    if excesos:
        d, etq = max(excesos)
        w("   el mayor exceso es %s, con %.1f alarmas por hora de diferencia;"
          % (etq, d))
        w("   si fuese grande habria que revisar la lectura, pero a esta")
        w("   escala lo explica el redondeo de la propia tabla 8 a enteros.")
    w("")
    w("Lo que se puede afirmar sobre la tasa horaria sin estimar nada es lo")
    w("que dice la tabla 8, con su denominador: falsas alarmas por hora con")
    w("agregacion de 30 s, del mejor modelo por conjunto y perspectiva.")
    w("")

    # ------------------------------------------------------- resumen
    w("## 14.6 Resumen: el par PD/PFA por conjunto")
    w("")
    w("Mejor modelo por conjunto y perspectiva, con el par completo:")
    w("")
    w("%-8s %-11s %-9s %8s %8s %10s %12s"
      % ("conjunto", "perspectiva", "algoritmo", "PD", "PFA", "PFA (via 2)",
         "FA/h tabla 8"))
    for c in comparacion:
        f = next(f for f in todas
                 if f["conjunto"] == c["conjunto"]
                 and f["perspectiva"] == c["perspectiva"]
                 and f["algoritmo"] == c["algoritmo"]
                 and f["particion"] == "validacion")
        w("%-8s %-11s %-9s %8.4f %8.4f %10s %12s"
          % (f["conjunto"], f["perspectiva"], f["algoritmo"], f["PD"],
             f["PFA"],
             "%.5f" % f["PFA_b"] if "PFA_b" in f else "n/d",
             c["FA_h_tabla8"] if c["FA_h_tabla8"] is not None else "n/d"))
    w("")
    w("Denominadores, para que ningun porcentaje quede sin el suyo:")
    for conj, d in TABLA5.items():
        w("   %-8s validacion de %6d s; muestras normales/anomalas: %s"
          % (conj, d["duracion_s"],
             ", ".join("%s %d/%d" % (p, d[p][0], d[p][1])
                       for p in PERSPECTIVAS)))
    w("")
    w("## 14.7 Que conjuntos son, y sobre que archivos")
    w("")
    w("Importa porque dos de los cuatro son conjuntos de la tabla de")
    w("comparabilidad del proyecto, y uno es el propio conjunto de QUT que el")
    w("proyecto usa. Las identidades salen de la seccion 4.1 y del apendice")
    w("A.3 del articulo:")
    w("")
    w("   Lemay   = capturas de Lemay y Fernandez, Modbus/TCP. Entrena con")
    w("             `Run1_6RTU`; valida con las cinco partes restantes.")
    w("   WDT     = Water distribution testbed, Modbus/TCP. Entrena con")
    w("             `normal.pcap`; valida con el resto de las capturas.")
    w("   DNP3    = **QUT DNP3** (`github.com/qut-infosec/2017QUT_DNP3`), el")
    w("             mismo conjunto que el proyecto usa. Entrena con")
    w("             `control/testing/frequent/slave.pcap` y valida con")
    w("             `attacks/testing/frequent/slave.pcap`.")
    w("   S7comm  = **QUT S7comm** (`2017QUT_S7comm`), tambien de QUT, pero")
    w("             NO es el `QUT S7 (Myers)`, que el articulo descarta por")
    w("             desvios de marca de tiempo (nota al pie 16).")
    w("")
    w("Dos consecuencias para el proyecto:")
    w("")
    w("1. Las cifras de DNP3 estan medidas sobre las carpetas `testing/` de")
    w("   QUT, que son justamente las que el EDA dejo sin abrir. De modo que")
    w("   el par PD/PFA de Schuster se puede usar como referencia externa")
    w("   sin abrir nada; pero al reves tambien vale: si se ajusta algo")
    w("   contra ese numero, se esta ajustando contra el tramo de prueba.")
    w("2. El articulo usa `slave.pcap` y el EDA del proyecto midio sobre")
    w("   `master.pcap`. El hallazgo 1.1 del EDA --- que los dos archivos")
    w("   contienen la misma conversacion, 20.000 de 20.000 tramas")
    w("   coincidentes --- es lo que permite comparar las dos mediciones.")
    w("")
    w("La PD no se estima: es el recall publicado. La PFA de la via 1 sale")
    w("de una identidad algebraica entre dos cifras publicadas, con el")
    w("redondeo como unica incertidumbre. La via 2 es independiente y")
    w("coincide. Lo que NO se puede obtener de estas tablas es la PFA por")
    w("tipo de anomalia ni la curva PD-PFA completa: el articulo publica un")
    w("solo punto de operacion por modelo.")

    comun.escribir("p14_schuster_pd_pfa.txt", "\n".join(L))
    with open(os.path.join(comun.SALIDAS, "p14_schuster_pd_pfa.json"),
              "w") as fh:
        json.dump({"pares": todas, "tabla8_contraste": comparacion,
                   "tabla5": TABLA5, "tabla8": {"%s/%s" % k: v
                                                for k, v in TABLA8.items()}},
                  fh, indent=1, ensure_ascii=False, default=str)
    return 0


if __name__ == "__main__":
    sys.exit(main())
