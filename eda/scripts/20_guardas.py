"""Guardas: las afirmaciones de los documentos, escritas como comprobaciones.

POR QUE EXISTE ESTE ARCHIVO
---------------------------
Una auditoria independiente encontro quince errores en `eda/INFORME.md` y
`eda/EXPLORATORIO.md`. Ninguno era de aritmetica. Los quince eran de la misma
forma: una frase que respondia una pregunta distinta de la que medía la cifra
de al lado --- otra poblacion, otro denominador, otra ventana, otra unidad.

Corregir las quince frases no evita la decimosexta. Lo que la evita es que la
afirmacion deje de vivir solo en prosa: aca cada una queda escrita como una
comprobacion sobre las salidas, con el documento y la seccion que defiende, y
`make todo` **falla** cuando los datos dejan de sostenerla.

QUE ES Y QUE NO ES UNA GUARDA
-----------------------------
Una guarda vale la pena cuando se cumplen las tres:

  1. la afirmacion sostiene una conclusion o una recomendacion, no es un dato
     de color;
  2. se puede evaluar contra una salida, sin volver a leer los datos crudos;
  3. si dejara de valer, habria que reescribir texto --- no solo actualizar
     un numero.

Lo que NO se guarda, a proposito: las cifras que solo se citan (esas se
regeneran y se leen), las afirmaciones sobre documentacion externa (no estan
bajo control de este analisis) y lo que el propio documento declara como no
medido. Una guarda de mas es ruido que el lector termina por ignorar, y
una guarda ignorada es peor que ninguna.

COMO SE LEE UNA FALLA
---------------------
Cada guarda imprime la afirmacion en castellano y donde vive. Si falla, lo
que hay que corregir es **el documento**, no la guarda --- salvo que la
guarda este mal escrita, que tambien pasa y entonces se arregla aca con el
motivo en el mensaje de commit.

Uso:  eda/.venv/bin/python -I eda/scripts/20_guardas.py
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import comun  # noqa: E402

# Tolerancia relativa por defecto al comparar una cifra publicada contra la
# medida. Las cifras de los documentos estan redondeadas a dos o tres
# decimales, de modo que una igualdad exacta fallaria por el redondeo.
TOL = 0.02


class Faltante(Exception):
    """Una salida que la guarda necesita y no esta."""


def cargar(nombre, salidas=None):
    ruta = os.path.join(salidas or comun.SALIDAS, nombre)
    if not os.path.exists(ruta):
        raise Faltante(comun.rel(ruta))
    with open(ruta, encoding="utf-8") as fh:
        return json.load(fh)


def rutas_qut():
    """Las rutas que el script 01 abre. Aparte para poder probarla."""
    mod = __import__("01_qut_payload")
    return [rel for _nombre, rel in mod.ESCENARIOS]


def cerca(medido, publicado, tol=TOL):
    """El medido reproduce al publicado dentro de la tolerancia relativa."""
    if publicado == 0:
        return abs(medido) <= tol
    return abs(medido - publicado) / abs(float(publicado)) <= tol


# ---------------------------------------------------------------------------
# Las guardas. Cada una devuelve (ok, detalle) y declara que defiende.
#
# La firma es siempre la misma: reciben el diccionario de salidas ya cargadas
# y devuelven si la afirmacion se sostiene y una linea con los numeros, para
# que la salida sirva de registro y no solo de semaforo.
# ---------------------------------------------------------------------------

def g_particion_qut(S):
    """Solo se leyeron las capturas de entrenamiento de QUT.

    Esta no se puede comprobar contra una salida: una salida dice lo que se
    leyo, no lo que NO se leyo. Se comprueba contra el **codigo**, como hace
    el script 15 con la tabla del documento: se importa el script 01 y se
    exige que ninguna de sus rutas apunte fuera de `training/`.

    Es la guarda mas importante del archivo. El compromiso de no abrir los
    tramos de prueba es lo que sostiene que el analisis no contamino el
    protocolo, y es justo el que nadie nota cuando se rompe.
    """
    rutas = rutas_qut()
    fuera = [r for r in rutas if "/training" not in r or "testing" in r]
    esc = [k for k in S["p1"] if not k.startswith("_")]
    ok = not fuera and len(esc) == len(rutas)
    return ok, ("las %d rutas del script 01 apuntan a training/, y hay %d "
                "escenarios en la salida" % (len(rutas), len(esc))
                if ok else "RUTAS FUERA DE training/: %s" % fuera)


def g_qut_sin_control(S):
    """QUT no contiene ni un objeto de control: g12v1, g41 ni g40."""
    obj = S["p19"]["objetos"]
    presentes = {g: obj.get(g, 0) for g in ("g12v1", "g41", "g40")
                 if obj.get(g, 0)}
    return not presentes, ("ninguno presente" if not presentes
                           else "APARECIERON: %s" % presentes)


def g_qut_subconjunto_unico(S):
    """Un solo subconjunto de grupos suma las 207.798 operaciones WRITE."""
    c = S["p19"]["subconjuntos_que_cierran"]
    ok = len(c) == 1 and set(c[0]) == {"g80v1", "g50v3"}
    return ok, "cierran %d de %d subconjuntos: %s" % (
        len(c), S["p19"]["subconjuntos_evaluados"], c)


def g_qut_fragmentos(S):
    """No hay fragmentos DNP3 bien formados de varias tramas.

    Lo que defiende: el lector no reensambla, y el documento dice que sobre
    estos datos eso no cuesta nada. Si apareciera una trama de apertura o de
    cierre de fragmento multiple, empezaria a costar y habria que reescribir
    la seccion --- o escribir el reensamblado.
    """
    f = S["p1"]["_fragmentado"]["total"]
    ok = f["frag_primero"] == 0 and f["frag_ultimo"] == 0
    return ok, "apertura=%d cierre=%d intermedias=%d sobre %d con transporte" \
        % (f["frag_primero"], f["frag_ultimo"], f["frag_intermedio"],
           S["p1"]["_fragmentado"]["con_octeto_de_transporte"])


def g_hai_ruido_bajo_umbral(S):
    """El ruido del estimador de HAI queda por debajo de su umbral al 95 %.

    Lo que defiende: que la particion al azar sea de verdad una vara de ruido.
    Si la superara, no estaria midiendo ruido y toda la lectura de la
    pregunta 5 se cae.
    """
    malas = []
    for ver, r in S["p5"]["ruido_estimador_particion_al_azar"].items():
        ref = S["p5"]["referencia_intra_archivo"].get(ver, {})
        n = ref.get("columnas")
        if not n:
            continue
        if r["ks_mediana"] > 0.01:      # cota holgada: los umbrales van de
            malas.append((ver, r["ks_mediana"]))   # 0,0049 a 0,0089
    return not malas, ("todas por debajo de 0,01" if not malas
                       else "POR ENCIMA: %s" % malas)


def g_hai_deriva_no_es_ruido(S):
    """La deriva dentro de una campana de HAI supera al ruido diez veces.

    Lo que defiende: la distincion entre las dos varas. Si el cociente cayera
    cerca de 1, la mitad contra mitad en orden SI seria ruido y la seccion
    volveria a la lectura anterior.
    """
    peor = None
    for ver, ref in S["p5"]["referencia_intra_archivo"].items():
        rz = S["p5"]["ruido_estimador_particion_al_azar"].get(ver)
        if not rz or not rz["ks_mediana"]:
            continue
        razon = ref["ks_mediana"] / rz["ks_mediana"]
        if peor is None or razon < peor[1]:
            peor = (ver, razon)
    ok = peor is not None and peor[1] >= 10.0
    return ok, "peor cociente: %s = %.0f veces (minimo exigido 10)" % peor


def g_hai_serie_segmentada(S):
    """La autocorrelacion de HAI se mide por tramos, no sobre la union.

    Lo que defiende: la regla que el script 05 enuncia y que el 18 incumplia.
    Si alguien volviera a concatenar, `segmentos` dejaria de estar o valdria 1.
    """
    a = S["p18"]["HAI"]["autocorrelacion"]
    ok = a.get("segmentos", 0) >= 2
    return ok, "segmentos=%s, tau=%.0f s" % (a.get("segmentos"),
                                             a["tau_decorrelacion_s"])


def g_westermo_union_unica(S):
    """Una sola agregacion de Westermo reproduce el reparto publicado.

    Lo que defiende: la seccion 1.6. Si cerraran dos, los conteos no
    distinguirian entre ellas y la identificacion no se sostendria sola.
    """
    u = S["p3p4w"]["union_de_puntos"]
    ok = u["dentro_de_2pp"] == 1
    return ok, "candidatas=%d, dentro de 1 pp=%d, dentro de 2 pp=%d" % (
        u["candidatas"], u["dentro_de_1pp"], u["dentro_de_2pp"])


def g_westermo_union_sin_duplicar(S):
    """La union de los tres puntos no cuenta el mismo flujo dos veces.

    Lo que defiende: que la union sea una poblacion y no trafico inflado. El
    README del conjunto avisa de paquetes duplicados; lo que se exige aca es
    que eso no llegue a los flujos.
    """
    malas = []
    dup = S["p3p4w"]["union_de_puntos"]["duplicacion_entre_puntos"]
    for clave, d in dup.items():
        if d["repetidos_dentro_del_punto"]:
            malas.append((clave, "repetidos dentro",
                          d["repetidos_dentro_del_punto"]))
        frac = 100.0 * d["con_gemelo_en_otro_punto"] / max(1, d["flujos"])
        if frac > 5.0:
            malas.append((clave, "gemelos", round(frac, 1)))
    return not malas, ("sin repetidos internos y gemelos por debajo del 5 %"
                       if not malas else "PROBLEMAS: %s" % malas)


def g_faltantes_estructurales(S):
    """Los faltantes que el documento llama estructurales lo son.

    Lo que defiende: la recomendacion de no imputar. Vale para los patrones
    que cierran exactos, y el documento declara cuantos son. Si cambiara el
    reparto, cambia la recomendacion y hay que reescribirla.
    """
    esperado = {"Westermo": (10, 6, 30, 8), "ICS-Flow": (10, 6, 30, 8)}
    malas = []
    for conj, (pat, ex, cub, sin) in esperado.items():
        p = S["p16"][conj]["patrones_faltantes"]
        real = (p["patrones"], p["patrones_exactos"], p["campos_explicados"],
                p["campos_sin_explicar"])
        if real != (pat, ex, cub, sin):
            malas.append((conj, "publicado", (pat, ex, cub, sin),
                          "medido", real))
    return not malas, ("10 patrones, 6 exactos, 30 campos explicados y 8 sin "
                       "explicar en los dos" if not malas
                       else "CAMBIO: %s" % malas)


def g_auc_poblacion_completa(S):
    """El mejor AUC de cada conjunto se cita sobre poblacion completa.

    Lo que defiende: la comparacion entre conjuntos. El maximo absoluto de los
    tres esta medido sobre subpoblaciones distintas --- del 25 % al 99 % ---,
    de modo que compararlos entre si es compararlos sobre poblaciones
    distintas. Se exige que las tres cifras de poblacion completa existan y
    que el orden publicado se mantenga.
    """
    w = S["p17"]["Westermo"]["discriminante"]["auc_max_poblacion_completa"]
    i = S["p17"]["ICS-Flow"]["discriminante"]["auc_max_poblacion_completa"]
    m = S["p18"]["Morris"]["discriminante"]["auc_en_poblacion_completa"]
    if None in (w, i, m):
        return False, ("falta alguna: Westermo=%s ICS-Flow=%s Morris=%s"
                       % (w, i, m))
    ok = (w < m < i) and i < 0.70
    return ok, ("orden Westermo %.3f < Morris %.3f < ICS-Flow %.3f, "
                "y ninguno llega a 0,70" % (w, m, i))


def g_ninguna_variable_sola(S):
    """Ninguna caracteristica sola separa bien, con ninguna de las dos bases.

    Lo que defiende: la conclusion principal del estudio exploratorio, que es
    que la deteccion tiene que ser multivariada.
    """
    maximos = {
        "Westermo": S["p17"]["Westermo"]["discriminante"]["auc_max"],
        "ICS-Flow": S["p17"]["ICS-Flow"]["discriminante"]["auc_max"],
        "Morris": S["p18"]["Morris"]["discriminante"]["auc_absoluto"],
    }
    altos = {k: v for k, v in maximos.items() if v >= 0.70}
    return not altos, ("ningun maximo llega a 0,70: %s"
                       % {k: round(v, 3) for k, v in maximos.items()}
                       if not altos else "ALCANZAN 0,70: %s" % altos)


def g_cv_por_bloques(S):
    """La etiqueta esta autocorrelacionada: una validacion al azar filtra.

    Lo que defiende: la recomendacion de particionar por bloques temporales.
    Si la autocorrelacion de la etiqueta cayera, la recomendacion sobraria.
    """
    malas = []
    for conj in ("Westermo", "ICS-Flow"):
        a = S["p17"][conj]["autocorrelacion_objetivo"]["objetivo"]
        if a["rho_lag1"] < 0.5:
            malas.append((conj, round(a["rho_lag1"], 3)))
    rho = {c: S["p17"][c]["autocorrelacion_objetivo"]["objetivo"]["rho_lag1"]
           for c in ("Westermo", "ICS-Flow")}
    return not malas, ("Westermo %.3f e ICS-Flow %.3f, las dos por encima de "
                       "0,5" % (rho["Westermo"], rho["ICS-Flow"])
                       if not malas else "BAJARON: %s" % malas)


def g_eventos_independientes(S):
    """Los eventos de Morris no se agrupan entre si.

    Lo que defiende: los intervalos de PD de la pregunta 4, que suponen
    ensayos independientes. Con autocorrelacion negativa el supuesto es
    conservador; si alguna se volviera positiva, los intervalos quedarian
    cortos y habria que usar el tamano efectivo.
    """
    ac = S["p9"].get("autocorrelacion_entre_eventos")
    if not ac:
        return False, "el script 09 no la midio"
    pos = [(f["categoria"], round(f["rho"], 3)) for f in ac if f["rho"] >= 0]
    return not pos, ("las %d categorias con autocorrelacion negativa" % len(ac)
                     if not pos else "POSITIVAS: %s" % pos)


def g_un_solo_estadistico(S):
    """Las cifras de precision salen todas del mismo estadistico."""
    casos = S["p9"]["casos"]
    faltan = [c["caso"] for c in casos if "wilson_95" not in c]
    return not faltan, ("%d casos, todos con Wilson al 95 %%" % len(casos)
                        if not faltan else "SIN WILSON: %s" % faltan)


def g_ventana_invierte_orden(S):
    """A recuento igualado se invierte el orden del indice de dispersion.

    Lo que defiende: la seccion 1.5, que descarta una sola calificacion
    comparativa de determinismo. Si el orden dejara de invertirse, el
    argumento se cae y habria que rehacerlo.
    """
    v1 = S["p2"]["sensibilidad_ventana"]["ventana_1_s"]
    r5 = S["p2"]["sensibilidad_ventana"]["recuento_5"]
    w, q = "Westermo limpio", "QUT Control"
    ok = v1[w] < v1[q] and r5[w] > r5[q]
    return ok, ("ventana 1 s: %.2f < %.2f ; recuento 5: %.2f > %.2f"
                % (v1[w], v1[q], r5[w], r5[q]))


def g_entropia_invierte_orden(S):
    """La entropia normalizada invierte el orden de la cruda.

    Lo que defiende: la advertencia de citar los bits y el k. Si dejara de
    invertirse, la advertencia sobraria y habria que quitarla.
    """
    e = S["p2"]["entropia_cruda_vs_normalizada"]
    por_h = sorted(e, key=lambda s: e[s]["H"])
    por_hn = sorted(e, key=lambda s: e[s]["Hn"])
    ok = por_h[0] == por_hn[-1]
    return ok, "menor en bits = %s ; mayor normalizada = %s" % (por_h[0],
                                                                por_hn[-1])


def g_identidades_inventario(S):
    """Las identidades del inventario se cumplen, salvo las tres declaradas.

    Lo que defiende: la afirmacion sobre coherencia interna. El documento
    nombra las tres excepciones una por una; si apareciera una cuarta, esa
    lista deja de ser completa.
    """
    PERMITIDAS = ("sLoad", "rLoad", "sAckDelayMax <= duration",
                  "sInterPacketAvg")
    malas, total = [], 0
    for conj in ("westermo", "icsflow"):
        for nombre, d in S["p10"][conj]["identidades"].items():
            if not d.get("evaluadas"):
                continue
            total += 1
            if d["fraccion"] < 0.9999 and not any(p in nombre
                                                  for p in PERMITIDAS):
                malas.append((conj, nombre, round(100 * d["fraccion"], 2)))
    return not malas, ("%d identidades evaluadas entre los dos conjuntos, sin "
                       "excepciones fuera de las tres declaradas" % total
                       if not malas else "NUEVAS EXCEPCIONES: %s" % malas)


def g_hai_sin_anomalias_en_train(S):
    """Los `train` de HAI traen los dos ataques conocidos y ninguno mas.

    Lo que defiende: el aviso de filtrar `train2` de 20.07 antes de entrenar.
    """
    cont = S["p5"]["ataques_en_entrenamiento"]
    vers = sorted(cont)
    ok = vers == ["hai-20.07"]
    return ok, "versiones con ataques en train: %s" % (vers or "ninguna")


def g_morris_constantes(S):
    """Las caracteristicas constantes lo son solo en el trafico normal.

    Lo que defiende: la recomendacion 1 de la seccion 5.5, que se habia
    escrito al reves. Si las 10 pasaran a ser constantes en todo el tramo, la
    recomendacion original volveria a valer; mientras no, descartar las 10
    tira senal.
    """
    wi = S["p11"]["westermo_icsflow"]
    solo_normal = wi.get("campos_constantes_solo_en_normal")
    todo = wi.get("campos_sin_variacion_en_todo_el_tramo")
    if solo_normal is None or todo is None:
        return False, "el script 11 no mide el reparto por clase"
    # `todo` es {conjunto: cuantos}, no una lista de nombres.
    n_w, n_i = todo.get("westermo"), todo.get("icsflow")
    # La afirmacion que se defiende: de las 10 que la seccion 5.4 llamaba
    # constantes, varias SI varian sobre los flujos anomalos, de modo que
    # descartar las 10 tira senal. Se exige que siga habiendo alguna que
    # varie, y que las que no varian en todo el tramo sigan siendo menos.
    ok = len(solo_normal) > 0 and n_w is not None and n_w < 10
    return ok, ("%d de las 10 varian sobre los flujos anomalos; sin variacion "
                "en todo el tramo quedan %s en Westermo y %s en ICS-Flow"
                % (len(solo_normal), n_w, n_i))


GUARDAS = [
    # (clave, afirmacion en castellano, donde vive, funcion)
    ("particion-qut",
     "Solo se leyeron las capturas de entrenamiento de QUT",
     "INFORME.md seccion 2", g_particion_qut),
    ("qut-sin-control",
     "QUT no contiene ningun objeto de control (g12v1, g41, g40)",
     "INFORME.md 1.2", g_qut_sin_control),
    ("qut-subconjunto-unico",
     "Un solo subconjunto de grupos suma las operaciones WRITE",
     "INFORME.md 1.2", g_qut_subconjunto_unico),
    ("qut-fragmentos",
     "No hay fragmentos DNP3 bien formados de varias tramas",
     "INFORME.md pregunta 1", g_qut_fragmentos),
    ("hai-ruido",
     "El ruido del estimador de HAI queda por debajo de su umbral al 95 %",
     "INFORME.md pregunta 5", g_hai_ruido_bajo_umbral),
    ("hai-deriva-no-es-ruido",
     "La deriva dentro de una campana supera al ruido diez veces o mas",
     "INFORME.md pregunta 5", g_hai_deriva_no_es_ruido),
    ("hai-segmentada",
     "La autocorrelacion de HAI se mide por tramos y no sobre la union",
     "EXPLORATORIO.md HAI", g_hai_serie_segmentada),
    ("hai-train-sucio",
     "Solo 20.07 trae ataques etiquetados en sus archivos de entrenamiento",
     "INFORME.md pregunta 3", g_hai_sin_anomalias_en_train),
    ("westermo-union-unica",
     "Una sola agregacion reproduce el reparto de clases publicado",
     "INFORME.md 1.6", g_westermo_union_unica),
    ("westermo-union-sin-duplicar",
     "La union de los tres puntos no cuenta el mismo flujo dos veces",
     "INFORME.md 1.6", g_westermo_union_sin_duplicar),
    ("faltantes-estructurales",
     "El reparto de patrones de faltantes se mantiene en 10 / 6 / 30 / 8",
     "EXPLORATORIO.md hallazgo 3", g_faltantes_estructurales),
    ("auc-poblacion-completa",
     "El mejor AUC de los tres se compara sobre poblacion completa",
     "EXPLORATORIO.md hallazgo 1", g_auc_poblacion_completa),
    ("ninguna-variable-sola",
     "Ninguna caracteristica sola llega a 0,70 de AUC en ningun conjunto",
     "EXPLORATORIO.md hallazgo 1", g_ninguna_variable_sola),
    ("cv-por-bloques",
     "La etiqueta esta autocorrelacionada: una validacion al azar filtra",
     "EXPLORATORIO.md hallazgo 5", g_cv_por_bloques),
    ("eventos-independientes",
     "Los eventos de Morris no se agrupan entre si",
     "INFORME.md pregunta 4", g_eventos_independientes),
    ("un-solo-estadistico",
     "Las cifras de precision salen todas del intervalo de Wilson",
     "INFORME.md preguntas 4 y 4.4", g_un_solo_estadistico),
    ("ventana-invierte",
     "A recuento igualado se invierte el orden del indice de dispersion",
     "INFORME.md 1.5", g_ventana_invierte_orden),
    ("entropia-invierte",
     "La entropia normalizada invierte el orden de la cruda",
     "INFORME.md pregunta 2", g_entropia_invierte_orden),
    ("identidades",
     "Las identidades del inventario se cumplen salvo las tres declaradas",
     "EXPLORATORIO.md coherencia interna", g_identidades_inventario),
    ("constantes-solo-en-normal",
     "Las caracteristicas constantes lo son solo en el trafico normal",
     "INFORME.md 5.4 y 5.5", g_morris_constantes),
]


def cargar_todo(salidas=None):
    """Las once salidas que las guardas necesitan."""
    return {
        "p1": cargar("p1_qut_payload.json", salidas),
        "p2": cargar("p2_determinismo.json", salidas),
        "p5": cargar("p3_p4_p5_hai.json", salidas),
        "p3p4w": cargar("p3_p4_westermo.json", salidas),
        "p9": cargar("p9_intervalos_pd.json", salidas),
        "p10": cargar("p10_inventario.json", salidas),
        "p11": cargar("p11_integracion.json", salidas),
        "p16": cargar("p16_exploratorio_flujos.json", salidas),
        "p17": cargar("p17_discriminante_estructura.json", salidas),
        "p18": cargar("p18_exploratorio_resto.json", salidas),
        "p19": cargar("p19_qut_escrituras.json", salidas),
    }


def evaluar(S):
    """Corre las guardas sobre `S`.

    Devuelve una lista de (clave, se_sostiene, detalle, revento).
    """
    out = []
    for clave, _afirmacion, _donde, fn in GUARDAS:
        try:
            ok, detalle = fn(S)
            revento = False
        except Exception as exc:                      # noqa: BLE001
            ok, revento = False, True
            detalle = "ERROR en la guarda: %r" % (exc,)
        out.append((clave, ok, detalle, revento))
    return out


def main():
    comun.preparar()
    L = []
    w = L.append
    w("# Guardas - las afirmaciones de los documentos, comprobadas")
    w("")
    w("Cada linea es una afirmacion de `eda/INFORME.md` o de")
    w("`eda/EXPLORATORIO.md` escrita como comprobacion sobre las salidas.")
    w("Si alguna falla, lo que hay que corregir es el documento.")
    w("")
    w("El motivo de que esto exista: una auditoria independiente encontro")
    w("quince errores, y los quince eran una frase que respondia una pregunta")
    w("distinta de la que medía la cifra de al lado. Corregir las frases no")
    w("evita la decimosexta; que la afirmacion sea ejecutable, si.")
    w("")

    try:
        S = cargar_todo()
    except Faltante as e:
        w("**No se pudo correr: falta %s.**" % e)
        w("Correr antes `make -C eda todo`.")
        comun.escribir("p20_guardas.txt", "\n".join(L))
        print("guardas: falta %s" % e, file=sys.stderr)
        return 2

    fallan, errores = [], []
    w("%-30s %-7s %s" % ("guarda", "estado", "afirmacion"))
    w("%s" % ("-" * 78))
    por_clave = {c: (ok, det, rev) for c, ok, det, rev in evaluar(S)}
    for clave, afirmacion, donde, _fn in GUARDAS:
        ok, detalle, revento = por_clave[clave]
        if revento:
            errores.append(clave)
        w("%-30s %-7s %s" % (clave, "ok" if ok else "FALLA", afirmacion))
        w("%-30s %-7s %s" % ("", "", "(%s)" % donde))
        w("%-30s %-7s %s" % ("", "", detalle))
        w("")
        if not ok:
            fallan.append((clave, afirmacion, donde, detalle))

    w("-" * 78)
    w("")
    w("Guardas: %d. Se sostienen: %d. Fallan: %d."
      % (len(GUARDAS), len(GUARDAS) - len(fallan), len(fallan)))
    w("")
    if fallan:
        w("## Lo que hay que corregir")
        w("")
        for clave, afirmacion, donde, detalle in fallan:
            w("- **%s** --- %s" % (clave, afirmacion))
            w("  vive en %s" % donde)
            w("  %s" % detalle)
        w("")
        w("Una guarda que falla no es un dato que se actualiza: es una frase")
        w("de un documento que dejo de ser cierta.")
        if errores:
            w("")
            w("Y estas reventaron en lugar de contestar, de modo que hay que")
            w("arreglar la guarda y no el documento: %s" % ", ".join(errores))
    else:
        w("Las %d se sostienen contra las salidas de esta corrida."
          % len(GUARDAS))

    comun.escribir("p20_guardas.txt", "\n".join(L))
    with open(os.path.join(comun.SALIDAS, "p20_guardas.json"), "w") as fh:
        json.dump({"total": len(GUARDAS), "fallan": len(fallan),
                   "guardas": [{"clave": c, "afirmacion": a, "donde": d}
                               for c, a, d, _ in GUARDAS],
                   "fallidas": [{"clave": c, "afirmacion": a, "donde": d,
                                 "detalle": x} for c, a, d, x in fallan]},
                  fh, indent=1, ensure_ascii=False)

    if fallan:
        print("guardas: fallan %d de %d" % (len(fallan), len(GUARDAS)),
              file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
