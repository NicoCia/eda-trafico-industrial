"""Comprueba que las guardas del script 20 pueden fallar.

UNA GUARDA QUE NO PUEDE FALLAR NO ES UNA GUARDA
-----------------------------------------------
Que las veinte den «ok» no dice nada por si solo: una guarda mal escrita ---
que lea una clave que no existe, que compare contra si misma, que tenga la
condicion invertida --- tambien da «ok», y da «ok» para siempre. El error es
facil de cometer y dificil de ver, porque el sintoma es que todo anda bien.

Este script rompe una cosa por vez y exige que la guarda que corresponde
**falle**, y que no arrastre a las demas. Es la prueba de que el semaforo
esta conectado.

NO TOCA LAS SALIDAS REALES
--------------------------
Trabaja sobre una copia de `eda/salidas/` en un directorio temporal que borra
al terminar. El script 20 acepta un directorio alternativo justamente para
esto. La unica guarda que no lee un JSON --- `particion-qut`, que mira el
codigo del script 01 --- se prueba sustituyendo la funcion que devuelve las
rutas, sin tocar el archivo.

Uso:  eda/.venv/bin/python -I eda/scripts/21_guardas_muerden.py
"""

import copy
import json
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import comun  # noqa: E402

guardas = __import__("20_guardas")


# ---------------------------------------------------------------------------
# Cada caso rompe una cosa sobre la copia y nombra la guarda que tiene que
# saltar. Si alguna vez una rotura deja de hacer saltar a su guarda, es que
# la guarda dejo de mirar lo que decia mirar.
# ---------------------------------------------------------------------------

def _primera_clave(d):
    return list(d)[0]


CASOS = [
    ("qut-sin-control", "aparece un objeto de control g12v1 en QUT",
     lambda S: S["p19"]["objetos"].update({"g12v1": 3})),

    ("qut-subconjunto-unico", "cierra un segundo subconjunto de grupos",
     lambda S: S["p19"]["subconjuntos_que_cierran"].append(["g60v2"])),

    ("qut-fragmentos", "aparece una trama de apertura de fragmento multiple",
     lambda S: S["p1"]["_fragmentado"]["total"].update({"frag_primero": 4})),

    ("hai-ruido", "el ruido del estimador sube por encima del umbral",
     lambda S: S["p5"]["ruido_estimador_particion_al_azar"]["hai-20.07"]
     .update({"ks_mediana": 0.08})),

    ("hai-deriva-no-es-ruido",
     "la deriva interna deja de superar al ruido diez veces",
     lambda S: S["p5"]["referencia_intra_archivo"]["hai-20.07"]
     .update({"ks_mediana": 0.004})),

    ("hai-segmentada", "la autocorrelacion vuelve a medirse sobre la union",
     lambda S: S["p18"]["HAI"]["autocorrelacion"].update({"segmentos": 1})),

    ("hai-train-sucio", "otra version trae ataques en entrenamiento",
     lambda S: S["p5"]["ataques_en_entrenamiento"].update({"hai-22.04": []})),

    ("westermo-union-unica", "dos agregaciones caen dentro de 2 pp",
     lambda S: S["p3p4w"]["union_de_puntos"].update({"dentro_de_2pp": 2})),

    ("westermo-union-sin-duplicar", "aparecen flujos repetidos en un punto",
     lambda S: S["p3p4w"]["union_de_puntos"]["duplicacion_entre_puntos"][
         _primera_clave(S["p3p4w"]["union_de_puntos"]
                        ["duplicacion_entre_puntos"])]
     .update({"repetidos_dentro_del_punto": 17})),

    ("faltantes-estructurales", "cambia el reparto de patrones de faltantes",
     lambda S: S["p16"]["Westermo"]["patrones_faltantes"]
     .update({"campos_explicados": 26, "campos_sin_explicar": 12})),

    ("auc-poblacion-completa", "se invierte el orden entre conjuntos",
     lambda S: S["p17"]["Westermo"]["discriminante"]
     .update({"auc_max_poblacion_completa": 0.81})),

    ("ninguna-variable-sola", "una caracteristica sola llega a 0,72",
     lambda S: S["p17"]["Westermo"]["discriminante"].update({"auc_max": 0.72})),

    ("cv-por-bloques", "la etiqueta deja de estar autocorrelacionada",
     lambda S: S["p17"]["Westermo"]["autocorrelacion_objetivo"]["objetivo"]
     .update({"rho_lag1": 0.11})),

    ("eventos-independientes", "una categoria de Morris se agrupa",
     lambda S: S["p9"]["autocorrelacion_entre_eventos"][0].update({"rho": 0.44})),

    ("un-solo-estadistico", "un caso se publica sin el intervalo de Wilson",
     lambda S: S["p9"]["casos"][0].pop("wilson_95", None)),

    ("ventana-invierte", "deja de invertirse el orden a recuento igualado",
     lambda S: S["p2"]["sensibilidad_ventana"]["recuento_5"]
     .update({"Westermo limpio": 1.4})),

    ("entropia-invierte", "la normalizada deja de invertir el orden",
     lambda S: S["p2"]["entropia_cruda_vs_normalizada"]["QUT solo DNP3"]
     .update({"Hn": 0.11})),

    ("identidades", "una identidad nueva deja de cumplirse",
     lambda S: S["p10"]["westermo"]["identidades"]["duration == end - start"]
     .update({"fraccion": 0.72})),

    ("constantes-solo-en-normal",
     "las diez vuelven a ser constantes en todo el tramo",
     lambda S: S["p11"]["westermo_icsflow"]
     .update({"campos_constantes_solo_en_normal": []})),
]


def main():
    comun.preparar()
    L = []
    w = L.append
    w("# Las guardas muerden?")
    w("")
    w("Que las guardas del script 20 den «ok» no prueba nada por si solo: una")
    w("guarda mal escrita tambien da «ok», y lo da para siempre. Aca se rompe")
    w("una cosa por vez sobre una COPIA de las salidas y se exige que la")
    w("guarda que corresponde falle.")
    w("")

    try:
        base = guardas.cargar_todo()
    except guardas.Faltante as e:
        w("**No se pudo correr: falta %s.** Correr antes `make -C eda todo`." % e)
        comun.escribir("p21_guardas_muerden.txt", "\n".join(L))
        print("guardas-muerden: falta %s" % e, file=sys.stderr)
        return 2

    limpio = {c: ok for c, ok, _d, _r in guardas.evaluar(base)}
    no_ok = [c for c, ok in limpio.items() if not ok]
    if no_ok:
        w("**Las guardas no se sostienen en limpio: %s.**" % ", ".join(no_ok))
        w("Hay que resolver eso antes de probar si muerden.")
        comun.escribir("p21_guardas_muerden.txt", "\n".join(L))
        print("guardas-muerden: no parten de verde", file=sys.stderr)
        return 2
    w("En limpio se sostienen las %d." % len(limpio))
    w("")

    # `particion-qut` no lee un JSON, de modo que no entra en CASOS: se prueba
    # mas abajo sustituyendo la funcion que devuelve las rutas. Cuenta igual
    # como cubierta.
    cubiertas = {c for c, _d, _f in CASOS} | {"particion-qut"}
    todas = {c for c, _a, _d, _f in guardas.GUARDAS}
    sin_probar = sorted(todas - cubiertas)

    w("%-30s %-10s %s" % ("guarda", "resultado", "que se rompe"))
    w("-" * 78)
    malas = []
    for clave, descripcion, romper in CASOS:
        S = copy.deepcopy(base)
        try:
            romper(S)
        except Exception as exc:                      # noqa: BLE001
            malas.append((clave, "la rotura no se pudo aplicar: %r" % (exc,)))
            w("%-30s %-10s %s" % (clave, "ROTO", descripcion))
            continue
        res = {c: (ok, rev) for c, ok, _d, rev in guardas.evaluar(S)}
        salto = not res[clave][0]
        revento = res[clave][1]
        otras = [c for c, (ok, _r) in res.items() if not ok and c != clave]
        if salto and not revento and not otras:
            estado = "ok"
        elif salto and not revento:
            estado = "ok (+%d)" % len(otras)
        elif revento:
            estado = "REVIENTA"
            malas.append((clave, "la guarda lanza excepcion en lugar de fallar"))
        else:
            estado = "NO MUERDE"
            malas.append((clave, "la rotura no la hizo fallar"))
        w("%-30s %-10s %s" % (clave, estado, descripcion))
    w("-" * 78)
    w("")

    # La que no lee un JSON se prueba sustituyendo la funcion, sin tocar el
    # archivo del script 01.
    original = guardas.rutas_qut
    try:
        guardas.rutas_qut = lambda: ["Control/control/testing",
                                     "Attacks/attacks/training"]
        ok, _detalle = guardas.g_particion_qut(base)
    finally:
        guardas.rutas_qut = original
    if ok:
        malas.append(("particion-qut", "no falla con una ruta a testing/"))
        w("particion-qut                  NO MUERDE  una ruta apunta a testing/")
    else:
        w("particion-qut                  ok         una ruta apunta a testing/")
    w("")

    w("Casos probados: %d de %d guardas." % (len(CASOS) + 1, len(todas)))
    if sin_probar:
        w("Sin caso de rotura: %s." % ", ".join(sin_probar))
        w("No es un error, pero cada una sin probar es una que podria estar")
        w("mirando el aire sin que nadie se entere.")
    w("")
    if malas:
        w("## Guardas que no muerden")
        w("")
        for clave, motivo in malas:
            w("- **%s**: %s" % (clave, motivo))
        w("")
        w("Hay que arreglar la guarda en `20_guardas.py`, no el documento.")
    else:
        w("**Todas muerden**, y cada rotura hace saltar a la suya.")

    comun.escribir("p21_guardas_muerden.txt", "\n".join(L))
    with open(os.path.join(comun.SALIDAS, "p21_guardas_muerden.json"),
              "w") as fh:
        json.dump({"guardas": len(todas), "casos": len(CASOS) + 1,
                   "sin_caso": sin_probar,
                   "no_muerden": [{"clave": c, "motivo": m} for c, m in malas]},
                  fh, indent=1, ensure_ascii=False)

    if malas:
        print("guardas-muerden: %d no muerden" % len(malas), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
