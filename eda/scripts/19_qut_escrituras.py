"""Pregunta 19 --- que escriben las operaciones WRITE de QUT?

La seccion 1.2 de INFORME.md afirma que QUT no contiene comandos de control
con parametros. Eso esta medido: g12v1, g41 y g40 no aparecen ni una vez entre
las 2.318.278 cabeceras de objeto. Lo que durante un tiempo estuvo mal dicho
es el paso siguiente --- que escriben entonces las 207.798 operaciones WRITE.

LO QUE NO SE PUEDE MEDIR CON LO QUE HAY
---------------------------------------
`eda/salidas/p1_qut_payload.json` guarda, por cada par rol-captura, dos
contadores independientes: `func_app` (codigos de funcion de aplicacion) y
`objetos` (grupo y variacion de cada cabecera de objeto). **No hay ninguna
clave que los cruce**, de modo que la atribucion mensaje por mensaje --- que
objeto lleva cada WRITE --- no existe en esta salida y no se puede reconstruir
sin volver a leer los PCAP. Este script no la inventa.

LO QUE SI SE PUEDE MEDIR
------------------------
Una pregunta de conteos, que se responde de forma exhaustiva: de los grupos de
objetos que la captura contiene, **cuales subconjuntos tienen conteos que suman
exactamente el numero de operaciones WRITE**. Se enumeran todos los
subconjuntos no vacios y se informa cuantos cierran.

El resultado no es una coincidencia entre dos numeros elegidos de antemano: es
el unico subconjunto del espacio entero que cierra. Es un argumento de conteo y
se sostiene sin apoyarse en el protocolo para nada.

Lo que si necesita al protocolo es que **son** esos objetos, y queda atribuido
como tal: g80v1 es el bit de reinicio de las indicaciones internas y g50v3 es
la hora. Ninguno de los dos es un parametro de proceso.

Este script tambien es una guarda: termina con codigo distinto de cero si el
subconjunto que cierra deja de ser unico, porque entonces el argumento de
conteo ya no alcanza y la frase de INFORME.md habria que rehacerla.

Uso:  python eda/scripts/19_qut_escrituras.py
"""

import itertools
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import comun  # noqa: E402

FUENTE = os.path.join(comun.SALIDAS, "p1_qut_payload.json")

# Por encima de este numero de grupos la enumeracion exhaustiva deja de ser
# barata (2**n). Con los 11 grupos de QUT son 2047 subconjuntos.
MAX_GRUPOS = 20

# Los tres objetos de control: si alguno apareciera, la seccion 1.2 cambia.
CONTROL = ("g12v1", "g41", "g40")


def agregar(datos):
    """Suma `objetos` y `func_app` sobre todos los pares rol-captura."""
    objetos, funciones, pares = {}, {}, 0
    for escenario in datos.values():
        for captura in escenario.values():
            for rol in captura.get("roles", {}).values():
                pares += 1
                for k, v in rol.get("objetos", {}).items():
                    objetos[k] = objetos.get(k, 0) + v
                for k, v in rol.get("func_app", {}).items():
                    funciones[k] = funciones.get(k, 0) + v
    return objetos, funciones, pares


def subconjuntos_que_cierran(objetos, objetivo):
    """Todos los subconjuntos no vacios cuyos conteos suman `objetivo`."""
    nombres = [k for k, _ in sorted(objetos.items(), key=lambda kv: -kv[1])]
    valores = [objetos[k] for k in nombres]
    n = len(nombres)
    cierran, evaluados = [], 0
    for r in range(1, n + 1):
        for comb in itertools.combinations(range(n), r):
            evaluados += 1
            if sum(valores[i] for i in comb) == objetivo:
                cierran.append(tuple(nombres[i] for i in comb))
    return cierran, evaluados


def main():
    comun.preparar()
    L = []
    w = L.append

    if not os.path.exists(FUENTE):
        print("falta %s: correr primero 01_qut_payload.py"
              % comun.rel(FUENTE), file=sys.stderr)
        return 2

    with open(FUENTE, encoding="utf-8") as fh:
        objetos, funciones, pares = agregar(json.load(fh))

    escrituras = funciones.get("WRITE", 0)
    total_obj = sum(objetos.values())

    w("# Pregunta 19 - que escriben las operaciones WRITE de QUT")
    w("")
    w("Fuente: %s, agregando los %d pares rol-captura"
      % (comun.rel(FUENTE), pares))
    w("del tramo de entrenamiento.")
    w("")
    w("## 19.1 Los conteos de partida")
    w("")
    w("%-10s %12d" % ("WRITE", escrituras))
    w("%-10s %12d  (en %d grupos distintos)"
      % ("objetos", total_obj, len(objetos)))
    w("")
    for k, v in sorted(objetos.items(), key=lambda kv: -kv[1]):
        w("   %-8s %12d" % (k, v))
    w("")

    w("## 19.2 Los objetos de control no aparecen")
    w("")
    presentes = [g for g in CONTROL if objetos.get(g, 0) > 0]
    for g in CONTROL:
        w("   %-8s %12d" % (g, objetos.get(g, 0)))
    w("")
    if presentes:
        w("**Aparecio un objeto de control: %s.** La seccion 1.2 de"
          % ", ".join(presentes))
        w("INFORME.md se apoya en que no aparece ninguno, de modo que hay que")
        w("rehacerla.")
        comun.escribir("p19_qut_escrituras.txt", "\n".join(L))
        return 1
    w("Ninguno de los tres. Es lo que sostiene la seccion 1.2: sobre QUT no")
    w("hay parametros de comando que extraer.")
    w("")

    w("## 19.3 Que escriben entonces las %d operaciones WRITE" % escrituras)
    w("")
    w("La atribucion mensaje por mensaje **no esta en esta salida**:")
    w("`func_app` y `objetos` son contadores independientes y nada los cruza.")
    w("Lo que si se puede responder de forma exhaustiva es una pregunta de")
    w("conteos: de los %d grupos presentes, que subconjuntos suman" % len(objetos))
    w("exactamente %d." % escrituras)
    w("")

    if len(objetos) > MAX_GRUPOS:
        w("**No se enumero.** Hay %d grupos y el limite de este script son"
          % len(objetos))
        w("%d, porque la enumeracion es 2**n. Sin la enumeracion no hay" % MAX_GRUPOS)
        w("argumento de conteo, de modo que la frase de INFORME.md queda sin")
        w("respaldo y hay que rehacer la comprobacion de otro modo.")
        comun.escribir("p19_qut_escrituras.txt", "\n".join(L))
        return 1

    cierran, evaluados = subconjuntos_que_cierran(objetos, escrituras)
    w("Subconjuntos no vacios evaluados: %d" % evaluados)
    w("Subconjuntos que cierran:         %d" % len(cierran))
    w("")
    for c in cierran:
        w("   %s = %d" % (" + ".join(c), sum(objetos[x] for x in c)))
    w("")

    if len(cierran) != 1:
        w("**El subconjunto que cierra no es unico.** El argumento de conteo")
        w("solo alcanza cuando hay exactamente uno: con %d, los conteos no"
          % len(cierran))
        w("distinguen entre las alternativas y la frase de la seccion 1.2 hay")
        w("que rehacerla.")
        comun.escribir("p19_qut_escrituras.txt", "\n".join(L))
        return 1

    unico = cierran[0]
    w("**Cierra uno solo, en todo el espacio de %d subconjuntos: %s.**"
      % (evaluados, " + ".join(unico)))
    w("")
    w("Eso es lo que esta medido, y es un argumento de conteo: no se apoya en")
    w("el protocolo en ningun paso. Lo que si sale del protocolo, y queda")
    w("atribuido como tal, es que **son** esos dos objetos:")
    w("")
    w("   g80v1   el bit de reinicio de las indicaciones internas")
    w("   g50v3   la hora")
    w("")
    w("Ninguno de los dos es un parametro de proceso. De modo que la")
    w("conclusion de la seccion 1.2 se sostiene por dos caminos: los objetos")
    w("de control no aparecen (19.2), y lo que las escrituras mueven son el")
    w("bit de reinicio y la hora.")
    w("")
    w("Lo que sigue sin medirse es cuantas de las %d escrituras lleva cada"
      % escrituras)
    w("uno de los dos. Para eso hay que volver a leer los PCAP registrando")
    w("objeto y funcion juntos, y ninguna conclusion de este analisis lo")
    w("necesita.")

    comun.escribir("p19_qut_escrituras.txt", "\n".join(L))
    with open(os.path.join(comun.SALIDAS, "p19_qut_escrituras.json"),
              "w") as fh:
        json.dump({"pares_rol_captura": pares, "write": escrituras,
                   "objetos": objetos, "subconjuntos_evaluados": evaluados,
                   "subconjuntos_que_cierran": [list(c) for c in cierran]},
                  fh, indent=1, ensure_ascii=False)
    return 0


if __name__ == "__main__":
    sys.exit(main())
