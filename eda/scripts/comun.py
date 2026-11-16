"""Rutas, semilla y utilidades compartidas por los scripts del EDA.

Las rutas se derivan de la ubicacion de este archivo, de modo que los scripts
corren desde cualquier directorio sin depender de rutas absolutas de la maquina.
"""

import os
import random
import sys

import numpy as np

SEMILLA = 20261024

RAIZ = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DATOS = os.path.join(RAIZ, "datasets")
EDA = os.path.join(RAIZ, "eda")
SALIDAS = os.path.join(EDA, "salidas")
FIGURAS = os.path.join(EDA, "figuras")
DERIVADOS = os.path.join(EDA, "derivados")

WESTERMO = os.path.join(DATOS, "westermo", "data")
QUT = os.path.join(DATOS, "qut-dnp3")
HAI = os.path.join(DATOS, "hai")
MORRIS = os.path.join(DATOS, "morris-turnipseed")

# Particion temporal de Westermo, fijada en eda/INSTRUCCIONES.md (segundos de
# `startOffset`). El EDA solo explora el tramo de entrenamiento.
WESTERMO_CORTES = (3265.0, 4354.0)
WESTERMO_DURACION = 5442.0

# Particion temporal de Morris, fijada en eda/INSTRUCCIONES.md (timestamp Unix).
MORRIS_T0 = 1418682163
MORRIS_T1 = 1418957854
MORRIS_CORTES = (MORRIS_T0 + 165415, MORRIS_T0 + 165415 + 55138)


def westermo_flujos(variante="reduced", punto="bottom", unico=True,
                    **kwargs):
    """Los flujos de Westermo, con los contadores de volumen corregidos.

    EL EQUIPO QUE GRABA CUENTA CADA PAQUETE DOS VECES. El README del conjunto
    avisa que captura la trama al entrar y al salir, y los contadores de
    volumen de los CSV publicados cuentan esas copias: medido en
    `22_westermo_duplicados.py`, `reduced/bottom` viene inflado 1,95 veces.

    Por eso **ningun script debe abrir `output_*.csv` directamente** para
    nada que use volumen. Esta funcion devuelve la tabla con las mismas filas
    y columnas del conjunto y los seis contadores de volumen recontados sobre
    paquetes unicos, que es lo que escribe el script 22 en `eda/derivados/`.

    Con `unico=False` devuelve el CSV publicado tal cual, que sirve para
    comparar las dos versiones y para lo que no depende del volumen.

    Si la tabla corregida no esta, avisa por `stderr` y cae al publicado:
    preferible a romper, pero el aviso tiene que verse.
    """
    import pandas as pd

    pub = os.path.join(WESTERMO, variante, "flows", "output_%s.csv" % punto)
    if not unico:
        return pd.read_csv(pub, **kwargs)
    corr = os.path.join(DERIVADOS,
                        "westermo_%s_%s_unico.csv" % (variante, punto))
    if os.path.exists(corr):
        return pd.read_csv(corr, **kwargs)
    print("AVISO: falta %s; se usa el CSV publicado, con los contadores de "
          "volumen inflados por el doble conteo. Correr antes "
          "`make -C eda duplicados`." % rel(corr), file=sys.stderr)
    return pd.read_csv(pub, **kwargs)


def preparar():
    """Fija la semilla y crea los directorios de salida."""
    random.seed(SEMILLA)
    np.random.seed(SEMILLA)
    for d in (SALIDAS, FIGURAS, DERIVADOS):
        os.makedirs(d, exist_ok=True)


def rel(path):
    """Devuelve `path` relativo a la raiz del repositorio, para imprimir."""
    try:
        return os.path.relpath(path, RAIZ)
    except ValueError:
        return path


def escribir(nombre, texto):
    """Guarda un texto en eda/salidas y lo imprime."""
    os.makedirs(SALIDAS, exist_ok=True)
    destino = os.path.join(SALIDAS, nombre)
    with open(destino, "w") as fh:
        fh.write(texto)
    print(texto)
    print("\n[escrito] %s" % rel(destino))


def estilo_figura():
    """Estilo comun y sobrio para las figuras."""
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    plt.rcParams.update({
        "figure.dpi": 130,
        "savefig.dpi": 130,
        "font.size": 9,
        "axes.grid": True,
        "grid.alpha": 0.25,
        "axes.spines.top": False,
        "axes.spines.right": False,
        "figure.autolayout": True,
    })
    return plt
