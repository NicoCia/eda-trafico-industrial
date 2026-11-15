"""Rutas, semilla y utilidades compartidas por los scripts del EDA.

Las rutas se derivan de la ubicacion de este archivo, de modo que los scripts
corren desde cualquier directorio sin depender de rutas absolutas de la maquina.
"""

import os
import random

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
