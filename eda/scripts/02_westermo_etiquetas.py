"""Preguntas 3 y 4 --- Westermo: etiquetas, eventos y tamano de muestra.

Pregunta 3: verifica contra los archivos las afirmaciones publicadas sobre
Westermo (reparto 75/18,5/6,5; seis tipos de evento; 96 eventos en 16 tandas;
diferencia entre las estrategias de etiquetado IT y NST).

Pregunta 4: cuenta instancias y, sobre todo, **eventos distintos** por tipo, y
como quedan repartidos entre los tres tramos de la particion temporal. El
conteo sobre el tramo de prueba es la excepcion admitida por el brief: solo
conteos, sin mirar distribuciones.

Uso:  python eda/scripts/02_westermo_etiquetas.py
"""

import collections
import json
import os
import re
import sys

import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import comun  # noqa: E402

VARIANTES = ["reduced", "extended"]
PUNTOS = ["bottom", "left", "right"]

# Agrupacion de la cifra publicada: normal / malas config. y SSH malicioso /
# ataques. GOOD-SSH es trafico legitimo, va con el normal.
GRUPO = {
    "Normal": "normal",
    "GOOD-SSH": "normal",
    "BAD-SSH": "misconf_y_ssh",
    "BAD-MISCONF": "misconf_y_ssh",
    "BAD-MISCONF-DUPLICATION": "misconf_y_ssh",
    "BAD-PORTSCAN1": "ataques",
    "BAD-PORTSCAN2": "ataques",
    "BAD-MITM": "ataques",
}

LINEA = re.compile(r"^\[(\d+\.\d+) -- ([\d\- :]+) -- (-?[\d.]+)\] \[([A-Z0-9\-]+)\](.*)$")


def leer_eventos(path):
    """Devuelve la lista de eventos (tipo, inicio, fin) desde events.txt."""
    abiertos = {}
    eventos = []
    otras = []
    with open(path) as fh:
        for linea in fh:
            m = LINEA.match(linea.strip())
            if not m:
                if linea.strip():
                    otras.append(linea.strip())
                continue
            _epoch, _fecha, off, tag, texto = m.groups()
            off = float(off)
            if tag.endswith("-START"):
                abiertos[tag[:-6]] = (off, texto.strip())
            elif tag.endswith("-END"):
                base = tag[:-4]
                if base in abiertos:
                    ini, txt = abiertos.pop(base)
                    eventos.append({"tipo": base, "inicio": ini, "fin": off,
                                    "texto": txt})
                else:
                    otras.append("END sin START: " + linea.strip())
            else:
                otras.append("%s %s %s" % (off, tag, texto.strip()))
    sin_cerrar = [{"tipo": k, "inicio": v[0], "fin": None}
                  for k, v in abiertos.items()]
    eventos.sort(key=lambda e: e["inicio"])
    return eventos, sin_cerrar, otras


def tandas(eventos):
    """Agrupa los eventos en tandas: una tanda nueva cuando un tipo se repite."""
    lotes = []
    actual = []
    vistos = set()
    for e in eventos:
        if e["tipo"] in vistos:
            lotes.append(actual)
            actual = []
            vistos = set()
        actual.append(e)
        vistos.add(e["tipo"])
    if actual:
        lotes.append(actual)
    return lotes


def particion(off):
    a, b = comun.WESTERMO_CORTES
    if off < a:
        return "entrenamiento"
    if off < b:
        return "calibracion"
    return "prueba"


def main():
    comun.preparar()
    L = []
    w = L.append
    w("# Preguntas 3 y 4 - Westermo")
    w("")

    # ------------------------------------------------------------------
    # Eventos declarados en events.txt
    # ------------------------------------------------------------------
    ruta_ev = os.path.join(comun.WESTERMO, "events.txt")
    eventos, sin_cerrar, otras = leer_eventos(ruta_ev)
    lotes = tandas(eventos)
    por_tipo = collections.Counter(e["tipo"] for e in eventos)

    w("## P3.a Inventario de eventos (data/events.txt)")
    w("")
    w("Eventos START/END emparejados: **%d**" % len(eventos))
    w("Eventos START sin END: %d %s"
      % (len(sin_cerrar), [e["tipo"] for e in sin_cerrar] or ""))
    w("Tandas detectadas (un tipo no se repite dentro de una tanda): **%d**"
      % len(lotes))
    w("Lineas INFO u otras: %d" % len(otras))
    w("")
    w("%-26s %8s %10s %10s %10s" % ("tipo", "eventos", "dur.med.s",
                                    "dur.min.s", "dur.max.s"))
    for tipo, n in sorted(por_tipo.items(), key=lambda kv: -kv[1]):
        durs = sorted(e["fin"] - e["inicio"] for e in eventos
                      if e["tipo"] == tipo and e["fin"] is not None)
        w("%-26s %8d %10.1f %10.1f %10.1f"
          % (tipo, n, durs[len(durs) // 2], durs[0], durs[-1]))
    w("")
    w("Tamano de cada tanda: %s" % [len(x) for x in lotes])
    w("")
    tipos_colapsados = set()
    for t in por_tipo:
        tipos_colapsados.add("BAD-PORTSCAN" if t.startswith("BAD-PORTSCAN")
                             else t)
    w("Tipos distintos tal como aparecen: %d -> %s"
      % (len(por_tipo), sorted(por_tipo)))
    w("Tipos si se unifica PORTSCAN1 y PORTSCAN2: %d -> %s"
      % (len(tipos_colapsados), sorted(tipos_colapsados)))
    w("")

    # ------------------------------------------------------------------
    # Reparto de etiquetas en los seis CSV
    # ------------------------------------------------------------------
    w("## P3.b Reparto de etiquetas en los seis CSV de flujos")
    w("")
    w("Agrupacion de la cifra publicada: normal (incluye GOOD-SSH) / malas")
    w("config. y SSH malicioso (BAD-SSH, BAD-MISCONF, BAD-MISCONF-DUPLICATION)")
    w("/ ataques (BAD-PORTSCAN1, BAD-PORTSCAN2, BAD-MITM).")
    w("")
    w("Cifra publicada en la bibliografia: 75,0 / 18,5 / 6,5 por ciento.")
    w("")
    w("%-9s %-7s %8s  %-28s  %-28s" % ("variante", "punto", "flujos",
                                       "NST  normal/misconf/ataque",
                                       "IT   normal/misconf/ataque"))
    resumen = {}
    total_global = collections.Counter()
    for var in VARIANTES:
        for pt in PUNTOS:
            ruta = os.path.join(comun.WESTERMO, var, "flows",
                                "output_%s.csv" % pt)
            if not os.path.exists(ruta):
                continue
            df = pd.read_csv(ruta)
            fila = {"filas": len(df), "columnas": df.shape[1]}
            txt = []
            for estr in ("NST", "IT"):
                col = "%s_M_Label" % estr
                g = collections.Counter()
                for etq, n in df[col].value_counts().items():
                    g[GRUPO.get(etq, "desconocido")] += int(n)
                tot = sum(g.values())
                fila[estr] = {k: int(v) for k, v in g.items()}
                fila["%s_pct" % estr] = {k: 100.0 * v / tot
                                         for k, v in g.items()}
                txt.append("%5.1f / %5.1f / %5.1f"
                           % (fila["%s_pct" % estr].get("normal", 0),
                              fila["%s_pct" % estr].get("misconf_y_ssh", 0),
                              fila["%s_pct" % estr].get("ataques", 0)))
                if estr == "NST":
                    total_global.update(g)
            w("%-9s %-7s %8d  %-28s  %-28s"
              % (var, pt, len(df), txt[0], txt[1]))
            resumen["%s/%s" % (var, pt)] = fila
    w("")
    w("Union de los tres puntos de captura dentro de cada variante (sumar las")
    w("dos variantes duplicaria el mismo trafico, asi que no se hace):")
    w("")
    for var in VARIANTES:
        for estr in ("NST", "IT"):
            g = collections.Counter()
            for pt in PUNTOS:
                clave = "%s/%s" % (var, pt)
                if clave in resumen:
                    g.update(resumen[clave][estr])
            t = sum(g.values())
            if not t:
                continue
            w("  %-9s %-4s %7d flujos -> %.1f / %.1f / %.1f"
              % (var, estr, t, 100.0 * g["normal"] / t,
                 100.0 * g["misconf_y_ssh"] / t, 100.0 * g["ataques"] / t))
    w("")

    # ------------------------------------------------------------------
    # IT frente a NST
    # ------------------------------------------------------------------
    w("## P3.c Cuanto cambia el problema segun la estrategia de etiquetado")
    w("")
    ruta_b = os.path.join(comun.WESTERMO, "reduced", "flows",
                          "output_bottom.csv")
    df = pd.read_csv(ruta_b)
    w("Archivo de referencia: %s (%d filas, %d columnas)"
      % (comun.rel(ruta_b), len(df), df.shape[1]))
    w("")
    it = df["IT_B_Label"].astype(int)
    nst = df["NST_B_Label"].astype(int)
    w("%-14s %16s %16s" % ("", "normal", "anomalo"))
    for nom, s in (("IT_B_Label", it), ("NST_B_Label", nst)):
        w("%-14s %6d (%4.1f%%) %6d (%4.1f%%)"
          % (nom, (s == 0).sum(), 100 * (s == 0).mean(),
             (s == 1).sum(), 100 * (s == 1).mean()))
    w("")
    amb = ((it == 1) & (nst == 1)).sum()
    solo_it = ((it == 1) & (nst == 0)).sum()
    solo_nst = ((it == 0) & (nst == 1)).sum()
    w("Flujos anomalos para ambas estrategias : %d" % amb)
    w("Anomalos solo para IT                  : %d  (%.1f%% del total)"
      % (solo_it, 100.0 * solo_it / len(df)))
    w("Anomalos solo para NST                 : %d" % solo_nst)
    w("")
    w("Es decir: NST marca un subconjunto estricto de IT. Los %d flujos que"
      % solo_it)
    w("separan una estrategia de la otra son trafico de terceros capturado")
    w("durante la ventana de un evento, y son el %.1f%% de la captura."
      % (100.0 * solo_it / len(df)))
    w("")
    w("Por tipo, cuantos flujos marca cada estrategia:")
    w("")
    w("%-26s %10s %10s %8s" % ("tipo", "IT_M", "NST_M", "NST/IT"))
    vc_it = df["IT_M_Label"].value_counts()
    vc_nst = df["NST_M_Label"].value_counts()
    for tipo in sorted(set(vc_it.index) | set(vc_nst.index)):
        a = int(vc_it.get(tipo, 0))
        b = int(vc_nst.get(tipo, 0))
        w("%-26s %10d %10d %7.1f%%" % (tipo, a, b,
                                       100.0 * b / a if a else float("nan")))
    w("")

    # ------------------------------------------------------------------
    # Pregunta 4: eventos por tipo y por particion
    # ------------------------------------------------------------------
    w("## P4 Muestras y eventos distintos por tipo (Westermo)")
    w("")
    w("Particion temporal fijada en el brief sobre startOffset:")
    w("  entrenamiento 0-%.0f s | calibracion %.0f-%.0f s | prueba %.0f-%.0f s"
      % (comun.WESTERMO_CORTES[0], comun.WESTERMO_CORTES[0],
         comun.WESTERMO_CORTES[1], comun.WESTERMO_CORTES[1],
         comun.WESTERMO_DURACION))
    w("")
    w("Eventos de events.txt asignados por su instante de inicio:")
    w("")
    w("%-26s %8s %14s %12s %8s" % ("tipo", "total", "entrenamiento",
                                   "calibracion", "prueba"))
    cuenta = collections.defaultdict(collections.Counter)
    for e in eventos:
        cuenta[e["tipo"]][particion(e["inicio"])] += 1
    for tipo in sorted(por_tipo, key=lambda t: -por_tipo[t]):
        c = cuenta[tipo]
        w("%-26s %8d %14d %12d %8d"
          % (tipo, por_tipo[tipo], c["entrenamiento"], c["calibracion"],
             c["prueba"]))
    tot = collections.Counter()
    for c in cuenta.values():
        tot.update(c)
    w("%-26s %8d %14d %12d %8d" % ("TOTAL", len(eventos),
                                   tot["entrenamiento"], tot["calibracion"],
                                   tot["prueba"]))
    w("")
    w("Flujos por tipo y particion (NST_M_Label, %s):" % comun.rel(ruta_b))
    w("")
    df["particion"] = df["startOffset"].map(particion)
    tab = pd.crosstab(df["NST_M_Label"], df["particion"])
    for col in ("entrenamiento", "calibracion", "prueba"):
        if col not in tab.columns:
            tab[col] = 0
    tab = tab[["entrenamiento", "calibracion", "prueba"]]
    w("%-26s %14s %12s %8s" % ("tipo", "entrenamiento", "calibracion",
                               "prueba"))
    for tipo, fila in tab.iterrows():
        w("%-26s %14d %12d %8d" % (tipo, fila["entrenamiento"],
                                   fila["calibracion"], fila["prueba"]))
    w("")
    w("Flujos por evento individual (mediana por tipo), util para saber si un")
    w("tipo con muchos flujos tiene en realidad pocos eventos:")
    w("")
    w("%-26s %8s %7s %7s %7s %7s %12s"
      % ("tipo", "eventos", "min", "mediana", "max", "ev=0", "flujos tot"))
    flujos_por_evento = {}
    for tipo in sorted(por_tipo, key=lambda t: -por_tipo[t]):
        porev = []
        for e in eventos:
            if e["tipo"] != tipo or e["fin"] is None:
                continue
            m = ((df["startOffset"] >= e["inicio"]) &
                 (df["startOffset"] <= e["fin"]) &
                 (df["NST_M_Label"] == tipo))
            porev.append(int(m.sum()))
        porev.sort()
        flujos_por_evento[tipo] = porev
        w("%-26s %8d %7d %7d %7d %7d %12d"
          % (tipo, len(porev), porev[0] if porev else 0,
             porev[len(porev) // 2] if porev else 0,
             porev[-1] if porev else 0, sum(1 for x in porev if x == 0),
             sum(porev)))
    w("")
    w("Reparto completo de flujos por evento, por tipo:")
    for tipo, porev in flujos_por_evento.items():
        w("  %-26s %s" % (tipo, porev))
    w("")
    w("Los eventos de SSH que no dejan ningun flujo en este punto de captura:")
    w("contra que equipo iba cada uno. El texto de events.txt trae el objetivo,")
    w("asi que se puede comprobar si la invisibilidad depende de la topologia")
    w("en lugar de suponerlo.")
    w("")
    w("%-10s %-18s %8s" % ("tipo", "objetivo", "flujos"))
    objetivo_ip = re.compile(r"(198\.\d+\.\d+\.\d+)")
    visibilidad = collections.defaultdict(lambda: [0, 0])
    for tipo in ("BAD-SSH", "GOOD-SSH"):
        for e in eventos:
            if e["tipo"] != tipo or e["fin"] is None:
                continue
            m = ((df["startOffset"] >= e["inicio"]) &
                 (df["startOffset"] <= e["fin"]) &
                 (df["NST_M_Label"] == tipo))
            mo = objetivo_ip.search(e.get("texto", ""))
            objetivo = mo.group(1) if mo else "?"
            n = int(m.sum())
            w("%-10s %-18s %8d" % (tipo, objetivo, n))
            visibilidad[objetivo][0] += 1
            if n == 0:
                visibilidad[objetivo][1] += 1
    w("")
    w("Resumen por objetivo (eventos / de ellos sin ningun flujo):")
    for ip, (tot_ip, ceros) in sorted(visibilidad.items()):
        w("  %-18s %2d / %2d" % (ip, tot_ip, ceros))
    w("")

    comun.escribir("p3_p4_westermo.txt", "\n".join(L))

    with open(os.path.join(comun.SALIDAS, "p3_p4_westermo.json"), "w") as fh:
        json.dump({
            "eventos_total": len(eventos),
            "eventos_por_tipo": dict(por_tipo),
            "tandas": len(lotes),
            "tamano_tandas": [len(x) for x in lotes],
            "sin_cerrar": sin_cerrar,
            "reparto_csv": resumen,
            "eventos_por_particion": {k: dict(v) for k, v in cuenta.items()},
        }, fh, indent=1, ensure_ascii=False)

    # Figura: linea de tiempo de los eventos y los cortes de la particion.
    plt = comun.estilo_figura()
    tipos = sorted(por_tipo)
    fig, ax = plt.subplots(figsize=(10, 3.6))
    colores = plt.cm.tab10.colors
    for i, tipo in enumerate(tipos):
        for e in eventos:
            if e["tipo"] != tipo:
                continue
            fin = e["fin"] if e["fin"] is not None else e["inicio"] + 1
            ax.barh(i, fin - e["inicio"], left=e["inicio"], height=0.62,
                    color=colores[i % len(colores)])
    for x, nom in zip(comun.WESTERMO_CORTES, ("60 %", "80 %")):
        ax.axvline(x, color="k", lw=1.1, ls="--")
        ax.text(x, len(tipos) - 0.3, " " + nom, fontsize=8, va="top")
    ax.set_yticks(range(len(tipos)))
    ax.set_yticklabels(tipos, fontsize=8)
    ax.set_xlabel("segundos desde el inicio de la captura (startOffset)")
    ax.set_xlim(0, comun.WESTERMO_DURACION)
    ax.set_title("Westermo: %d eventos a lo largo de la captura y cortes de la "
                 "particion\n(entrenamiento | calibracion | prueba)"
                 % len(eventos), fontsize=9)
    fig.savefig(os.path.join(comun.FIGURAS, "p4_westermo_eventos.png"))
    print("[figura] %s" % comun.rel(
        os.path.join(comun.FIGURAS, "p4_westermo_eventos.png")))


if __name__ == "__main__":
    main()
