"""Westermo cuenta cada paquete dos veces. Cuanto, y como se corrige.

EL PROBLEMA
-----------
El README del conjunto avisa que el equipo que graba captura la trama al
entrar y al salir, de modo que hay paquetes duplicados. Lo que no estaba
medido es que **los contadores de volumen de los CSV de flujo publicados
cuentan esas copias**. Medido aca: para el trafico que cruza el equipo, el
`sPackets` publicado es el doble del numero de paquetes distintos.

Eso afecta a `sPackets`, `rPackets`, los `Bytes*` y los `Payload*`, que son
las caracteristicas de volumen --- justo las que el analisis identifica como
portadoras de senal.

QUE HACE ESTE SCRIPT, Y QUE NO
------------------------------
**No rearma los flujos.** Armarlos con un armador propio cambiaria dos cosas
a la vez --- el conteo de paquetes, que es lo que hay que corregir, y la
definicion de flujo, que no --- y romperia la comparabilidad con ICS-Flow,
que sale del mismo generador publicado: toda la seccion 5 de INFORME.md se
apoya en que los dos vengan de la misma herramienta.

Conserva **la fila de flujo publicada** --- sus limites, su par de
direcciones, su asignacion de emisor y receptor --- y recuenta sus
contadores de volumen asignando cada paquete del PCAP a la fila que le
corresponde. Lo unico que cambia es que cada paquete se cuenta una vez.

LA REGLA DE DEDUPLICACION, Y POR QUE ES ESA
-------------------------------------------
Dos paquetes son la misma captura si son **identicos octeto a octeto** y
estan separados por menos de `DEDUP_US`. La ventana no es arbitraria: la
separacion entre apariciones de una misma firma es marcadamente bimodal.
Sobre `reduced/bottom`, de unos 300.000 pares de apariciones consecutivas,
291.926 estan por debajo de 100 us --- la mediana es 1,0 us --- y 7.079 caen
entre 1 y 10 segundos. Entre 100 us y 1 ms hay 198. Los primeros son la copia
de captura; los segundos son balizas periodicas identicas, que son trafico
legitimo y no se tocan. Un deduplicado por firma sin ventana borraria las
balizas: hay firmas que aparecen 3189 veces.

LA VALIDACION, QUE ES LO QUE HACE CONFIABLE AL RESTO
-----------------------------------------------------
Primero se recuenta **sin** deduplicar y se compara fila por fila contra el
CSV publicado. Si eso reproduce, la asignacion paquete-fila es correcta, y
entonces el recuento deduplicado es la version corregida de esas mismas
cifras. Si la validacion se degrada, el script **termina con codigo distinto
de cero** en lugar de publicar una correccion que no se puede sostener.

Uso:  eda/.venv/bin/python -I eda/scripts/22_westermo_duplicados.py
"""

import bisect
import collections
import hashlib
import os
import socket
import sys

import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import comun  # noqa: E402

VARIANTES = ("reduced", "extended")
PUNTOS = ("bottom", "left", "right")

# Ventana de deduplicacion, en microsegundos. Cae en el valle entre los dos
# fenomenos; ver el encabezado.
DEDUP_US = 1000.0

# Campos que el doble conteo afecta.
CAMPOS = ("sPackets", "rPackets", "sBytesSum", "rBytesSum",
          "sPayloadSum", "rPayloadSum")

# Campos DERIVADOS de los anteriores. No se recuentan: se recalculan con la
# misma definicion del conjunto a partir de los contadores ya corregidos.
# Corregir solo los sumatorios dejaria estos inconsistentes con ellos, y son
# los que encabezan la tabla de divergencia de la seccion 5.3.
DERIVADOS_RAZON = ("sBytesAvg", "rBytesAvg", "sPayloadAvg", "rPayloadAvg",
                   "sLoad", "rLoad")

# Intervalo medio entre paquetes: se recalcula desde las marcas de tiempo de
# los paquetes unicos de cada fila.
DERIVADOS_TIEMPO = ("sInterPacketAvg", "rInterPacketAvg")

# Lo que NO se corrige, y queda declarado: los retardos de ACK. Reconstruirlos
# exige seguir el emparejamiento TCP de cada flujo, que es otro trabajo.
SIN_CORREGIR = ("sAckDelayMin", "sAckDelayMax", "sAckDelayAvg",
                "rAckDelayMin", "rAckDelayMax", "rAckDelayAvg")

# Si la reproduccion del CSV publicado cae por debajo de esto, no se publica
# ninguna correccion: querria decir que la asignacion paquete-fila dejo de
# ser correcta y lo que salga del deduplicado no significa nada.
MIN_REPRODUCE = 0.95

# `sBytesSum` reproduce peor que los demas por el relleno de las tramas que
# no son IP, de modo que se le admite un piso mas bajo. La razon agregada
# sigue exigiendose cerca de 1.
MIN_REPRODUCE_BYTES = 0.85
TOL_RAZON = 0.01

# Holgura al comparar el instante de un paquete contra los limites de su
# fila: el CSV publica `startOffset` y `duration` con seis decimales.
TOL_BORDE = 1e-5


def etiqueta(eth, dpkt):
    """Protocolo con la convencion del conjunto, y las direcciones de red."""
    t = eth.type
    if t == dpkt.ethernet.ETH_TYPE_ARP:
        return "ARP", None, None
    if t == 0x88cc:
        return "LLDP", None, None
    if t == dpkt.ethernet.ETH_TYPE_IP:
        ip = eth.data
        if not isinstance(ip, dpkt.ip.IP):
            return None, None, None
        s = socket.inet_ntoa(ip.src)
        d = socket.inet_ntoa(ip.dst)
        if ip.p == dpkt.ip.IP_PROTO_TCP:
            return "IPV4-TCP", s, d
        if ip.p == dpkt.ip.IP_PROTO_UDP:
            return "IPV4-UDP", s, d
        return "IPV4-%d" % ip.p, s, d
    return None, None, None


def _mac(b):
    return ":".join("%02x" % x for x in b)


def recontar(variante, punto):
    """Recuenta los contadores de una captura, crudo y deduplicado."""
    import dpkt

    pcap = os.path.join(comun.WESTERMO, variante, "pcaps", "%s.pcap" % punto)
    ruta_csv = os.path.join(comun.WESTERMO, variante, "flows",
                            "output_%s.csv" % punto)
    if not (os.path.exists(pcap) and os.path.exists(ruta_csv)):
        return None

    csv = pd.read_csv(ruta_csv)
    t0 = float(csv["start"].min() - csv["startOffset"].min())

    idx = collections.defaultdict(list)
    for i, r in enumerate(csv.itertuples(index=False)):
        idx[(frozenset((r.sAddress, r.rAddress)), r.protocol)].append(
            (r.startOffset, r.startOffset + r.duration, i))
    for k in idx:
        idx[k].sort()
    inicios = {k: [x[0] for x in v] for k, v in idx.items()}

    n = len(csv)
    crudo = {c: np.zeros(n) for c in CAMPOS}
    unico = {c: np.zeros(n) for c in CAMPOS}
    # Marcas de tiempo de los paquetes unicos de cada fila, por lado, para
    # recalcular el intervalo medio entre paquetes.
    marcas = {"s": collections.defaultdict(list),
              "r": collections.defaultdict(list)}
    sAddr = csv["sAddress"].to_numpy()

    recientes = {}
    leidos = sin_fila = copias = 0
    with open(pcap, "rb") as fh:
        for ts, buf in dpkt.pcap.Reader(fh):
            leidos += 1
            try:
                eth = dpkt.ethernet.Ethernet(buf)
            except Exception:
                continue
            proto, s, d = etiqueta(eth, dpkt)
            if proto is None:
                continue
            if s is None:
                s, d = _mac(eth.src), _mac(eth.dst)
            k = (frozenset((s, d)), proto)
            lst = idx.get(k)
            if not lst:
                sin_fila += 1
                continue
            off = ts - t0
            j = bisect.bisect_right(inicios[k], off) - 1
            # El `startOffset` del CSV viene redondeado a seis decimales, de
            # modo que el instante calculado del paquete puede caer unos
            # nanosegundos ANTES del inicio de su propia fila y la busqueda
            # binaria lo manda a la anterior. Si no entra en la fila j, se
            # prueba la siguiente antes de darlo por perdido.
            if j < 0 or off > lst[j][1] + TOL_BORDE:
                if j + 1 < len(lst) and off >= lst[j + 1][0] - TOL_BORDE \
                        and off <= lst[j + 1][1] + TOL_BORDE:
                    j += 1
                else:
                    sin_fila += 1
                    continue
            i = lst[j][2]

            # La convencion de octetos del conjunto, deducida de sus propias
            # cifras y validada abajo: para IP cuenta `ip.len`, es decir
            # desde la capa de red; para lo que no es IP cuenta la trama
            # entera. Se ve en el CSV publicado: toda fila ARP da exactamente
            # 60 octetos por paquete, que es la trama Ethernet con relleno, y
            # no 46, que seria sin la cabecera.
            ip = eth.data
            if isinstance(ip, dpkt.ip.IP):
                nb = ip.len
                pl = len(getattr(ip.data, "data", b"") or b"")
            else:
                nb, pl = len(buf), 0
            lado = "s" if s == sAddr[i] else "r"

            crudo["%sPackets" % lado][i] += 1
            crudo["%sBytesSum" % lado][i] += nb
            crudo["%sPayloadSum" % lado][i] += pl

            h = hashlib.md5(buf).digest()
            prev = recientes.get(h)
            recientes[h] = ts
            if prev is not None and (ts - prev) * 1e6 < DEDUP_US:
                copias += 1
                continue
            unico["%sPackets" % lado][i] += 1
            unico["%sBytesSum" % lado][i] += nb
            unico["%sPayloadSum" % lado][i] += pl
            marcas[lado][i].append(ts)

    return {"csv": csv, "crudo": crudo, "unico": unico, "leidos": leidos,
            "sin_fila": sin_fila, "copias": copias, "marcas": marcas}


def derivar(csv, unico, marcas):
    """Recalcula los campos derivados con la definicion del conjunto."""
    out = {}
    dur = csv["duration"].to_numpy(dtype=float)
    for lado in ("s", "r"):
        pk = unico["%sPackets" % lado]
        con = pk > 0
        for base, campo in (("BytesSum", "BytesAvg"),
                            ("PayloadSum", "PayloadAvg")):
            v = np.full(len(csv), np.nan)
            v[con] = unico["%s%s" % (lado, base)][con] / pk[con]
            out["%s%s" % (lado, campo)] = v
        # `Load` es 8 * octetos / duracion, en bit/s. Donde ese lado no tiene
        # paquetes el conjunto publica CERO y no un nulo --- medido: las 257
        # filas de `reduced/bottom` con `sPackets` = 0 traen `sLoad` = 0 ---,
        # de modo que aca tambien, o la tabla corregida tendria un patron de
        # faltantes que el conjunto no tiene.
        v = np.zeros(len(csv))
        m = con & (dur > 0)
        v[m] = 8.0 * unico["%sBytesSum" % lado][m] / dur[m]
        out["%sLoad" % lado] = v
        # Intervalo medio entre paquetes unicos. Con menos de dos no existe,
        # que es la misma regla del conjunto.
        v = np.full(len(csv), np.nan)
        for i, ts_ in marcas[lado].items():
            if len(ts_) > 1:
                ts_ = sorted(ts_)
                v[i] = float(np.mean(np.diff(ts_)))
        out["%sInterPacketAvg" % lado] = v
    return out


def main():
    comun.preparar()
    L = []
    w = L.append
    w("# Pregunta 22 - Westermo cuenta cada paquete dos veces")
    w("")
    w("Los contadores de volumen de los CSV de flujo publicados cuentan las")
    w("copias que deja el equipo que graba al capturar la trama al entrar y")
    w("al salir. Aca se recuentan sobre paquetes unicos, **conservando la")
    w("fila de flujo publicada**: lo unico que cambia es que cada paquete se")
    w("cuenta una vez.")
    w("")
    w("Regla: dos paquetes son la misma captura si son identicos octeto a")
    w("octeto y estan separados por menos de %.0f us." % DEDUP_US)
    w("")

    res = {}
    fallos = []
    for variante in VARIANTES:
        for punto in PUNTOS:
            print("  recontando %s/%s" % (variante, punto), file=sys.stderr)
            r = recontar(variante, punto)
            if r is None:
                continue
            res["%s/%s" % (variante, punto)] = r

    if not res:
        w("**No hay capturas.** Se necesita `datasets/westermo/data/*/pcaps/`.")
        comun.escribir("p22_westermo_duplicados.txt", "\n".join(L))
        return 2

    w("## 22.1 Validacion: el recuento crudo reproduce el CSV publicado?")
    w("")
    w("Si esto no reproduce, la asignacion paquete-fila esta mal y nada de")
    w("lo que sigue significa algo. El script termina con codigo distinto de")
    w("cero en ese caso.")
    w("")
    w("%-18s %-14s %9s %9s" % ("captura", "campo", "filas ok", "razon"))
    salida = {}
    for clave, r in res.items():
        csv = r["csv"]
        for c in CAMPOS:
            a = csv[c].to_numpy(dtype=float)
            b = r["crudo"][c]
            ig = float(np.mean(np.isclose(a, b, rtol=1e-9, atol=1e-6)))
            razon = b.sum() / a.sum() if a.sum() else float("nan")
            piso = MIN_REPRODUCE_BYTES if "Bytes" in c else MIN_REPRODUCE
            mal = ig < piso or abs(razon - 1.0) > TOL_RAZON
            w("%-18s %-14s %8.1f%% %9.4f%s"
              % (clave, c, 100 * ig, razon, "   <-- FALLA" if mal else ""))
            if mal:
                fallos.append((clave, c, ig, razon))
            salida.setdefault(clave, {})[c] = {
                "filas_exactas": ig, "razon_crudo_publicado": razon}
    w("")
    if fallos:
        w("**La validacion falla en %d casos.** No se publica ninguna"
          % len(fallos))
        w("correccion: habria que arreglar la asignacion primero.")
        comun.escribir("p22_westermo_duplicados.txt", "\n".join(L))
        with open(os.path.join(comun.SALIDAS,
                               "p22_westermo_duplicados.json"), "w") as fh:
            import json
            json.dump({"validacion": salida, "fallos": len(fallos)}, fh,
                      indent=1, ensure_ascii=False)
        print("22: la validacion fallo en %d casos" % len(fallos),
              file=sys.stderr)
        return 1
    w("Reproduce en las %d capturas. La asignacion paquete-fila es correcta."
      % len(res))
    w("")

    w("## 22.2 Cuanto infla el doble conteo")
    w("")
    w("Las dos primeras columnas son del PCAP y las dos ultimas de los CSV")
    w("de flujo, que no contabilizan todos los paquetes del archivo. Son dos")
    w("poblaciones, de modo que el factor **no se deduce** de las copias que")
    w("tiene al lado: se informan los dos.")
    w("")
    w("%-18s %9s %9s %8s %11s %11s"
      % ("captura", "paquetes", "copias", "% copias",
         "infl. paq.", "infl. CSV"))
    for clave, r in res.items():
        tot = r["crudo"]["sPackets"].sum() + r["crudo"]["rPackets"].sum()
        uni = r["unico"]["sPackets"].sum() + r["unico"]["rPackets"].sum()
        f = tot / uni if uni else float("nan")
        unicos_pcap = r["leidos"] - r["copias"]
        f_pcap = r["leidos"] / unicos_pcap if unicos_pcap else float("nan")
        w("%-18s %9d %9d %7.1f%% %10.3fx %10.3fx"
          % (clave, r["leidos"], r["copias"],
             100.0 * r["copias"] / max(1, r["leidos"]), f_pcap, f))
        salida[clave]["inflacion_contadores_csv"] = float(f)
        salida[clave]["inflacion_paquetes_pcap"] = float(f_pcap)
        salida[clave]["copias"] = int(r["copias"])
        salida[clave]["paquetes_leidos"] = int(r["leidos"])
        salida[clave]["paquetes_contabilizados_en_csv"] = int(tot)
    w("")

    w("## 22.3 El efecto campo por campo")
    w("")
    w("%-18s %-14s %14s %14s %8s"
      % ("captura", "campo", "publicado", "unico", "razon"))
    for clave, r in res.items():
        for c in CAMPOS:
            a = r["crudo"][c].sum()
            b = r["unico"][c].sum()
            w("%-18s %-14s %14d %14d %8.4f"
              % (clave, c, a, b, b / a if a else float("nan")))
            salida[clave][c]["razon_unico_crudo"] = float(b / a) if a else None
    w("")

    # La tabla corregida, para que la use el resto del analisis. Va a
    # derivados/ y no a salidas/: son 117.000 filas y el repositorio no
    # versiona tablas de ese tamano.
    os.makedirs(comun.DERIVADOS, exist_ok=True)
    for clave, r in res.items():
        variante, punto = clave.split("/")
        d = r["csv"].copy()
        for c in CAMPOS:
            d[c] = r["unico"][c]
        for c, v in derivar(r["csv"], r["unico"], r["marcas"]).items():
            d[c] = v
        ruta = os.path.join(comun.DERIVADOS,
                            "westermo_%s_%s_unico.csv" % (variante, punto))
        d.to_csv(ruta, index=False)
    w("Tabla corregida escrita en `eda/derivados/westermo_*_unico.csv`, con")
    w("las mismas filas y columnas del CSV publicado y:")
    w("")
    w("  - los %d contadores de volumen recontados sobre paquetes unicos:"
      % len(CAMPOS))
    w("    %s" % ", ".join(CAMPOS))
    w("  - los %d derivados recalculados con la definicion del conjunto a"
      % (len(DERIVADOS_RAZON) + len(DERIVADOS_TIEMPO)))
    w("    partir de esos contadores: %s"
      % ", ".join(DERIVADOS_RAZON + DERIVADOS_TIEMPO))
    w("")
    w("**Lo que NO se corrige**: %s." % ", ".join(SIN_CORREGIR))
    w("Una version anterior decia que quedaban pendientes porque")
    w("reconstruir el retardo de ACK exige seguir el emparejamiento TCP de")
    w("cada flujo, y agregaba que las copias separadas por un microsegundo")
    w("tiraban el minimo y el promedio hacia abajo. Lo primero es cierto; lo")
    w("segundo era un mecanismo supuesto y no medido, y la medicion dice")
    w("otra cosa: **esos seis no hacen falta corregirlos**, por el mismo")
    w("motivo que los minimos y maximos de octetos y de carga util. Son")
    w("minimo, promedio y maximo de un conjunto, no sumas, y duplicar cada")
    w("elemento de un conjunto no le cambia ninguno de los tres.")
    w("")
    w("La medicion esta en `p11_integracion.txt`, en la seccion de poblacion:")
    w("en las filas que traen el dato la duplicacion es exactamente doble en")
    w("el 98 % de los casos, y en el resto el desplazamiento esta acotado por")
    w("la separacion entre copias --- mediana de 1 us --- contra retardos")
    w("cuyas medianas son de 0,55 ms y 29 ms.")
    w("")
    w("## 22.4 `duration` no se corrige, y para algunas filas es un artefacto")
    w("")
    w("`duration` es del conjunto y no se toca: es el intervalo entre el")
    w("primero y el ultimo paquete de la fila, copias incluidas. Para una")
    w("fila cuyo contenido real es UN SOLO paquete, eso no es una duracion")
    w("sino la separacion entre sus dos copias, del orden del microsegundo,")
    w("y cualquier tasa dividida por ella sale disparada.")
    w("")
    w("No es algo que introduzca esta correccion: ya esta en el conjunto")
    w("publicado, donde los flujos de un solo paquete traen `duration` de")
    w("1 us y `sLoad` del orden de 10^8 bit/s. Lo que la correccion hace es")
    w("volverlo visible, porque ahora se sabe cuantas filas tienen un solo")
    w("paquete de verdad.")
    w("")
    w("%-18s %9s %9s %12s %14s"
      % ("captura", "filas", "1 paq.", "% del total", "mediana dur."))
    art_tot = {}
    for clave, r in res.items():
        csv = r["csv"]
        tot = r["crudo"]["sPackets"] + r["crudo"]["rPackets"]
        uni = r["unico"]["sPackets"] + r["unico"]["rPackets"]
        art = (uni == 1) & (tot > 1)
        dur = csv["duration"].to_numpy(dtype=float)[art]
        w("%-18s %9d %9d %11.1f %% %13.6f s"
          % (clave, len(csv), int(art.sum()), 100.0 * art.mean(),
             float(np.median(dur)) if art.sum() else float("nan")))
        art_tot[clave] = {"filas": int(len(csv)),
                          "un_solo_paquete_real": int(art.sum()),
                          "fraccion": float(art.mean())}
    w("")
    w("**Para esas filas `sLoad`, `rLoad` y los intervalos entre paquetes no")
    w("son usables**, y el valor extremo que traen es del instrumento y no")
    w("del trafico. Es la excepcion a la regla de no descartar extremos que")
    w("`EXPLORATORIO.md` enuncia: ahi el extremo no es la rafaga ni el")
    w("escaneo, es la grabadora.")
    salida["filas_con_un_solo_paquete_real"] = art_tot
    w("")

    comun.escribir("p22_westermo_duplicados.txt", "\n".join(L))
    import json
    with open(os.path.join(comun.SALIDAS,
                           "p22_westermo_duplicados.json"), "w") as fh:
        json.dump({"validacion": salida, "fallos": 0,
                   "dedup_us": DEDUP_US}, fh, indent=1, ensure_ascii=False)
    return 0


if __name__ == "__main__":
    sys.exit(main())
