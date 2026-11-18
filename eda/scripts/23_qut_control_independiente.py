"""Pregunta 23 --- hay comandos de control en QUT? Medido sin el lector propio.

La seccion 1.2 de INFORME.md afirma que QUT no contiene comandos de control
con parametros: g12, g40 y g41 no aparecen ni una vez entre las 2.318.092
cabeceras de objeto. Es una afirmacion de AUSENCIA, y una ausencia es
exactamente lo que fabrica un lector que no sepa decodificar algo.

El unico respaldo que tenia esa frase era `eda/scripts/dnp3.py`, el lector de
este trabajo, y esa capa ya se equivoco una vez de una manera que ningun
control de sumas podia encontrar: no miraba el bit FIR, de modo que en una
trama de continuacion leia octetos de datos como cabecera de aplicacion e
inventaba una funcion por trama. Eran 186 tramas y movieron tres cifras
publicadas. Las sumas de un parseo mal hecho cierran igual de bien que las de
uno bien hecho.

QUE HACE ESTE SCRIPT, Y POR QUE ES INDEPENDIENTE
------------------------------------------------
**No importa `dnp3.py`.** Usa `dpkt` solo para lo que dpkt hace --- abrir el
PCAP y sacar el payload TCP --- y de ahi en adelante reimplementa lo minimo
desde la especificacion: el CRC-16 de DNP3 y los desplazamientos fijos de la
cabecera. No reutiliza ni una linea de la capa de aplicacion del lector.

Un comando de control en DNP3 tiene que dejar una de dos marcas:

1. un codigo de funcion SELECT (3), OPERATE (4), DIRECT_OPERATE (5) o
   DIRECT_OPERATE_NR (6); o
2. un WRITE (2) sobre un grupo de salida: g12 (bloque de control de salida
   binaria), g40 (estado de salida analogica) o g41 (bloque de salida
   analogica).

Las dos marcas viven en posiciones FIJAS de la trama, de modo que se leen sin
decodificar ningun objeto: payload[0] es el octeto de transporte, [1] el
control de aplicacion, [2] el codigo de funcion y [3] el grupo del primer
objeto. Nada de eso necesita interpretar calificadores ni rangos, que es donde
un lector se puede equivocar en silencio.

CONTANDO DE MAS, A PROPOSITO
----------------------------
La unica ambiguedad real es la que causo el error de 2026: si una trama abre
un fragmento o lo continua. Para que el resultado no dependa de haber resuelto
bien esa pregunta, cada trama se lee de las DOS maneras:

    A (correcta)   transporte en [0], funcion en [2], grupo en [3]
    B (la del bug) funcion en [1], grupo en [2]

y se cuentan los aciertos de las dos. Si el total da cero contando de las dos
formas, la ausencia de comandos de control no puede ser un falso negativo del
lector, porque no hay interpretacion del bit FIR bajo la cual aparezcan.

Lo que si se valida por protocolo y no por criterio: el CRC de cabecera de
enlace y el CRC del primer bloque de datos. El segundo importa tanto como el
primero, porque los cuatro octetos que este script lee viven en ese bloque: si
el bloque no cerrara, los desplazamientos leerian basura.

LO QUE ESTE SCRIPT NO PRUEBA
----------------------------
No es un censo y no reemplaza a `dnp3.py`. No cuenta cabeceras de objeto mas
alla de la primera de cada trama, no reensambla fragmentos multiples y no
valida los bloques de datos posteriores al primero. Contesta una sola
pregunta, la de la ausencia, y para el resto el lector del trabajo sigue
siendo la fuente.

Solo lee `training/`. El tramo `testing/` no se abre.

Uso:  python eda/scripts/23_qut_control_independiente.py
"""

import glob
import json
import os
import sys

import dpkt

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import comun  # noqa: E402

# Los 42 agregados, con la misma lista de escenarios que usa el script 01.
ESCENARIOS = (
    ("Attacks", "Attacks/attacks/training"),
    ("Control", "Control/control/training"),
    ("Flooding", "Flooding/flooding/training"),
    ("Injection", "Injection/injection/training"),
    ("MITM", "MITM/MITM/training"),
    ("Masqurading", "Masqurading/masquerading/training"),
    ("Replay", "Replay/replay/training"),
)

PUERTO = 20000

# Codigos de funcion de comando de control.
FUNC_CONTROL = {3: "SELECT", 4: "OPERATE", 5: "DIRECT_OPERATE",
                6: "DIRECT_OPERATE_NR"}
FUNC_WRITE = 2
# Grupos de objeto de salida. Si apareciera cualquiera, la seccion 1.2 cambia.
GRUPOS_CONTROL = {12: "g12 control de salida binaria",
                  40: "g40 estado de salida analogica",
                  41: "g41 bloque de salida analogica"}

# --- Las dos guardas, que son el punto mas delicado de este script --------
#
# Un resultado negativo es facil de fabricar sin querer: si el CRC estuviera
# mal implementado, no validaria ninguna trama, el recuento de comandos de
# control daria cero y eso se LEERIA como confirmacion. Lo mismo si los
# desplazamientos estuvieran corridos. De modo que antes de afirmar la
# ausencia hay que mostrar que se estaba mirando donde hay que mirar.
#
# Guarda 1: el censo de `dnp3.py` encuentra 2.372.794 tramas de enlace. Este
# recuento es naturalmente algo menor ---descarta la trama cuyo primer bloque
# no cierra y no reensambla fragmentos--- pero del mismo orden. Por debajo de
# este piso, el framing no reprodujo y no se concluye nada.
PISO_TRAMAS = 2000000
# Guarda 2: los codigos de funcion que la especificacion define. Si el
# desplazamiento de la funcion estuviera corrido, esta posicion traeria
# octetos de datos y el histograma se desparramaria fuera de este conjunto.
FUNC_VALIDAS = set(range(0, 34)) | {129, 130, 131}
PISO_FUNC_VALIDAS = 0.99

# Para contrastar contra el censo de `dnp3.py`, que escribe los codigos con
# nombre. La medicion de este script no usa esta tabla: solo la comparacion.
NOMBRE = {0: "CONFIRM", 1: "READ", 2: "WRITE", 3: "SELECT", 4: "OPERATE",
          5: "DIRECT_OPERATE", 6: "DIRECT_OPERATE_NR", 7: "IMMED_FREEZE",
          8: "IMMED_FREEZE_NR", 13: "COLD_RESTART", 14: "WARM_RESTART",
          20: "ENABLE_UNSOLICITED", 21: "DISABLE_UNSOLICITED",
          22: "ASSIGN_CLASS", 23: "DELAY_MEASURE",
          24: "RECORD_CURRENT_TIME", 129: "RESPONSE",
          130: "UNSOLICITED_RESPONSE"}

# La divergencia ESPERADA, y es una sola. La lectura A de este script lee los
# desplazamientos sin mirar el bit FIR, a proposito, porque la gracia es no
# depender de haber resuelto bien esa pregunta. De modo que en las tramas de
# continuacion lee octetos de objeto como codigo de funcion, que es el error
# que `dnp3.py` tenia antes de mirar el FIR: las 186 que daban
# UNSOLICITED_RESPONSE falso. Este script tiene que reproducir el numero
# VIEJO de 130, y que la diferencia sea exactamente esa es una confirmacion
# independiente del tamano de aquel error, no un conflicto.
DIVERGENCIA_ESPERADA = {130: 186}

# CRC-16 de DNP3, de la especificacion: polinomio 0x3D65 reflejado, init
# 0x0000, XOR final 0xFFFF. Se construye la tabla aca en lugar de importarla,
# porque importarla seria volver a depender del lector que esto audita.
def _tabla_crc():
    tabla = []
    for byte in range(256):
        crc = byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA6BC if crc & 1 else crc >> 1
        tabla.append(crc)
    return tabla


TABLA = _tabla_crc()


def crc(datos):
    c = 0x0000
    for b in datos:
        c = (c >> 8) ^ TABLA[(c ^ b) & 0xFF]
    return c ^ 0xFFFF


def _u16(b, i):
    return b[i] | (b[i + 1] << 8)


def tramas(buf):
    """Saca de `buf` las tramas de enlace cuyo CRC de cabecera cierra.

    Devuelve (lista de payloads del primer bloque, bytes consumidos,
    cuantas cabeceras cerraron, cuantos primeros bloques cerraron).
    El payload devuelto es el del PRIMER bloque de datos nada mas: es donde
    viven los desplazamientos que interesan.
    """
    salida = []
    i = 0
    n = len(buf)
    cab_ok = 0
    blq_ok = 0
    while True:
        j = buf.find(b"\x05\x64", i)
        if j < 0:
            # Se deja la cola por si un 0x05 quedo al final del segmento.
            i = max(i, n - 1)
            break
        if j + 10 > n:
            i = j
            break
        if crc(buf[j:j + 8]) != _u16(buf, j + 8):
            i = j + 1
            continue
        cab_ok += 1
        largo = buf[j + 2]
        if largo < 5:
            i = j + 2
            continue
        datos = largo - 5                     # octetos de usuario
        bloques = (datos + 15) // 16
        fin = j + 10 + datos + 2 * bloques
        if fin > n:
            i = j
            break
        primero = min(16, datos)
        if primero:
            cuerpo = buf[j + 10:j + 10 + primero]
            if crc(cuerpo) == _u16(buf, j + 10 + primero):
                blq_ok += 1
                salida.append(bytes(cuerpo))
        i = fin
    return salida, i, cab_ok, blq_ok


def revisar(payload, acc):
    """Lee los desplazamientos fijos de las dos maneras y acumula."""
    # A: la lectura correcta. [0] transporte, [1] control, [2] funcion.
    if len(payload) >= 3:
        f = payload[2]
        acc["func_A"][f] = acc["func_A"].get(f, 0) + 1
        if f in FUNC_CONTROL:
            acc["control_A"].append(("func", f, payload[:6].hex()))
        if f == FUNC_WRITE and len(payload) >= 4:
            g = payload[3]
            acc["grupo_write_A"][g] = acc["grupo_write_A"].get(g, 0) + 1
            if g in GRUPOS_CONTROL:
                acc["control_A"].append(("write", g, payload[:6].hex()))
    # B: la lectura del bug del bit FIR. [0] control, [1] funcion.
    if len(payload) >= 2:
        f = payload[1]
        acc["func_B"][f] = acc["func_B"].get(f, 0) + 1
        if f in FUNC_CONTROL:
            acc["control_B"].append(("func", f, payload[:6].hex()))
        if f == FUNC_WRITE and len(payload) >= 3:
            g = payload[2]
            acc["grupo_write_B"][g] = acc["grupo_write_B"].get(g, 0) + 1
            if g in GRUPOS_CONTROL:
                acc["control_B"].append(("write", g, payload[:6].hex()))


def leer(ruta, acc):
    flujos = {}
    with open(ruta, "rb") as fh:
        try:
            pcap = dpkt.pcap.Reader(fh)
        except ValueError:
            return 0
        paquetes = 0
        for _ts, raw in pcap:
            paquetes += 1
            try:
                eth = dpkt.ethernet.Ethernet(raw)
            except dpkt.UnpackError:
                continue
            ip = eth.data
            if not isinstance(ip, dpkt.ip.IP):
                continue
            tcp = ip.data
            if not isinstance(tcp, dpkt.tcp.TCP):
                continue
            if tcp.sport != PUERTO and tcp.dport != PUERTO:
                continue
            if not tcp.data:
                continue
            k = (ip.src, tcp.sport, ip.dst, tcp.dport)
            buf = flujos.get(k)
            if buf is None:
                buf = flujos[k] = bytearray()
            buf += tcp.data
            if len(buf) < 12:
                continue
            payloads, consumido, cab, blq = tramas(buf)
            acc["cabeceras_crc_ok"] += cab
            acc["primer_bloque_crc_ok"] += blq
            for p in payloads:
                revisar(p, acc)
            if consumido:
                del buf[:consumido]
    return paquetes


def main():
    comun.preparar()
    L = []

    def w(s=""):
        L.append(s)

    w("# Pregunta 23 - comandos de control en QUT, sin el lector propio")
    w("")
    w("Generado por `eda/scripts/23_qut_control_independiente.py`.")
    w("Solo tramo `training/`. No importa `dnp3.py`: el CRC y los")
    w("desplazamientos estan reimplementados desde la especificacion.")
    w("")

    acc = {"cabeceras_crc_ok": 0, "primer_bloque_crc_ok": 0,
           "func_A": {}, "func_B": {}, "grupo_write_A": {},
           "grupo_write_B": {}, "control_A": [], "control_B": []}
    archivos = 0
    paquetes = 0
    for _esc, base in ESCENARIOS:
        for sub in ("frequent", "infrequent"):
            patron = os.path.join(comun.QUT, base, sub, "*.pcap")
            for ruta in sorted(glob.glob(patron)):
                archivos += 1
                paquetes += leer(ruta, acc)

    w("## Cuanto se leyo")
    w("")
    w("%-38s %12d" % ("agregados abiertos", archivos))
    w("%-38s %12d" % ("paquetes", paquetes))
    w("%-38s %12d" % ("cabeceras de enlace con CRC valido",
                      acc["cabeceras_crc_ok"]))
    w("%-38s %12d" % ("primeros bloques con CRC valido",
                      acc["primer_bloque_crc_ok"]))
    w("")
    w("El censo de `dnp3.py` publica 2.372.794 tramas de enlace. Este")
    w("recuento no tiene por que coincidir al numero: no reensambla")
    w("fragmentos y descarta la trama cuyo primer bloque no cierra. Lo que")
    w("importa es que sea del mismo orden, porque una diferencia grande")
    w("diria que uno de los dos lectores no esta viendo el mismo trafico.")
    w("")

    w("## Las guardas, antes del resultado")
    w("")
    total_a = sum(acc["func_A"].values())
    buenas = sum(c for f, c in acc["func_A"].items() if f in FUNC_VALIDAS)
    prop = (buenas / total_a) if total_a else 0.0
    g1 = acc["cabeceras_crc_ok"] >= PISO_TRAMAS
    g2 = prop >= PISO_FUNC_VALIDAS
    w("Un resultado negativo se fabrica sin querer: con el CRC mal o los")
    w("desplazamientos corridos, no validaria nada, el recuento daria cero")
    w("y se leeria como confirmacion. Las dos guardas miden que se estaba")
    w("mirando donde hay que mirar.")
    w("")
    w("   %-44s %12d  %s"
      % ("tramas con CRC valido (piso %d)" % PISO_TRAMAS,
         acc["cabeceras_crc_ok"], "pasa" if g1 else "NO PASA"))
    w("   %-44s %11.2f%%  %s"
      % ("funciones dentro de la especificacion (piso %.0f%%)"
         % (100 * PISO_FUNC_VALIDAS), 100 * prop, "pasa" if g2 else "NO PASA"))
    w("")
    if not (g1 and g2):
        w("**No se concluye nada.** Al menos una guarda no pasa, de modo que")
        w("este script no esta leyendo DNP3 donde cree, y un cero suyo no")
        w("dice nada sobre la seccion 1.2.")
        w("")
        comun.escribir("p23_qut_control_independiente.txt", "\n".join(L))
        return 2

    w("## El resultado")
    w("")
    hallados = acc["control_A"] + acc["control_B"]
    if hallados:
        w("**APARECEN comandos de control.** La seccion 1.2 de INFORME.md")
        w("hay que rehacerla. Primeros casos:")
        w("")
        for marca, valor, muestra in hallados[:20]:
            w("   %-6s %3d   primeros octetos: %s" % (marca, valor, muestra))
    else:
        w("**No aparece ni uno, contando de las dos maneras.**")
        w("")
        w("Ni un codigo de funcion SELECT (3), OPERATE (4), DIRECT_OPERATE")
        w("(5) o DIRECT_OPERATE_NR (6), ni un WRITE sobre g12, g40 o g41,")
        w("en ninguna de las dos lecturas de la trama. De modo que la")
        w("ausencia de comandos de control no depende de como `dnp3.py`")
        w("resuelva el bit FIR: no hay interpretacion bajo la cual")
        w("aparezcan.")
    w("")

    w("## Que hay en esas posiciones, entonces")
    w("")
    w("Si la posicion de la funcion no trae comandos, conviene mostrar que")
    w("si trae, porque un histograma vacio o absurdo delataria que los")
    w("desplazamientos estan mal elegidos.")
    w("")
    w("Lectura A (la correcta), codigos de funcion mas frecuentes:")
    w("")
    w("   %6s %12s" % ("func", "tramas"))
    for f, c in sorted(acc["func_A"].items(), key=lambda kv: -kv[1])[:12]:
        w("   %6d %12d" % (f, c))
    w("")
    w("Grupo del primer objeto de cada WRITE (lectura A). Es la atribucion")
    w("que el script 19 declara no poder hacer con lo que habia, y que esta")
    w("pasada si registra, porque lee funcion y grupo juntos:")
    w("")
    w("   %6s %12s" % ("grupo", "escrituras"))
    for g, c in sorted(acc["grupo_write_A"].items(), key=lambda kv: -kv[1]):
        w("   %6d %12d" % (g, c))
    w("")

    w("## Contra el censo del lector del trabajo")
    w("")
    w("La medicion de arriba no usa `dnp3.py`. Esta comparacion si lee su")
    w("salida, porque de eso se trata: dos lectores escritos aparte sobre")
    w("los mismos archivos.")
    w("")
    censo = {}
    fuente = os.path.join(comun.SALIDAS, "p1_qut_payload.json")
    if os.path.exists(fuente):
        with open(fuente) as fh:
            crudo = json.load(fh)

        def recorrer(o):
            if isinstance(o, dict):
                if isinstance(o.get("func_app"), dict):
                    for k, c in o["func_app"].items():
                        censo[k] = censo.get(k, 0) + c
                for v in o.values():
                    recorrer(v)
        recorrer(crudo)
    difiere = {}
    sin_nombre = []
    if not censo:
        w("**No se pudo comparar**: falta `p1_qut_payload.json`. Correr")
        w("`make -C eda p1` y repetir.")
    else:
        w("   %-22s %6s %12s %12s %9s"
          % ("funcion", "cod", "dnp3.py", "este", "difer."))
        for f in sorted(acc["func_A"], key=lambda x: -acc["func_A"][x]):
            nom = NOMBRE.get(f)
            if nom is None:
                sin_nombre.append(f)
                continue
            viejo = censo.get(nom, 0)
            nuevo = acc["func_A"][f]
            if nuevo != viejo:
                difiere[f] = nuevo - viejo
            w("   %-22s %6d %12d %12d %9s"
              % (nom, f, viejo, nuevo,
                 (nuevo - viejo) if nuevo != viejo else "="))
        w("")
        iguales = len(acc["func_A"]) - len(difiere) - len(sin_nombre)
        w("Coinciden exactos %d de %d codigos."
          % (iguales, len(acc["func_A"])))
        w("")
        if difiere == DIVERGENCIA_ESPERADA:
            w("Y la unica diferencia es la esperada: **+%d en"
              % DIVERGENCIA_ESPERADA[130])
            w("UNSOLICITED_RESPONSE**. La lectura A no mira el bit FIR a")
            w("proposito, de modo que en las tramas de continuacion lee")
            w("octetos de objeto como codigo de funcion ---el error que")
            w("`dnp3.py` tenia antes de mirarlo--- y reproduce el numero")
            w("viejo, 151.146 en lugar de 150.960. Que la diferencia sea")
            w("exactamente %d es una confirmacion independiente del tamano"
              % DIVERGENCIA_ESPERADA[130])
            w("de aquel error: dos lectores escritos aparte llegan al mismo")
            w("recuento de tramas de continuacion.")
        else:
            w("**La divergencia no es la esperada.** Se esperaba %s y se"
              % DIVERGENCIA_ESPERADA)
            w("midio %s. Uno de los dos lectores cambio de comportamiento y"
              % (difiere or "ninguna"))
            w("hay que mirarlo antes de confiar en cualquiera de los dos.")
        if sin_nombre:
            w("")
            w("Codigos sin nombre en la tabla de comparacion: %s" % sin_nombre)
    w("")

    comun.escribir("p23_qut_control_independiente.txt", "\n".join(L))
    with open(os.path.join(comun.SALIDAS,
                           "p23_qut_control_independiente.json"), "w") as fh:
        json.dump({
            "agregados": archivos, "paquetes": paquetes,
            "cabeceras_crc_ok": acc["cabeceras_crc_ok"],
            "primer_bloque_crc_ok": acc["primer_bloque_crc_ok"],
            "func_lectura_A": acc["func_A"],
            "func_lectura_B": acc["func_B"],
            "grupo_write_lectura_A": acc["grupo_write_A"],
            "grupo_write_lectura_B": acc["grupo_write_B"],
            "control_lectura_A": acc["control_A"][:200],
            "control_lectura_B": acc["control_B"][:200],
            "hay_control": bool(hallados),
            "guarda_tramas": {"piso": PISO_TRAMAS,
                              "medido": acc["cabeceras_crc_ok"],
                              "pasa": g1},
            "guarda_funciones": {"piso": PISO_FUNC_VALIDAS,
                                 "medido": prop, "pasa": g2},
            "contra_censo_dnp3": {"divergencia": difiere,
                                  "esperada": DIVERGENCIA_ESPERADA,
                                  "es_la_esperada":
                                      difiere == DIVERGENCIA_ESPERADA},
        }, fh, indent=1, ensure_ascii=False)

    # Guarda: si aparecen comandos de control, la seccion 1.2 esta mal y el
    # script tiene que fallar en lugar de dejarlo en un parrafo.
    if hallados:
        return 1
    # Si la divergencia contra el censo deja de ser la unica esperada, uno de
    # los dos lectores cambio y el contraste ya no dice lo que dice.
    if censo and difiere != DIVERGENCIA_ESPERADA:
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
