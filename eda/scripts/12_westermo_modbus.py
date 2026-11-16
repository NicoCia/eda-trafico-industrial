"""Pregunta 12 --- Westermo publica semantica de protocolo de control? (D3)

La tabla de criterios de comparabilidad le asigna a Westermo **D3 = no
cumple**,
es decir, sin semantica de protocolo de control. Esa calificacion no se habia
medido: venia de la ficha del conjunto, que enumera ARP, ICMP, IGMP, LLDP,
RSTP, TCP y UDP sin nombrar ningun protocolo industrial. Una sonda sobre
`reduced/pcaps/bottom.pcap` encontro Modbus/TCP en el puerto 5502, de modo que
hay que medir los seis PCAP antes de dejar la calificacion como esta.

Mide, por archivo (reduced y extended x bottom, left, right):

  1. unidades de datos de aplicacion (ADU) Modbus delimitadas, y validez de la
     cabecera MBAP medida por contabilidad de octetos: cuantos octetos de la
     carga TCP del puerto Modbus entran en una ADU bien formada, cuantos hay
     que saltear para resincronizar y cuantos quedan en el buffer al cerrar la
     captura;
  2. distribucion de codigos de funcion, separando peticion de respuesta.
     **Lo decisivo es si aparece alguna funcion de escritura (5, 6, 15, 16)**:
     eso distingue un conjunto con escrituras de consigna de uno de solo
     lectura, y por lo tanto si D3 se cumple del todo o en parte;
  3. si hay escrituras: cuantas, a que direccion de registro y con que valor;
  4. emparejamiento de peticion y respuesta por identificador de transaccion,
     con la latencia;
  5. mapa de registros leidos y, para las respuestas que se pueden emparejar,
     el valor de los registros devueltos. El conjunto fue generado con ICSSIM
     --- el propio README de Westermo lo dice ---, de modo que se prueba el
     mismo mapa de variables que ya se verifico en ICS-Flow (script 06), con
     dos registros de 16 bits por variable y escala 10000.

Las cifras se informan dos veces: sobre el archivo completo y sobre el tramo
de entrenamiento (`startOffset` < 3265 s, el corte de `comun.WESTERMO_CORTES`),
para no mezclar la pregunta "que publica el conjunto" --- que es de archivo
completo --- con la particion que respeta el resto del EDA.

Reuso de codigo: toda la logica de protocolo sale de `modbus.py` sin tocarlo
--- `adus_del_buffer` delimita, `Adu` y `_interpretar_escritura` interpretan,
`nombre_funcion` nombra ---, y el mapa de variables de ICSSIM se importa de
`06_icsflow_escrituras.py`. Lo unico que se reescribe aca es el recorrido del
PCAP, porque `modbus.leer_pcap` fija el puerto 502 en una constante de modulo
y no lleva la cuenta de octetos que hace falta para medir la validez del MBAP.
El criterio de delimitacion, de interpretacion y de emparejamiento es el mismo.

Uso:  python eda/scripts/12_westermo_modbus.py [max_paquetes]
"""

import collections
import importlib
import json
import os
import socket
import sys

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import comun  # noqa: E402
import modbus  # noqa: E402

# El mapa de variables de ICSSIM ya esta verificado en el script 06 contra las
# cabeceras de snapshots_PLC1.csv y snapshots_PLC2.csv. Se importa en lugar de
# copiarlo para que no puedan divergir.
_icsflow = importlib.import_module("06_icsflow_escrituras")
VARIABLE = _icsflow.VARIABLE
ESCALA = _icsflow.ESCALA
variable_de = _icsflow.variable_de

# Puerto donde la sonda encontro Modbus/TCP en Westermo. ICSSIM usa 5502 en
# lugar del 502 registrado, que es lo que explica que el protocolo no aparezca
# en la ficha del conjunto: un disector que solo mire el 502 no lo ve.
PUERTO_MODBUS = 5502

ARCHIVOS = [(v, p) for v in ("reduced", "extended")
            for p in ("bottom", "left", "right")]

ESCRITURAS = (5, 6, 15, 16, 21, 22, 23)


def recorrer(ruta, puerto, corte=None, max_paquetes=None):
    """Itera las ADU Modbus de un PCAP sobre `puerto`, con contabilidad.

    Replica `modbus.leer_pcap` --- mismo reensamblado por flujo TCP, misma
    delimitacion con `modbus.adus_del_buffer`, misma interpretacion con
    `modbus._interpretar_escritura` --- y agrega dos cosas que esa funcion no
    puede dar: el puerto como parametro y la cuenta de octetos de carga que
    entran en una ADU, que se saltean al resincronizar o que quedan sin cerrar.

    El README del conjunto avisa que un paquete que entra y sale del mismo
    equipo queda grabado dos veces. Por eso se lleva ademas la cuenta de
    copias exactas: un paquete cuya quintupla (IP origen, IP destino, puerto
    origen, puerto destino, numero de secuencia TCP) y carga ya se vieron es
    una copia, no una unidad de dialogo nueva. Se guarda el retardo entre
    copias, que es lo que distingue la duplicacion del punto de captura
    (microsegundos) de una retransmision TCP real (cientos de ms).

    Devuelve tuplas (adu, offset_s, es_copia, contadores); la ultima lleva
    adu = None.
    """
    import dpkt

    flujos = {}
    vistos = {}
    c = {"paquetes": 0, "ip": 0, "tcp": 0, "no_ip": {}, "no_tcp": {},
         "con_carga": 0, "pkt_puerto": 0, "adus": 0,
         "bytes_carga_puerto": 0, "bytes_en_adu": 0, "bytes_salteados": 0,
         "bytes_sin_cerrar": 0, "puertos_con_carga": collections.Counter(),
         "primer_ts": None, "ultimo_ts": None,
         "paquetes_hasta_corte": 0,
         "pkt_puerto_copias": 0, "retardo_copias_ms": []}
    with open(ruta, "rb") as fh:
        pcap = dpkt.pcap.Reader(fh)
        for ts, buf in pcap:
            c["paquetes"] += 1
            if c["primer_ts"] is None:
                c["primer_ts"] = ts
            c["ultimo_ts"] = ts
            off = ts - c["primer_ts"]
            if corte is not None and off < corte:
                c["paquetes_hasta_corte"] += 1
            if max_paquetes and c["paquetes"] > max_paquetes:
                break
            try:
                eth = dpkt.ethernet.Ethernet(buf)
            except Exception:
                continue
            ip = eth.data
            if not isinstance(ip, dpkt.ip.IP):
                k = type(ip).__name__
                c["no_ip"][k] = c["no_ip"].get(k, 0) + 1
                continue
            c["ip"] += 1
            tr = ip.data
            # Hay ICMP y UDP en la captura: hay que descartarlos ANTES de leer
            # un puerto que no existe.
            if not isinstance(tr, dpkt.tcp.TCP):
                k = type(tr).__name__
                c["no_tcp"][k] = c["no_tcp"].get(k, 0) + 1
                continue
            c["tcp"] += 1
            if not tr.data:
                continue
            c["con_carga"] += 1
            c["puertos_con_carga"][min(tr.sport, tr.dport)] += 1
            if puerto not in (tr.sport, tr.dport):
                continue
            c["pkt_puerto"] += 1
            carga = bytes(tr.data)
            c["bytes_carga_puerto"] += len(carga)
            k_dup = (ip.src, ip.dst, tr.sport, tr.dport, tr.seq,
                     hash(carga))
            ts_previo = vistos.get(k_dup)
            es_copia = ts_previo is not None
            if es_copia:
                c["pkt_puerto_copias"] += 1
                if len(c["retardo_copias_ms"]) < 200000:
                    c["retardo_copias_ms"].append((ts - ts_previo) * 1000.0)
            vistos[k_dup] = ts
            clave = (ip.src, ip.dst, tr.sport, tr.dport)
            previo = flujos.get(clave, b"")
            entrada = previo + carga
            adus, resto = modbus.adus_del_buffer(entrada)
            # Contabilidad: de los octetos que el delimitador consumio
            # (entrada menos resto), los que entraron en una ADU bien formada
            # son 8 de cabecera mas el cuerpo; el saldo se salteo para
            # resincronizar, o sea que NO formaba una cabecera MBAP plausible.
            consumidos = len(entrada) - len(resto)
            en_adu = sum(8 + len(d) for _t, _u, _f, d in adus)
            c["bytes_en_adu"] += en_adu
            c["bytes_salteados"] += consumidos - en_adu
            flujos[clave] = resto if len(resto) < 65536 else b""
            if not adus:
                continue
            src = socket.inet_ntoa(ip.src)
            dst = socket.inet_ntoa(ip.dst)
            smac = ":".join("%02x" % b for b in eth.src)
            dmac = ":".join("%02x" % b for b in eth.dst)
            for trans, unidad, funcion, datos in adus:
                a = modbus.Adu()
                a.ts, a.src_ip, a.dst_ip = ts, src, dst
                a.sport, a.dport = tr.sport, tr.dport
                a.src_mac, a.dst_mac = smac, dmac
                a.transaccion, a.unidad, a.funcion, a.datos = (
                    trans, unidad, funcion, datos)
                a.es_peticion = (tr.dport == puerto)
                if funcion & 0x80:
                    a.excepcion = datos[0] if datos else None
                elif a.es_peticion:
                    modbus._interpretar_escritura(a)
                c["adus"] += 1
                yield a, off, es_copia, c
    c["bytes_sin_cerrar"] = sum(len(v) for v in flujos.values())
    c["flujos_puerto"] = len(flujos)
    yield None, None, False, c


TOPE_CONTRASTE = 600000


def contraste_puertos(ruta, puertos, tope=TOPE_CONTRASTE):
    """Corre el delimitador MBAP sobre puertos que NO son el de Modbus.

    Es el control de la medida de validez: si la contabilidad de octetos
    diese un numero alto en cualquier flujo, no mediria nada. Se limita a
    los primeros `tope` paquetes de cada archivo, porque es un control y no
    una medicion del conjunto; el tope queda escrito en la salida.
    """
    import dpkt

    bufs = {}
    acc = {p: {"bytes": 0, "en_adu": 0, "salteados": 0, "muestra": b""}
           for p in puertos}
    if not puertos:
        return acc, 0
    n = 0
    with open(ruta, "rb") as fh:
        for _ts, buf in dpkt.pcap.Reader(fh):
            n += 1
            if n > tope:
                break
            try:
                eth = dpkt.ethernet.Ethernet(buf)
            except Exception:
                continue
            ip = eth.data
            if not isinstance(ip, dpkt.ip.IP):
                continue
            tr = ip.data
            if not isinstance(tr, dpkt.tcp.TCP) or not tr.data:
                continue
            p = min(tr.sport, tr.dport)
            if p not in acc:
                continue
            carga = bytes(tr.data)
            a = acc[p]
            if not a["muestra"]:
                a["muestra"] = carga[:40]
            k = (ip.src, ip.dst, tr.sport, tr.dport)
            entrada = bufs.get(k, b"") + carga
            adus, resto = modbus.adus_del_buffer(entrada)
            consumidos = len(entrada) - len(resto)
            en_adu = sum(8 + len(d) for _t, _u, _f, d in adus)
            a["bytes"] += len(carga)
            a["en_adu"] += en_adu
            a["salteados"] += consumidos - en_adu
            bufs[k] = resto if len(resto) < 65536 else b""
    for a in acc.values():
        a["frac_en_adu"] = (a["en_adu"] / a["bytes"]) if a["bytes"] else None
        a["muestra"] = repr(a["muestra"])
    return acc, min(n, tope)


def registros_de(datos):
    """Valores de 16 bits de una respuesta de lectura (funcion 1..4).

    El cuerpo es: cuenta de octetos(1) + los octetos. Devuelve None si la
    cuenta declarada no cierra contra el largo real, que es justamente la
    comprobacion que interesa para decir si la carga es interpretable.
    """
    if not datos:
        return None
    n = datos[0]
    cuerpo = datos[1:]
    if n != len(cuerpo):
        return None
    return [int.from_bytes(cuerpo[i:i + 2], "big")
            for i in range(0, len(cuerpo) - 1, 2)]


def analizar(ruta, corte, max_paquetes=None):
    """Mide un PCAP y devuelve el diccionario de resultados."""
    r = {"archivo": comun.rel(ruta)}
    fn_pet = collections.Counter()
    fn_resp = collections.Counter()
    fn_pet_tr = collections.Counter()
    fn_resp_tr = collections.Counter()
    unidades = collections.Counter()
    servidores = collections.Counter()
    pares = collections.Counter()
    lecturas = collections.Counter()      # (dst, direccion, cantidad)
    escrituras = []
    excepciones = collections.Counter()
    pend = {}
    latencias = []
    lat_tr = []
    # Respuestas de lectura emparejadas: se decodifican los registros con el
    # mapa de ICSSIM y se acumula el rango por variable.
    valores_por_var = collections.defaultdict(list)
    resp_cuenta_ok = 0
    resp_cuenta_mal = 0

    fn_pet_u = collections.Counter()
    fn_resp_u = collections.Counter()
    esc_u = 0

    cont = None
    for adu, off, es_copia, c in recorrer(ruta, PUERTO_MODBUS, corte,
                                          max_paquetes):
        if adu is None:
            cont = c
            break
        en_tr = off < corte
        if not es_copia:
            if adu.es_peticion:
                fn_pet_u[adu.nombre] += 1
                if adu.funcion in ESCRITURAS:
                    esc_u += 1
            else:
                fn_resp_u[adu.nombre] += 1
        if adu.funcion & 0x80:
            excepciones[(modbus.nombre_funcion(adu.funcion),
                         adu.excepcion)] += 1
        unidades[adu.unidad] += 1
        if adu.es_peticion:
            fn_pet[adu.nombre] += 1
            if en_tr:
                fn_pet_tr[adu.nombre] += 1
            servidores[adu.dst_ip] += 1
            pares[(adu.src_ip, adu.dst_ip)] += 1
            pend[(adu.src_ip, adu.dst_ip, adu.transaccion)] = (adu, off)
            if adu.funcion in (1, 2, 3, 4) and len(adu.datos) >= 4:
                direccion = int.from_bytes(adu.datos[0:2], "big")
                cantidad = int.from_bytes(adu.datos[2:4], "big")
                lecturas[(adu.dst_ip, direccion, cantidad)] += 1
            elif adu.funcion in ESCRITURAS:
                escrituras.append({
                    "off": off, "en_entrenamiento": bool(en_tr),
                    "src": adu.src_ip, "dst": adu.dst_ip,
                    "unidad": adu.unidad, "funcion": adu.funcion,
                    "nombre": adu.nombre, "direccion": adu.direccion,
                    "cantidad": adu.cantidad, "valor32": adu.valor32,
                    "valores": list(adu.valores)[:8],
                })
        else:
            fn_resp[adu.nombre] += 1
            if en_tr:
                fn_resp_tr[adu.nombre] += 1
            k = (adu.dst_ip, adu.src_ip, adu.transaccion)
            previo = pend.pop(k, None)
            if previo is not None:
                pet, poff = previo
                latencias.append(adu.ts - pet.ts)
                if en_tr:
                    lat_tr.append(adu.ts - pet.ts)
                if (adu.funcion in (1, 2, 3, 4)
                        and pet.funcion == adu.funcion
                        and len(pet.datos) >= 4):
                    regs = registros_de(adu.datos)
                    if regs is None:
                        resp_cuenta_mal += 1
                    else:
                        resp_cuenta_ok += 1
                        base = int.from_bytes(pet.datos[0:2], "big")
                        # ICSSIM reparte cada variable en dos registros de 16
                        # bits, el mas significativo primero.
                        for i in range(0, len(regs) - 1, 2):
                            dirv = base + i
                            idx, nombre = variable_de(dirv)
                            if nombre is None:
                                continue
                            v32 = (regs[i] << 16) | regs[i + 1]
                            valores_por_var[(adu.src_ip, dirv, idx, nombre)] \
                                .append(v32 / ESCALA)

    retardos = cont.pop("retardo_copias_ms", [])
    r["copias"] = {
        "pkt_puerto": cont["pkt_puerto"],
        "copias": cont["pkt_puerto_copias"],
        "frac_copias": (cont["pkt_puerto_copias"] / cont["pkt_puerto"]
                        if cont["pkt_puerto"] else None),
        "retardo_mediana_ms": (float(np.median(retardos)) if retardos
                               else None),
        "retardo_p95_ms": (float(np.percentile(retardos, 95)) if retardos
                           else None),
        "retardos_muestreados": len(retardos),
    }
    r["contadores"] = {k: (dict(v) if isinstance(v, collections.Counter)
                           else v)
                       for k, v in cont.items()}
    r["funciones_peticion_unicas"] = dict(fn_pet_u.most_common())
    r["funciones_respuesta_unicas"] = dict(fn_resp_u.most_common())
    r["escrituras_n_unicas"] = esc_u
    r["duracion_s"] = (cont["ultimo_ts"] - cont["primer_ts"]
                       if cont["primer_ts"] else None)
    r["corte_entrenamiento_s"] = corte
    r["paquetes_hasta_corte"] = cont["paquetes_hasta_corte"]
    r["funciones_peticion"] = dict(fn_pet.most_common())
    r["funciones_respuesta"] = dict(fn_resp.most_common())
    r["funciones_peticion_entrenamiento"] = dict(fn_pet_tr.most_common())
    r["funciones_respuesta_entrenamiento"] = dict(fn_resp_tr.most_common())
    r["escrituras"] = escrituras
    r["escrituras_n"] = len(escrituras)
    r["escrituras_n_entrenamiento"] = sum(
        1 for e in escrituras if e["en_entrenamiento"])
    r["excepciones"] = {"%s / codigo %s" % (n, cod): v
                        for (n, cod), v in excepciones.most_common()}
    r["unidades"] = dict(unidades.most_common())
    r["servidores"] = dict(servidores.most_common())
    r["pares"] = {"%s -> %s" % (s, d): n for (s, d), n in pares.most_common()}
    r["lecturas_por_registro"] = {
        "%s dir=%d cant=%d" % (d, a, q): n
        for (d, a, q), n in lecturas.most_common()}
    r["emparejadas"] = len(latencias)
    r["emparejadas_entrenamiento"] = len(lat_tr)
    r["sin_emparejar"] = len(pend)
    if latencias:
        lv = np.array(latencias) * 1000.0
        r["latencia_ms"] = {
            "mediana": float(np.median(lv)), "p05": float(np.percentile(lv, 5)),
            "p95": float(np.percentile(lv, 95)), "min": float(lv.min()),
            "max": float(lv.max()),
            "cv": float(lv.std() / lv.mean()) if lv.mean() else None}
    if lat_tr:
        lv = np.array(lat_tr) * 1000.0
        r["latencia_ms_entrenamiento"] = {"mediana": float(np.median(lv)),
                                          "p95": float(np.percentile(lv, 95))}
    r["respuestas_lectura_cuenta_ok"] = resp_cuenta_ok
    r["respuestas_lectura_cuenta_mal"] = resp_cuenta_mal
    detalle = {}
    for (srv, dirv, idx, nombre), vs in sorted(valores_por_var.items()):
        a = np.array(vs)
        detalle["%s dir=%d" % (srv, dirv)] = {
            "variable_idx": idx, "variable": nombre, "muestras": int(a.size),
            "distintos": int(np.unique(a).size),
            "min": float(a.min()), "max": float(a.max()),
            "mediana": float(np.median(a))}
    r["variables_leidas"] = detalle
    b = cont["bytes_carga_puerto"]
    r["mbap"] = {
        "bytes_carga": b,
        "bytes_en_adu": cont["bytes_en_adu"],
        "bytes_salteados": cont["bytes_salteados"],
        "bytes_sin_cerrar": cont["bytes_sin_cerrar"],
        "frac_en_adu": (cont["bytes_en_adu"] / b) if b else None,
        "frac_salteados": (cont["bytes_salteados"] / b) if b else None,
    }
    return r


def imprimir(r, w):
    c = r["contadores"]
    w("### %s" % r["archivo"])
    w("")
    w("Paquetes: %d  |  IP %d  |  TCP %d  |  TCP con carga %d  |  "
      "puerto %d: %d" % (c["paquetes"], c["ip"], c["tcp"], c["con_carga"],
                         PUERTO_MODBUS, c["pkt_puerto"]))
    w("Duracion de la captura: %.0f s. Paquetes antes del corte de "
      "entrenamiento (%.0f s): %d (%.1f %% del archivo)."
      % (r["duracion_s"], r["corte_entrenamiento_s"],
         r["paquetes_hasta_corte"],
         100.0 * r["paquetes_hasta_corte"] / c["paquetes"]))
    if c["no_ip"]:
        w("Tramas que no son IP: %s" % c["no_ip"])
    if c["no_tcp"]:
        w("Paquetes IP que no son TCP: %s" % c["no_tcp"])
    w("Puertos TCP con carga (servicio = menor de los dos): %s"
      % dict(collections.Counter(c["puertos_con_carga"]).most_common(8)))
    w("")
    if r.get("contraste"):
        w("Control de la medida: el mismo delimitador MBAP corrido sobre los")
        w("OTROS puertos con carga, en los primeros %d paquetes del archivo."
          % r.get("contraste_paquetes", 0))
        w("Si la contabilidad de octetos no distinguiera Modbus de cualquier")
        w("otro flujo, el 100 %s del puerto 5502 no mediria nada." % "%")
        w("   %-8s %12s %12s %10s  %s"
          % ("puerto", "octetos", "en ADU", "en ADU %", "primeros octetos"))
        for p, a in sorted(r["contraste"].items(),
                           key=lambda kv: -kv[1]["bytes"]):
            if not a["bytes"]:
                continue
            w("   %-8d %12d %12d %9.2f  %s"
              % (p, a["bytes"], a["en_adu"], 100.0 * a["frac_en_adu"],
                 a["muestra"][:46]))
        w("")
    w("ADU Modbus delimitadas: **%d**" % c["adus"])
    m = r["mbap"]
    if m["bytes_carga"]:
        w("Validez de la cabecera MBAP, por contabilidad de octetos sobre la")
        w("carga TCP del puerto %d:" % PUERTO_MODBUS)
        w("   octetos de carga        %12d" % m["bytes_carga"])
        w("   dentro de una ADU valida%12d  (%.4f %%)"
          % (m["bytes_en_adu"], 100.0 * m["frac_en_adu"]))
        w("   salteados al resincronizar%10d  (%.4f %%)"
          % (m["bytes_salteados"], 100.0 * m["frac_salteados"]))
        w("   sin cerrar al final de la captura %4d  (en %d flujos)"
          % (m["bytes_sin_cerrar"], c.get("flujos_puerto", 0)))
        w("   Un octeto salteado es un octeto que NO formaba una cabecera")
        w("   MBAP plausible (identificador de protocolo 0 y longitud entre")
        w("   2 y 254). Cero salteados = el flujo entero se lee como Modbus.")
    else:
        w("No hay carga TCP en el puerto %d: **no hay Modbus en este "
          "archivo**." % PUERTO_MODBUS)
        w("")
        return
    w("")
    cp = r["copias"]
    w("Copias exactas en el punto de captura: %d de %d paquetes del puerto"
      % (cp["copias"], cp["pkt_puerto"]))
    w("%d (%.1f %%). Retardo entre copias: mediana %s ms, p95 %s ms"
      % (PUERTO_MODBUS, 100.0 * cp["frac_copias"],
         "%.4f" % cp["retardo_mediana_ms"]
         if cp["retardo_mediana_ms"] is not None else "n/d",
         "%.4f" % cp["retardo_p95_ms"]
         if cp["retardo_p95_ms"] is not None else "n/d"))
    w("   Es la duplicacion que avisa el README: el mismo paquete grabado al")
    w("   entrar y al salir del equipo. Un retardo de microsegundos no es")
    w("   una retransmision TCP. Las columnas `unicas` descuentan esas")
    w("   copias y son las que cuentan unidades de dialogo.")
    w("")
    w("Codigos de funcion (archivo completo):")
    w("   %-30s %10s %10s %10s %10s"
      % ("funcion", "peticion", "pet. unic.", "respuesta", "resp. unic."))
    claves = list(r["funciones_peticion"])
    claves += [k for k in r["funciones_respuesta"] if k not in claves]
    for k in claves:
        w("   %-30s %10d %10d %10d %10d"
          % (k, r["funciones_peticion"].get(k, 0),
             r["funciones_peticion_unicas"].get(k, 0),
             r["funciones_respuesta"].get(k, 0),
             r["funciones_respuesta_unicas"].get(k, 0)))
    w("")
    w("Codigos de funcion (solo tramo de entrenamiento, sin descontar "
      "copias):")
    w("   %-34s %10s %10s" % ("funcion", "peticion", "respuesta"))
    for k in claves:
        w("   %-34s %10d %10d"
          % (k, r["funciones_peticion_entrenamiento"].get(k, 0),
             r["funciones_respuesta_entrenamiento"].get(k, 0)))
    w("")
    if r["escrituras_n"]:
        w("**ESCRITURAS: %d** (%d en el tramo de entrenamiento)"
          % (r["escrituras_n"], r["escrituras_n_entrenamiento"]))
        por = collections.Counter(
            (e["dst"], e["funcion"], e["direccion"]) for e in r["escrituras"])
        w("   %-16s %8s %8s %8s  %s"
          % ("destino", "funcion", "dir.", "escrit.", "valores"))
        for (dst, fn, dirv), n in por.most_common():
            vs = [e["valor32"] if e["valor32"] is not None else e["valores"]
                  for e in r["escrituras"]
                  if (e["dst"], e["funcion"], e["direccion"]) == (dst, fn, dirv)]
            idx, nombre = variable_de(dirv) if dirv is not None else (None, None)
            w("   %-16s %8d %8s %8d  %s  %s"
              % (dst, fn, dirv, n, str(vs[:6]), nombre or ""))
    else:
        w("**No hay ninguna peticion de escritura (funciones 5, 6, 15, 16,")
        w("21, 22, 23) en todo el archivo.** El dialogo es de solo lectura.")
    w("")
    if r["excepciones"]:
        w("Respuestas de excepcion: %s" % r["excepciones"])
    w("Identificadores de unidad: %s" % r["unidades"])
    w("Servidores Modbus (destino de las peticiones): %s" % r["servidores"])
    w("Pares cliente -> servidor: %s" % r["pares"])
    w("")
    w("El emparejamiento que sigue recorre el flujo CON copias: cuenta cada")
    w("vez que una respuesta encuentra su peticion pendiente. Las dos copias")
    w("de una peticion escriben la misma clave y la primera copia de la")
    w("respuesta la consume, de modo que el total queda cerca del numero de")
    w("dialogos sin ser igual --- da unos pocos mas que las peticiones")
    w("unicas de la tabla de arriba, y a que interleavings se deben esos")
    w("pocos no se midio ---. No es un recuento de mensajes; para")
    w("eso estan las columnas `unicas`. Para la latencia da lo mismo, porque")
    w("son los mismos dialogos.")
    w("")
    w("Emparejamiento de peticion y respuesta por (origen, destino,")
    w("identificador de transaccion): %d emparejadas, %d peticiones sin"
      % (r["emparejadas"], r["sin_emparejar"]))
    w("respuesta al cerrar la captura.")
    if "latencia_ms" in r:
        la = r["latencia_ms"]
        w("Latencia de respuesta: mediana %.2f ms, p05 %.2f, p95 %.2f, "
          "min %.2f, max %.2f, CV %.2f"
          % (la["mediana"], la["p05"], la["p95"], la["min"], la["max"],
             la["cv"]))
    if "latencia_ms_entrenamiento" in r:
        la = r["latencia_ms_entrenamiento"]
        w("   solo entrenamiento (%d pares): mediana %.2f ms, p95 %.2f"
          % (r["emparejadas_entrenamiento"], la["mediana"], la["p95"]))
    w("")
    w("Mapa de registros leidos (destino, direccion de inicio, cantidad):")
    for k, n in list(r["lecturas_por_registro"].items())[:15]:
        w("   %-34s %10d peticiones" % (k, n))
    if len(r["lecturas_por_registro"]) > 15:
        w("   ... y %d combinaciones mas"
          % (len(r["lecturas_por_registro"]) - 15))
    w("")
    w("Respuestas de lectura con la cuenta de octetos coherente: %d; "
      "incoherente: %d" % (r["respuestas_lectura_cuenta_ok"],
                           r["respuestas_lectura_cuenta_mal"]))
    if r["variables_leidas"]:
        w("")
        w("Valores devueltos, decodificados con el mapa de ICSSIM (dos")
        w("registros de 16 bits por variable, el mas significativo primero,")
        w("escala %.0f). Es el mismo mapa que el script 06 verifico en"
          % ESCALA)
        w("ICS-Flow contra las cabeceras de snapshots_PLC*.csv:")
        w("   %-22s %-28s %9s %9s %10s %10s %10s"
          % ("servidor / registro", "variable", "muestras", "distintos",
             "min", "mediana", "max"))
        for k, v in r["variables_leidas"].items():
            w("   %-22s %-28s %9d %9d %10.4f %10.4f %10.4f"
              % (k, "(%s) %s" % (v["variable_idx"], v["variable"]),
                 v["muestras"], v["distintos"], v["min"], v["mediana"],
                 v["max"]))
    w("")


def main():
    comun.preparar()
    tope = int(sys.argv[1]) if len(sys.argv) > 1 else 0
    tope = tope or None
    corte = comun.WESTERMO_CORTES[0]

    L = []
    w = L.append
    w("# Pregunta 12 - Westermo publica semantica de protocolo de control?")
    w("")
    w("La tabla de criterios de comparabilidad le asigna a Westermo D3 = no")
    w("cumple. Esa calificacion no estaba medida: sale de la ficha del")
    w("conjunto, que enumera ARP, ICMP, IGMP, LLDP, RSTP, TCP y UDP sin")
    w("nombrar ningun protocolo industrial. Aca se delimita Modbus/TCP sobre")
    w("el puerto %d en los seis PCAP." % PUERTO_MODBUS)
    w("")
    w("Que decide que: si solo hay funcion 3 (lectura de registros), el")
    w("conjunto publica carga util interpretable pero no escrituras de")
    w("consigna, y D3 se cumple en parte. Si aparece alguna funcion de")
    w("escritura (5, 6, 15, 16), se cumple del todo.")
    w("")
    w("Corte de entrenamiento: %.0f s (comun.WESTERMO_CORTES[0]), medido "
      "desde el primer paquete de cada archivo." % corte)
    w("")

    resultados = {}
    for variante, punto in ARCHIVOS:
        ruta = os.path.join(comun.WESTERMO, variante, "pcaps",
                            "%s.pcap" % punto)
        if not os.path.exists(ruta):
            w("### %s/%s: no existe" % (variante, punto))
            continue
        print("  leyendo %s" % comun.rel(ruta), file=sys.stderr)
        r = analizar(ruta, corte, tope)
        otros = [p for p in r["contadores"]["puertos_con_carga"]
                 if p != PUERTO_MODBUS]
        if otros:
            print("  contraste de puertos en %s" % comun.rel(ruta),
                  file=sys.stderr)
            r["contraste"], r["contraste_paquetes"] = contraste_puertos(
                ruta, otros)
        clave = "%s_%s" % (variante, punto)
        resultados[clave] = r
        w("## %s / %s" % (variante, punto))
        w("")
        imprimir(r, w)

    # ------------------------------- resumen -------------------------------
    w("## Resumen")
    w("")
    w("%-10s %-8s %12s %12s %10s %10s %10s %9s %9s"
      % ("variante", "punto", "paquetes", "ADU Modbus", "ADU unicas",
         "pet. fn3", "resp. fn3", "escrit.", "MBAP mal"))
    tot_adus = tot_esc = tot_unicas = 0
    for clave, r in resultados.items():
        variante, punto = clave.split("_", 1)
        c = r["contadores"]
        f3p = r["funciones_peticion"].get("Read Holding Registers", 0)
        f3r = r["funciones_respuesta"].get("Read Holding Registers", 0)
        unicas = (sum(r["funciones_peticion_unicas"].values())
                  + sum(r["funciones_respuesta_unicas"].values()))
        w("%-10s %-8s %12d %12d %10d %10d %10d %9d %9d"
          % (variante, punto, c["paquetes"], c["adus"], unicas, f3p, f3r,
             r["escrituras_n"], r["mbap"]["bytes_salteados"]))
        tot_adus += c["adus"]
        tot_unicas += unicas
        tot_esc += r["escrituras_n"]
    w("")
    w("Total de ADU Modbus observadas en los seis archivos: %d" % tot_adus)
    w("Total descontando las copias del punto de captura: %d" % tot_unicas)
    w("Total de peticiones de escritura en los seis archivos: **%d**"
      % tot_esc)
    w("")
    todas = collections.Counter()
    for r in resultados.values():
        todas.update(r["funciones_peticion"])
        todas.update(r["funciones_respuesta"])
    w("Repertorio de funciones Modbus en todo el conjunto (peticion y")
    w("respuesta sumadas): %s" % dict(todas.most_common()))
    w("")
    if tot_esc == 0:
        w("**Westermo NO tiene escrituras de consigna.** El unico codigo de")
        w("funcion presente es el 3, lectura de registros de retencion. El")
        w("conjunto publica carga util Modbus interpretable --- cabecera")
        w("MBAP, codigo de funcion, direccion de registro, cantidad y los")
        w("valores devueltos ---, pero el dialogo es de solo lectura: no hay")
        w("ningun comando con parametro que un atacante pueda manipular.")
    else:
        w("**Westermo SI tiene escrituras de consigna**: %d peticiones de "
          "escritura. Ver el detalle por archivo." % tot_esc)
    w("")
    w("Ojo con los duplicados: el propio README advierte que un paquete que")
    w("entra y sale del mismo equipo aparece dos veces, de modo que los")
    w("conteos de ADU no son unidades de dialogo distintas sino unidades")
    w("observadas en el punto de captura.")

    comun.escribir("p12_westermo_modbus.txt", "\n".join(L))
    with open(os.path.join(comun.SALIDAS, "p12_westermo_modbus.json"),
              "w") as fh:
        json.dump(resultados, fh, indent=1, ensure_ascii=False, default=str)
    return 0


if __name__ == "__main__":
    sys.exit(main())
