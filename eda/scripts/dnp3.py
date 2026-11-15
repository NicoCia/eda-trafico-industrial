"""Lector de DNP3 sobre TCP, escrito sobre dpkt (Python puro, sin tshark).

Implementa lo necesario para el analisis exploratorio:

* reensamblado por flujo TCP y busqueda de tramas de enlace DNP3 (0x05 0x64),
* verificacion del CRC de enlace, que es lo que permite afirmar que una trama
  es DNP3 real y no una coincidencia de dos bytes,
* extraccion de la capa de aplicacion (codigo de funcion, control, IIN) y de
  las cabeceras de objeto (grupo, variacion, calificador, rango),
* decodificacion de los parametros de los comandos de control CROB (grupo 12)
  y de salida analogica (grupo 41).

LO QUE NO HACE, Y HAY QUE SABERLO ANTES DE REUSARLO
---------------------------------------------------
**No reensambla fragmentos de aplicacion repartidos en varias tramas de
enlace.** La cabecera de aplicacion (control, codigo de funcion, IIN) vive
solo en la trama que abre el fragmento, la que trae FIR=1. Este lector mira
ese bit y **no interpreta** las tramas de continuacion: las cuenta en
`sin_cabecera_app` y sigue. Un fragmento repartido queda, entonces, leido a
medias --- se ven sus objetos hasta donde llega la primera trama ---, y eso es
preferible a lo que hacia antes, que era leer los octetos 1 y 2 de una trama
de continuacion como si fueran control de aplicacion y codigo de funcion, con
lo que inventaba una funcion y una cabecera de objeto por trama.

Sobre el tramo de entrenamiento de QUT el caso es raro y vale dejar la cifra:
de 2.372.108 tramas, 2.371.922 son fragmento unico (FIR=1 y FIN=1) y **186**
--- el 0,008 % --- son de continuacion. No hay ni una trama de apertura de
fragmento multiple (FIR=1, FIN=0) ni de cierre (FIR=0, FIN=1), de modo que
esas 186 no son fragmentos bien formados; aparecen solo en los escenarios de
ataque (Attacks, Flooding, Masqurading y Replay) y ninguna en Control,
Injection ni MITM, que es lo esperable de trafico DNP3 fabricado.

Referencia de formato: IEEE 1815-2012.
"""

import struct

# --- CRC de DNP3: polinomio 0x3D65 reflejado, init 0x0000, xor final 0xFFFF ---

def _build_crc_table():
    table = []
    for i in range(256):
        crc = i
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA6BC if crc & 1 else crc >> 1
        table.append(crc)
    return table


_CRC_TABLE = _build_crc_table()


def crc(data):
    value = 0x0000
    for byte in data:
        value = (value >> 8) ^ _CRC_TABLE[(value ^ byte) & 0xFF]
    return value ^ 0xFFFF


# --- Diccionarios de la norma ---

FUNC_APP = {
    0: "CONFIRM", 1: "READ", 2: "WRITE", 3: "SELECT", 4: "OPERATE",
    5: "DIRECT_OPERATE", 6: "DIRECT_OPERATE_NR", 7: "IMMED_FREEZE",
    8: "IMMED_FREEZE_NR", 9: "FREEZE_CLEAR", 10: "FREEZE_CLEAR_NR",
    11: "FREEZE_AT_TIME", 12: "FREEZE_AT_TIME_NR", 13: "COLD_RESTART",
    14: "WARM_RESTART", 15: "INITIALIZE_DATA", 16: "INITIALIZE_APPL",
    17: "START_APPL", 18: "STOP_APPL", 19: "SAVE_CONFIG",
    20: "ENABLE_UNSOLICITED", 21: "DISABLE_UNSOLICITED", 22: "ASSIGN_CLASS",
    23: "DELAY_MEASURE", 24: "RECORD_CURRENT_TIME", 25: "OPEN_FILE",
    26: "CLOSE_FILE", 27: "DELETE_FILE", 28: "GET_FILE_INFO",
    29: "AUTHENTICATE_FILE", 30: "ABORT_FILE", 31: "ACTIVATE_CONFIG",
    32: "AUTHENTICATE_REQ", 33: "AUTH_REQ_NO_ACK",
    129: "RESPONSE", 130: "UNSOLICITED_RESPONSE", 131: "AUTHENTICATE_RESP",
}

FUNC_LINK_PRI = {
    0: "RESET_LINK_STATES", 1: "RESET_USER_PROCESS", 2: "TEST_LINK_STATES",
    3: "CONFIRMED_USER_DATA", 4: "UNCONFIRMED_USER_DATA",
    9: "REQUEST_LINK_STATUS",
}

FUNC_LINK_SEC = {0: "ACK", 1: "NACK", 11: "LINK_STATUS", 15: "NOT_SUPPORTED"}

CROB_CODE = {
    0: "NUL", 1: "PULSE_ON", 2: "PULSE_OFF", 3: "LATCH_ON", 4: "LATCH_OFF",
}

# Longitud del campo de rango segun el codigo especificador (bits 3..0 del
# calificador). None = formato variable, no se puede saltear a ciegas.
_RANGE_LEN = {0: 2, 1: 4, 2: 8, 3: 2, 4: 4, 5: 8, 6: 0, 7: 1, 8: 2, 9: 4,
              11: 1}

# Longitud del prefijo por objeto segun bits 6..4 del calificador.
_PREFIX_LEN = {0: 0, 1: 1, 2: 2, 3: 4, 4: 1, 5: 2, 6: 4}


class Frame(object):
    """Una trama de enlace DNP3 ya validada por CRC y sin los CRC intermedios."""

    __slots__ = ("ts", "src_ip", "dst_ip", "sport", "dport", "length",
                 "control", "dest", "source", "link_dir", "link_prm",
                 "link_func", "transport", "app_control", "func", "iin",
                 "objects", "app_seq", "payload", "truncated",
                 "bloques_ok", "bloques_total", "fir", "fin")

    def __init__(self):
        self.objects = []
        self.iin = None
        self.func = None
        self.app_control = None
        self.app_seq = None
        self.transport = None
        self.payload = b""
        self.truncated = False
        self.bloques_ok = 0
        self.bloques_total = 0
        self.fir = False
        self.fin = False

    @property
    def func_name(self):
        return FUNC_APP.get(self.func, "DESCONOCIDO_%s" % self.func)

    @property
    def link_func_name(self):
        table = FUNC_LINK_PRI if self.link_prm else FUNC_LINK_SEC
        return table.get(self.link_func, "LINK_%s" % self.link_func)

    @property
    def is_response(self):
        return self.func in (129, 130, 131)


def _strip_crcs(body):
    """Quita los CRC de bloque. Devuelve (datos, bloques_ok, bloques_total)."""
    out = bytearray()
    ok = 0
    total = 0
    i = 0
    n = len(body)
    while i < n:
        # Cada bloque son hasta 16 octetos de datos seguidos de 2 de CRC: el
        # ultimo bloque es corto, de modo que el largo de datos sale de lo que
        # queda menos los dos octetos del CRC.
        dlen = min(16, n - i - 2)
        if dlen <= 0:
            total += 1
            break
        block = body[i:i + dlen]
        tail = body[i + dlen:i + dlen + 2]
        total += 1
        if crc(block) == struct.unpack("<H", tail)[0]:
            ok += 1
        out += block
        i += dlen + 2
    return bytes(out), ok, total


def parse_object_headers(app, start):
    """Lee las cabeceras de objeto desde `start`.

    Devuelve una lista de diccionarios. Cuando el tamano del cuerpo del objeto
    no se puede derivar del calificador, se marca `completo=False` y se corta:
    es preferible reportar menos cabeceras que inventar un salto.
    """
    objs = []
    i = start
    n = len(app)
    while i + 3 <= n:
        group = app[i]
        var = app[i + 1]
        qual = app[i + 2]
        i += 3
        prefix_code = (qual >> 4) & 0x07
        range_code = qual & 0x0F
        rlen = _RANGE_LEN.get(range_code)
        if rlen is None or i + rlen > n:
            objs.append({"grupo": group, "variacion": var, "calificador": qual,
                         "completo": False})
            break
        raw_range = app[i:i + rlen]
        i += rlen

        start_idx = stop_idx = count = None
        if range_code in (0, 1, 2):
            half = rlen // 2
            start_idx = int.from_bytes(raw_range[:half], "little")
            stop_idx = int.from_bytes(raw_range[half:], "little")
            count = stop_idx - start_idx + 1
        elif range_code in (3, 4, 5):
            half = rlen // 2
            start_idx = int.from_bytes(raw_range[:half], "little")
            stop_idx = int.from_bytes(raw_range[half:], "little")
            count = stop_idx - start_idx + 1
        elif range_code in (7, 8, 9, 11):
            count = int.from_bytes(raw_range, "little")
        elif range_code == 6:
            count = None  # todos los objetos

        header = {"grupo": group, "variacion": var, "calificador": qual,
                  "prefijo": prefix_code, "rango": range_code,
                  "indice_inicial": start_idx, "indice_final": stop_idx,
                  "cantidad": count, "completo": True, "valores": []}

        if range_code == 6:
            # "Todos los objetos": la cabecera no lleva cuerpo. Es el caso de
            # las lecturas por clase (grupo 60), y esta completa tal cual.
            objs.append(header)
            continue

        if count is not None and _es_empaquetado(group, var):
            # Formatos empaquetados: el cuerpo es un mapa de bits comun, no un
            # cuerpo por objeto. El ancho por punto depende del grupo.
            ancho = _bits_por_punto(group, var)
            nbytes = (count * ancho + 7) // 8
            if i + nbytes > n:
                header["completo"] = False
                objs.append(header)
                break
            bits = app[i:i + nbytes]
            i += nbytes
            mascara = (1 << ancho) - 1
            for k in range(count):
                punto = None if start_idx is None else start_idx + k
                desde = k * ancho
                valor = (bits[desde // 8] >> (desde % 8)) & mascara
                header["valores"].append({
                    "punto": punto,
                    "tipo": "g%dv%d_bit%d" % (group, var, ancho),
                    "valor": valor})
            objs.append(header)
            continue

        body_len = _object_body_len(group, var)
        if count is None or body_len is None or range_code == 11:
            # No se puede recorrer el cuerpo con seguridad: se deja la cabecera
            # y se corta el barrido de esta trama.
            header["completo"] = False
            objs.append(header)
            break

        plen = _PREFIX_LEN.get(prefix_code, 0)
        need = count * (plen + body_len)
        if i + need > n:
            header["completo"] = False
            objs.append(header)
            break

        for k in range(count):
            idx = None
            if plen and prefix_code in (1, 2, 3):
                idx = int.from_bytes(app[i:i + plen], "little")
            i += plen
            body = app[i:i + body_len]
            i += body_len
            header["valores"].append(_decode_value(group, var, idx, body,
                                                   start_idx, k))
        objs.append(header)
    return objs


def _bits_por_punto(group, var):
    """Ancho, en bits, de las variaciones empaquetadas. None si no lo es.

    CUIDADO con el grupo 3: es Double-bit Binary Input y empaqueta **dos**
    bits por punto (00 intermedio, 01 apagado, 10 encendido, 11
    indeterminado), no uno. Tratarlo como de un bit consume la mitad de los
    octetos que debe y desalinea todo lo que siga en el mismo fragmento.
    """
    return {(1, 1): 1, (10, 1): 1, (80, 1): 1, (3, 1): 2}.get((group, var))


def _es_empaquetado(group, var):
    """Variaciones de un bit o dos por punto (mapa de bits comun)."""
    return _bits_por_punto(group, var) is not None


def _object_body_len(group, var):
    """Tamano fijo del cuerpo de un objeto, o None si es variable/desconocido."""
    if group == 12 and var == 1:
        return 11                      # CROB
    if group == 41:
        return {1: 5, 2: 3, 3: 5, 4: 9}.get(var)   # salida analogica
    if group == 40:
        return {1: 5, 2: 3, 3: 5, 4: 9}.get(var)   # estado de salida analogica
    if group == 1:
        return {2: 1}.get(var)         # entrada binaria con bandera
    if group == 2:                     # eventos de entrada binaria
        # v2 = bandera + tiempo absoluto (6); v3 = bandera + tiempo relativo (2)
        return {1: 1, 2: 7, 3: 3}.get(var)
    if group == 10:
        return {2: 1}.get(var)         # salida binaria con bandera
    if group == 20:                    # contadores
        return {1: 5, 2: 3, 5: 4, 6: 2}.get(var)
    if group == 21:                    # contadores congelados
        return {1: 5, 2: 3, 5: 11, 6: 9, 9: 4, 10: 2}.get(var)
    if group == 22:                    # eventos de contador
        return {1: 5, 2: 3, 5: 11, 6: 9}.get(var)
    if group == 30:
        return {1: 5, 2: 3, 3: 4, 4: 2, 5: 5, 6: 9}.get(var)
    if group == 32:
        return {1: 5, 2: 3, 3: 11, 4: 9, 5: 5, 7: 11}.get(var)
    if group == 50:
        # v3 = tiempo absoluto del ultimo registro, 6 octetos.
        return {1: 6, 2: 10, 3: 6, 4: 11}.get(var)  # tiempo
    if group == 51:
        return {1: 6, 2: 6}.get(var)
    if group == 52:
        return {1: 2, 2: 2}.get(var)   # retardo
    return None


def _decode_value(group, var, idx, body, start_idx, k):
    point = idx if idx is not None else (
        None if start_idx is None else start_idx + k)
    out = {"punto": point}
    if group == 12 and var == 1 and len(body) == 11:
        code = body[0]
        out.update({
            "tipo": "CROB",
            "codigo_control": code & 0x0F,
            "codigo_control_nombre": CROB_CODE.get(code & 0x0F, "?"),
            "clear": bool(code & 0x20),
            "trip_close": (code >> 6) & 0x03,
            "repeticiones": body[1],
            "tiempo_on_ms": struct.unpack("<I", body[2:6])[0],
            "tiempo_off_ms": struct.unpack("<I", body[6:10])[0],
            "estado": body[10],
        })
    elif group == 41 and var == 1 and len(body) == 5:
        out.update({"tipo": "AOB32", "valor": struct.unpack("<i", body[0:4])[0],
                    "estado": body[4]})
    elif group == 41 and var == 2 and len(body) == 3:
        out.update({"tipo": "AOB16", "valor": struct.unpack("<h", body[0:2])[0],
                    "estado": body[2]})
    elif group == 30 and var == 3 and len(body) == 4:
        out.update({"tipo": "AI32", "valor": struct.unpack("<i", body)[0]})
    elif group == 30 and var == 1 and len(body) == 5:
        out.update({"tipo": "AI32F", "bandera": body[0],
                    "valor": struct.unpack("<i", body[1:5])[0]})
    elif group == 1 and var == 2 and len(body) == 1:
        out.update({"tipo": "BI", "bandera": body[0],
                    "valor": body[0] & 0x80 and 1 or 0})
    else:
        out.update({"tipo": "g%dv%d" % (group, var), "crudo": body.hex()})
    return out


def frames_from_stream(buf):
    """Extrae tramas DNP3 de un buffer de bytes de un flujo TCP.

    Devuelve (lista_de_tramas_crudas, resto, estadisticas). Cada trama cruda es
    (cabecera10, cuerpo_con_crc). Resincroniza buscando 0x0564 y validando CRC.
    """
    out = []
    stats = {"crc_ok": 0, "crc_malo": 0, "resinc": 0}
    i = 0
    n = len(buf)
    while True:
        j = buf.find(b"\x05\x64", i)
        if j < 0:
            i = max(i, n - 1)
            break
        if j + 10 > n:
            i = j
            break
        head = buf[j:j + 10]
        if crc(head[:8]) != struct.unpack("<H", head[8:10])[0]:
            stats["crc_malo"] += 1
            i = j + 2
            stats["resinc"] += 1
            continue
        length = head[2]
        if length < 5:
            i = j + 2
            continue
        udata = length - 5
        nblocks = (udata + 15) // 16
        total = 10 + udata + 2 * nblocks
        if j + total > n:
            i = j
            break
        out.append((head, buf[j + 10:j + total]))
        stats["crc_ok"] += 1
        i = j + total
    return out, buf[i:], stats


def build_frame(head, body, ts, src_ip, dst_ip, sport, dport):
    f = Frame()
    f.ts = ts
    f.src_ip, f.dst_ip, f.sport, f.dport = src_ip, dst_ip, sport, dport
    f.length = head[2]
    f.control = head[3]
    f.dest = struct.unpack("<H", head[4:6])[0]
    f.source = struct.unpack("<H", head[6:8])[0]
    f.link_dir = bool(f.control & 0x80)
    f.link_prm = bool(f.control & 0x40)
    f.link_func = f.control & 0x0F
    app, ok, tot = _strip_crcs(body)
    f.payload = app
    f.bloques_ok, f.bloques_total = ok, tot
    if len(app) >= 1:
        f.transport = app[0]
        f.fir = bool(app[0] & 0x40)
        f.fin = bool(app[0] & 0x80)
    # La cabecera de aplicacion vive SOLO en la trama que abre el fragmento,
    # la que trae FIR=1. En una trama de continuacion los octetos 1 y 2 son
    # datos de objeto, y leerlos como control de aplicacion y codigo de
    # funcion inventa una funcion y una cabecera de objeto que no existen.
    # Este lector no reensambla fragmentos de varias tramas: cuenta las de
    # continuacion y no las interpreta, que es preferible a inventarlas.
    if len(app) >= 3 and f.fir:
        f.app_control = app[1]
        f.func = app[2]
        f.app_seq = app[1] & 0x0F
        off = 3
        if f.is_response:
            if len(app) >= 5:
                f.iin = struct.unpack("<H", app[3:5])[0]
                off = 5
            else:
                f.truncated = True
                return f
        f.objects = parse_object_headers(app, off)
    return f


def read_pcap(path, max_packets=None, dnp3_port=20000):
    """Itera tramas DNP3 de un PCAP. Requiere dpkt."""
    import dpkt
    import socket

    streams = {}
    counts = {"paquetes": 0, "tcp": 0, "con_carga": 0, "puerto_dnp3": 0,
              "crc_ok": 0, "crc_malo": 0, "frag_unico": 0, "frag_primero": 0,
              "frag_ultimo": 0, "frag_intermedio": 0, "sin_cabecera_app": 0}
    with open(path, "rb") as fh:
        try:
            pcap = dpkt.pcap.Reader(fh)
        except ValueError:
            return
        for ts, buf in pcap:
            counts["paquetes"] += 1
            if max_packets and counts["paquetes"] > max_packets:
                break
            try:
                eth = dpkt.ethernet.Ethernet(buf)
            except Exception:
                continue
            ip = eth.data
            if not isinstance(ip, dpkt.ip.IP):
                continue
            tcp = ip.data
            if not isinstance(tcp, dpkt.tcp.TCP):
                continue
            counts["tcp"] += 1
            if not tcp.data:
                continue
            counts["con_carga"] += 1
            if dnp3_port not in (tcp.sport, tcp.dport):
                continue
            counts["puerto_dnp3"] += 1
            key = (ip.src, ip.dst, tcp.sport, tcp.dport)
            buf_prev = streams.get(key, b"")
            frames, rest, st = frames_from_stream(buf_prev + tcp.data)
            streams[key] = rest if len(rest) < 65536 else b""
            counts["crc_ok"] += st["crc_ok"]
            counts["crc_malo"] += st["crc_malo"]
            src = socket.inet_ntoa(ip.src)
            dst = socket.inet_ntoa(ip.dst)
            for head, body in frames:
                f = build_frame(head, body, ts, src, dst, tcp.sport,
                                tcp.dport)
                # Contabilidad del fragmentado, para que el lector no esconda
                # lo que decide no interpretar.
                if f.transport is not None:
                    if f.fir and f.fin:
                        counts["frag_unico"] += 1
                    elif f.fir:
                        counts["frag_primero"] += 1
                    elif f.fin:
                        counts["frag_ultimo"] += 1
                    else:
                        counts["frag_intermedio"] += 1
                    if not f.fir:
                        counts["sin_cabecera_app"] += 1
                yield f, counts
    yield None, counts
