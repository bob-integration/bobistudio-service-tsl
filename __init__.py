# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 BOBI SAS, France
# Auteur : Cyril Mazouer, pour le compte de BOBI SAS
# Distribué sous licence GNU GPL v3 (ou ultérieure) ; voir le fichier LICENSE.

"""Service TSL 5.0 centralisé pour l'orchestrateur Bobi.Studio.

Reçoit les paquets TSL 5.0 (TCP) depuis un contrôleur externe (VSM, Ross, etc.)
sur un port unique, maintient un état tally global par index TSL, et distribue
les changements à chaque container multiview concerné via POST :8082/tally.

Avantages vs. TSL décentralisé (un port par multiview) :
- Un seul point de réception pour le contrôleur externe
- Vue globale du tally → peut alimenter Skaarhoj, ATEM, Ember+ en plus des multiviews
- Si un multiview redémarre, il récupère l'état au reconnect

Protocole TSL 5.0 (format observé) :
  SOM(2=0xFE02) + VER(1) + FLAGS(1) + SCREEN(2LE) + INDEX(2LE)
  + EXTRA(2) + CONTROL(2LE) + LENGTH(2LE) + TEXT(LENGTH bytes Latin-1)
CONTROL bits : 0-1=RH tally, 2-3=TT (text) tally, 4-5=LH tally
               0=off, 1=red, 2=green, 3=amber
"""
import logging
import socket
import struct
import threading
import time

log = logging.getLogger(__name__)

TSL_SOM          = b"\xfe\x02"
TSL_SLOT_TTL_F   = 2.5    # TTL = factor × intervalle keepalive mesuré
TSL_SLOT_TTL_MIN = 0.05   # 50 ms plancher absolu

# ─── État global ───────────────────────────────────────────────────────────────
_lock       = threading.Lock()
_server_thr = None
_dist_thr   = None
_stop_evt   = threading.Event()
_running    = False
_port       = 0
_started_at = None
_clients    = 0
_last_pkt   = None   # timestamp dernier paquet reçu
_last_error = ""

# Tally state par index TSL : {index: "off"|"red"|"green"|"amber"}
_tally_state: dict = {}
_tally_dirty = threading.Event()

# Keepalive tracker : (index, 'rh'|'tt'|'lh') → [value, ts, interval_s]
_tsl_slots:    dict = {}
_tsl_combined: dict = {}   # index → True si mode combined détecté

# ─── Parser TSL 5.0 ────────────────────────────────────────────────────────────
def _tsl_color(val):
    if val == 0: return "off"
    if val == 2: return "green"
    if val == 3: return "amber"
    return "red"

def _tally_dominant(rh, lh, tt):
    has_red   = any(v in (1, 3) for v in (rh, lh, tt))
    has_green = any(v == 2      for v in (rh, lh, tt))
    has_amber = any(v == 3      for v in (rh, lh, tt))
    if has_amber or (has_red and has_green):
        return "amber"
    if has_red:   return "red"
    if has_green: return "green"
    return "off"

def _apply_tsl(index: int, control: int, text: str):
    """Met à jour _tally_state pour un index TSL. Retourne True si l'état a changé."""
    global _last_pkt
    _last_pkt = time.time()

    rh = control & 0x03
    tt = (control >> 2) & 0x03
    lh = (control >> 4) & 0x03
    now = time.monotonic()

    with _lock:
        if (control & 0x3F) == 0:
            for s in ('rh', 'tt', 'lh'):
                _tsl_slots.pop((index, s), None)
        else:
            for s, v in (('rh', rh), ('tt', tt), ('lh', lh)):
                if v:
                    key = (index, s)
                    prev = _tsl_slots.get(key)
                    if prev is not None:
                        _pv, prev_ts, prev_iv = prev
                        raw_iv = now - prev_ts
                        iv = raw_iv if prev_iv is None else 0.5 * prev_iv + 0.5 * raw_iv
                    else:
                        iv = None
                    _tsl_slots[key] = [v, now, iv]

            if sum(1 for v in (rh, tt, lh) if v) > 1:
                _tsl_combined[index] = True

            active = {s for s, v in (('rh', rh), ('tt', tt), ('lh', lh)) if v}
            combined = _tsl_combined.get(index, False)
            stale = []
            for k, (sv, ts, iv) in list(_tsl_slots.items()):
                if k[0] != index or iv is None:
                    continue
                age = now - ts
                if k[1] not in active:
                    if combined or age >= iv * 0.9:
                        stale.append(k)
                elif age > max(TSL_SLOT_TTL_MIN, iv * TSL_SLOT_TTL_F):
                    stale.append(k)
            for k in stale:
                del _tsl_slots[k]

        rh_v = _tsl_slots.get((index, 'rh'), [0])[0]
        tt_v = _tsl_slots.get((index, 'tt'), [0])[0]
        lh_v = _tsl_slots.get((index, 'lh'), [0])[0]
        color = _tally_dominant(rh_v, lh_v, tt_v)
        changed = _tally_state.get(index) != color
        if changed:
            _tally_state[index] = color

    if changed:
        _tally_dirty.set()
    return changed

def _parse_stream(buf: bytearray):
    """Extrait et traite tous les paquets TSL complets du buffer. Retourne le buffer résiduel."""
    while True:
        som = buf.find(TSL_SOM)
        if som < 0:
            return bytearray(buf[-1:]) if buf else bytearray()
        if som > 0:
            buf = buf[som:]
        if len(buf) < 14:
            return buf
        control = struct.unpack_from("<H", buf, 10)[0]
        length  = struct.unpack_from("<H", buf, 12)[0]
        total   = 14 + length
        if len(buf) < total:
            return buf
        index = struct.unpack_from("<H", buf, 6)[0]
        text  = buf[14:14 + length].decode("latin-1", errors="replace") if length else ""
        buf   = buf[total:]
        _apply_tsl(index, control, text)

# ─── Thread de distribution vers les multiviews ────────────────────────────────
def _distributor():
    """Pousse les changements de tally vers chaque multiview concerné."""
    import requests as _req
    from app.database import db_get_setting
    from app.metrics import get_container_ip

    while not _stop_evt.is_set():
        _tally_dirty.wait(timeout=0.1)
        if _stop_evt.is_set():
            break
        _tally_dirty.clear()

        mapping = db_get_setting("tsl_mapping", []) or []
        with _lock:
            state = dict(_tally_state)

        # Regrouper les updates par vmid
        updates_by_vmid: dict = {}
        for entry in mapping:
            try:
                tsl_idx  = int(entry["tsl_index"])
                vmid     = int(entry["vmid"])
                flux_idx = int(entry["flux_idx"])
            except (KeyError, ValueError, TypeError):
                continue
            color = state.get(tsl_idx, "off")
            updates_by_vmid.setdefault(vmid, []).append(
                {"flux_idx": flux_idx, "slot": "L", "color": color}
            )
            updates_by_vmid.setdefault(vmid, []).append(
                {"flux_idx": flux_idx, "slot": "R", "color": color}
            )

        for vmid, updates in updates_by_vmid.items():
            try:
                ip = get_container_ip(vmid)
                if not ip:
                    continue
                _req.post(f"http://{ip}:8082/tally_bulk",
                          json={"updates": updates}, timeout=1)
            except Exception:
                pass

# ─── Thread serveur TCP ────────────────────────────────────────────────────────
def _handle_client(conn):
    global _clients
    with _lock:
        _clients += 1
    buf = bytearray()
    try:
        with conn:
            while not _stop_evt.is_set():
                chunk = conn.recv(4096)
                if not chunk:
                    break
                buf.extend(chunk)
                buf = _parse_stream(buf)
    except Exception as e:
        log.debug(f"TSL client error: {e}")
    finally:
        with _lock:
            _clients -= 1

def _server_thread(port):
    global _running, _started_at, _last_error
    while not _stop_evt.is_set():
        srv = None
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("0.0.0.0", port))
            srv.listen(8)
            srv.settimeout(1.0)
            with _lock:
                _running    = True
                _started_at = time.time()
                _last_error = ""
            log.info(f"TSL: serveur démarré sur TCP {port}")
            while not _stop_evt.is_set():
                try:
                    conn, _ = srv.accept()
                    threading.Thread(target=_handle_client, args=(conn,), daemon=True).start()
                except socket.timeout:
                    continue
        except Exception as e:
            _last_error = str(e)
            log.warning(f"TSL: erreur serveur ({e}), retry dans 3s")
            with _lock:
                _running = False
        finally:
            if srv:
                try: srv.close()
                except Exception: pass
        if not _stop_evt.is_set():
            _stop_evt.wait(3)
    with _lock:
        _running = False

# ─── API publique ──────────────────────────────────────────────────────────────
def start(port: int = 12345):
    global _server_thr, _dist_thr, _port
    stop()
    _stop_evt.clear()
    _port = port
    _server_thr = threading.Thread(target=_server_thread, args=(port,), daemon=True)
    _dist_thr   = threading.Thread(target=_distributor, daemon=True)
    _server_thr.start()
    _dist_thr.start()

def stop():
    global _server_thr, _dist_thr
    _stop_evt.set()
    _tally_dirty.set()   # débloquer le distributor
    if _server_thr and _server_thr.is_alive():
        _server_thr.join(timeout=3)
    if _dist_thr and _dist_thr.is_alive():
        _dist_thr.join(timeout=3)
    _server_thr = None
    _dist_thr   = None

def is_running():
    with _lock:
        return _running

def get_tally_state() -> dict:
    with _lock:
        return dict(_tally_state)

def status_dict() -> dict:
    with _lock:
        up = None
        if _started_at and _running:
            s = int(time.time() - _started_at)
            up = f"{s//3600:02d}:{(s%3600)//60:02d}:{s%60:02d}"
        last_ago = None
        if _last_pkt:
            last_ago = round(time.time() - _last_pkt, 1)
        return {
            "running":   _running,
            "port":      _port,
            "clients":   _clients,
            "uptime":    up,
            "last_pkt_ago_s": last_ago,
            "error":     _last_error,
            "tally":     dict(_tally_state),
        }

# ─── Routes Flask ──────────────────────────────────────────────────────────────
def register_routes(bp):
    from flask import request, jsonify
    from app.auth import require_login, require_perm
    from app.database import db_get_setting, db_set_setting

    @bp.route("/api/tsl/status", methods=["GET"])
    @require_login
    def tsl_status():
        st = status_dict()
        st["enabled_setting"] = bool(db_get_setting("tsl_enabled", False))
        st["port_setting"]    = int(db_get_setting("tsl_port", 12345) or 12345)
        return jsonify(st)

    @bp.route("/api/tsl/apply", methods=["POST"])
    @require_perm("settings.edit")
    def tsl_apply():
        data    = request.json or {}
        enabled = bool(data.get("enabled"))
        port    = int(data.get("port") or 12345)
        if not (1 <= port <= 65535):
            return jsonify({"error": "port invalide"}), 400
        db_set_setting("tsl_enabled", enabled)
        db_set_setting("tsl_port",    port)
        if enabled:
            start(port)
        else:
            stop()
        return jsonify(status_dict())

    @bp.route("/api/tsl/mapping", methods=["GET"])
    @require_login
    def tsl_mapping_get():
        return jsonify(db_get_setting("tsl_mapping", []) or [])

    @bp.route("/api/tsl/mapping", methods=["POST"])
    @require_perm("settings.edit")
    def tsl_mapping_set():
        data = request.json
        if not isinstance(data, list):
            return jsonify({"error": "liste attendue"}), 400
        db_set_setting("tsl_mapping", data)
        return jsonify({"ok": True})

    @bp.route("/api/tsl/state", methods=["GET"])
    @require_login
    def tsl_state():
        return jsonify(get_tally_state())
