# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 BOBI SAS, France
# Auteur : Cyril Mazouer, pour le compte de BOBI SAS
# Distribué sous licence GNU GPL v3 (ou ultérieure) ; voir le fichier LICENSE.

"""Service TSL 5.0 centralisé — multi-connexions, 10 niveaux tally, 10 colonnes labels.

Chaque connexion TSL (tsl_connections DB) ouvre son propre serveur TCP.
Le tally est stocké par (index, niveau) où niveau = tally_base + {0=LH, 1=RH, 2=TT}.
Le distributor lit les deploy_config des multiviews et envoie color + text par fenêtre.

Protocole TSL 5.0 :
  SOM(2=0xFE02) + VER(1) + FLAGS(1) + SCREEN(2LE) + INDEX(2LE)
  + EXTRA(2) + CONTROL(2LE) + LENGTH(2LE) + TEXT(LENGTH bytes Latin-1)
CONTROL bits : 0-1=RH tally, 2-3=TT tally, 4-5=LH tally  (0=off 1=red 2=green 3=amber)
"""
import json
import logging
import socket
import struct
import threading
import time

log = logging.getLogger(__name__)

TSL_SOM          = b"\xfe\x02"
TSL_SLOT_TTL_F   = 2.5
TSL_SLOT_TTL_MIN = 0.05

# ─── État global ───────────────────────────────────────────────────────────────
_lock       = threading.Lock()
_dist_thr   = None
_stop_evt   = threading.Event()

# {(tsl_index: int, level: int): "off"|"red"|"green"|"amber"}
_tally_state: dict = {}
_tally_dirty = threading.Event()

# _connections : {conn_id: _TslServer}
_connections: dict = {}


# ─── Parser TSL 5.0 ────────────────────────────────────────────────────────────
def _tsl_color(val):
    if val == 0: return "off"
    if val == 2: return "green"
    if val == 3: return "amber"
    return "red"


class _TslServer:
    """Un serveur TCP TSL pour une ligne tsl_connections."""

    def __init__(self, conn_id, port, label_col, tally_base):
        self.conn_id    = conn_id
        self.port       = port
        self.label_col  = label_col    # colonne label mise à jour par TSL text
        self.tally_base = tally_base   # LH=base, RH=base+1, TT=base+2
        self._stop      = threading.Event()
        self._thread    = None
        self._lock      = threading.Lock()
        self.running    = False
        self.clients    = 0
        self.started_at = None
        self.last_pkt   = None
        self.last_error = ""
        # keepalive tracker : (index, 'rh'|'tt'|'lh') → [value, ts, interval_s]
        self._slots: dict    = {}
        self._combined: dict = {}

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3)
        self._thread = None
        with self._lock:
            self.running = False

    def _apply_tsl(self, index: int, control: int, text: str):
        rh = control & 0x03
        tt = (control >> 2) & 0x03
        lh = (control >> 4) & 0x03
        now = time.monotonic()

        with self._lock:
            self.last_pkt = time.time()
            if (control & 0x3F) == 0:
                for s in ('rh', 'tt', 'lh'):
                    self._slots.pop((index, s), None)
            else:
                for s, v in (('rh', rh), ('tt', tt), ('lh', lh)):
                    if v:
                        key = (index, s)
                        prev = self._slots.get(key)
                        if prev is not None:
                            _pv, prev_ts, prev_iv = prev
                            raw_iv = now - prev_ts
                            iv = raw_iv if prev_iv is None else 0.5 * prev_iv + 0.5 * raw_iv
                        else:
                            iv = None
                        self._slots[key] = [v, now, iv]
                if sum(1 for v in (rh, tt, lh) if v) > 1:
                    self._combined[index] = True
                active = {s for s, v in (('rh', rh), ('tt', tt), ('lh', lh)) if v}
                stale  = []
                combined = self._combined.get(index, False)
                for k, (sv, ts, iv) in list(self._slots.items()):
                    if k[0] != index or iv is None:
                        continue
                    age = now - ts
                    if k[1] not in active:
                        if combined or age >= iv * 0.9:
                            stale.append(k)
                    elif age > max(TSL_SLOT_TTL_MIN, iv * TSL_SLOT_TTL_F):
                        stale.append(k)
                for k in stale:
                    del self._slots[k]

            rh_v = self._slots.get((index, 'rh'), [0])[0]
            tt_v = self._slots.get((index, 'tt'), [0])[0]
            lh_v = self._slots.get((index, 'lh'), [0])[0]

            def _dom(a, b, c):
                has_red   = any(v in (1, 3) for v in (a, b, c))
                has_green = any(v == 2      for v in (a, b, c))
                has_amber = any(v == 3      for v in (a, b, c))
                if has_amber or (has_red and has_green): return "amber"
                if has_red:   return "red"
                if has_green: return "green"
                return "off"

            colors = {
                self.tally_base:     _tsl_color(lh_v),   # LH
                self.tally_base + 1: _tsl_color(rh_v),   # RH
                self.tally_base + 2: _tsl_color(tt_v),   # TT
            }

        changed = False
        with _lock:
            for lvl, color in colors.items():
                key = (index, lvl)
                if _tally_state.get(key) != color:
                    _tally_state[key] = color
                    changed = True
        if changed:
            _tally_dirty.set()

        # Mettre à jour la colonne label depuis le texte TSL (cols 2-9 seulement)
        if text and self.label_col >= 2:
            try:
                from app.database import db_upsert_tsl_source
                db_upsert_tsl_source(index, {f"label_{self.label_col}": text})
            except Exception:
                pass

    def _parse_stream(self, buf: bytearray):
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
            self._apply_tsl(index, control, text)

    def _handle_client(self, conn):
        with self._lock:
            self.clients += 1
        buf = bytearray()
        try:
            with conn:
                while not self._stop.is_set():
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    buf.extend(chunk)
                    buf = self._parse_stream(buf)
        except Exception as e:
            log.debug(f"TSL conn {self.conn_id} client error: {e}")
        finally:
            with self._lock:
                self.clients -= 1

    def _serve(self):
        while not self._stop.is_set():
            srv = None
            try:
                srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                srv.bind(("0.0.0.0", self.port))
                srv.listen(8)
                srv.settimeout(1.0)
                with self._lock:
                    self.running    = True
                    self.started_at = time.time()
                    self.last_error = ""
                log.info(f"TSL conn {self.conn_id}: démarré sur TCP {self.port}")
                while not self._stop.is_set():
                    try:
                        conn, _ = srv.accept()
                        threading.Thread(target=self._handle_client, args=(conn,), daemon=True).start()
                    except socket.timeout:
                        continue
            except Exception as e:
                with self._lock:
                    self.last_error = str(e)
                    self.running = False
                log.warning(f"TSL conn {self.conn_id} erreur ({e}), retry dans 3s")
            finally:
                if srv:
                    try: srv.close()
                    except Exception: pass
            if not self._stop.is_set():
                self._stop.wait(3)
        with self._lock:
            self.running = False

    def status_dict(self):
        with self._lock:
            up = None
            if self.started_at and self.running:
                s = int(time.time() - self.started_at)
                up = f"{s//3600:02d}:{(s%3600)//60:02d}:{s%60:02d}"
            last_ago = round(time.time() - self.last_pkt, 1) if self.last_pkt else None
            return {
                "conn_id":       self.conn_id,
                "port":          self.port,
                "label_col":     self.label_col,
                "tally_base":    self.tally_base,
                "running":       self.running,
                "clients":       self.clients,
                "uptime":        up,
                "last_pkt_ago_s": last_ago,
                "error":         self.last_error,
            }


# ─── Distributor ───────────────────────────────────────────────────────────────
def _distributor():
    """Pousse tally + texte label vers chaque multiview selon sa flux_config."""
    import requests as _req
    from app.database import (db_get_containers, db_get_tsl_source_label,
                               db_get_setting)

    while not _stop_evt.is_set():
        _tally_dirty.wait(timeout=0.1)
        if _stop_evt.is_set():
            break
        _tally_dirty.clear()

        with _lock:
            state = dict(_tally_state)

        try:
            containers = db_get_containers()
        except Exception:
            continue

        updates_by_vmid: dict = {}
        for ct in containers:
            dc_raw = ct.get("deploy_config")
            if not dc_raw:
                continue
            try:
                dc = json.loads(dc_raw) if isinstance(dc_raw, str) else dc_raw
            except Exception:
                continue
            if (dc.get("type") or "") != "multiview":
                continue
            params = dc.get("params") or {}
            flux_config = params.get("flux_config") or []
            vmid = ct["vmid"]
            for i, fc in enumerate(flux_config):
                if not isinstance(fc, dict):
                    continue
                if not fc.get("show_tally"):
                    continue
                tsl_index = int(fc.get("tsl_index") or 0)
                if not tsl_index:
                    continue
                tally_l_level = int(fc.get("tally_l_level") or 0)
                tally_r_level = int(fc.get("tally_r_level") or 1)
                label_col     = int(fc.get("label_col") or 0)

                color_l = state.get((tsl_index, tally_l_level), "off")
                color_r = state.get((tsl_index, tally_r_level), "off")
                try:
                    text = db_get_tsl_source_label(tsl_index, label_col)
                except Exception:
                    text = ""

                upd = updates_by_vmid.setdefault(vmid, [])
                upd.append({"flux_idx": i, "slot": "L", "color": color_l, "text": text})
                upd.append({"flux_idx": i, "slot": "R", "color": color_r, "text": text})

        from app.metrics import get_container_ip
        for vmid, updates in updates_by_vmid.items():
            try:
                ip = get_container_ip(vmid)
                if not ip:
                    continue
                _req.post(f"http://{ip}:8080/tally_bulk",
                          json={"updates": updates}, timeout=1)
            except Exception:
                pass


# ─── API publique ──────────────────────────────────────────────────────────────
def start_all():
    """Démarre le distributor + tous les serveurs TSL activés depuis la DB."""
    global _dist_thr
    stop_all()
    _stop_evt.clear()
    _tally_dirty.clear()
    _dist_thr = threading.Thread(target=_distributor, daemon=True)
    _dist_thr.start()
    reload()

def stop_all():
    global _dist_thr
    _stop_evt.set()
    _tally_dirty.set()
    with _lock:
        for srv in _connections.values():
            srv.stop()
        _connections.clear()
    if _dist_thr and _dist_thr.is_alive():
        _dist_thr.join(timeout=3)
    _dist_thr = None

def reload():
    """Synchronise _connections depuis la DB (crée/met à jour/supprime)."""
    try:
        from app.database import db_get_tsl_connections
        rows = db_get_tsl_connections()
    except Exception as e:
        log.warning(f"TSL reload: impossible de lire les connexions ({e})")
        return

    with _lock:
        wanted_ids = {r["id"] for r in rows if r["enabled"]}
        current_ids = set(_connections.keys())

        for cid in current_ids - wanted_ids:
            _connections[cid].stop()
            del _connections[cid]

        for row in rows:
            cid = row["id"]
            if not row["enabled"]:
                if cid in _connections:
                    _connections[cid].stop()
                    del _connections[cid]
                continue
            srv = _connections.get(cid)
            if srv is None:
                srv = _TslServer(cid, row["port"], row["label_col"], row["tally_base"])
                _connections[cid] = srv
                srv.start()
            elif srv.port != row["port"] or srv.label_col != row["label_col"] or srv.tally_base != row["tally_base"]:
                srv.stop()
                srv2 = _TslServer(cid, row["port"], row["label_col"], row["tally_base"])
                _connections[cid] = srv2
                srv2.start()

def get_tally_state() -> dict:
    with _lock:
        return {f"{idx}_{lvl}": color for (idx, lvl), color in _tally_state.items()}

def get_tally_level(tsl_index: int, level: int) -> str:
    with _lock:
        return _tally_state.get((tsl_index, level), "off")

def connections_status() -> list:
    with _lock:
        return [srv.status_dict() for srv in _connections.values()]


# ─── Compat : anciens appels start/stop/is_running ────────────────────────────
def start(port: int = 12345):
    start_all()

def stop():
    stop_all()

def is_running():
    with _lock:
        return any(srv.running for srv in _connections.values())

def status_dict() -> dict:
    """Retour agrégé pour compatibilité."""
    with _lock:
        running = any(s.running for s in _connections.values())
        clients = sum(s.clients for s in _connections.values())
        last_pkts = [s.last_pkt for s in _connections.values() if s.last_pkt]
        last_pkt = max(last_pkts) if last_pkts else None
        last_ago = round(time.time() - last_pkt, 1) if last_pkt else None
        errors = [s.last_error for s in _connections.values() if s.last_error]
        return {
            "running":        running,
            "clients":        clients,
            "uptime":         None,
            "last_pkt_ago_s": last_ago,
            "error":          "; ".join(errors) if errors else "",
            "tally":          {f"{idx}_{lvl}": color for (idx, lvl), color in _tally_state.items()},
        }


# ─── Routes Flask ──────────────────────────────────────────────────────────────
def register_routes(bp):
    from flask import request, jsonify
    from app.auth import require_login, require_perm
    from app.database import (db_get_setting, db_set_setting,
                               db_get_tsl_connections, db_upsert_tsl_connection,
                               db_delete_tsl_connection,
                               db_get_tsl_sources, db_upsert_tsl_source,
                               db_delete_tsl_source, db_get_tsl_sources_by_shm)

    # ── Connexions ────────────────────────────────────────────────────────────

    @bp.route("/api/tsl/connections", methods=["GET"])
    @require_login
    def tsl_connections_get():
        conns = db_get_tsl_connections()
        status_map = {s["conn_id"]: s for s in connections_status()}
        for c in conns:
            c["status"] = status_map.get(c["id"], {})
        return jsonify(conns)

    @bp.route("/api/tsl/connections", methods=["POST"])
    @require_perm("settings.edit")
    def tsl_connection_create():
        data = request.json or {}
        lid = db_upsert_tsl_connection(data)
        reload()
        return jsonify({"id": lid, "ok": True})

    @bp.route("/api/tsl/connections/<int:cid>", methods=["PUT"])
    @require_perm("settings.edit")
    def tsl_connection_update(cid):
        data = request.json or {}
        data["id"] = cid
        db_upsert_tsl_connection(data)
        reload()
        return jsonify({"ok": True})

    @bp.route("/api/tsl/connections/<int:cid>", methods=["DELETE"])
    @require_perm("settings.edit")
    def tsl_connection_delete(cid):
        db_delete_tsl_connection(cid)
        reload()
        return jsonify({"ok": True})

    # ── Sources ───────────────────────────────────────────────────────────────

    @bp.route("/api/tsl/sources", methods=["GET"])
    @require_login
    def tsl_sources_get():
        return jsonify(db_get_tsl_sources())

    @bp.route("/api/tsl/sources", methods=["POST"])
    @require_perm("settings.edit")
    def tsl_sources_upsert():
        data = request.json or {}
        idx = data.get("tsl_index")
        if idx is None:
            return jsonify({"error": "tsl_index requis"}), 400
        fields = {k: v for k, v in data.items() if k != "tsl_index"}
        db_upsert_tsl_source(int(idx), fields)
        return jsonify({"ok": True})

    @bp.route("/api/tsl/sources/<int:idx>", methods=["DELETE"])
    @require_perm("settings.edit")
    def tsl_source_delete(idx):
        db_delete_tsl_source(idx)
        return jsonify({"ok": True})

    @bp.route("/api/tsl/sources/batch", methods=["POST"])
    @require_perm("settings.edit")
    def tsl_sources_batch():
        rows = request.json or []
        if not isinstance(rows, list):
            return jsonify({"error": "liste attendue"}), 400
        saved = 0
        for row in rows:
            idx = row.get("tsl_index")
            if idx is None:
                continue
            fields = {k: v for k, v in row.items() if k != "tsl_index"}
            db_upsert_tsl_source(int(idx), fields)
            saved += 1
        return jsonify({"ok": True, "saved": saved})

    @bp.route("/api/tsl/sources/by_shm", methods=["GET"])
    @require_login
    def tsl_sources_by_shm():
        return jsonify(db_get_tsl_sources_by_shm())

    # ── Noms des colonnes ──────────────────────────────────────────────────────

    @bp.route("/api/tsl/label_names", methods=["GET"])
    @require_login
    def tsl_label_names_get():
        names = db_get_setting("tsl_label_names", None)
        if not names or len(names) < 10:
            names = ["Hostname", "MXL", "Label 2", "Label 3", "Label 4",
                     "Label 5", "Label 6", "Label 7", "Label 8", "Label 9"]
        return jsonify(names)

    @bp.route("/api/tsl/label_names", methods=["POST"])
    @require_perm("settings.edit")
    def tsl_label_names_set():
        data = request.json
        if not isinstance(data, list) or len(data) != 10:
            return jsonify({"error": "liste de 10 noms attendue"}), 400
        db_set_setting("tsl_label_names", [str(n) for n in data])
        return jsonify({"ok": True})

    # ── État tally ────────────────────────────────────────────────────────────

    @bp.route("/api/tsl/state", methods=["GET"])
    @require_login
    def tsl_state():
        return jsonify(get_tally_state())

    # ── Compat : anciens endpoints ────────────────────────────────────────────

    @bp.route("/api/tsl/status", methods=["GET"])
    @require_login
    def tsl_status():
        st = status_dict()
        # Pour la rétro-compatibilité de l'ancienne UI
        st["enabled_setting"] = bool(db_get_setting("tsl_enabled", False))
        st["port_setting"]    = int(db_get_setting("tsl_port", 12345) or 12345)
        st["connections"]     = connections_status()
        return jsonify(st)

    @bp.route("/api/tsl/apply", methods=["POST"])
    @require_perm("settings.edit")
    def tsl_apply():
        """Compat : active/désactive la première connexion ou en crée une."""
        data    = request.json or {}
        enabled = bool(data.get("enabled"))
        port    = int(data.get("port") or 12345)
        conns   = db_get_tsl_connections()
        if conns:
            conns[0]["enabled"] = enabled
            conns[0]["port"]    = port
            db_upsert_tsl_connection(conns[0])
        else:
            db_upsert_tsl_connection(
                {"name": "Connexion par défaut", "port": port, "enabled": enabled,
                 "label_col": 2, "tally_base": 0})
        reload()
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
