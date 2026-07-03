# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 BOBI SAS, France
# Auteur : Cyril Mazouer, pour le compte de BOBI SAS
# Distribué sous licence GNU GPL v3 (ou ultérieure) ; voir le fichier LICENSE.

"""Service TSL 5.0 centralisé — multi-connexions, 10 niveaux tally, 10 colonnes labels.

Chaque connexion TSL (tsl_connections DB) ouvre son propre serveur TCP.
Le tally est stocké par (index, niveau) où niveau = tally_base + {0=LH, 1=RH, 2=TT}.
Le distributor lit les deploy_config des multiviews et envoie color + text par fenêtre.

Protocole TSL 5.0 (offsets vérifiés sur le fil VSM, capture 2026-06-30) :
  SOM `FE 02`@0 + LEN(2LE)@2 + VER/FLAGS@4 + SCREEN(2LE)@6 + INDEX(2LE)@8
  + CONTROL(2LE)@10 + LENGTH(2LE)@12 + TEXT@14 (LENGTH bytes Latin-1)
INDEX = display index (la source). CONTROL bits : 0-1=RH, 2-3=TT, 4-5=LH (0=off 1=red 2=green 3=amber)
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
        # dernier paquet reçu (diagnostic interne, non affiché)
        self.last_index   = None
        self.last_control = None
        self.last_text    = ""
        # dernier CHANGEMENT d'état tally (affiché — pas chaque keepalive)
        self.last_change        = None   # ts
        self.last_change_idx    = None
        self.last_change_colors = None   # {"lh","rh","tt"}
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
            self.last_pkt     = time.time()
            self.last_index   = index
            self.last_control = control
            self.last_text    = text
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
            with self._lock:
                self.last_change        = time.time()
                self.last_change_idx    = index
                self.last_change_colors = {
                    "lh": colors[self.tally_base],
                    "rh": colors[self.tally_base + 1],
                    "tt": colors[self.tally_base + 2],
                }

        # Mettre à jour la colonne label depuis le texte TSL (cols 2-9 seulement)
        if text and self.label_col >= 2:
            try:
                from app.database import db_get_source_for_tsl, db_upsert_source_label
                shm = db_get_source_for_tsl(self.conn_id, index)
                if shm:
                    db_upsert_source_label(shm, {f"label_{self.label_col}": text})
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
            index = struct.unpack_from("<H", buf, 8)[0]   # display index @ offset 8 (vérifié sur le fil VSM)
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
            last_change = None
            if self.last_change:
                last_change = {
                    "index":  self.last_change_idx,
                    **(self.last_change_colors or {}),
                    "ago_s":  round(time.time() - self.last_change, 1),
                }
            return {
                "conn_id":       self.conn_id,
                "port":          self.port,
                "label_col":     self.label_col,
                "tally_base":    self.tally_base,
                "running":       self.running,
                "clients":       self.clients,
                "uptime":        up,
                "last_pkt_ago_s": last_ago,
                "last_change":   last_change,
                "error":         self.last_error,
            }


# ─── Distributor ───────────────────────────────────────────────────────────────
def _distributor():
    """Pousse tally + texte label vers chaque multiview selon sa flux_config."""
    import requests as _req
    from app.database import (db_get_containers, db_get_source_label_for_shm,
                               db_get_setting, db_get_tsl_connections,
                               db_get_tsl_mappings_all)
    _OFF = {"lh": 0, "rh": 1, "tt": 2}

    while not _stop_evt.is_set():
        _tally_dirty.wait(timeout=0.1)
        if _stop_evt.is_set():
            break
        _tally_dirty.clear()

        with _lock:
            state = dict(_tally_state)

        try:
            containers = db_get_containers()
            # Niveau de Tally = bande tally_base : indexer les connexions actives par bande.
            conns_by_base = {int(c.get("tally_base") or 0): c
                             for c in db_get_tsl_connections() if c.get("enabled")}
            # En central l'index TSL d'un PiP est déduit de SA source : lookup inverse
            # (connexion, source_shm) → tsl_index dans le tsl_mapping.
            idx_by_conn_shm: dict = {}
            for m in db_get_tsl_mappings_all():
                shm_m = (m.get("source_shm") or "").strip()
                if shm_m:
                    idx_by_conn_shm[(int(m.get("connection_id") or 0), shm_m)] = \
                        int(m.get("tsl_index") or 0)
        except Exception:
            continue

        updates_by_vmid: dict = {}
        overlays_by_vmid: dict = {}
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
            # Mode Direct : le multiview reçoit le TSL via son serveur local → ne pas double-piloter.
            tsl_mode = params.get("tsl_mode") or (
                "direct" if (int(params.get("tsl_port") or 0) > 0 and not params.get("tsl_remote"))
                else "central")
            if tsl_mode == "direct":
                continue
            flux_config = params.get("flux_config") or []
            vmid = ct["vmid"]
            for i, fc in enumerate(flux_config):
                if not isinstance(fc, dict):
                    continue
                # Niveau de Tally (1-4) = bande tally_base ; couleurs = Rouge/Vert cochées.
                niveau = int(fc.get("tally_level") or 0)
                want_red   = bool(fc.get("tally_red"))
                want_green = bool(fc.get("tally_green"))
                want_text  = fc.get("label_source") == "protocol"
                if not niveau or not (want_red or want_green or want_text):
                    continue
                base = (niveau - 1) * 3
                conn = conns_by_base.get(base)        # connexion servant ce niveau (Rouge/Vert)
                if not conn:
                    continue
                # Index TSL déduit de la source du PiP (pas saisi à la main en central).
                # flux_config[i] câble via "path" ("/dev/shm/<shm>"), jamais "shm" (cf. app/routes.py:750).
                shm = (fc.get("path") or "").strip()
                if shm.startswith("/dev/shm/"):
                    shm = shm[len("/dev/shm/"):]
                tsl_index = idx_by_conn_shm.get((int(conn.get("id") or 0), shm))
                if tsl_index is None:
                    continue
                r_lvl  = base + _OFF.get(conn.get("rouge_field") or "tt", 2)
                v_lvl  = base + _OFF.get(conn.get("vert_field")  or "lh", 0)
                label_col = int(fc.get("label_col") or 0)

                # Couleur FORCÉE (Rouge/Vert) si le champ correspondant est actif (≠ off).
                color_l = "red"   if (want_red   and state.get((tsl_index, r_lvl), "off") != "off") else "off"
                color_r = "green" if (want_green and state.get((tsl_index, v_lvl), "off") != "off") else "off"
                try:
                    text = db_get_source_label_for_shm(shm, label_col)
                except Exception:
                    text = ""

                upd = updates_by_vmid.setdefault(vmid, [])
                upd.append({"flux_idx": i, "slot": "L", "color": color_l, "text": text})
                upd.append({"flux_idx": i, "slot": "R", "color": color_r, "text": text})

            # Overlays texte « TSL/Tableau » : reliés à une LIGNE du tableau /labels (label_row)
            # + une colonne (texte) + un niveau de Tally (allumage). Tout résolu côté orchestrateur.
            for ov in (params.get("overlays") or []):
                if not isinstance(ov, dict) or (ov.get("kind") or "") != "text":
                    continue
                if (ov.get("text_source") or "local") != "tsl":
                    continue
                row_shm = (ov.get("label_row") or "").strip()
                if not row_shm:
                    continue
                try:
                    o_text = db_get_source_label_for_shm(row_shm, int(ov.get("label_col") or 0))
                except Exception:
                    o_text = ""
                active = False
                o_niveau = int(ov.get("tally_level") or 0)
                if o_niveau and (ov.get("tally_red") or ov.get("tally_green")):
                    o_base = (o_niveau - 1) * 3
                    o_conn = conns_by_base.get(o_base)
                    if o_conn:
                        o_idx = idx_by_conn_shm.get((int(o_conn.get("id") or 0), row_shm))
                        if o_idx is not None:
                            r_l = o_base + _OFF.get(o_conn.get("rouge_field") or "tt", 2)
                            v_l = o_base + _OFF.get(o_conn.get("vert_field")  or "lh", 0)
                            red_on   = bool(ov.get("tally_red"))   and state.get((o_idx, r_l), "off") != "off"
                            green_on = bool(ov.get("tally_green")) and state.get((o_idx, v_l), "off") != "off"
                            active = red_on or green_on
                ovl = overlays_by_vmid.setdefault(vmid, [])
                ovl.append({"id": ov.get("id"), "text": o_text, "active": active})

        from app.metrics import get_container_ip
        for vmid in set(updates_by_vmid) | set(overlays_by_vmid):
            try:
                ip = get_container_ip(vmid)
                if not ip:
                    continue
                _req.post(f"http://{ip}:8080/tally_bulk",
                          json={"updates": updates_by_vmid.get(vmid, []),
                                "overlays": overlays_by_vmid.get(vmid, [])}, timeout=1)
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
                               db_get_source_labels, db_upsert_source_label,
                               db_delete_source_label, db_get_source_labels_by_shm,
                               db_get_tsl_mapping, db_upsert_tsl_mapping,
                               db_delete_tsl_mapping, db_get_tsl_mappings_all,
                               db_set_tsl_mapping_for_source,
                               db_get_tsl_sources_by_shm)

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

    # ── Source labels ─────────────────────────────────────────────────────────

    @bp.route("/api/source_labels", methods=["GET"])
    @require_login
    def source_labels_get():
        return jsonify(db_get_source_labels())

    @bp.route("/api/source_labels/batch", methods=["POST"])
    @require_perm("settings.edit")
    def source_labels_batch():
        rows = request.json or []
        if not isinstance(rows, list):
            return jsonify({"error": "liste attendue"}), 400
        saved = 0
        for row in rows:
            shm = (row.get("shm") or "").strip()
            if not shm:
                continue
            fields = {k: v for k, v in row.items() if k != "shm"}
            db_upsert_source_label(shm, fields)
            saved += 1
        return jsonify({"ok": True, "saved": saved})

    @bp.route("/api/source_labels/<path:shm>", methods=["DELETE"])
    @require_perm("settings.edit")
    def source_label_delete(shm):
        db_delete_source_label(shm)
        return jsonify({"ok": True})

    @bp.route("/api/tsl/sources/by_shm", methods=["GET"])
    @require_login
    def tsl_sources_by_shm():
        return jsonify(db_get_source_labels_by_shm())

    # ── Suffix map (héritage parent → label auto) ─────────────────────────────

    _DEFAULT_SUFFIX_MAP = {"_audio_0": "_A1", "_audio_1": "_A2", "_anc_0": "_Anc"}

    @bp.route("/api/source_labels/suffix_map", methods=["GET"])
    @require_login
    def source_labels_suffix_map_get():
        stored = db_get_setting("source_label_suffix_map", None)
        return jsonify(stored if isinstance(stored, dict) else _DEFAULT_SUFFIX_MAP)

    @bp.route("/api/source_labels/suffix_map", methods=["POST"])
    @require_perm("settings.edit")
    def source_labels_suffix_map_set():
        data = request.json
        if not isinstance(data, dict):
            return jsonify({"error": "dict attendu"}), 400
        db_set_setting("source_label_suffix_map", {str(k): str(v) for k, v in data.items()})
        return jsonify({"ok": True})

    # ── Mapping par connexion ─────────────────────────────────────────────────

    @bp.route("/api/tsl/mapping/<int:cid>", methods=["GET"])
    @require_login
    def tsl_mapping_for_conn(cid):
        return jsonify(db_get_tsl_mapping(cid))

    @bp.route("/api/tsl/mapping/<int:cid>/<int:idx>", methods=["POST", "PUT"])
    @require_perm("settings.edit")
    def tsl_mapping_upsert(cid, idx):
        data = request.json or {}
        source_shm = (data.get("source_shm") or "").strip()
        db_upsert_tsl_mapping(cid, idx, source_shm)
        return jsonify({"ok": True})

    @bp.route("/api/tsl/mapping/<int:cid>/<int:idx>", methods=["DELETE"])
    @require_perm("settings.edit")
    def tsl_mapping_delete(cid, idx):
        db_delete_tsl_mapping(cid, idx)
        return jsonify({"ok": True})

    # ── Mapping vu par-source (éditeur de labels, colonnes par connexion) ──────

    @bp.route("/api/tsl/mapping_all", methods=["GET"])
    @require_login
    def tsl_mapping_all():
        return jsonify(db_get_tsl_mappings_all())

    @bp.route("/api/tsl/mapping/by_source/batch", methods=["POST"])
    @require_perm("settings.edit")
    def tsl_mapping_by_source_batch():
        rows = request.json or []
        if not isinstance(rows, list):
            return jsonify({"error": "liste attendue"}), 400
        saved = 0
        for row in rows:
            shm = (row.get("shm") or "").strip()
            if not shm or row.get("connection_id") is None:
                continue
            idx = row.get("tsl_index")
            if isinstance(idx, str):
                idx = idx.strip() or None
            db_set_tsl_mapping_for_source(int(row["connection_id"]), shm, idx)
            saved += 1
        return jsonify({"ok": True, "saved": saved})

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

