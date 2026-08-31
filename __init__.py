# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 BOBI SAS, France
# Auteur : Cyril Mazouer, pour le compte de BOBI SAS
# Distribué sous licence GNU GPL v3 (ou ultérieure) ; voir le fichier LICENSE.

"""Service TSL 5.0 centralisé — multi-connexions, 10 niveaux tally, 10 colonnes labels.

Chaque connexion TSL (tsl_connections DB) ouvre son propre serveur TCP.
Le tally est stocké par (index, niveau), où `niveau` est un identifiant de `tally_levels` —
une ENTITÉ nommée, pas un décalage. TSL projette ses trois champs (LH/RH/TT) sur trois niveaux
affectés par connexion : le « 3 » est la trame de TSL, il ne structure plus le modèle.
Le distributor lit les deploy_config des multiviews et envoie color + text par fenêtre.

Protocole TSL 5.0 (offsets vérifiés sur le fil VSM, capture 2026-06-30) :
  SOM `FE 02`@0 + LEN(2LE)@2 + VER/FLAGS@4 + SCREEN(2LE)@6 + INDEX(2LE)@8
  + CONTROL(2LE)@10 + LENGTH(2LE)@12 + TEXT@14 (LENGTH bytes Latin-1)
INDEX = display index (la source). CONTROL bits : 0-1=RH, 2-3=TT, 4-5=LH (0=off 1=red 2=green 3=amber)
"""
import json
from app.numerotation import cle_input
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

_COLOR_CODE = {"off": 0, "red": 1, "green": 2, "amber": 3}
_OFF_FIELD  = {"lh": 0, "rh": 1, "tt": 2}


# ─── Ports virtuels de projet (chantier 4/5) ──────────────────────────────────
# Un mapping/label peut référencer "port:<id>" au lieu d'un shm brut : l'adresse reste
# stable côté contrôleur broadcast, le binding du port suit les rebinds/chargements.
_ports_cache = {"ts": 0.0, "by_id": {}, "by_pid": {}}

def _ports_snapshot():
    import time as _t
    now = _t.monotonic()
    if now - _ports_cache["ts"] > 3.0:
        try:
            from app.database import db_project_ports
            ports = db_project_ports(None)
        except Exception:
            ports = []
        _ports_cache["by_id"] = {p["id"]: p for p in ports}
        by_pid: dict = {}
        for p in ports:
            by_pid.setdefault(p["project_id"], []).append(p)
        _ports_cache["by_pid"] = by_pid
        _ports_cache["ts"] = now
    return _ports_cache

def _port_shm(port):
    """shm réel d'un port : binding.shm (source) ou binding.internal_shm (destination)."""
    b = (port or {}).get("binding") or {}
    return (b.get("shm") if (port or {}).get("kind") == "source"
            else b.get("internal_shm")) or None

def resolve_ref(ref):
    """"port:<id>" → shm réel du binding ; sinon renvoie ref tel quel."""
    ref = (ref or "").strip()
    if ref.startswith("port:"):
        try:
            port = _ports_snapshot()["by_id"].get(int(ref[5:]))
        except (TypeError, ValueError):
            port = None
        return _port_shm(port)
    return ref


# ─── Encodeur TSL 5.0 (miroir du parser — offsets vérifiés sur le fil VSM) ────
def encode_tsl_frame(index: int, control: int, text: str = "") -> bytes:
    """SOM(2) + LEN(2) + VER/FLAGS(2) + SCREEN(2) + INDEX(2) + CONTROL(2)
    + LENGTH(2) + TEXT (Latin-1)."""
    raw = (text or "").encode("latin-1", errors="replace")
    return (TSL_SOM
            + struct.pack("<H", 10 + len(raw))   # octets après le champ LEN
            + struct.pack("<H", 0)               # VER/FLAGS
            + struct.pack("<H", 0)               # SCREEN
            + struct.pack("<H", int(index) & 0xFFFF)
            + struct.pack("<H", int(control) & 0xFFFF)
            + struct.pack("<H", len(raw))
            + raw)

def build_control(red: bool, green: bool, rouge_field: str, vert_field: str) -> int:
    """Control word : 2 bits/champ — RH=bits0-1, TT=bits2-3, LH=bits4-5."""
    shift = {"rh": 0, "tt": 2, "lh": 4}
    control = 0
    if red:
        control |= _COLOR_CODE["red"] << shift.get(rouge_field, 2)
    if green:
        control |= _COLOR_CODE["green"] << shift.get(vert_field, 4)
    return control


class _TslServer:
    """Un serveur TCP TSL pour une ligne tsl_connections."""

    def __init__(self, conn_id, port, label_col, niveaux):
        """`niveaux` = {"lh": id, "rh": id, "tt": id} — les trois niveaux que CETTE connexion
        alimente par ses trois champs.

        ★ Plus de base historique. Le mot de contrôle TSL 5.0 réserve deux bits par champ, pour trois
        champs : c'est SA trame, et elle reste ici. Ce qui a disparu, c'est que ce « 3 » structure
        le modèle interne — une production n'est plus plafonnée à trois chaînes de destination
        parce que TSL en a trois."""
        self.conn_id    = conn_id
        self.port       = port
        self.label_col  = label_col    # colonne label mise à jour par TSL text
        self.niveaux    = dict(niveaux or {})
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

            # Un champ dont le niveau n'est pas affecté n'écrit RIEN — plutôt que d'écrire
            # sur un niveau deviné, ce qui allumerait un rouge chez quelqu'un d'autre.
            par_champ = {"lh": _tsl_color(lh_v), "rh": _tsl_color(rh_v), "tt": _tsl_color(tt_v)}
            colors = {self.niveaux[ch]: v for ch, v in par_champ.items() if self.niveaux.get(ch)}

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
                    ch: colors.get(self.niveaux.get(ch), "off") for ch in ("lh", "rh", "tt")
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
                "niveaux":       dict(self.niveaux),
                "running":       self.running,
                "clients":       self.clients,
                "uptime":        up,
                "last_pkt_ago_s": last_ago,
                "last_change":   last_change,
                "error":         self.last_error,
            }


# ─── Distributor ───────────────────────────────────────────────────────────────
class _TslClient:
    """Connexion TSL 5.0 SORTANTE (direction='out') : client TCP vers un UMD/écran
    externe. Consomme _tally_state (réveillé par _tally_dirty, comme le distributor)
    et émet une trame par index mappé — uniquement sur changement (anti-spam),
    avec un rafraîchissement périodique keepalive."""

    KEEPALIVE_S = 5.0

    def __init__(self, conn_id, dest_host, dest_port, label_col, niveaux,
                 rouge_field="tt", vert_field="lh"):
        self.conn_id     = conn_id
        self.dest_host   = dest_host
        self.port        = dest_port
        self.label_col   = label_col
        self.niveaux     = dict(niveaux or {})   # {"lh"|"rh"|"tt": id de niveau}
        self.rouge_field = rouge_field
        self.vert_field  = vert_field
        self._stop   = threading.Event()
        self._thread = None
        self.running = False
        self.clients = 0          # 1 quand connecté (même shape que _TslServer pour l'UI)
        self.started_at = None
        self.last_error = ""
        self._last_sent: dict = {}   # idx → (control, text)

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3)
        self._thread = None
        self.running = False

    def _frames(self, force=False):
        """Trames à émettre pour l'état courant (diff contre _last_sent)."""
        from app.database import db_get_tsl_mapping, db_get_source_label_for_shm
        with _lock:
            state = dict(_tally_state)
        # Quel NIVEAU alimente le rouge, et lequel le vert : c'est un choix de l'afficheur d'en
        # face, pas une propriété du signal. `rouge_field`/`vert_field` disent lequel des trois
        # champs de CETTE connexion porte quoi ; le niveau, lui, vient de l'affectation.
        r_lvl = self.niveaux.get(self.rouge_field or "tt")
        v_lvl = self.niveaux.get(self.vert_field or "lh")
        out = []
        try:
            mapping = db_get_tsl_mapping(self.conn_id)
        except Exception:
            mapping = []
        for m in mapping:
            idx = int(m.get("tsl_index") or 0)
            ref = (m.get("source_shm") or "").strip()
            red   = state.get((idx, r_lvl), "off") != "off"
            green = state.get((idx, v_lvl), "off") != "off"
            control = build_control(red, green, self.rouge_field, self.vert_field)
            try:
                text = db_get_source_label_for_shm(ref, self.label_col) or ""
                if not text and ref.startswith("port:"):
                    resolved = resolve_ref(ref)
                    if resolved:
                        text = db_get_source_label_for_shm(resolved, self.label_col) or ""
            except Exception:
                text = ""
            if force or self._last_sent.get(idx) != (control, text):
                out.append((idx, control, text))
                self._last_sent[idx] = (control, text)
        return out

    def _run(self):
        while not self._stop.is_set():
            sock = None
            try:
                sock = socket.create_connection((self.dest_host, int(self.port)), timeout=5)
                sock.settimeout(5)
                self.running, self.clients = True, 1
                self.started_at = time.time()
                self.last_error = ""
                self._last_sent = {}
                last_keepalive = 0.0
                while not self._stop.is_set():
                    _tally_dirty.wait(timeout=0.2)
                    force = (time.time() - last_keepalive) >= self.KEEPALIVE_S
                    frames = self._frames(force=force)
                    if force:
                        last_keepalive = time.time()
                    for idx, control, text in frames:
                        sock.sendall(encode_tsl_frame(idx, control, text))
            except Exception as e:
                self.last_error = str(e)
            finally:
                self.running, self.clients = False, 0
                try:
                    if sock:
                        sock.close()
                except Exception:
                    pass
            # reconnexion douce
            if self._stop.wait(timeout=3):
                break


# ─── Publisher mixer → niveau de tally du projet (chantier 5) ─────────────────
# Un mélangeur peut ÉMETTRE son tally (PGM=rouge, PVW=vert) sur un niveau
# sélectionnable — défaut : le niveau du projet qui le porte. Activation par les
# params du mixer : tally_emit (bool) + tally_level_base (int, optionnel).
# Résolution entrée mixer → shm → PORT du projet → index (= port.ord).

_mixer_pub_thr = None
_mixer_written: dict = {}   # base → {(idx, lvl)} écrits par nous (pour purger proprement)

def _sortie_a_l_antenne(ct, niveaux, idx_for):
    """La sortie PGM de ce mélangeur porte-t-elle un tally, sur les niveaux de SA production ?

    ★ SUR SES NIVEAUX À LUI, pas sur n'importe lesquels. Le système fait tourner plusieurs
    productions en même temps, chacune possédant ses niveaux (`tally_levels.owner_*`) :
    « à l'antenne » n'a de sens que rapporté à une production. Regarder tous les niveaux ferait
    qu'un mélangeur de la production 2 s'allume parce qu'un signal homonyme est à l'antenne
    sur la production 5.

    C'est la sortie **PGM** qui décide — `CLEAN` et `PVW` ne disent rien de la diffusion.
    Renvoie False si on ne sait pas : ne pas savoir n'est pas une raison d'allumer un rouge."""
    import json as _json
    try:
        from app import plugins as _plg
        dc = ct.get("deploy_config")
        dc = _json.loads(dc) if isinstance(dc, str) else (dc or {})
        # ⚠ AVEC LES PARAMS. `derive_wiring` déplie les ports `repeat` sur eux : sans params, un
        # plugin dont les sorties se déplient (`repeat: "video_channels"`) renvoie une liste VIDE,
        # et la garde bloquerait son émission pour toujours. Le mélangeur y échappait parce que
        # ses trois sorties sont statiques — c'est une coïncidence, pas une propriété.
        w = _plg.derive_wiring(dc.get("type"), ct.get("hostname"), dc.get("params") or {}) or {}
        prod = w.get("produces") or []
        pgm = next((p for p in prod if (p.get("label") or "").upper() == "PGM"), None) or \
            (prod[0] if prod else None)
        shm = (pgm or {}).get("shm")
        if not shm:
            return False
        idx = idx_for(shm)
        if idx is None:
            return False
        with _lock:
            return any(_tally_state.get((idx, n)) == "red" for n in (niveaux or ()))
    except Exception as e:
        log.debug("TSL: propagation — sortie de %s indéterminable (%s)", ct.get("vmid"), e)
        return False


def _mixer_field_levels(niveaux):
    """(niveau du rouge, niveau du vert) parmi ceux d'un mélangeur.

    ⚠ Le PREMIER niveau porte le rouge et le SECOND le vert — c'est la convention héritée, et elle
    reste une convention, pas une règle. Le chantier `TODO.md § TALLY` prévoit de la rendre
    configurable par bus (émettre ou non sur PGM, sur PVW, et vers quel niveau) : la câbler ici
    serait refaire ce qu'on vient de dénouer. En attendant, on préserve le comportement existant."""
    n = list(niveaux or [])
    return (n[0] if n else None), (n[1] if len(n) > 1 else None)

def _mixer_publisher():
    import requests as _req
    from app.database import db_get_containers, db_get_projects, db_get_tsl_connections
    while not _stop_evt.is_set():
        try:
            _mixer_publisher_tick(_req, db_get_containers, db_get_projects,
                                  db_get_tsl_connections)
        except Exception as e:
            log.debug(f"TSL mixer publisher: {e}")
        if _stop_evt.wait(timeout=0.3):
            break

def _mixer_publisher_tick(_req, db_get_containers, db_get_projects,
                          db_get_tsl_connections):
    from app.metrics import get_container_ip
    # `db_get_projects` / `db_get_tsl_connections` restent dans la signature : l'appelant les
    # injecte, et les bancs s'en servent. Depuis le dénouement, les niveaux d'un mélangeur se
    # lisent sur `tally_levels`, plus en recoupant les bases des uns et des autres.
    ports_by_pid = _ports_snapshot()["by_pid"]
    changed = False
    for ct in db_get_containers():
        dc_raw = ct.get("deploy_config")
        if not dc_raw:
            continue
        try:
            dc = json.loads(dc_raw) if isinstance(dc_raw, str) else dc_raw
        except Exception:
            continue
        if (dc.get("type") or "") != "mixer":
            continue
        params = dc.get("params") or {}
        if not params.get("tally_emit"):
            continue
        # NIVEAUX de ce mélangeur : ceux qu'il déclare, sinon ceux de sa production. C'est une
        # LISTE depuis le dénouement — le cas « un seul » n'est que la liste à un élément.
        from app.database import db_get_tally_levels_of
        pid = ct.get("project_id")
        niveaux = params.get("tally_level_base") or []
        if isinstance(niveaux, int):
            niveaux = [niveaux]
        if not niveaux:
            niveaux = db_get_tally_levels_of("project", pid)
        if not niveaux:
            continue
        try:
            ip = get_container_ip(ct["vmid"])
            if not ip:
                continue
            st = _req.get(f"http://{ip}:8082/state", timeout=0.8).json()
        except Exception:
            continue
        pgm, pvw = st.get("pgm"), st.get("pvw")
        shm_pgm = (st.get(cle_input(pgm)) or "") if pgm is not None else ""
        shm_pvw = (st.get(cle_input(pvw)) or "") if pvw is not None else ""
        # shm → index via les ports du projet (binding.shm == shm → ord)
        def _idx_for(shm):
            if not shm:
                return None
            for p in ports_by_pid.get(pid, []):
                if p.get("kind") == "source" and _port_shm(p) == shm:
                    return int(p.get("ord") or 0)
            return None
        r_lvl, v_lvl = _mixer_field_levels(niveaux)
        want = {}
        # ★ LE TALLY SE PROPAGE : un mélangeur ne tallye ses entrées que si SA PROPRE SORTIE est
        # à l'antenne. Jusqu'ici l'émission était inconditionnelle — un mélangeur de préparation
        # allumait un rouge sur une caméra qui n'était diffusée nulle part. C'est le premier étage
        # du chantier « TALLY : le calculer par propagation » (TODO.md).
        #
        # `tally_force` (défaut VRAI) conserve l'ancien comportement : on livre la correction pour
        # tous, mais un site dont la sortie de mélangeur n'est mappée nulle part perdrait sinon
        # son tally du jour au lendemain, sans avoir rien demandé — sur une fonction d'antenne.
        # Le décocher, c'est demander la propagation.
        if not params.get("tally_force", True) and not _sortie_a_l_antenne(ct, niveaux, _idx_for):
            want = {}
        else:
            i_pgm, i_pvw = _idx_for(shm_pgm), _idx_for(shm_pvw)
            if i_pgm is not None:
                want[(i_pgm, r_lvl)] = "red"
            if i_pvw is not None:
                want[(i_pvw, v_lvl)] = "green"
        cle_ecrit = tuple(niveaux)
        prev = _mixer_written.get(cle_ecrit, {})
        if want != prev:
            with _lock:
                for key in prev:
                    if key not in want:
                        _tally_state.pop(key, None)
                _tally_state.update(want)
            _mixer_written[cle_ecrit] = want
            changed = True
    if changed:
        _tally_dirty.set()


# ══════════════════════════════════════════════════════════════════════════════════════════════
# PROPAGATION du tally — remonter le graphe depuis les sorties à l'antenne
# ══════════════════════════════════════════════════════════════════════════════════════════════
# La règle, en une ligne :
#
#     tally(entrée d'un élément) = tally(sortie de cet élément) ET (cette entrée CONTRIBUE)
#
# La récursion part des flux qu'un ÉMETTEUR a tallyés — aujourd'hui un contrôleur broadcast (VSM)
# via TSL, demain un Receiver IS-07 — et remonte le graphe de câblage (`derive_wiring`).
#
# ★ « CONTRIBUE » DÉPEND DU TYPE, et ce qu'on ne sait pas ne propage RIEN. Un élément traversant
#   (delay, correcteur, UDC) contribue toujours : sa sortie EST son entrée, transformée. Un
#   mélangeur ne contribue que par sa source PGM. Un DVE ne contribue que par ses sources
#   VISIBLES — et il ne sait pas encore le dire, donc il ne propage rien.
#
#   Inventer une contribution allumerait un rouge sur une source qui n'est pas à l'antenne : c'est
#   exactement le défaut qu'on corrige, à l'envers. `_CONTRIBUTION` est donc une liste FERMÉE, et
#   tout type absent vaut « je ne sais pas » — pas « tout ».
#
# ⚠ PLAFOND DE PROFONDEUR. Le graphe MXL peut boucler (une sortie recâblée sur une entrée en
#   amont, un aller-retour d'incrustation). Sans plafond, la propagation ne rendrait jamais la
#   main — et elle tourne dans la boucle du distributeur.

_PROFONDEUR_MAX = 12

# Ce qui contribue à la sortie d'un élément, PAR TYPE. Liste fermée : un type absent ne propage
# rien. Voir TODO.md § TALLY pour les deux familles qui manquent encore (mélangeur configurable,
# DVE), différées parce qu'elles demandent de toucher des plugins.
_CONTRIBUTION = {
    "delay":            "toutes",
    "color_corrector":  "toutes",
    "udc":              "toutes",
    "avsync":           "toutes",
    "transcoder":       "toutes",
    "v210_bridge":      "toutes",
    "mixer":            "pgm",
}


def _producteur_de(shm, par_shm):
    return par_shm.get(shm)


def _entrees_contributives(ct, dc, etat_ctrl):
    """Les shm d'entrée qui contribuent à la sortie de ce conteneur. [] si on ne sait pas.

    `etat_ctrl` = le `/state` du conteneur, ou None. Un mélangeur ne contribue que par sa source
    PGM : sans son état, on ne SAIT pas laquelle — et on ne propage rien plutôt que de deviner."""
    from app import plugins as _plg
    from app.numerotation import cle_input
    regle = _CONTRIBUTION.get(dc.get("type") or "")
    if not regle:
        return []
    params = dc.get("params") or {}
    w = _plg.derive_wiring(dc.get("type"), ct.get("hostname"), params) or {}
    entrees = []
    for p in (w.get("consumes") or []):
        if (p.get("essence") or "video") != "video":
            continue
        shm = (params.get(p.get("state_field") or "") or "").strip()
        if shm:
            entrees.append(shm)
    if regle == "toutes":
        return entrees
    if regle == "pgm":
        if not etat_ctrl:
            return []
        pgm = etat_ctrl.get("pgm")
        if pgm is None:
            return []
        # Le câblage vient de l'ÉTAT VIVANT, comme dans `_mixer_publisher_tick` : c'est lui qui
        # sait sur quoi le mélangeur est réellement branché à cet instant. Les params ne servent
        # que de repli — ils peuvent être en retard d'un câblage à chaud.
        shm = (etat_ctrl.get(cle_input(pgm)) or params.get(cle_input(pgm)) or "").strip()
        return [shm] if shm else []
    return []


def propager(etat, par_shm, idx_de_shm, etat_ctrl_de):
    """{(index, niveau): couleur} À AJOUTER par propagation. Ne modifie rien.

    `par_shm`       : shm produit → (conteneur, deploy_config)
    `idx_de_shm`    : shm → index TSL, ou None
    `etat_ctrl_de`  : vmid → `/state` du conteneur, ou None

    Renvoie un dict SÉPARÉ plutôt que d'écrire dans `_tally_state` : l'appelant doit pouvoir
    distinguer ce qu'un émetteur a dit de ce que nous avons déduit. Sans cette séparation, un
    tally propagé deviendrait indiscernable d'un tally reçu au tour suivant, et se propagerait
    à son tour — la boucle se referme sur elle-même."""
    ajouts = {}
    # File des (shm à l'antenne, niveau, couleur) à remonter.
    file = []
    for (idx, niveau), couleur in (etat or {}).items():
        if couleur == "off":
            continue
        for shm, i in (idx_de_shm or {}).items():
            if i == idx:
                file.append((shm, niveau, couleur, 0))
    vus = set()
    while file:
        shm, niveau, couleur, prof = file.pop()
        if prof >= _PROFONDEUR_MAX or (shm, niveau) in vus:
            continue
        vus.add((shm, niveau))
        cible = _producteur_de(shm, par_shm)
        if not cible:
            continue
        ct, dc = cible
        for amont in _entrees_contributives(ct, dc, etat_ctrl_de.get(ct.get("vmid"))):
            idx_amont = (idx_de_shm or {}).get(amont)
            if idx_amont is None:
                continue          # une source sans index n'est adressable par personne
            cle = (idx_amont, niveau)
            if (etat or {}).get(cle, "off") == "off" and ajouts.get(cle, "off") == "off":
                ajouts[cle] = couleur
            file.append((amont, niveau, couleur, prof + 1))
    return ajouts


def _distributor():
    """Pousse tally + texte label vers chaque multiview selon sa flux_config."""
    import requests as _req
    from app.database import (db_get_containers, db_get_source_label_for_shm,
                               db_get_setting, db_get_tsl_connections,
                               db_get_tsl_mappings_all)
    _OFF = {"lh": 0, "rh": 1, "tt": 2}
    _last_push: dict = {}   # vmid → (dernier payload poussé, ts) — anti-repush identique (cf. plus bas)

    while not _stop_evt.is_set():
        _tally_dirty.wait(timeout=0.1)
        if _stop_evt.is_set():
            break
        _tally_dirty.clear()

        with _lock:
            state = dict(_tally_state)

        try:
            containers = db_get_containers()
            # PORTEURS de niveaux : les connexions ENTRANTES actives (les sortantes consomment
            # l'état, elles ne le servent pas) et les productions. Depuis le dénouement, chacun
            # POSSÈDE ses niveaux — on ne les recoupe plus par une bande commune, et deux
            # porteurs ne peuvent plus se disputer un niveau par construction.
            from app.database import db_get_tally_levels_of, db_get_projects
            porteurs = []
            for c in db_get_tsl_connections():
                if not c.get("enabled") or (c.get("direction") or "in") != "in":
                    continue
                niv = [c.get("%s_level_id" % ch) for ch in ("lh", "rh", "tt")]
                porteurs.append({"_key": int(c.get("id") or 0), "niveaux": niv,
                                 "rouge_field": c.get("rouge_field") or "tt",
                                 "vert_field": c.get("vert_field") or "lh", "_project": None})
            # Pseudo-porteurs PAR PRODUCTION : l'écrivain est l'émetteur du mélangeur, et
            # l'index d'une source est son port (ord).
            try:
                for pr in db_get_projects():
                    niv = db_get_tally_levels_of("project", pr["id"])
                    if not niv:
                        continue
                    porteurs.append({"_key": "proj:%s" % pr["id"], "niveaux": niv,
                                     "rouge_field": "lh", "vert_field": "rh",
                                     "_project": pr["id"]})
            except Exception:
                pass
            # niveau → porteur : c'est par là que le multiview retrouve qui sert son niveau.
            porteur_de_niveau = {}
            for pt in porteurs:
                for n in pt["niveaux"]:
                    if n:
                        porteur_de_niveau.setdefault(n, pt)
            # En central l'index TSL d'un PiP est déduit de SA source : lookup inverse
            # (connexion, source_shm RÉSOLU) → tsl_index. Un mapping peut référencer
            # "port:<id>" — résolu vers le shm bindé ; le label garde la ref d'origine.
            idx_by_conn_shm: dict = {}
            label_ref: dict = {}      # (conn_key, shm_résolu) → ref d'origine (labels)
            for m in db_get_tsl_mappings_all():
                ref = (m.get("source_shm") or "").strip()
                if not ref:
                    continue
                shm_m = resolve_ref(ref) or ref
                key = (int(m.get("connection_id") or 0), shm_m)
                idx_by_conn_shm[key] = int(m.get("tsl_index") or 0)
                if ref != shm_m:
                    label_ref[key] = ref
            # Ports des pseudo-porteurs projet : index d'une source = son port (ord).
            for c in porteurs:
                pidc = c.get("_project")
                if not pidc:
                    continue
                for p in _ports_snapshot()["by_pid"].get(pidc, []):
                    shm_p = _port_shm(p)
                    if shm_p:
                        key = (c["_key"], shm_p)
                        idx_by_conn_shm[key] = int(p.get("ord") or 0)
                        label_ref[key] = f"port:{p['id']}"
            # Niveaux par projet : défaut d'un conteneur qui n'en déclare pas.
            try:
                proj_niv = {pr["id"]: db_get_tally_levels_of("project", pr["id"])
                            for pr in db_get_projects()}
            except Exception:
                proj_niv = {}
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
            type_ct = (dc.get("type") or "")
            if type_ct != "multiview":
                # ── AUTRES PLUGINS : le plugin DIT ce qu'il veut voir allumé ──────────────
                # ★ UN HOOK, PAS UNE BRANCHE PAR TYPE. Le distributeur connaissait un seul
                # modèle de données (`flux_config` du mur) ; chaque plugin qui voudrait du
                # tally aurait ajouté ici sa propre lecture, et ce fichier serait devenu un
                # catalogue de modèles étrangers. Le plugin déclare `tally_targets` et rend
                # une liste plate : le distributeur ne sait plus rien de personne.
                #
                # ⚠ LE MUR RESTE SUR SON CHEMIN. C'est le plus sensible du produit et il
                # tourne : on ne le fait pas passer sur du code neuf pour l'élégance.
                try:
                    from app import plugins as _plug
                    _h = _plug.get_hook(type_ct, "tally_targets")
                except Exception:
                    _h = None
                if not _h:
                    continue
                try:
                    cibles = _h(dc.get("params") or {},
                                {"vmid": ct["vmid"], "project_id": ct.get("project_id")}) or []
                except Exception:
                    continue
                for cible in cibles:
                    if not isinstance(cible, dict):
                        continue
                    shm_c = (cible.get("shm") or "").strip()
                    if shm_c.startswith("/dev/shm/"):
                        shm_c = shm_c[len("/dev/shm/"):]
                    if not shm_c:
                        continue
                    # Niveaux demandés par le plugin : liste d'identifiants, vide = ceux de
                    # son projet. Le champ garde son nom historique `niveau`, mais ce n'est plus
                    # un numéro de bande.
                    niv_c = cible.get("niveau") or []
                    if isinstance(niv_c, int):
                        niv_c = [niv_c] if niv_c else []
                    if not niv_c:
                        niv_c = proj_niv.get(ct.get("project_id")) or []
                    conn_c = next((porteur_de_niveau[n] for n in niv_c
                                   if n in porteur_de_niveau), None)
                    # LE TEXTE EST RÉSOLU MÊME SANS NIVEAU DE TALLY. Un scope peut vouloir le
                    # libellé vivant d'une source sans jamais l'allumer en rouge — et c'est
                    # même le cas courant : un instrument n'est pas à l'antenne.
                    try:
                        txt_c = db_get_source_label_for_shm(
                            shm_c, int(cible.get("label_col") or 0))
                    except Exception:
                        txt_c = ""
                    coul_r = coul_v = "off"
                    if conn_c:
                        ck_c = conn_c.get("_key", int(conn_c.get("id") or 0))
                        ti = idx_by_conn_shm.get((ck_c, shm_c))
                        if ti is not None:
                            _nc = conn_c["niveaux"]
                            rl = (_nc[_OFF.get(conn_c.get("rouge_field") or "tt", 2)]
                                  if len(_nc) > 2 else None)
                            vl = _nc[_OFF.get(conn_c.get("vert_field") or "lh", 0)] if _nc else None
                            if state.get((ti, rl), "off") != "off":
                                coul_r = "red"
                            if state.get((ti, vl), "off") != "off":
                                coul_v = "green"
                    updates_by_vmid.setdefault(ct["vmid"], []).append(
                        {"cle": str(cible.get("cle") or shm_c), "shm": shm_c,
                         "rouge": coul_r, "vert": coul_v, "texte": txt_c})
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
                # NIVEAUX de cette tuile : une LISTE d'identifiants depuis le dénouement.
                # Vide = « ceux de mon projet ». Le numéro de bande 1-based a disparu : il
                # réintroduisait le « 3 » de TSL au cœur d'un réglage de multiview.
                niveaux_fc = fc.get("tally_level") or []
                if isinstance(niveaux_fc, int):
                    niveaux_fc = [niveaux_fc]
                want_red   = bool(fc.get("tally_red"))
                want_green = bool(fc.get("tally_green"))
                want_text  = fc.get("label_source") == "protocol"
                if not niveaux_fc:
                    niveaux_fc = proj_niv.get(ct.get("project_id")) or []
                if not niveaux_fc or not (want_red or want_green or want_text):
                    continue
                # Le porteur est celui qui POSSÈDE ces niveaux — plus une bande à recouper.
                conn = next((porteur_de_niveau[n] for n in niveaux_fc
                             if n in porteur_de_niveau), None)
                if not conn:
                    continue
                # Index TSL déduit de la source du PiP (pas saisi à la main en central).
                # flux_config[i] câble via "path" ("/dev/shm/<shm>"), jamais "shm" (cf. app/routes.py:750).
                shm = (fc.get("path") or "").strip()
                if shm.startswith("/dev/shm/"):
                    shm = shm[len("/dev/shm/"):]
                ckey = conn.get("_key", int(conn.get("id") or 0))
                tsl_index = idx_by_conn_shm.get((ckey, shm))
                if tsl_index is None:
                    continue
                _niv = conn["niveaux"]
                r_lvl = _niv[_OFF.get(conn.get("rouge_field") or "tt", 2)] if len(_niv) > 2 else None
                v_lvl = _niv[_OFF.get(conn.get("vert_field") or "lh", 0)] if _niv else None
                label_col = int(fc.get("label_col") or 0)

                # Couleur FORCÉE (Rouge/Vert) si le champ correspondant est actif (≠ off).
                color_l = "red"   if (want_red   and state.get((tsl_index, r_lvl), "off") != "off") else "off"
                color_r = "green" if (want_green and state.get((tsl_index, v_lvl), "off") != "off") else "off"
                try:
                    lref = label_ref.get((ckey, shm))
                    text = db_get_source_label_for_shm(lref or shm, label_col)
                    if not text and lref:
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
                o_niv = ov.get("tally_level") or []
                if isinstance(o_niv, int):
                    o_niv = [o_niv] if o_niv else []
                if not o_niv:
                    o_niv = proj_niv.get(ct.get("project_id")) or []
                if o_niv and (ov.get("tally_red") or ov.get("tally_green")):
                    o_conn = next((porteur_de_niveau[n] for n in o_niv
                                   if n in porteur_de_niveau), None)
                    if o_conn:
                        row_res = resolve_ref(row_shm) or row_shm
                        o_idx = idx_by_conn_shm.get(
                            (o_conn.get("_key", int(o_conn.get("id") or 0)), row_res))
                        if o_idx is not None:
                            _no = o_conn["niveaux"]
                            r_l = (_no[_OFF.get(o_conn.get("rouge_field") or "tt", 2)]
                                   if len(_no) > 2 else None)
                            v_l = _no[_OFF.get(o_conn.get("vert_field") or "lh", 0)] if _no else None
                            red_on   = bool(ov.get("tally_red"))   and state.get((o_idx, r_l), "off") != "off"
                            green_on = bool(ov.get("tally_green")) and state.get((o_idx, v_l), "off") != "off"
                            active = red_on or green_on
                ovl = overlays_by_vmid.setdefault(vmid, [])
                ovl.append({"id": ov.get("id"), "text": o_text, "active": active})

        from app.metrics import get_container_ip
        _now_p = time.time()
        for vmid in set(updates_by_vmid) | set(overlays_by_vmid):
            try:
                ip = get_container_ip(vmid)
                if not ip:
                    continue
                payload = {"updates": updates_by_vmid.get(vmid, []),
                           "overlays": overlays_by_vmid.get(vmid, [])}
                # ★ PERF : ne POSTER que si l'état a RÉELLEMENT changé. Ce distributeur tourne
                # sur un timeout de 100 ms (il repasse même sans événement TSL) : re-pousser un
                # paquet identique 10×/s faisait re-baker l'habillage PLEIN CADRE du multiview
                # 10×/s (PIL + RGBA→YUV + upload GPU ≈ 25 ms, soit une trame perdue à chaque
                # fois — mur 333 Horace mesuré à 28-36 fps au lieu de 50). Le mur a lui aussi
                # sa garde (comparaison de valeur avant de marquer sale, multiview ≥ 0.39.2) ;
                # celle-ci évite en plus 10 requêtes HTTP/s et par mur.
                # Re-synchro périodique (5 s) : un mur redéployé repart avec un tally VIDE — sans
                # ce filet, il resterait éteint jusqu'au prochain changement TSL. Coût nul côté
                # mur grâce à sa garde de valeur (paquet identique = aucun re-bake).
                _prev, _pts = _last_push.get(vmid, (None, 0.0))
                if _prev == payload and (_now_p - _pts) < 5.0:
                    continue
                _req.post(f"http://{ip}:8080/tally_bulk", json=payload, timeout=1)
                _last_push[vmid] = (payload, _now_p)
            except Exception:
                _last_push.pop(vmid, None)   # échec → re-pousser au prochain tour


# ─── API publique ──────────────────────────────────────────────────────────────
def start_all():
    """Démarre le distributor + le publisher mixer + toutes les connexions activées."""
    global _dist_thr, _mixer_pub_thr
    stop_all()
    _stop_evt.clear()
    _tally_dirty.clear()
    _dist_thr = threading.Thread(target=_distributor, daemon=True)
    _dist_thr.start()
    _mixer_pub_thr = threading.Thread(target=_mixer_publisher, daemon=True)
    _mixer_pub_thr.start()
    reload()

def stop_all():
    global _dist_thr, _mixer_pub_thr
    _stop_evt.set()
    _tally_dirty.set()
    with _lock:
        for srv in _connections.values():
            srv.stop()
        _connections.clear()
    if _dist_thr and _dist_thr.is_alive():
        _dist_thr.join(timeout=3)
    _dist_thr = None
    if _mixer_pub_thr and _mixer_pub_thr.is_alive():
        _mixer_pub_thr.join(timeout=3)
    _mixer_pub_thr = None

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

        def _niveaux(row):
            """Les trois niveaux que cette connexion alimente, depuis ses colonnes dédiées."""
            return {ch: row.get("%s_level_id" % ch) for ch in ("lh", "rh", "tt")}

        def _mk(row):
            if (row.get("direction") or "in") == "out":
                return _TslClient(row["id"], row.get("dest_host") or "127.0.0.1",
                                  row["port"], row["label_col"], _niveaux(row),
                                  rouge_field=row.get("rouge_field") or "tt",
                                  vert_field=row.get("vert_field") or "lh")
            return _TslServer(row["id"], row["port"], row["label_col"], _niveaux(row))

        for row in rows:
            cid = row["id"]
            if not row["enabled"]:
                if cid in _connections:
                    _connections[cid].stop()
                    del _connections[cid]
                continue
            srv = _connections.get(cid)
            want_out = (row.get("direction") or "in") == "out"
            is_out = isinstance(srv, _TslClient) if srv is not None else None
            if srv is None:
                srv = _mk(row)
                _connections[cid] = srv
                srv.start()
            elif (srv.port != row["port"] or srv.label_col != row["label_col"]
                  or srv.niveaux != _niveaux(row) or is_out != want_out
                  or (want_out and getattr(srv, "dest_host", None) != (row.get("dest_host") or "127.0.0.1"))):
                srv.stop()
                srv2 = _mk(row)
                _connections[cid] = srv2
                srv2.start()

def get_tally_state() -> dict:
    with _lock:
        return {f"{idx}_{lvl}": color for (idx, lvl), color in _tally_state.items()}


# ─── Actions de service (chantier 6 — macros/shotbox) ─────────────────────────
def _ref_options(pid=None):
    """Sources labellisables : ports SOURCE + shms produits par les containers (bornés au
    projet si `pid`, sinon toute la flotte). {value, label} pour un menu déroulant."""
    out, seen = [], set()
    snap = _ports_snapshot()
    ports = snap["by_pid"].get(pid, []) if pid else list(snap["by_id"].values())
    for p in ports:
        if (p.get("kind") or "") != "source":
            continue
        val = f"port:{p['id']}"
        if val in seen:
            continue
        seen.add(val)
        out.append({"value": val, "label": p.get("name") or f"Port {p['id']}"})
    try:
        from app.database import db_get_containers
        from app.auth import vmid_project_ids
        from app import plugins as _plugins
        for c in db_get_containers():
            if pid and pid not in vmid_project_ids(c["vmid"]):
                continue
            dc = c.get("deploy_config")
            dc = json.loads(dc) if isinstance(dc, str) else (dc or {})
            t, prm = dc.get("type"), (dc.get("params") or {})
            if not _plugins.is_plugin(t):
                continue
            hn = prm.get("hostname") or c.get("hostname") or ""
            try:
                for pr in _plugins.derive_wiring(t, hn, prm)["produces"]:
                    shm = pr.get("shm")
                    if not shm or shm in seen:
                        continue
                    seen.add(shm)
                    lbl = (pr.get("label") or "").strip()
                    # Sans label propre, retomber sur le shm (les N sorties d'un moteur
                    # partagent le hostname → « hn » seul serait ambigu).
                    out.append({"value": shm, "label": (hn + " · " + lbl) if lbl else shm})
            except Exception:
                continue
    except Exception:
        pass
    return out


def action_options(action_id, key, pid=None):
    """Options dynamiques des params d'action TSL (menus déroulants au lieu de champs
    libres). `set_label.ref` → sources ; `set_label.col` → colonnes 2-9 avec leur nom
    (setting `tsl_label_names`). `pid` borne la liste de sources au projet."""
    if action_id != "set_label":
        return []
    if key == "ref":
        return _ref_options(pid)
    if key == "col":
        from app.database import db_get_setting
        names = db_get_setting("tsl_label_names", None)
        if isinstance(names, str):
            try:
                names = json.loads(names)
            except Exception:
                names = None
        names = names if isinstance(names, list) else []
        out = []
        for i in range(2, 10):
            nm = names[i] if i < len(names) and names[i] else f"Label {i}"
            out.append({"value": i, "label": f"{i} — {nm}"})
        return out
    return []


def run_action(action_id, params, ctx):
    """`tsl.set_label(ref, col, text)` : écrit une colonne de label d'une source.
    En contexte PROJET (ctx.project_id), la cible est BORNÉE aux refs du projet :
    un de ses ports (« port:<id> ») ou un shm produit par un de ses containers."""
    if action_id != "set_label":
        raise RuntimeError(f"action inconnue : {action_id}")
    ref = (params.get("ref") or "").strip()
    text = str(params.get("text") if params.get("text") is not None else "")
    try:
        col = int(params.get("col") or 2)
    except (TypeError, ValueError):
        col = 2
    if not ref:
        raise RuntimeError("ref requis (shm ou port:<id>)")
    if not (2 <= col <= 9):
        raise RuntimeError("col hors plage (2-9)")
    pid = (ctx or {}).get("project_id")
    if pid:
        ok = False
        if ref.startswith("port:"):
            port = _ports_snapshot()["by_id"].get(int(ref[5:]) if ref[5:].isdigit() else -1)
            ok = bool(port and port.get("project_id") == pid)
        else:
            # shm produit par un container du projet ?
            from app.database import db_get_containers
            from app.auth import vmid_project_ids
            from app import plugins as _plugins
            for c in db_get_containers():
                if pid not in vmid_project_ids(c["vmid"]):
                    continue
                dc = c.get("deploy_config")
                dc = json.loads(dc) if isinstance(dc, str) else (dc or {})
                t, p = dc.get("type"), (dc.get("params") or {})
                if not _plugins.is_plugin(t):
                    continue
                hn = p.get("hostname") or c.get("hostname") or ""
                try:
                    if any(pr.get("shm") == ref for pr in
                           _plugins.derive_wiring(t, hn, p)["produces"]):
                        ok = True
                        break
                except Exception:
                    continue
        if not ok:
            raise RuntimeError(f"« {ref} » n'appartient pas au projet (ports/sorties du projet seulement)")
    from app.database import db_upsert_source_label
    db_upsert_source_label(ref, {f"label_{col}": text})
    _tally_dirty.set()   # les multiviews re-résolvent leurs labels
    return True

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
    """Retour agrégé pour compatibilité.

    ★ L'ACTIVATION DE TSL EST PAR CONNEXION, PAS GLOBALE. Il n'y a plus de réglage
    `tsl_enabled` — il ne survit que pour la migration dans `init_db`. Chaque
    entrée de la table `tsl_connections` porte son propre `enabled` et son propre
    port. La page Services, qui cherchait une clé `*_enabled` dans le manifeste,
    n'en trouvait aucune et affichait « — » : un service avec deux ports TCP en
    écoute passait donc pour non activé.

    On publie donc `enabled` nous-mêmes — vrai dès qu'une connexion est activée —
    et l'agrégateur préfère ce que le service DIT à ce qu'un réglage laisse
    supposer. C'est la même règle que partout ailleurs : l'observé prime sur le
    déclaratif."""
    try:
        from app.database import get_db
        # Pas de close() : la connexion est thread-locale et partagée.
        lignes = get_db().execute(
            "SELECT enabled, port FROM tsl_connections").fetchall()
        n_tot = len(lignes)
        actives = [r["port"] for r in lignes if r["enabled"]]
    except Exception:
        n_tot, actives = 0, []
    with _lock:
        running = any(s.running for s in _connections.values())
        clients = sum(s.clients for s in _connections.values())
        last_pkts = [s.last_pkt for s in _connections.values() if s.last_pkt]
        last_pkt = max(last_pkts) if last_pkts else None
        last_ago = round(time.time() - last_pkt, 1) if last_pkt else None
        errors = [s.last_error for s in _connections.values() if s.last_error]
        return {
            "running":        running,
            "enabled":        bool(actives),
            "connexions":     n_tot,
            "connexions_actives": len(actives),
            "ports":          actives,
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

    @bp.route("/api/tsl/mapping/by_shm", methods=["GET"])
    @require_login
    def tsl_mapping_by_shm():
        """Inverse du mapping : {shm: [{connection_id, name, tsl_index, levels}]}.

        Sans ça, une UI ne peut PAS afficher le tally d'une source : le mapping est stocké par
        (connexion, index) → shm, et rien ne permettait de faire le chemin retour. `by_shm` ne
        renvoie que les LIBELLÉS, pas d'index — la page Câbles lisait donc `src.tsl_index` sur un
        objet qui n'a jamais eu ce champ, et ses pastilles de tally ne se sont jamais allumées.

        `levels` = les trois niveaux affectés à la connexion (ses champs LH/RH/TT) : deux
        connexions peuvent employer le MÊME index pour des sources différentes, l'index seul ne
        suffit donc pas à décider si une lampe nous concerne."""
        out = {}
        for c in db_get_tsl_connections():
            niv = [c.get("%s_level_id" % ch) for ch in ("lh", "rh", "tt")]
            for m in db_get_tsl_mapping(c["id"]):
                shm = (m.get("source_shm") or "").strip()
                if not shm:
                    continue
                out.setdefault(shm, []).append({
                    "connection_id": c["id"], "name": c.get("name") or "",
                    "tsl_index": m["tsl_index"], "levels": [n for n in niv if n]})
        return jsonify(out)

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
                 "label_col": 2})
        reload()
        return jsonify(status_dict())

