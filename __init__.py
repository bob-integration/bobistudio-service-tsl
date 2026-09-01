# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 BOBI SAS, France
# Auteur : Cyril Mazouer, pour le compte de BOBI SAS
# Distribué sous licence GNU GPL v3 (ou ultérieure) ; voir le fichier LICENSE.

"""Service TSL 5.0 centralisé — multi-connexions, 10 niveaux tally, 10 colonnes labels.

Chaque connexion TSL (tsl_connections DB) ouvre son propre serveur TCP.
Le tally est stocké par (index, niveau), où `niveau` est l'UUID d'une ligne de `tally_levels` —
une ENTITÉ nommée, pas un décalage, et une identité qui ne bouge JAMAIS (le numéro qu'affiche
l'interface n'est qu'un rang, que réordonner réécrit). Une connexion TSL alimente UN niveau : sa chaîne de
destination. Ses trois champs LH/RH/TT ne sont pas trois chaînes, ce sont trois façons
d'exprimer l'état de celle-ci — `rouge_field`/`vert_field` disent lesquels portent le rouge et
le vert, et un niveau a PLUSIEURS ÉTATS (`off`/`red`/`green`/`amber`), l'ambre étant le cumul.
Le « 3 » est la trame de TSL, il ne structure plus le modèle.
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

# ═══ L'ÉTAT DU TALLY, EN DEUX COUCHES ═════════════════════════════════════════════════════════
#
# ★ PLUSIEURS SOURCES PEUVENT SERVIR LE MÊME NIVEAU, et c'est un cas voulu : deux contrôleurs
# broadcast sur une même chaîne de destination, un émetteur TSL doublé par un Receiver IS-07, un
# mélangeur qui complète ce qu'un pupitre externe annonce. Une seule couche ne pouvait pas
# l'exprimer : le dernier écrivain écrasait les autres, et surtout, une source qui repasse au vert
# écrivait « off » sur le rouge d'une AUTRE — un tally qui s'éteint sans que personne ne l'ait
# demandé, sur une fonction d'antenne.
#
#   `_tally_par_source[(index, niveau)][source]` — ce que CHAQUE source affirme. Une source
#   remplace toujours sa contribution ENTIÈRE (`poser_tally`), jamais case par case : sinon un
#   signal qui sort du programme garderait son rouge, faute d'un « off » explicite.
#
#   `_tally_state[(index, niveau)]` — le CUMUL, seul lu par les consommateurs. Rouge + vert donne
#   l'ambre, exactement comme deux contributions d'un même mélangeur.
_tally_par_source: dict = {}
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

    def __init__(self, conn_id, port, label_col, niveau,
                 rouge_field="tt", vert_field="lh"):
        """`niveau` = l'UNIQUE niveau que cette connexion alimente (None = elle n'écrit rien).

        ★ Plus de base historique, et plus de niveau par champ. Le mot de contrôle TSL 5.0 réserve
        deux bits par champ, pour trois champs : c'est SA trame, elle reste ici et sert à décider
        de l'ÉTAT du niveau (`rouge_field` porte le rouge, `vert_field` le vert, les deux à la
        fois donnent l'ambre). Ce qui a disparu, c'est que ce « 3 » structure le modèle interne —
        une production n'est plus plafonnée à trois chaînes de destination parce que TSL en a
        trois, et une chaîne n'occupe plus trois numéros pour en exprimer un seul état."""
        self.conn_id    = conn_id
        self.port       = port
        self.label_col  = label_col    # colonne label mise à jour par TSL text
        self.niveau      = niveau
        self.rouge_field = (rouge_field or "tt").lower()
        self.vert_field  = (vert_field or "lh").lower()
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

            # Une connexion sans niveau affecté n'écrit RIEN — plutôt que d'écrire sur un
            # niveau deviné, ce qui allumerait un rouge chez quelqu'un d'autre.
            par_champ = {"lh": _tsl_color(lh_v), "rh": _tsl_color(rh_v), "tt": _tsl_color(tt_v)}
            colors = {}
            if self.niveau:
                rouge = par_champ.get(self.rouge_field, "off") in ("red", "amber")
                vert  = par_champ.get(self.vert_field,  "off") in ("green", "amber")
                colors = {self.niveau: ("amber" if rouge and vert else
                                        "red" if rouge else "green" if vert else "off")}

        # La contribution de CE serveur pour CET index. On ne remplace pas sa contribution
        # entière (les autres index qu'il tallye restent), mais bien sa case à lui : un serveur
        # TSL reçoit ses index un par un, chaque trame ne parlant que d'un seul.
        changed = _poser_cases("tsl:%s" % self.conn_id,
                               {(index, lvl): color for lvl, color in colors.items()})
        if changed:
            _tally_dirty.set()
            with self._lock:
                self.last_change        = time.time()
                self.last_change_idx    = index
                # Diagnostic : on montre les TROIS champs du fil, pas l'état déduit — c'est
                # justement l'écart entre les deux qu'on vient chercher quand ça ne s'allume pas.
                self.last_change_colors = dict(par_champ)

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
                "niveau":        self.niveau,
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

    def __init__(self, conn_id, dest_host, dest_port, label_col, niveau,
                 rouge_field="tt", vert_field="lh"):
        self.conn_id     = conn_id
        self.dest_host   = dest_host
        self.port        = dest_port
        self.label_col   = label_col
        self.niveau      = niveau                # l'UNIQUE niveau que cet afficheur montre
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
        # UN niveau, plusieurs ÉTATS. `rouge_field`/`vert_field` ne choisissent pas DEUX
        # niveaux : ils disent dans quel champ de la trame l'afficheur d'en face attend le rouge
        # et dans lequel il attend le vert. C'est un choix de câblage de l'afficheur, pas une
        # propriété du signal — et le cumul (`amber`) allume les deux champs.
        lvl = self.niveau
        out = []
        try:
            mapping = db_get_tsl_mapping(self.conn_id)
        except Exception:
            mapping = []
        for m in mapping:
            idx = int(m.get("tsl_index") or 0)
            ref = (m.get("source_shm") or "").strip()
            etat  = state.get((idx, lvl), "off") if lvl else "off"
            red   = etat in ("red", "amber")
            green = etat in ("green", "amber")
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
# Dernier `/state` connu de chaque mélangeur, DÉPOSÉ par l'émetteur qui l'interroge déjà toutes
# les 0,3 s. La propagation le relit : refaire la requête depuis le distributeur doublerait le
# trafic vers les conteneurs pour la même information, à la même fraîcheur.
_etat_mixer: dict = {}


def _plg_wiring(type_, hostname, params):
    from app import plugins as _plg
    return _plg.derive_wiring(type_, hostname, params) or {}

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


_CUMUL = {frozenset(("red", "green")): "amber"}

def cumuler(a, b):
    """Cumul de deux états sur UN MÊME niveau. Rouge + vert = ambre.

    ⚠ Ce n'est pas « PGM + PVW = orange » : rien ici ne connaît de bus. Deux CONTRIBUTIONS
    arrivent sur le même niveau pour le même index, et un niveau a plusieurs états dont l'un
    exprime la coexistence. C'est ce cumul, et lui seul, qui produit l'orange que voit
    l'exploitant quand une source est à la fois au programme et en préparation."""
    a, b = a or "off", b or "off"
    if a == "off":  return b
    if b == "off":  return a
    if a == b:      return a
    return _CUMUL.get(frozenset((a, b)), "amber")

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
        if not isinstance(niveaux, list):
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
        _etat_mixer[ct["vmid"]] = st
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
        want = {}
        def _poser(idx, couleur):
            """Pose une contribution sur TOUS les niveaux du mélangeur, en cumulant."""
            for lvl in niveaux:
                cle = (idx, lvl)
                want[cle] = cumuler(want.get(cle), couleur)
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
            # ★ MÊME NIVEAU pour les deux. Avant le dénouement, le rouge et le vert partaient sur
            # DEUX niveaux distincts (le 1er et le 2nd du mélangeur) : une source au programme ET
            # en préparation occupait deux entrées qui ne se rencontraient jamais, et c'est
            # l'afficheur qui recomposait l'orange en lisant les deux champs de la trame. Le cumul
            # a désormais lieu ICI, sur le niveau — donc IS-07 et le multiview le voient aussi.
            if i_pgm is not None:
                _poser(i_pgm, "red")
            if i_pvw is not None:
                _poser(i_pvw, "green")
        # ★ REMPLACEMENT INTÉGRAL, PAR MÉLANGEUR. `poser_tally` retire tout ce que CE mélangeur
        # avait posé et qu'il ne pose plus — un changement de PGM éteint donc l'ancienne source —
        # sans jamais toucher à ce qu'un autre écrivain affirme sur les mêmes clés.
        if poser_tally("mixer:%s" % ct["vmid"], want, reveiller=False):
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


def propager(etat, par_shm, idx_de, etat_ctrl_de):
    """{(index, niveau): couleur} À AJOUTER par propagation. Ne modifie rien.

    `par_shm`       : shm produit → (conteneur, deploy_config)
    `idx_de`        : callable(shm, niveau) → index TSL, ou None. Une CALLABLE et non un dict :
                      l'index d'un flux dépend du PORTEUR du niveau — deux porteurs peuvent
                      employer le même index pour des sources différentes, et une table à plat
                      ferait propager sur le mauvais signal.
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
        for shm in (par_shm or {}):
            if idx_de(shm, niveau) == idx:
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
            idx_amont = idx_de(amont, niveau)
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
                porteurs.append({"_key": int(c.get("id") or 0),
                                 "niveaux": [c.get("level_uuid")], "_project": None})
            # Pseudo-porteurs PAR PRODUCTION : l'écrivain est l'émetteur du mélangeur, et
            # l'index d'une source est son port (ord).
            try:
                for pr in db_get_projects():
                    niv = db_get_tally_levels_of("project", pr["id"])
                    if not niv:
                        continue
                    porteurs.append({"_key": "proj:%s" % pr["id"], "niveaux": niv,
                                     "_project": pr["id"]})
            except Exception:
                pass
            # niveau → porteur : c'est par là que le multiview retrouve qui sert son niveau.
            porteur_de_niveau = {}
            for pt in porteurs:
                for n in pt["niveaux"]:
                    if n:
                        porteur_de_niveau.setdefault(n, pt)

            def _porteur_pour(niveaux):
                """(niveau servi, porteur) pour une demande — le premier niveau demandé dont
                quelqu'un écrit l'état.

                ★ LE NIVEAU DEMANDÉ EST LE NIVEAU LU. Avant le dénouement, on retrouvait le
                porteur puis on RE-CHOISISSAIT deux de ses trois niveaux via `rouge_field`/
                `vert_field` : le niveau demandé ne servait qu'à désigner le porteur, et pouvait
                n'être lu par personne. Le rouge et le vert sont maintenant deux ÉTATS du même
                niveau, et les champs TSL ne concernent plus que la mise sur le fil."""
                for _n in (niveaux or ()):
                    _pt = porteur_de_niveau.get(_n)
                    if _pt:
                        return _n, _pt
                return None, None
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

            # ── PROPAGATION : remonter le graphe depuis les flux à l'antenne ──────────────
            # Ses déductions s'ajoutent à `state` POUR CE TOUR seulement, jamais à
            # `_tally_state`. C'est ce qui empêche la boucle : un tally propagé qu'on écrirait
            # dans l'état deviendrait, au tour suivant, indiscernable d'un tally REÇU, et se
            # propagerait à son tour d'un cran de plus, indéfiniment.
            try:
                par_shm = {}
                for _ct in containers:
                    _dc = _ct.get("deploy_config")
                    _dc = json.loads(_dc) if isinstance(_dc, str) else (_dc or {})
                    if not _dc:
                        continue
                    _w = _plg_wiring(_dc.get("type"), _ct.get("hostname"), _dc.get("params") or {})
                    for _p in (_w.get("produces") or []):
                        _shm = (_p.get("shm") or "").strip()
                        if _shm:
                            par_shm.setdefault(_shm, (_ct, _dc))

                def _idx_de(shm, niveau):
                    """Index de ce flux CHEZ LE PORTEUR du niveau — deux porteurs peuvent
                    employer le même index pour des sources différentes."""
                    pt = porteur_de_niveau.get(niveau)
                    if not pt:
                        return None
                    return idx_by_conn_shm.get((pt["_key"], resolve_ref(shm) or shm))

                deduits = propager(state, par_shm, _idx_de, _etat_mixer)
                for _k, _v in deduits.items():
                    state.setdefault(_k, _v)
            except Exception as e:
                log.debug("TSL: propagation ignorée ce tour (%s)", e)
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
                    if not isinstance(niv_c, list):
                        niv_c = [niv_c]
                    if not niv_c:
                        niv_c = proj_niv.get(ct.get("project_id")) or []
                    lvl_c, conn_c = _porteur_pour(niv_c)
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
                            _e = state.get((ti, lvl_c), "off")
                            coul_r = "red"   if _e in ("red", "amber")   else "off"
                            coul_v = "green" if _e in ("green", "amber") else "off"
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
                # ⚠ UNE CHAÎNE N'EST PAS UNE LISTE, et Python ne le dira pas : depuis que les
                # niveaux sont des UUID, un scalaire hérité est une CHAÎNE, et `for n in ...`
                # l'aurait parcourue caractère par caractère — trente-six « niveaux » d'une
                # lettre, dont aucun n'existe, donc un tally qui ne s'allume jamais et pas la
                # moindre erreur.
                niveaux_fc = fc.get("tally_level") or []
                if not isinstance(niveaux_fc, list):
                    niveaux_fc = [niveaux_fc]
                want_red   = bool(fc.get("tally_red"))
                want_green = bool(fc.get("tally_green"))
                want_text  = fc.get("label_source") == "protocol"
                if not niveaux_fc:
                    niveaux_fc = proj_niv.get(ct.get("project_id")) or []
                if not niveaux_fc or not (want_red or want_green or want_text):
                    continue
                # Le porteur est celui qui POSSÈDE ces niveaux — plus une bande à recouper.
                lvl_fc, conn = _porteur_pour(niveaux_fc)
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
                label_col = int(fc.get("label_col") or 0)

                # Le niveau a plusieurs états : `amber` allume les DEUX bandeaux de la tuile,
                # c'est ainsi que l'orange se voit sur le mur.
                _e = state.get((tsl_index, lvl_fc), "off")
                color_l = "red"   if (want_red   and _e in ("red", "amber"))   else "off"
                color_r = "green" if (want_green and _e in ("green", "amber")) else "off"
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
                if not isinstance(o_niv, list):
                    o_niv = [o_niv]
                if not o_niv:
                    o_niv = proj_niv.get(ct.get("project_id")) or []
                if o_niv and (ov.get("tally_red") or ov.get("tally_green")):
                    lvl_o, o_conn = _porteur_pour(o_niv)
                    if o_conn:
                        row_res = resolve_ref(row_shm) or row_shm
                        o_idx = idx_by_conn_shm.get(
                            (o_conn.get("_key", int(o_conn.get("id") or 0)), row_res))
                        if o_idx is not None:
                            _eo = state.get((o_idx, lvl_o), "off")
                            red_on   = bool(ov.get("tally_red"))   and _eo in ("red", "amber")
                            green_on = bool(ov.get("tally_green")) and _eo in ("green", "amber")
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

        def _mk(row):
            niveau = row.get("level_uuid")
            rf = row.get("rouge_field") or "tt"
            vf = row.get("vert_field") or "lh"
            if (row.get("direction") or "in") == "out":
                return _TslClient(row["id"], row.get("dest_host") or "127.0.0.1",
                                  row["port"], row["label_col"], niveau,
                                  rouge_field=rf, vert_field=vf)
            return _TslServer(row["id"], row["port"], row["label_col"], niveau,
                              rouge_field=rf, vert_field=vf)

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
                  or srv.niveau != row.get("level_uuid")
                  or srv.rouge_field != (row.get("rouge_field") or "tt")
                  or srv.vert_field != (row.get("vert_field") or "lh")
                  or is_out != want_out
                  or (want_out and getattr(srv, "dest_host", None) != (row.get("dest_host") or "127.0.0.1"))):
                srv.stop()
                srv2 = _mk(row)
                _connections[cid] = srv2
                srv2.start()

def _cumul_des_sources(cle):
    """Couleur résultante d'une case, tous écrivains confondus. À appeler SOUS `_lock`."""
    couleur = "off"
    for c in (_tally_par_source.get(cle) or {}).values():
        couleur = cumuler(couleur, c)
    return couleur


def _poser_cases(source, cases):
    """Pose/actualise les cases nommées pour cette source, sans toucher aux autres. Sous `_lock`
    en interne ; renvoie True si le CUMUL a bougé quelque part."""
    change = False
    with _lock:
        for cle, couleur in (cases or {}).items():
            par = _tally_par_source.setdefault(cle, {})
            if couleur == "off":
                if par.pop(source, None) is None:
                    continue
            elif par.get(source) == couleur:
                continue
            else:
                par[source] = couleur
            neuf = _cumul_des_sources(cle)
            if not par:
                _tally_par_source.pop(cle, None)
            if _tally_state.get(cle, "off") != neuf:
                if neuf == "off":
                    _tally_state.pop(cle, None)
                else:
                    _tally_state[cle] = neuf
                change = True
    return change


def poser_tally(source, cases, reveiller=True):
    """Remplace la contribution ENTIÈRE de `source`. Renvoie True si le cumul a bougé.

    ★ ENTIÈRE, ET C'EST LE POINT. Un écrivain qui ne poserait que ses cases allumées ne pourrait
    jamais en éteindre une : la source qui sort du programme garderait son rouge indéfiniment,
    faute d'un « off » explicite. On retire donc d'abord tout ce que cette source affirmait et
    qu'elle n'affirme plus — sans toucher à ce que les AUTRES affirment sur les mêmes cases.

    `source` est une chaîne qui identifie l'écrivain : `tsl:<id>`, `mixer:<vmid>`,
    `is07:<receiver>`. Deux écrivains sur le même niveau se CUMULENT (rouge + vert = ambre) au
    lieu de s'écraser."""
    cases = {k: v for k, v in (cases or {}).items() if v and v != "off"}
    change = False
    with _lock:
        # ⚠ CE FILTRE EST UNE OPTIMISATION, PAS LE GARDE-FOU. Ce qui protège les autres écrivains,
        # c'est le `par.pop(source)` de `_poser_cases` : retirer sa propre entrée d'une case ne
        # touche à rien d'autre. Vérifié par mutation — élargir cette liste à toutes les cases ne
        # change aucun résultat. Ne pas la « corriger » en croyant renforcer quelque chose.
        anciennes = [cle for cle, par in _tally_par_source.items() if source in par]
    a_retirer = {cle: "off" for cle in anciennes if cle not in cases}
    if a_retirer:
        change = _poser_cases(source, a_retirer) or change
    change = _poser_cases(source, cases) or change
    if change and reveiller:
        _tally_dirty.set()
    return change


def sources_du_tally() -> dict:
    """`{"<index>_<niveau>": {source: couleur}}` — QUI affirme quoi. Sert au diagnostic : sans
    ça, un niveau servi par deux écrivains ne dit pas lequel allume la lampe."""
    with _lock:
        return {f"{idx}_{lvl}": dict(par)
                for (idx, lvl), par in _tally_par_source.items() if par}


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


NOMS_COLONNES_DEFAUT = ["Hostname", "MXL", "Label 2", "Label 3", "Label 4",
                        "Label 5", "Label 6", "Label 7", "Label 8", "Label 9"]


def noms_colonnes():
    """Les DIX noms de colonnes, toujours — y compris ceux des colonnes masquées."""
    from app.database import db_get_setting
    noms = db_get_setting("tsl_label_names", None)
    if isinstance(noms, str):
        try:
            noms = json.loads(noms)
        except Exception:
            noms = None
    if not isinstance(noms, list):
        noms = []
    return [str(noms[i]) if i < len(noms) and noms[i] else NOMS_COLONNES_DEFAUT[i]
            for i in range(10)]


def nb_colonnes_actives():
    """Combien de colonnes PERSONNALISÉES sont offertes (1 à 8). Deux par défaut.

    ⚠ LE DÉFAUT NE S'APPLIQUE QU'AUX INSTALLATIONS NEUVES. `_migrer_colonnes_libelles` pose la
    valeur initiale au premier démarrage d'après ce qui EXISTE — une colonne renommée ou
    remplie compte — sinon un site qui se sert de six colonnes en verrait quatre disparaître de
    ses tableaux, sans un mot, pour un défaut qui ne le concernait pas."""
    from app.database import db_get_setting
    try:
        n = int(db_get_setting("label_cols_actives", 2))
    except (TypeError, ValueError):
        n = 2
    return max(1, min(8, n))


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
        del names
        noms = noms_colonnes()
        # Les colonnes MASQUÉES ne sont pas proposées : une macro qui écrirait dans une colonne
        # que personne n'affiche serait une action sans effet visible.
        return [{"value": i, "label": "%d — %s" % (i, noms[i])}
                for i in range(2, 2 + nb_colonnes_actives())]
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

    @bp.route("/api/source_labels/orphelins", methods=["GET"])
    @require_login
    def source_labels_orphelins():
        """Les lignes de libellé dont PLUS AUCUN conteneur ne produit le flux.

        ★ « ABSENT » VEUT DIRE ABSENT DE LA DÉCLARATION, PAS ÉTEINT. `/api/sources` dérive de
        `deploy_config` : un conteneur arrêté, un nœud injoignable, un flux qui ne coule pas —
        tout cela reste DÉCLARÉ. Ne sont orphelines que les lignes dont le producteur a été
        détruit ou renommé. Sans cette propriété, arrêter un conteneur ferait basculer tous ses
        libellés en « à nettoyer », et quelqu'un les supprimerait.

        ⚠ ON NE SUPPRIME RIEN ICI. Un libellé est du TRAVAIL — quelqu'un l'a écrit — et une ligne
        vide ne coûte qu'une ligne. On les CLASSE pour que l'exploitant tranche :
          · `rempli`  : au moins un libellé écrit. Le perdre, c'est perdre ce travail.
          · `mappe`   : une correspondance TSL ou IS-07 la vise encore. La retirer casserait le
                        tally de quelque chose que quelqu'un adresse — même si le flux a disparu,
                        c'est le signe qu'on n'a pas fini de ranger."""
        from app.database import (db_get_source_labels, db_get_tsl_mappings_all,
                                  db_get_is07_mappings_all, db_get_containers)
        from app import plugins as _plg
        import json as _json
        declares = set()
        for c in db_get_containers():
            try:
                dc = c.get("deploy_config")
                dc = _json.loads(dc) if isinstance(dc, str) else (dc or {})
                if not dc:
                    continue
                w = _plg.derive_wiring(dc.get("type"), c.get("hostname"),
                                       dc.get("params") or {}) or {}
                for prod in (w.get("produces") or []):
                    if prod.get("shm"):
                        declares.add(prod["shm"])
            except Exception:
                continue
        vises = set()
        for m in (db_get_tsl_mappings_all() or []):
            if m.get("source_shm"):
                vises.add(m["source_shm"])
        try:
            for m in (db_get_is07_mappings_all() or []):
                if m.get("source_shm"):
                    vises.add(m["source_shm"])
        except Exception:
            pass
        out = []
        for l in db_get_source_labels():
            shm = l.get("shm") or ""
            # Les lignes de TEXTE (`__umd:`) n'ont pas de producteur par construction : les
            # compter orphelines les proposerait au nettoyage à chaque passage.
            if not shm or shm.startswith("__umd:") or shm in declares:
                continue
            out.append({"shm": shm,
                        "rempli": [k for k in l if k.startswith("label_") and l[k]],
                        "mappe": shm in vises})
        return jsonify(sorted(out, key=lambda x: x["shm"]))

    @bp.route("/api/source_labels/orphelins", methods=["POST"])
    @require_perm("settings.edit")
    def source_labels_orphelins_purge():
        """`{"shms": [...]}` — retire ces lignes de libellé. Refuse celles qu'une correspondance
        vise encore : le tally les adresse, et les effacer serait casser en silence."""
        from app.database import (db_delete_source_label, db_get_tsl_mappings_all,
                                  db_get_is07_mappings_all)
        d = request.json or {}
        shms = d.get("shms")
        if not isinstance(shms, list):
            return jsonify({"error": "`shms` : liste attendue"}), 400
        vises = {m.get("source_shm") for m in (db_get_tsl_mappings_all() or [])}
        try:
            vises |= {m.get("source_shm") for m in (db_get_is07_mappings_all() or [])}
        except Exception:
            pass
        retires, refuses = 0, []
        for shm in shms:
            shm = str(shm or "").strip()
            if not shm:
                continue
            if shm in vises:
                refuses.append(shm)
                continue
            db_delete_source_label(shm)
            retires += 1
        return jsonify({"ok": True, "retires": retires, "refuses": refuses})

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

        `levels` = le niveau affecté à la connexion, en LISTE (l'appelant en attend une, et un
        porteur pourra en servir plusieurs) : deux connexions peuvent employer le MÊME index pour
        des sources différentes, l'index seul ne suffit donc pas à décider si une lampe nous
        concerne."""
        out = {}
        for c in db_get_tsl_connections():
            niv = [c.get("level_uuid")]
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
        """Les colonnes de libellé OFFERTES : hostname, MXL, puis les personnalisées actives.

        ★ ON EN REND MOINS QU'IL N'EN EXISTE, et c'est le point. Huit colonnes personnalisées
        étaient proposées d'office ; un site en utilise deux ou trois, et les cinq autres
        allongeaient chaque menu, chaque tableau et chaque sélecteur du produit sans rien porter.
        Le nombre actif est un réglage (`label_cols_actives`, 2 par défaut) et les colonnes
        s'ajoutent au besoin.

        ⚠ LES HUIT COLONNES PHYSIQUES RESTENT. Réduire l'affichage n'efface aucune donnée : un
        libellé écrit en colonne 7 reste lisible par son index (`db_get_source_label_for_shm`),
        et réaugmenter le nombre le fait réapparaître intact. C'est ce qui rend le réglage
        réversible sans risque."""
        return jsonify(noms_colonnes()[:2 + nb_colonnes_actives()])

    @bp.route("/api/tsl/label_names", methods=["POST"])
    @require_perm("settings.edit")
    def tsl_label_names_set():
        data = request.json
        if not isinstance(data, list) or not (3 <= len(data) <= 10):
            return jsonify({"error": "liste de 3 à 10 noms attendue"}), 400
        # On COMPLÈTE jusqu'à dix avec les noms déjà en base : enregistrer une liste tronquée
        # écraserait le nom des colonnes masquées, qu'on retrouverait anonymes en les rouvrant.
        anciens = noms_colonnes()
        noms = [str(n) for n in data] + anciens[len(data):]
        db_set_setting("tsl_label_names", noms[:10])
        return jsonify({"ok": True})

    @bp.route("/api/tsl/label_cols", methods=["GET"])
    @require_login
    def tsl_label_cols_get():
        return jsonify({"actives": nb_colonnes_actives(), "max": 8,
                        "noms": noms_colonnes()})

    @bp.route("/api/tsl/label_cols", methods=["POST"])
    @require_perm("settings.edit")
    def tsl_label_cols_set():
        """`{"actives": n}` — combien de colonnes personnalisées sont offertes (1 à 8)."""
        d = request.json or {}
        try:
            n = int(d.get("actives"))
        except (TypeError, ValueError):
            return jsonify({"error": "`actives` : entier attendu"}), 400
        if not (1 <= n <= 8):
            return jsonify({"error": "entre 1 et 8"}), 400
        db_set_setting("label_cols_actives", n)
        return jsonify({"ok": True, "actives": n})


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

