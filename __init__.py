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
import logging
import socket
import struct
import threading
import time

log = logging.getLogger(__name__)

# ─── LE MODÈLE DE TALLY VIT DANS `app/tally.py` ─────────────────────────────────────────
# ★ CE MODULE N'EST PLUS QU'UN ADAPTATEUR DE PROTOCOLE. Le modèle — niveaux, contributions
# cumulées, propagation dans le graphe, résolution de référence — était ici parce que c'est
# TSL qui l'a fait naître. Conséquence : `services/nmos/is07*.py` importait TSL pour poser son
# tally, donc supprimer TSL aurait emporté IS-07. Le protocole qu'on remplace tenait le modèle.
#
from app import tally as _tally

# Ce que le SERVICE emploie du modèle. Ce n'est plus une passerelle : rien n'est réexporté ici,
# et un appelant tiers qui voudrait le tally vise `app.tally`. La liste est courte, et c'est le
# but — elle mesure ce qu'un protocole a besoin de savoir du tally, soit : poser une
# contribution, lire l'état pour le mettre sur le fil, se déclarer porteur, et résoudre une
# référence de source. Rien sur le CALCUL du tally, qui ne le regarde pas.
from app.tally import (
    poser_tally, etat_brut, get_tally_state, signaler_changement, attendre_changement,
    resolve_ref, _ports_snapshot,
    enregistrer_porteur, retirer_porteur, liste_porteurs,
    noms_colonnes, nb_colonnes_actives,
)

# Propres au service : le verrou des CONNEXIONS, distinct de celui du modèle (cf. app/tally.py).
_lock_conn = threading.Lock()
_dist_thr  = None
_stop_evt  = threading.Event()

# _connections : {conn_id: _TslServer}
_connections: dict = {}


def _invalider_mapping(cid=None):
    """Le mapping vient de changer : les serveurs concernés re-traduisent ce qu'ils affirment.

    Sans cet appel, un tally déjà reçu resterait accroché à la source qu'il désignait AVANT
    l'édition — un serveur TSL n'émettant que sur changement, rien ne viendrait le corriger."""
    with _lock_conn:
        cibles = [srv for c, srv in _connections.items()
                  if (cid is None or int(c) == int(cid)) and hasattr(srv, "invalider_mapping")]
    for srv in cibles:
        try:
            srv.invalider_mapping()
        except Exception:
            pass
    signaler_changement()



TSL_SOM          = b"\xfe\x02"
TSL_SLOT_TTL_F   = 2.5
TSL_SLOT_TTL_MIN = 0.05

# ─── Parser TSL 5.0 ────────────────────────────────────────────────────────────
def _tsl_color(val):
    if val == 0: return "off"
    if val == 2: return "green"
    if val == 3: return "amber"
    return "red"

_COLOR_CODE = {"off": 0, "red": 1, "green": 2, "amber": 3}
_OFF_FIELD  = {"lh": 0, "rh": 1, "tt": 2}




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

        # Ce que CE serveur affirme, indexé par index de TRAME. C'est la seule mémoire du
        # protocole : le modèle, lui, est adressé par source. On la garde parce qu'un
        # changement de mapping doit re-router un tally déjà reçu, alors qu'un serveur TSL
        # ne réémet pas spontanément — il n'envoie que sur changement.
        self._brut = {}
        self._map_cache = None
        self._map_exp   = 0.0
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

    def _mapping(self):
        """index de trame → référence de source, mémorisé quelques secondes.

        Un serveur TSL peut recevoir des dizaines de trames par seconde ; relire la table à
        chaque trame la ferait payer au réseau. `invalider_mapping()` force la relecture dès
        que quelqu'un édite le mapping — le cache ne masque donc jamais une modification."""
        now = time.monotonic()
        with self._lock:
            if self._map_cache is not None and now < self._map_exp:
                return self._map_cache
        try:
            from app.database import db_get_tsl_mapping
            m = {int(r["tsl_index"]): (r.get("source_shm") or "")
                 for r in db_get_tsl_mapping(self.conn_id)}
        except Exception:
            m = {}
        with self._lock:
            self._map_cache, self._map_exp = m, now + 2.0
        return m

    def invalider_mapping(self):
        with self._lock:
            self._map_cache = None
        self._republier()

    def _republier(self):
        """Traduit ce que ce serveur affirme (par index de TRAME) en cases du modèle (par
        SOURCE), et republie sa contribution ENTIÈRE.

        ★ Entière, et c'est le point. Un index qui perd son mapping disparaît de l'ensemble
        posé, donc s'éteint — alors qu'une pose case-par-case l'aurait laissé figé sur la
        source qu'il désignait avant. C'est exactement la panne vue en production sur PiP4.

        C'est ici, et NULLE PART AILLEURS, que l'index TSL touche le tally : au-delà de cette
        méthode, le protocole n'existe plus. Le jour où l'on passe en IS-07, c'est ce seul
        traducteur qui disparaît."""
        mapping = self._mapping()
        with self._lock:
            brut = {i: dict(c) for i, c in self._brut.items()}
        cases = {}
        for idx, colors in brut.items():
            ref = _tally.resolve_ref(mapping.get(idx) or "")
            if not ref:
                continue          # index non mappé : il ne désigne aucune source, il n'allume rien
            for lvl, color in colors.items():
                cle = (ref, lvl)
                # Deux index de trame peuvent viser la même source : on cumule au lieu
                # d'écraser, sinon le dernier index lu gagnerait arbitrairement.
                cases[cle] = _tally.cumuler(cases.get(cle), color)
        return poser_tally("tsl:%s" % self.conn_id, cases, reveiller=False)

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

        with self._lock:
            self._brut[index] = dict(colors)
        changed = self._republier()
        if changed:
            signaler_changement()
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
    externe. Consomme l'état du modèle (réveillé par `attendre_changement`, comme le distributeur)
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
        from app.database import db_get_tsl_mapping
        state = etat_brut()          # le modèle prend SON verrou
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
            # ★ C'EST ICI QUE L'INDEX NAÎT, au dernier moment, pour la trame et pour elle seule.
            # L'état est lu PAR SOURCE ; le mapping ne sert qu'à savoir sous quel numéro
            # l'afficheur d'en face attend ce signal. Le modèle, lui, n'a jamais vu ce numéro.
            etat  = state.get((_tally.resolve_ref(ref) or ref, lvl), "off") if lvl else "off"
            red   = etat in ("red", "amber")
            green = etat in ("green", "amber")
            control = build_control(red, green, self.rouge_field, self.vert_field)
            # Pas de repli de colonne sur le fil : un UMD physique est câblé sur UNE colonne, et
            # lui envoyer le contenu d'une autre parce que la sienne est vide serait mentir sur
            # ce qu'affiche l'écran. Le repli n'a lieu que pour nos propres afficheurs.
            text = _tally.libelle_de(ref, self.label_col, replier=False)
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
                    attendre_changement(0.2)
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


# ─── API publique ──────────────────────────────────────────────────────────────
def start_all():
    """Démarre les serveurs/clients TSL activés.

    ⚠ LE MODÈLE D'ABORD. `app.tally.demarrer()` lance le distributeur ; un serveur TSL qui
    recevrait une trame avant lui poserait un tally que personne ne distribue. L'ordre est
    tenu ici plutôt que laissé à l'appelant — main.py n'a pas à connaître cette contrainte.

    Le modèle est démarré même si aucune connexion TSL n'existe : IS-07 et le mélangeur
    écrivent dans le même état, et ils n'ont pas à dépendre de la présence d'une connexion TSL."""
    _tally.demarrer()
    reload()


def stop_all():
    """Arrête les connexions TSL. Le MODÈLE N'EST PAS ARRÊTÉ : ses deux fils servent aussi
    IS-07 et le mélangeur. Les couper ici éteindrait tous les murs parce qu'on a désactivé
    une connexion TSL — exactement le couplage que ce chantier retire."""
    with _lock_conn:
        for srv in _connections.values():
            srv.stop()
        _connections.clear()
    _publier_porteurs()

def reload():
    """Synchronise _connections depuis la DB (crée/met à jour/supprime)."""
    try:
        from app.database import db_get_tsl_connections
        rows = db_get_tsl_connections()
    except Exception as e:
        log.warning(f"TSL reload: impossible de lire les connexions ({e})")
        return

    with _lock_conn:
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

    _publier_porteurs()


def _index_de_connexion(cid):
    """Fabrique le `index_de` d'une connexion TSL : shm → index déclaré dans SON mapping.

    ⚠ Une FERMETURE qui relit le mapping à chaque appel, et non une table capturée : un
    exploitant ajoute une correspondance sans redémarrer, et un index figé au démarrage
    l'ignorerait jusqu'au prochain `reload()` — un PiP qui reste éteint sans rien à voir
    dans les journaux."""
    def index_de(shm, _niveau=None):
        if not shm:
            return None
        try:
            from app.database import db_get_tsl_mappings_all
            cible = resolve_ref(shm) or shm
            for m in db_get_tsl_mappings_all():
                if int(m.get("connection_id") or 0) != int(cid):
                    continue
                ref = (m.get("source_shm") or "").strip()
                if ref and (resolve_ref(ref) or ref) == cible:
                    return int(m.get("tsl_index") or 0)
        except Exception:
            return None
        return None
    return index_de


def _ref_de_connexion(cid):
    """Fabrique le `ref_de` d'une connexion : shm → la référence telle qu'elle est ÉCRITE dans
    le mapping, quand elle diffère du shm résolu.

    Un mapping peut viser `port:<id>` ; le libellé, lui, a été écrit sous cette référence-là.
    Chercher le texte sous le shm résolu le ferait disparaître, sans erreur."""
    def ref_de(shm):
        if not shm:
            return None
        try:
            from app.database import db_get_tsl_mappings_all
            cible = resolve_ref(shm) or shm
            for m in db_get_tsl_mappings_all():
                if int(m.get("connection_id") or 0) != int(cid):
                    continue
                ref = (m.get("source_shm") or "").strip()
                if ref and (resolve_ref(ref) or ref) == cible and ref != cible:
                    return ref
        except Exception:
            return None
        return None
    return ref_de


def _publier_porteurs():
    """Déclare au MODÈLE les niveaux que ce protocole porte, et retire ceux qu'il ne porte plus.

    ★ C'EST L'INVERSION DE DÉPENDANCE. Le distributeur allait chercher ses porteurs dans
    `db_get_tsl_connections()` : le modèle lisait donc la table d'un protocole, et il aurait
    fallu lui apprendre `is07_connections`, puis celle du suivant. Désormais chaque protocole
    se DÉCLARE, et `app/tally.py` ne connaît aucune table de protocole.

    Seules les connexions ENTRANTES sont des porteurs : une sortante consomme l'état, elle ne
    le sert pas — l'inscrire ferait croire au distributeur que quelqu'un écrit ce niveau."""
    vivants = set()
    with _lock_conn:
        entrantes = [(cid, srv) for cid, srv in _connections.items()
                     if isinstance(srv, _TslServer) and srv.niveau]
    for cid, srv in entrantes:
        cle = "tsl:%s" % cid
        vivants.add(cle)
        enregistrer_porteur(cle, [srv.niveau], _index_de_connexion(cid),
                            nom="TSL #%s" % cid, ref_de=_ref_de_connexion(cid))
    # Ne retirer QUE nos porteurs : ceux d'un autre protocole ne nous appartiennent pas.
    for cle in [c for c in liste_porteurs() if c.startswith("tsl:")]:
        if cle not in vivants:
            retirer_porteur(cle)


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
    signaler_changement()   # les multiviews re-résolvent leurs libellés
    return True

def connections_status() -> list:
    with _lock_conn:
        return [srv.status_dict() for srv in _connections.values()]


# ─── Compat : anciens appels start/stop/is_running ────────────────────────────
def start(port: int = 12345):
    start_all()

def stop():
    stop_all()

def is_running():
    with _lock_conn:
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
    with _lock_conn:
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
            "tally":          get_tally_state(),
        }


# ─── Routes Flask ──────────────────────────────────────────────────────────────
def register_routes(bp):
    from flask import request, jsonify
    from app.auth import require_login, require_perm
    # Les fonctions de LIBELLÉS sont parties avec leurs routes (app/routes/labels_api.py).
    from app.database import (db_get_setting,
                              db_get_tsl_connections,
                              db_upsert_tsl_connection,
                              db_delete_tsl_connection,
                              db_get_tsl_mapping,
                              db_upsert_tsl_mapping,
                              db_delete_tsl_mapping,
                              db_get_tsl_mappings_all,
                              db_set_tsl_mapping_for_source)

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

    # ── Suffix map (héritage parent → label auto) ─────────────────────────────

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
        _invalider_mapping(cid)
        return jsonify({"ok": True})

    @bp.route("/api/tsl/mapping/<int:cid>/<int:idx>", methods=["DELETE"])
    @require_perm("settings.edit")
    def tsl_mapping_delete(cid, idx):
        db_delete_tsl_mapping(cid, idx)
        _invalider_mapping(cid)
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
        _invalider_mapping()
        return jsonify({"ok": True, "saved": saved})

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

    # ─── Compatibilité : les adresses de LIBELLÉS ont quitté ce service ─────────────────
    # ★ ELLES N'AVAIENT RIEN DE PROTOCOLAIRE. `/api/tsl/label_names`, `/api/tsl/label_cols`,
    # `/api/tsl/sources/by_shm` et `/api/tsl/state` servaient les libellés d'une source et
    # l'état CUMULÉ du tally — que celui-ci vienne de TSL, d'IS-07 ou d'un mélangeur. Elles
    # vivent désormais sous `/api/labels/*` et `/api/tally/state`.
    #
    # ⚠ 308 ET NON 301 : un 301 autorise le client à retomber en GET, et un POST de libellés
    # y perdrait son corps — donc l'écriture, sans la moindre erreur visible.
    for _i, (_vieux, _neuf) in enumerate([
            ("/api/tsl/label_names",    "/api/labels/names"),
            ("/api/tsl/label_cols",     "/api/labels/cols"),
            ("/api/tsl/sources/by_shm", "/api/labels/by_shm"),
            ("/api/tsl/state",          "/api/tally/state")]):
        def _mk(neuf=_neuf):
            def _redir(**kw):
                from flask import redirect
                return redirect(neuf, code=308)
            return _redir
        bp.add_url_rule(_vieux, endpoint="tsl_compat_%d" % _i, view_func=_mk(),
                        methods=["GET", "POST"])
