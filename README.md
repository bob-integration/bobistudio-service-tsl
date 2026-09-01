# TSL — service tally et labels de Bobi.Studio

*[English version](README.en.md)*

Implémentation **TSL 5.0** (tally et UMD) pour [Bobi.Studio](https://github.com/bob-integration/bobistudio).
Reçoit le tally d'un contrôleur broadcast, le distribue aux fenêtres des multiviews, et écrit
les libellés de source.

---

## Le modèle, et pourquoi il ne ressemble pas à la trame

TSL 5.0 réserve deux bits pour chacun de ses trois champs — **LH**, **RH**, **TT**. Un
« pas de 3 » qui vient du **format de trame**, et non d'une réalité de production.

Ce service ne le reprend pas. Un **niveau de tally** y est une entité nommée, identifiée par un
UUID qui ne bouge jamais — le numéro affiché dans l'interface n'est qu'un rang, que réordonner
réécrit librement. Une installation en déclare autant qu'elle veut — le code n'impose
aucun plafond — et peut les renommer ou les réordonner sans réécrire une seule configuration.

Une connexion TSL alimente **un** niveau : sa chaîne de destination. Ses trois champs
LH/RH/TT ne sont pas trois chaînes, mais trois façons d'exprimer l'état de celle-ci —
`rouge_field` et `vert_field` disent lesquels portent le rouge et le vert. Un niveau a
plusieurs états : `off`, `red`, `green`, `amber`, l'ambre étant le cumul des deux.

**Une connexion, un serveur TCP.** Plusieurs contrôleurs peuvent alimenter la même installation
sans se marcher dessus, chacun sur son port.

---

## Le protocole sur le fil

Offsets **vérifiés par capture**, pas lus dans une documentation :

```
SOM `FE 02` @0 · LEN (2, LE) @2 · VER/FLAGS @4 · SCREEN (2, LE) @6
INDEX (2, LE) @8 · CONTROL (2, LE) @10 · LENGTH (2, LE) @12 · TEXT @14 (Latin-1)
```

`INDEX` est le *display index*, c'est-à-dire la source. Dans `CONTROL`, les bits 0-1 portent
RH, 2-3 TT, 4-5 LH — chacun valant `0=off`, `1=red`, `2=green`, `3=amber`.

⚠ **L'index est à l'offset 8.** Une version antérieure de notre documentation le plaçait à 4,
et tout retombait sur l'index 0 — une régression silencieuse, chaque source affichant le tally
de la première. Si vous implémentez TSL 5.0 de votre côté, c'est l'erreur à ne pas refaire.

---

## L'utiliser

Ce dépôt est un **service** de Bobi.Studio, monté dans `services/tsl/`. Il se configure sous
**Réglages → Protocoles → TSL** : connexions, niveaux, colonnes de libellés.

Le distributeur lit la configuration des multiviews déployés et envoie couleur et texte par
fenêtre. L'action `set_label` est exposée aux macros, pour écrire un libellé de source depuis
un enchaînement.

Il ne s'utilise pas seul : ses connexions et ses niveaux vivent dans la base de l'orchestrateur.

---

## Licence

GPL-3.0-or-later — voir [LICENSE](LICENSE). Copyright © 2026 BOBI SAS, France.
