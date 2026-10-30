# Projet 1 — Analyse des journaux d'un pare-feu

**Auteur :** NDOUR Diambogne — L3 Réseaux / Sécurité / IoT

Analyse d'une semaine de logs de pare-feu (`data/logs_reseau.csv`) : nettoyage, indicateurs clés,
graphiques et détection de comportements suspects (scan de ports, exfiltration).

## Lancer le projet

```bash
pip install -r requirements.txt
python analyse.py
```

Le script :
1. nettoie les données (doublons, casse de `protocol`, médiane pour `bytes_sent` manquants) ;
2. écrit les 5 indicateurs dans `resultats.json` ;
3. enregistre les graphiques dans `figures/` ;
4. affiche dans la console le détail des deux IP suspectes.

## Résultats

| Indicateur | Valeur |
|---|---|
| Lignes après nettoyage | 5440 |
| Port le plus fréquent | 443 |
| Taux de DENY | 13,57 % |
| IP scanner | 192.168.1.99 |
| IP exfiltration | 192.168.1.11 |

L'interprétation et les recommandations sont dans [`rapport.md`](rapport.md).

## Structure

```
├── README.md
├── requirements.txt
├── analyse.py
├── rapport.md
├── resultats.json
├── data/logs_reseau.csv
└── figures/*.png
```
