# Projet 1 — Analyse des journaux d'un pare-feu (Réseaux / Sécurité / IoT)

**Niveau** : L3 · **Durée conseillée** : 1 semaine · **Travail** : individuel · **Langage** : Python (pandas, matplotlib)

## Contexte
Tu es technicien·ne sécurité dans une entreprise qui possède des PC, des serveurs et des objets connectés
(caméras, capteurs). Le pare-feu a enregistré **une semaine de connexions** dans `data/logs_reseau.csv`.
Ton chef te demande : *« Que s'est-il passé sur le réseau, et y a-t-il des comportements suspects ? »*

## Les données
| Colonne | Signification |
|---|---|
| `timestamp` | date et heure de la connexion |
| `src_ip` / `dst_ip` | adresse source / destination |
| `dst_port` | port de destination (80 = HTTP, 443 = HTTPS, 22 = SSH, 53 = DNS, 1883 = MQTT, 23 = Telnet…) |
| `protocol` | TCP, UDP ou ICMP |
| `bytes_sent` | octets envoyés |
| `duration_s` | durée en secondes |
| `device_type` | PC, serveur, camera_IoT, capteur_IoT |
| `action` | ALLOW (autorisé) ou DENY (bloqué) |

⚠️ Le fichier est volontairement « sale » (doublons, valeurs manquantes, casse incohérente).

## Ce que tu dois faire
Crée un script **`analyse.py`** (à la racine du dépôt) qui lit `data/logs_reseau.csv`, fait le nettoyage, calcule les résultats, enregistre les figures et écrit `resultats.json`. Rédige ensuite **`rapport.md`**.

### 1. Nettoyage
1. Supprimer les **doublons exacts**.
2. Mettre `protocol` en **MAJUSCULES**.
3. Remplacer les `bytes_sent` manquants par la **médiane** de la colonne (calculée après suppression des doublons).

### 2. Résultats (écrits automatiquement dans `resultats.json`)
| Clé | Type | Définition |
|---|---|---|
| `nb_lignes_apres_nettoyage` | entier | nombre de lignes après nettoyage |
| `top_port` | entier | port de destination le plus fréquent |
| `taux_deny_pct` | décimal (2 chiffres) | pourcentage de connexions `DENY` |
| `ip_scanner` | texte | `src_ip` qui a contacté le plus de **ports distincts** |
| `ip_exfiltration` | texte | `src_ip` avec le plus grand **total** de `bytes_sent` |

### 3. Figures (au moins 3, enregistrées en PNG dans `figures/`)
Par exemple : top des ports, connexions par heure/jour, volume d'octets par type d'appareil,
répartition ALLOW/DENY. Chaque graphique doit avoir **un titre et des axes lisibles**.

### 4. Rapport (`rapport.md`, 1 à 2 pages)
- Résumé de ce que tu as observé (3 à 5 phrases).
- **Les 2 comportements suspects** que tu as trouvés, avec la preuve (chiffre ou graphique).
- **Au moins 3 recommandations de sécurité** concrètes (ex. : règle de pare-feu, segmentation des objets IoT, fermer Telnet…).

## Rendu sur GitHub
1. Crée un dépôt **public** nommé `projet-analyse-NOM-Prenom`.
2. Pousse tout le travail (au moins **3 commits** avec des messages clairs).
3. Le dépôt doit respecter la structure ci-dessous.
4. Envoie le **lien du dépôt** au responsable de classe avec ton **nom et prénom**.

## Barème (/20)
- **12 points automatiques** : structure du dépôt (3), le script s'exécute (2), les 5 résultats justes (5), les figures (2).
- **8 points qualité** : rapport et interprétation (4), qualité du code (2), historique de commits (1), recommandations (1).

## Structure attendue du dépôt
```
projet-analyse-NOM-Prenom/
├── README.md          (ton nom + comment lancer le projet)
├── requirements.txt   (pandas, matplotlib…)
├── analyse.py         (se lance avec : python analyse.py)
├── rapport.md
├── resultats.json     (généré par analyse.py)
├── data/logs_reseau.csv
└── figures/*.png
```
