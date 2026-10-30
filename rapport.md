# Rapport — Analyse des journaux du pare-feu (semaine du 05 au 11/10/2026)

**Auteur :** NDOUR Diambogne

## 1. Résumé

Après nettoyage (60 doublons supprimés, protocoles harmonisés en majuscules, 166 valeurs `bytes_sent` manquantes remplacées par la médiane), le journal contient **5 440 connexions** sur 7 jours. Le trafic est dominé par le web chiffré (**port 443**, 1 874 connexions), suivi de HTTP (80), DNS (53) et MQTT (1883), ce qui correspond à un parc mêlant PC, serveurs et objets connectés. **13,57 %** des connexions ont été bloquées (`DENY`), mais ce taux monte à 25 % pour les PC à cause d'un seul poste. Le volume est réparti de façon homogène (~700 connexions/jour), sauf le **08/10** (1 137 connexions) où un pic apparaît. Deux comportements anormaux ressortent nettement : un **scan de ports** et une **exfiltration de données** par une caméra IoT.

## 2. Comportements suspects

### Suspect n°1 — Scan de ports depuis `192.168.1.99` (PC)
- **400 connexions en 15 minutes** (08/10 entre 00:00 et 00:15, en pleine nuit), toutes vers la même cible `10.0.0.5`.
- **328 ports distincts** contactés, alors qu'une IP normale n'en touche qu'une dizaine (voir `figures/05_ports_distincts_par_ip.png`).
- **96 % de ces connexions sont bloquées** (`DENY`) : le pare-feu a fait son travail, mais la machine cherche activement des services ouverts. Ce scan explique à lui seul le pic du 08/10 et le taux de DENY élevé des PC (`figures/04_allow_deny_par_appareil.png`).
- Interprétation : PC compromis (malware qui fait de la reconnaissance) ou utilisateur interne malveillant.

### Suspect n°2 — Exfiltration de données par la caméra `192.168.1.11` (camera_IoT)
- **259,9 Mo envoyés**, soit **95 % de tout le volume** de la semaine ; l'IP suivante n'envoie que 0,6 Mo (`figures/06_octets_par_ip.png`, `figures/03_octets_par_appareil.png`).
- **38 transferts de 5 à 8,7 Mo chacun**, tous vers la **même IP externe `8.8.8.8` sur le port 8080**, tous **autorisés** (`ALLOW`), répartis jour et nuit (y compris entre 0 h et 5 h).
- `8.8.8.8` est normalement un serveur DNS public (port 53) : y envoyer de gros volumes en HTTP alternatif (8080) n'a aucune raison légitime. Une caméra n'a pas non plus à pousser du contenu vers Internet sans passer par l'enregistreur interne.
- Interprétation : caméra probablement piratée (botnet type Mirai ou fuite du flux vidéo / de données internes).

### Observation complémentaire — Telnet encore utilisé
100 connexions vers le **port 23 (Telnet)**, dont **26 autorisées**, surtout depuis des capteurs IoT. Telnet transmet les identifiants en clair et est le vecteur d'infection classique des objets connectés.

## 3. Recommandations de sécurité

1. **Isoler immédiatement les deux machines** : mettre `192.168.1.99` et `192.168.1.11` en quarantaine (VLAN isolé), analyser le PC (antivirus, processus), réinitialiser la caméra aux paramètres usine, mettre à jour son firmware et changer ses identifiants.
2. **Bloquer Telnet partout** : règle `DENY` sur le port 23 (TCP) en entrée et en sortie ; utiliser SSH (port 22) avec clés à la place.
3. **Segmenter le réseau IoT** : caméras et capteurs dans un VLAN dédié ; ils ne peuvent joindre que le broker MQTT (1883/8883) et l'enregistreur vidéo internes. Tout trafic IoT sortant vers Internet est refusé par défaut (liste blanche).
4. **Filtrage sortant (egress)** : interdire le port 8080 vers l'extérieur et n'autoriser le DNS (53) que vers les résolveurs de l'entreprise ; cela aurait bloqué l'exfiltration vers `8.8.8.8:8080`.
5. **Détection automatique** : mettre en place des alertes (IDS/SIEM) quand une IP contacte plus de 50 ports distincts en quelques minutes, ou quand un appareil dépasse un seuil de volume sortant (ex. 10 Mo/heure pour une caméra). Activer une limitation de débit (rate limiting) sur les tentatives de connexion.
6. **Restreindre RDP (3389)** : 111 connexions observées ; RDP ne doit être accessible que via VPN.

## Figures

| Fichier | Contenu |
|---|---|
| `figures/01_top_ports.png` | Top 10 des ports de destination |
| `figures/02_connexions_par_heure.png` | Connexions par heure de la journée |
| `figures/03_octets_par_appareil.png` | Volume envoyé par type d'appareil |
| `figures/04_allow_deny_par_appareil.png` | ALLOW / DENY par type d'appareil |
| `figures/05_ports_distincts_par_ip.png` | Ports distincts par IP source (scan) |
| `figures/06_octets_par_ip.png` | Octets envoyés par IP source (exfiltration) |
