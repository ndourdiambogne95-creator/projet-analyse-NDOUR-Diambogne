"""
Projet 1 — Analyse des journaux d'un pare-feu (Réseaux / Sécurité / IoT)

Lancement :  python analyse.py

Étapes :
  1. Chargement de data/logs_reseau.csv
  2. Nettoyage (doublons, casse du protocole, valeurs manquantes)
  3. Calcul des 5 indicateurs -> resultats.json
  4. Génération des figures -> figures/*.png
  5. Affichage d'éléments d'analyse complémentaires (pour le rapport)
"""

import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")  # pas d'affichage à l'écran : on enregistre seulement les PNG
import matplotlib.pyplot as plt
import pandas as pd

BASE_DIR = Path(__file__).resolve().parent
DATA_FILE = BASE_DIR / "data" / "logs_reseau.csv"
FIG_DIR = BASE_DIR / "figures"
RESULTS_FILE = BASE_DIR / "resultats.json"


# ---------------------------------------------------------------------------
# 1. Chargement et nettoyage
# ---------------------------------------------------------------------------
def charger_donnees(chemin: Path) -> pd.DataFrame:
    """Lit le fichier CSV des logs du pare-feu."""
    return pd.read_csv(chemin)


def nettoyer(df: pd.DataFrame) -> pd.DataFrame:
    """Applique les 3 règles de nettoyage demandées dans l'énoncé."""
    # 1) suppression des doublons exacts
    df = df.drop_duplicates().copy()

    # 2) protocole en MAJUSCULES (tcp -> TCP, udp -> UDP, ...)
    df["protocol"] = df["protocol"].str.strip().str.upper()

    # 3) bytes_sent manquants remplacés par la médiane (calculée APRÈS dédoublonnage)
    mediane = df["bytes_sent"].median()
    df["bytes_sent"] = df["bytes_sent"].fillna(mediane)

    # conversion de la date pour les analyses temporelles
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df.reset_index(drop=True)


# ---------------------------------------------------------------------------
# 2. Indicateurs
# ---------------------------------------------------------------------------
def calculer_resultats(df: pd.DataFrame) -> dict:
    """Calcule les 5 indicateurs attendus par le correcteur."""
    ports_distincts = df.groupby("src_ip")["dst_port"].nunique()
    octets_par_ip = df.groupby("src_ip")["bytes_sent"].sum()

    return {
        "nb_lignes_apres_nettoyage": int(len(df)),
        "top_port": int(df["dst_port"].value_counts().idxmax()),
        "taux_deny_pct": round(float((df["action"] == "DENY").mean() * 100), 2),
        "ip_scanner": str(ports_distincts.idxmax()),
        "ip_exfiltration": str(octets_par_ip.idxmax()),
    }


# ---------------------------------------------------------------------------
# 3. Figures
# ---------------------------------------------------------------------------
def _sauver(fig, nom: str) -> None:
    fig.tight_layout()
    fig.savefig(FIG_DIR / nom, dpi=120)
    plt.close(fig)


def fig_top_ports(df: pd.DataFrame) -> None:
    top = df["dst_port"].value_counts().head(10)
    fig, ax = plt.subplots(figsize=(9, 5))
    ax.bar(top.index.astype(str), top.values, color="#3b6ea5")
    ax.set_title("Top 10 des ports de destination")
    ax.set_xlabel("Port de destination")
    ax.set_ylabel("Nombre de connexions")
    _sauver(fig, "01_top_ports.png")


def fig_connexions_par_heure(df: pd.DataFrame) -> None:
    par_heure = df.groupby(df["timestamp"].dt.hour).size()
    fig, ax = plt.subplots(figsize=(9, 5))
    ax.plot(par_heure.index, par_heure.values, marker="o", color="#3b6ea5")
    ax.set_title("Connexions par heure de la journée (semaine entière)")
    ax.set_xlabel("Heure")
    ax.set_ylabel("Nombre de connexions")
    ax.set_xticks(range(0, 24))
    ax.grid(alpha=0.3)
    _sauver(fig, "02_connexions_par_heure.png")


def fig_octets_par_appareil(df: pd.DataFrame) -> None:
    octets = df.groupby("device_type")["bytes_sent"].sum().sort_values() / 1e6
    fig, ax = plt.subplots(figsize=(9, 5))
    ax.barh(octets.index, octets.values, color="#3b6ea5")
    ax.set_title("Volume total envoyé par type d'appareil")
    ax.set_xlabel("Octets envoyés (millions)")
    ax.set_ylabel("Type d'appareil")
    _sauver(fig, "03_octets_par_appareil.png")


def fig_allow_deny(df: pd.DataFrame) -> None:
    tableau = pd.crosstab(df["device_type"], df["action"])
    fig, ax = plt.subplots(figsize=(9, 5))
    tableau.plot(kind="bar", stacked=True, ax=ax, color=["#4c9a5b", "#c0392b"])
    ax.set_title("Connexions autorisées (ALLOW) et bloquées (DENY) par type d'appareil")
    ax.set_xlabel("Type d'appareil")
    ax.set_ylabel("Nombre de connexions")
    ax.tick_params(axis="x", rotation=0)
    ax.legend(title="Action")
    _sauver(fig, "04_allow_deny_par_appareil.png")


def fig_ports_distincts(df: pd.DataFrame) -> None:
    top = df.groupby("src_ip")["dst_port"].nunique().sort_values(ascending=False).head(10)
    fig, ax = plt.subplots(figsize=(9, 5))
    couleurs = ["#c0392b"] + ["#3b6ea5"] * (len(top) - 1)
    ax.bar(top.index, top.values, color=couleurs)
    ax.set_title("Nombre de ports distincts contactés par IP source (top 10)")
    ax.set_xlabel("IP source")
    ax.set_ylabel("Ports distincts")
    ax.tick_params(axis="x", rotation=45)
    _sauver(fig, "05_ports_distincts_par_ip.png")


def fig_octets_par_ip(df: pd.DataFrame) -> None:
    top = df.groupby("src_ip")["bytes_sent"].sum().sort_values(ascending=False).head(10) / 1e6
    fig, ax = plt.subplots(figsize=(9, 5))
    couleurs = ["#c0392b"] + ["#3b6ea5"] * (len(top) - 1)
    ax.bar(top.index, top.values, color=couleurs)
    ax.set_title("Total d'octets envoyés par IP source (top 10)")
    ax.set_xlabel("IP source")
    ax.set_ylabel("Octets envoyés (millions)")
    ax.tick_params(axis="x", rotation=45)
    _sauver(fig, "06_octets_par_ip.png")


def generer_figures(df: pd.DataFrame) -> None:
    FIG_DIR.mkdir(exist_ok=True)
    fig_top_ports(df)
    fig_connexions_par_heure(df)
    fig_octets_par_appareil(df)
    fig_allow_deny(df)
    fig_ports_distincts(df)
    fig_octets_par_ip(df)


# ---------------------------------------------------------------------------
# 4. Analyse complémentaire (affichée dans la console, sert au rapport)
# ---------------------------------------------------------------------------
def afficher_details(df: pd.DataFrame, res: dict) -> None:
    scan = df[df["src_ip"] == res["ip_scanner"]]
    exfil = df[df["src_ip"] == res["ip_exfiltration"]]

    print("\n--- Détails IP scanner :", res["ip_scanner"])
    print(f"connexions : {len(scan)} | ports distincts : {scan['dst_port'].nunique()}"
          f" | DENY : {(scan['action'] == 'DENY').mean():.0%}")
    print("appareil :", scan["device_type"].unique().tolist(),
          "| période :", scan["timestamp"].min(), "->", scan["timestamp"].max())

    print("\n--- Détails IP exfiltration :", res["ip_exfiltration"])
    print(f"connexions : {len(exfil)} | total : {exfil['bytes_sent'].sum() / 1e6:.1f} Mo"
          f" | part du total : {exfil['bytes_sent'].sum() / df['bytes_sent'].sum():.0%}")
    print("appareil :", exfil["device_type"].unique().tolist())
    print("destinations :", exfil["dst_ip"].value_counts().head(3).to_dict())
    print("ports :", exfil["dst_port"].value_counts().head(3).to_dict())

    telnet = df[df["dst_port"] == 23]
    print(f"\n--- Telnet (port 23) : {len(telnet)} connexions, "
          f"{(telnet['action'] == 'ALLOW').sum()} autorisées")


# ---------------------------------------------------------------------------
def main() -> None:
    brut = charger_donnees(DATA_FILE)
    df = nettoyer(brut)
    print(f"Lignes brutes : {len(brut)} -> après nettoyage : {len(df)}")

    resultats = calculer_resultats(df)
    with open(RESULTS_FILE, "w", encoding="utf-8") as f:
        json.dump(resultats, f, indent=2, ensure_ascii=False)
    print("Résultats :", json.dumps(resultats, indent=2, ensure_ascii=False))

    generer_figures(df)
    print(f"Figures enregistrées dans {FIG_DIR}")

    afficher_details(df, resultats)


if __name__ == "__main__":
    main()
