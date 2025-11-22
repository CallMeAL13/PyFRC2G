import requests
import json
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import re
from collections import OrderedDict
from graphviz import Digraph
import os
import csv
from config import INTERFACE_MAP, NET_MAP, ADDRESS_MAP, PORT_MAP

# --- CONFIG ---
PFS_URL = "https://VOTRE_PASSERELLE/api/v2/firewall/rules"
PFS_TOKEN = "VOTRE_CLE"
FICHIER_CSV = "output_pfs01.csv"  # fichier de sortie CSV

# =====================================
# FONCTIONS
# =====================================

def recup_regles(url, token):
    try:
        headers = {"accept": "application/json", "X-API-Key": token}
        reponse = requests.get(url, headers=headers, verify=False)
        return reponse.json()
    except ValueError:
        print("Échec de la connexion:", reponse.status_code, reponse.text)
        exit()

def safe_value(value, field=None):
    if value is None:
        return "Any"
    if isinstance(value, list):
        value = ", ".join(map(str, value))
    if field in ("source", "interface"):
        val = str(value).lower()
        if val in INTERFACE_MAP:
            return INTERFACE_MAP[val]
    if str(field) in ("destination_port"):
        val = str(value)
        if val in PORT_MAP:
            return PORT_MAP[val]
    if str(field) in ("destination"):
        val = str(value).lower()
        if val in NET_MAP:
            return NET_MAP[val]
    if str(field) in ("destination"):
        val = str(value).lower()
        if val in ADDRESS_MAP:
            return ADDRESS_MAP[val]
    return value

def normalize_ports(port_field):
    if not port_field:
        return "Any"
    return re.sub(r'\s+', '', port_field.strip()) or "Any"

# =====================================
# 🎨 FONCTION : GÉNÉRATION DES GRAPHES
# =====================================
def parse_csv_and_generate(csv_path, output_dir="graphs"):
    os.makedirs(output_dir, exist_ok=True)
    flux_par_passerelle = OrderedDict()
    next_id = 0

    def get_node(nodes_local, key, label=None, color=None, force_unique=False):
        """Crée ou récupère un nœud factorisé par cluster/source sauf si force_unique."""
        nonlocal next_id
        actual_key = f"{key}__{next_id}" if force_unique else key
        if actual_key not in nodes_local:
            nodes_local[actual_key] = (f"node{next_id}", color, label if label else key)
            next_id += 1
        return nodes_local[actual_key][0]

    def get_action_color(action):
        return "#a3f7a3" if action == "PASS" else "#f7a3a3" if action == "BLOCK" else None

    def get_destination_color(disabled):
        return "#ffcc00" if disabled == "True" else None

    with open(csv_path, newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            source = (row.get("SOURCE") or "").strip()
            passerelle = (row.get("PASSERELLE") or "").strip()
            action = (row.get("ACTION") or "").strip().upper()
            protocole = (row.get("PROTOCOLE") or "").strip() or "Any"
            ports = normalize_ports(row.get("PORT"))
            destination = (row.get("DESTINATION") or "").strip()
            descr = (row.get("COMMENTAIRE") or "").strip()
            disabled = (row.get("DESACTIVE") or "").strip()

            source_label = f"SOURCE | {source}" if source else "SOURCE | <inconnu>"
            passerelle_label = f"PASSERELLE | {passerelle}" if passerelle else "PASSERELLE | <inconnu>"
            action_label = f"ACTION | {action}" if action else "ACTION | <inconnu>"
            proto_label = f"PROTOCOLE | {protocole}"
            port_label = f"PORT | {ports}"
            if disabled == "False":
                destination_label = f"{destination} | {descr}" if descr else f" VLAN | {destination}" or "<inconnu>"
            else:
                destination_label = f"{destination} | {descr} | Règle désactivée" if descr else f" VLAN | {destination} | Règle désactivée" or "<inconnu>"

            # --- Initialisation cluster/source ---
            if passerelle not in flux_par_passerelle:
                flux_par_passerelle[passerelle] = OrderedDict()
            if source not in flux_par_passerelle[passerelle]:
                flux_par_passerelle[passerelle][source] = {"nodes": OrderedDict(), "edges": set()}

            cluster = flux_par_passerelle[passerelle][source]

            # --- Création des nœuds ---
            n_source = get_node(cluster["nodes"], source_label)
            n_pass = get_node(cluster["nodes"], passerelle_label)
            n_action = get_node(cluster["nodes"], action_label, color=get_action_color(action))
            proto_key = f"{protocole}|{action}"
            n_proto = get_node(cluster["nodes"], proto_key, label=proto_label)
            port_key = f"{ports}|{proto_key}"
            n_port = get_node(cluster["nodes"], port_key, label=port_label)
            n_destination = get_node(cluster["nodes"], destination_label, force_unique=True, color=get_destination_color(disabled))  # DESTINATION non factorisée
                
            edges = [
                (n_source, n_pass),
                (n_pass, n_action),
                (n_action, n_proto),
                (n_proto, n_port),
                (n_port, n_destination),
            ]

            cluster["edges"].update(edges)

    # --- Génération des graphes ---
    for passerelle, sources in flux_par_passerelle.items():
        filename = os.path.join(output_dir, f"{passerelle.replace('/', '_')}.gv")
        g = Digraph('g', filename=filename, format='png')
        g.attr(fontname="Helvetica,Arial,sans-serif")
        g.attr("node", fontname="Helvetica,Arial,sans-serif", fontsize="11", shape="record")
        g.attr("edge", fontname="Helvetica,Arial,sans-serif")
        g.attr(rankdir="LR")
        g.attr(label=f"PASSERELLE : {passerelle} INTERFACE", labelloc="t", fontsize="14", color="#8888ff")

        for source, cluster in sources.items():
            with g.subgraph(name=f"cluster_{source.replace(' ', '_')}") as sg:
                sg.attr(label=f"SOURCE : {source}", style="dashed", color="#aaaaaa")
                for nid, color, label in cluster["nodes"].values():
                    sg.node(nid, label=label, shape="record", **({"style":"filled","fillcolor":color} if color else {}))
                for src, dst in cluster["edges"]:
                    sg.edge(src, dst)

        g.render(view=False)
        print(f"✅ Graph généré : {filename}.png")
        total_nodes = sum(len(c["nodes"]) for c in sources.values())
        total_edges = sum(len(c["edges"]) for c in sources.values())
        print(f"   - {total_nodes} nœuds")
        print(f"   - {total_edges} arêtes")


# --- EXTRACTION DES DONNÉES ---
data = recup_regles(PFS_URL, PFS_TOKEN)
entries = data.get("data", [])

# --- CRÉATION DU CSV ---
with open(FICHIER_CSV, "w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(
        f,
        fieldnames=["SOURCE", "PASSERELLE", "ACTION", "PROTOCOLE", "PORT", "DESTINATION", "COMMENTAIRE","DESACTIVE"]
    )
    writer.writeheader()
    for entry in entries:
        writer.writerow({
            "SOURCE": safe_value(entry.get("source"), "source"),
            "PASSERELLE": "VOTRE_PASSERELLE/"+safe_value(entry.get("interface"), "interface"),
            "ACTION": safe_value(entry.get("type")),
            "PROTOCOLE": safe_value(entry.get("protocol")),
            "PORT": safe_value(entry.get("destination_port"), "destination_port"),
            "DESTINATION": safe_value(entry.get("destination"), "destination"),
            "COMMENTAIRE": safe_value(entry.get("descr")),
            "DESACTIVE": safe_value(entry.get("disabled"))
        })

parse_csv_and_generate(FICHIER_CSV)

print(f"✅ Fichier CSV généré : {FICHIER_CSV}")
