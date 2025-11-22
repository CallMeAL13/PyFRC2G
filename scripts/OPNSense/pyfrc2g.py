import requests
import json
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import re
from collections import OrderedDict
from graphviz import Digraph
import os
import logging
import glob
import csv
from config import INTERFACE_MAP, NET_MAP, ADDRESS_MAP, PORT_MAP
import hashlib

logging.basicConfig(level=logging.INFO)

# --- CONFIG ---
OPNS_URL = "https://<OPNS_ADDRESS/api/firewall/filter/search_rule"
OPNS_SECRET = "<API_SECRET>"
OPNS_KEY = "<API_KEY>"
PASSERELLE = "GW_NAME"
FICHIER_CSV = "output_"+PASSERELLE+".csv"
GRAPH_OUTPUT_DIR = "tmp/graphs_"+PASSERELLE
# Déclaration des interfaces présentes sur OPNSense
INTERFACES = ["wan","lan","opt1"]

def md5sum(path):
    md5 = hashlib.md5()
    with open(path, "rb") as f:
        # Lire le fichier par blocs pour éviter de saturer la mémoire
        for chunk in iter(lambda: f.read(4096), b""):
            md5.update(chunk)
    return md5.hexdigest()

def recup_regles(url, api_secret, api_key, params):
    try:
        #headers = {"accept": "application/json", "X-API-Key": token}
        reponse = requests.get(
            url,
            params=params,
            auth=(api_key, api_secret),   # même ordre que -u "SECRET:KEY"
            verify=False                  # équivalent de curl -k
        )
        return reponse.json()
    except ValueError:
        print("Échec de la connexion:", reponse.status_code, reponse.text)
        exit()

def safe_value(value, field=None):
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

def parse_csv_and_generate(csv_path, output_dir):
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

            source_label = f"SOURCE | {source}" if source else "SOURCE | <inconnu>"
            passerelle_label = f"PASSERELLE | {passerelle}" if passerelle else "PASSERELLE | <inconnu>"
            action_label = f"ACTION | {action}" if action else "ACTION | <inconnu>"
            proto_label = f"PROTOCOLE | {protocole}"
            port_label = f"PORT | {ports}"
            destination_label = f"{destination} | {descr}" if descr else f" VLAN | {destination}" or "<inconnu>"

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
            if "Regles-flottantes" in passerelle:
                n_destination = get_node(cluster["nodes"], destination_label)
            else:
                n_destination = get_node(cluster["nodes"], destination_label, force_unique=True)  # DESTINATION non factorisée
                
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
        g.attr(label=f"PASSERELLE : {passerelle}", labelloc="t", fontsize="14", color="#8888ff")

        for source, cluster in sources.items():
            with g.subgraph(name=f"cluster_{source.replace(' ', '_')}") as sg:
                sg.attr(label=f"SOURCE : {source}", style="dashed", color="#aaaaaa")
                for nid, color, label in cluster["nodes"].values():
                    sg.node(nid, label=label, shape="record", **({"style":"filled","fillcolor":color} if color else {}))
                for src, dst in cluster["edges"]:
                    sg.edge(src, dst)

        output_path = g.render(view=False)

        # Suppression du fichier .gv après rendu
        try:
            if os.path.exists(filename):
                os.remove(filename)
                print(f"🗑️  Fichier temporaire supprimé : {filename}")
        except Exception as e:
            print(f"⚠️  Impossible de supprimer {filename} : {e}")

        print(f"✅ Graph généré : {filename}.png")
    
    try:
        from reportlab.pdfgen import canvas
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.utils import ImageReader

        # Récupération des PNG
        png_files = sorted(glob.glob(os.path.join(output_dir, "*.png")))
        if not png_files:
            print("⚠️ Aucun fichier PNG trouvé pour le PDF.")
            return

        pdf_path = os.path.join(output_dir, PASSERELLE+"_MATRICE_DES_FLUX.pdf")

        # Création PDF
        c = canvas.Canvas(pdf_path, pagesize=A4)
        width, height = A4

        c.setTitle(f"Matrice des flux de la passerelle {PASSERELLE} ")

        for i, png in enumerate(png_files):
            # --- Titre / chapitre = nom du fichier ---
            titre_page = os.path.basename(png).replace(".gv.png", "")

            # Ajout du signet PDF
            c.bookmarkPage(titre_page)
            c.addOutlineEntry(titre_page, titre_page, level=0)

            # Chargement de l'image
            img = ImageReader(png)
            img_width, img_height = img.getSize()

            # Mise à l’échelle automatique
            scale = min(width / img_width, height / img_height)
            new_width = img_width * scale
            new_height = img_height * scale

            # Centrage
            x = (width - new_width) / 2
            y = (height - new_height) / 2

            # Dessin
            c.drawImage(img, x, y, width=new_width, height=new_height)

            c.showPage()

        c.save()
        print(f"📄 PDF avec chapitres généré : {pdf_path}")

        try:
            for png in png_files:
                if os.path.exists(png):
                    os.remove(png)
                    print(f"🗑️  PNG supprimé : {png}")
        except Exception as e:
            print(f"⚠️  Impossible de supprimer certains PNG : {e}")


    except Exception as e:
        print(f"⚠️ Erreur lors de la génération du PDF : {e}")


# --- EXTRACTION DES DONNÉES ---
with open(FICHIER_CSV, "w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(
        f,
        fieldnames=["SOURCE", "PASSERELLE", "ACTION", "PROTOCOLE", "PORT", "DESTINATION", "COMMENTAIRE"]
    )
    writer.writeheader()   # → On écrit l’entête une seule fois

    # Boucle sur les interfaces
    for interface in INTERFACES:
        params = {
            "interface": interface,
            "show_all": "1"
        }

        data = recup_regles(OPNS_URL, OPNS_SECRET, OPNS_KEY, params)
        entries = data.get("rows", [])

        # Écriture des entrées
        for entry in entries:
            source_val = (
                entry.get('source', {}).get('network')
                or entry.get('source', {}).get('address')
                or entry.get('source_net')
                or entry.get('source', {}).get('any')
            )
            destination_val = (
                entry.get('destination', {}).get('network')
                or entry.get('destination', {}).get('address')
                or entry.get('destination', {}).get('any')
                or entry.get("destination_net")
            )
            port_dest_val = (
                entry.get('destination', {}).get('port')
                or entry.get("destination_port")
            )
            writer.writerow({
                "SOURCE": safe_value(source_val, "source"),
                "PASSERELLE": PASSERELLE + "/" + safe_value(entry.get("interface"), "interface")
                                if entry.get("interface")
                                else PASSERELLE + "/Regles-flottantes",
                "ACTION": safe_value(entry.get("action")),
                "PROTOCOLE": safe_value(entry.get("protocol")),
                "PORT": safe_value(port_dest_val, "destination_port"),
                "DESTINATION": safe_value(destination_val, "destination"),
                "COMMENTAIRE": safe_value(entry.get("description"))
            })


# Récupération de la précédente somme md5sum
with open("md5sum.txt", "r") as f:
    prev_md5sum = f.readline().strip()  # .strip() enlève les retours à la ligne
# Génération de la somme md5sum du fichier csv généré
actual_md5sum = md5sum(FICHIER_CSV)

# Comparaison des sommes md5sum. 
# Si différentes => génération de la matrice.
# Si identique => arrêt du script.
if prev_md5sum != actual_md5sum:
    with open("md5sum.txt", "w") as f:
        f.write(actual_md5sum + "\n")
    parse_csv_and_generate(FICHIER_CSV,GRAPH_OUTPUT_DIR)
else:
    logging.info("Pas de règles crées ou modifiées")

if os.path.exists(FICHIER_CSV):
    os.remove(FICHIER_CSV)
