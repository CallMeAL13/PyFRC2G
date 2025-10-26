# PyFRC2G

Script python de conversion de règles firewall **PfSense** en graphique.

## 👋 Présentation

Le script a été codé pour répondre à deux objectifs :
* Avoir une vision graphique globale des règles firewall (une image vaut mille mots).
* Fournir des preuves permettant de répondre à des exigences de sécurité édictées par les différents référentiels existants.

## ⚡ Caractéristiques

* Script basé sur **Python** (développé et testé sur GNU/Linux).
* Utilisation de l'API de pfSense fournie par [pfSense REST API Package](https://pfrest.org/).
* Génération des flux graphiques avec la bibliothèque python **Graphviz**.
* Génération d'un fichier PNG par interface.
* Distinction entre un VLAN/réseau de destination et un hôte de destination.
* Mapping des interfaces, des ports et des destnations.

## 💾 Installation

1. Prérequis

Installation des bibliothèques Python :

```Bash
pip install requests graphviz
```

Installation de **pfSense REST API Package** : [https://github.com/jaredhendrickson13/pfsense-api?tab=readme-ov-file#quickstart](https://github.com/jaredhendrickson13/pfsense-api?tab=readme-ov-file#quickstart)

Une fois le paquet **pfSense REST API** installé, configurez la ou les interface(s) d'écoute sur **pfSense** puis générez une clé qui nous servira pour l'authentification à l'API. 

2. Configuration du script

Récupérez les fichiers **pyfrc2g.py** et **config.py**.

Configurez l'**URL** de votre pfSense et vos **credentials** dans le fichier **pyfrc2g.py**.

Exemple :
```python
# --- CONFIG ---
PFS_URL = "https://pfs01.domaine.lan/api/v2/firewall/rules"
PFS_TOKEN = "VOTRE_CLE_GENEREE_AVEC_PFSENSE_REST_API"
```

Configurez ensuite vos interfaces, les réseaux, les adresses des interfaces et les ports dans le fichier **config.py**. C'est certainement récupérable depuis pfSense mais je suis allé au plus facile à mettre en place.

Exemple :
```python
INTERFACE_MAP = {
    "wan": "WAN",
    "lan": "ADMINISTRATION",
    "opt1": "LAN",
    "opt2": "DMZ"
}

NET_MAP = {
    "wan": "WAN SUBNET",
    "lan": "ADMINISTRATION SUBNET",
    "opt1": "LAN SUBNET",
    "opt2": "DMZ SUBNET"
}

ADDRESS_MAP = {
    "wan:ip": "WAN ADDRESS",
    "lan:ip": "ADMINISTRATION ADDRESS",
    "opt1:ip": "LAN ADDRESS",
    "opt2:ip": "DMZ ADDRESS"
}

PORT_MAP = {
    "WEB_ACCESS": "80/443"
}
```