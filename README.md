# 🚀 NTLMAudit


## 📋 Description

**NTLMAudit** est un outil d'audit des événements d'authentification NTLM sur Windows. Il extrait et analyse les événements du journal de sécurité Windows pour identifier les endpoints utilisant l'authentification NTLM, permettant ainsi de détecter les usages legacy et les potentielles vulnérabilités de sécurité.

Développé par **Ayi NEDJIMI**.


## ✨ Fonctionnalités

- Extraction des événements de connexion NTLM (Event ID 4624)
- Filtrage par type de connexion réseau (LogonType 3)
- Affichage détaillé: horodatage, IP client, nom client, utilisateur, service
- Analyse configurable sur N jours
- Export des résultats en CSV UTF-8
- Logging détaillé dans %TEMP%


## 📌 Prérequis

- Windows 10/11 ou Windows Server 2016+
- Visual Studio Build Tools ou MSVC compilateur
- **Privilèges Administrateur** (requis pour accéder au journal Security)


## Compilation

Utilisez le script `go.bat` fourni:

```batch
go.bat
```

Ou compilez manuellement:

```batch
cl.exe /EHsc /std:c++17 /DUNICODE /D_UNICODE NTLMAudit.cpp ^
/Fe:NTLMAudit.exe /link user32.lib comctl32.lib wevtapi.lib
```


## 🚀 Utilisation

1. **Lancer en tant qu'Administrateur** (clic droit → Exécuter en tant qu'administrateur)
2. Spécifier le nombre de jours à analyser (1-365)
3. Cliquer sur "Scanner"
4. Consulter les résultats dans la ListView
5. Optionnel: Exporter en CSV


## Interface

### Contrôles

- **Nombre de jours à analyser**: Période d'extraction des événements
- **Scanner**: Démarre l'analyse du journal Security
- **Exporter CSV**: Sauvegarde les résultats au format CSV UTF-8

### Colonnes ListView

| Colonne | Description |
|---------|-------------|
| Horodatage | Date et heure de l'événement |
| IP Client | Adresse IP source de la connexion |
| Nom Client | Nom de la machine cliente |
| Utilisateur | Compte utilisateur cible |
| Service | Processus/service d'authentification |
| Event ID | Identifiant de l'événement (4624) |


## Logs

Les logs sont stockés dans:
```
%TEMP%\WinTools_NTLMAudit_log.txt
```


## 🚀 Cas d'usage

- **Migration Kerberos**: Identifier les systèmes utilisant encore NTLM
- **Audit de sécurité**: Détecter les authentifications NTLM suspectes
- **Conformité**: Documenter l'utilisation NTLM pour rapports de conformité
- **Troubleshooting**: Analyser les échecs d'authentification


## 🔒 Sécurité & Éthique

**ATTENTION**: Cet outil nécessite des privilèges administrateur et accède aux journaux de sécurité système.

- Utiliser uniquement sur des systèmes dont vous êtes propriétaire/administrateur
- Respecter les politiques de sécurité de votre organisation
- Ne pas partager les exports CSV (contiennent des informations sensibles)
- Destiné à l'audit de sécurité légitime uniquement


## Limitations

- Nécessite des privilèges administrateur
- Performance dépend de la taille du journal Security
- Ne détecte que les événements LogonType 3 (réseau)
- Parsing XML simplifié (peut manquer certains cas edge)


## Support

Pour toute question ou suggestion:
- Auteur: Ayi NEDJIMI
- Projet: WinToolsSuite


## 📄 Licence

MIT License - Copyright (c) 2025 Ayi NEDJIMI


---

<div align="center">

**⭐ Si ce projet vous plaît, n'oubliez pas de lui donner une étoile ! ⭐**

</div>