# RepoGuard — guide en français

RepoGuard est un outil libre en ligne de commande pour effectuer un **premier contrôle local** d'un projet : il recherche certains secrets potentiellement exposés et peut, sur demande, consulter la base OSV pour certaines dépendances. Il génère des rapports texte, HTML autonome, JSON ou SARIF, avec une explication et une piste d'action pour chaque résultat.

[Documentation complète en anglais](README.md) · [Site de présentation](https://mindcompta.github.io/repoguard/) · [Rapport de démonstration fictif](https://mindcompta.github.io/repoguard/demo/)

> RepoGuard n'est pas un audit complet. Il peut manquer des problèmes ou signaler des exemples inoffensifs. **Un rapport vide ne garantit pas la sécurité du projet.**

## Prérequis et démarrage

Il faut Python 3.10 ou plus récent. Aucune bibliothèque externe n'est nécessaire pour exécuter l'outil depuis ce dossier.

```bash
git clone https://github.com/mindcompta/repoguard.git
cd repoguard
python3 -m repoguard scan /chemin/vers/mon-projet
```

Pour créer un rapport lisible dans un navigateur, de préférence en dehors du projet analysé :

```bash
python3 -m repoguard scan /chemin/vers/mon-projet --format html -o ~/rapport-repoguard.html
```

Pour voir un rapport **fictif**, sans analyser de projet ni contacter Internet :

```bash
python3 -m repoguard demo --format html -o ~/demo-repoguard.html
```

L'option `-o` crée un nouveau fichier et refuse d'écraser un fichier existant, sauf avec `--force`. Un lien symbolique final est refusé ; `--force` peut ne pas être disponible sur certains systèmes. Pour installer la commande `repoguard`, lancer `python3 -m pip install .` depuis le dossier du projet : l'installation peut télécharger des outils de construction.

## Dépendances : consultation OSV facultative

```bash
python3 -m repoguard scan /chemin/vers/mon-projet --osv --format html -o ~/rapport-osv.html
```

**Sans `--osv`, aucune consultation réseau n'est effectuée par l'analyse.** Avec `--osv`, les **noms, écosystèmes et versions exactes** des dépendances inventoriées sont envoyés à `api.osv.dev`. Le contenu des fichiers, les chemins et les valeurs détectées ne sont pas envoyés en tant que tels. Les coordonnées elles-mêmes peuvent être sensibles ; OSV et les intermédiaires réseau peuvent aussi voir des métadonnées de connexion, comme l'adresse IP.

Cette première version lit les versions exactes dans certains fichiers `requirements*.txt` et les fichiers `package-lock.json` npm versions 1 à 3. Les versions non exactes, les autres formats et certaines dépendances locales peuvent être ignorés ; voir les avertissements et la [liste des limites](README.md#coverage-and-limitations). Les marqueurs d'environnement Python ne sont pas évalués. Les résultats OSV pointent vers les avis ; RepoGuard n'évalue pas leur gravité ni ne choisit automatiquement une version corrigée. Les avis ont une gravité « inconnue ».

## Confidentialité et limites

- Le projet analysé n'est pas exécuté ni modifié. L'écriture d'un rapport, lorsqu'elle est demandée, est l'exception. Le résultat de détection ne recopie pas volontairement les lignes sources ou les valeurs trouvées.
- **Attention :** les noms de projet, les chemins et les coordonnées de paquets présents dans les rapports peuvent être sensibles ; un secret peut exceptionnellement figurer dans un nom de fichier ou de paquet. Vérifiez le rapport avant de le partager.
- L'analyse couvre les fichiers UTF-8 du répertoire courant, pas l'historique Git, les archives, les binaires ou toutes les dépendances. Des dossiers générés et les liens symboliques internes sont ignorés. Des plafonds et des erreurs de lecture peuvent rendre l'analyse incomplète.
- Le marqueur `repoguard:ignore` ne masque rien par défaut. L'option explicite `--respect-inline-ignores` ignore toute ligne contenant ce marqueur, sans analyser la syntaxe des commentaires ; elle peut donc cacher un vrai secret.
- En cas d'exposition réelle, révoquez ou faites tourner d'abord la clé, puis retirez-la des fichiers et de l'historique. Modifier l'historique ne révoque pas la clé.

Les codes de sortie sont **0** (analyse terminée dans son périmètre, sans seuil atteint), **1** (résultat au-dessus du seuil `--fail-on` demandé) et **2** (erreur ou analyse/consultation OSV incomplète). Par défaut, les résultats ne provoquent pas d'échec. Une gravité inconnue compte comme élevée pour `--fail-on high`, par prudence ; cela ne remplace pas la lecture de l'avis.

## Tests et licence

```bash
python3 -m unittest discover -s tests -v
```

Les tests utilisent des données fictives. Licence [MIT](LICENSE). Le nom RepoGuard est également utilisé par d'autres projets indépendants.
