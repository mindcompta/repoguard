# RepoGuard — guide en français

RepoGuard est un outil libre pour examiner **localement** les fichiers texte d’un projet. Il cherche certains secrets possibles, inventorie certaines versions de dépendances et peut, si vous le demandez, consulter les avis de sécurité d’OSV. Il affiche séparément quelques informations de configuration publiques, comme un identifiant AdSense ou une clé API Google au format reconnaissable.

[Documentation en anglais](README.md) · [Site de présentation](https://mindcompta.github.io/repoguard/) · [Rapport de démonstration fictif](https://mindcompta.github.io/repoguard/demo/)

> **Important :** RepoGuard n’est pas un audit complet. Il peut manquer des problèmes ou signaler des exemples inoffensifs. **Un rapport vide ne garantit pas la sécurité d’un projet.** Une clé API cliente, un domaine Firebase ou un identifiant AdSense visible ne prouve pas automatiquement une fuite ou une faille.

## Démarrer

Il faut Python 3.10 ou plus récent. Aucune bibliothèque externe n’est nécessaire à l’exécution depuis ce dossier.

```bash
git clone https://github.com/mindcompta/repoguard.git
cd repoguard
python3 -m repoguard scan /chemin/vers/mon-projet --lang fr
```

### Rapport approfondi en français

```bash
python3 -m repoguard scan /chemin/vers/mon-projet --deep --lang fr \
  --progress --format html -o ~/rapport-repoguard.html
```

Ouvrez le fichier HTML local dans votre navigateur. Il n’est **pas publié sur Internet**. Choisissez un nouveau nom à chaque fois, car RepoGuard ne remplace pas un fichier existant sans `--force` ; cette option n’est pas disponible sur certains systèmes, notamment Windows. Le mode approfondi peut prendre plusieurs minutes et produire de nombreuses alertes dans des fichiers tiers : une alerte demande une vérification, ce n’est pas une faille confirmée.

### Windows avec PowerShell

Après avoir cloné ou décompressé RepoGuard, ouvrez PowerShell dans son dossier et remplacez le chemin par celui de votre projet :

```powershell
.\scripts\analyser-projet.ps1 -Projet "C:\chemin\vers\Briefly-"
```

Le script choisit `py -3` ou `python`, crée un nom de rapport unique dans `RepoGuard-rapports` et essaie de l’ouvrir. Il n’utilise pas `--force`. Si PowerShell bloque les scripts, lancez seulement pour ce processus :

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\analyser-projet.ps1 -Projet "C:\chemin\vers\Briefly-"
```

Pour demander **en plus** une consultation OSV, ajoutez `-OSV` à la commande du script. Sur Termux ou Linux, utilisez la commande `python -m repoguard scan ... --deep --lang fr`.

## Deux niveaux de périmètre

- **Standard**, sans `--deep` : les fichiers texte du projet et les dossiers générés comme `dist` et `build` sont inclus. Les gros dossiers tiers comme `node_modules` et `vendor` sont ignorés, sauf le fichier caché `node_modules/.package-lock.json` s’il existe ; ce fichier peut aider à inventorier les paquets installés.
- **Approfondi**, avec `--deep` : les dossiers de dépendances, de code tiers et les caches sont également parcourus. Le rapport distingue les résultats du projet, les fichiers générés et les fichiers tiers. Il peut donc être beaucoup plus long et contenir de nombreux exemples ou faux positifs.

Dans les deux cas, les métadonnées `.git`, `.hg` et `.svn` ne sont pas parcourues, et les liens symboliques internes ne sont pas suivis. **L’historique Git et les autres branches ne sont pas analysés.** Les binaires, images, PDF et contenus d’archives ne sont pas ouverts. Les textes UTF-8, UTF-16/32 avec marqueur BOM et, sous réserve d’une détection heuristique, Windows-1252 sont pris en charge. Le contenu de certains formats encodés ou échappés peut ne pas être interprété. Le projet n’est pas exécuté.

### Comprendre le rapport

- **Alertes à vérifier :** chaînes ressemblant à certains secrets ou correspondances avec des avis OSV ; elles peuvent être fausses et les avis peuvent décrire le même problème.
- **Informations publiques et configurations :** indices AdSense, publicité Google, clé API Google au format connu, adresse Firebase, identifiant Analytics ou Tag Manager. Aucun de ces indices ne prouve à lui seul une faille. Les valeurs détectées ne sont pas volontairement recopiées ; consultez le fichier et la ligne indiqués. Les restrictions d’une clé Google et les règles Firebase ne sont pas vérifiées automatiquement. Une clé réservée à certains autres services, notamment l’API Gemini Developer, peut devoir rester secrète : voir la [documentation Firebase](https://firebase.google.com/docs/projects/api-keys).
- **Couverture et contexte :** nombre de fichiers analysés, liste des chemins enregistrés, raisons et liste des exclusions, limites atteintes et avertissements. Un dossier ignoré compte pour **un** élément : ses fichiers internes n’ont pas été comptés. Dans le rapport texte, seuls les 100 premiers chemins enregistrés par liste sont affichés ; HTML et JSON en montrent davantage, dans les limites ci-dessous.
- Une règle produit au maximum un résultat par ligne, même si une ligne minifiée contient plusieurs correspondances. Les numéros de colonne sont des positions en caractères, pas forcément en octets.

Les limites par défaut sont de **2 Mio par fichier, 20 000 entrées et 256 Mio au total** en mode standard, ou **16 Mio par fichier, 100 000 entrées et 2 Gio au total** en mode approfondi. Si un fichier reconnu comme texte dépasse la limite par fichier, seul son début est analysé et l’analyse est signalée incomplète. Ces plafonds peuvent être ajustés avec `--max-file-mib N` (1 à 128), `--max-files N` (1 à 500 000) et `--max-total-mib N` (1 à 16 384). La liste des fichiers analysés est limitée à 25 000 chemins et celle des éléments ignorés à 1 000 ; si elles sont tronquées, le nombre omis est affiché. D’autres limites concernent les résultats et dépendances ; voir le rapport et la [documentation complète](README.md#coverage-and-limitations).

## Dépendances : OSV est facultatif

```bash
python3 -m repoguard scan /chemin/vers/mon-projet --deep --lang fr --osv \
  --format html -o ~/rapport-osv.html
```

**Sans `--osv`, l’analyse ne fait aucune consultation réseau.** Avec cette option, les **noms, écosystèmes et versions exactes** inventoriés sont envoyés à `api.osv.dev`, mais pas le contenu des fichiers, les chemins ou les valeurs trouvées en tant que tels. Les coordonnées de paquets et les métadonnées de connexion, comme l’adresse IP, peuvent être sensibles.

RepoGuard lit les versions exactes dans les fichiers `requirements*.txt`, les fichiers npm `package-lock.json`, `npm-shrinkwrap.json` et `node_modules/.package-lock.json`, ainsi que les `package.json` à la racine de paquets installés parcourus en mode approfondi. Le fichier npm caché peut être périmé et ne garantit pas un inventaire complet. Les versions non exactes, les liens locaux et d’autres formats comme Yarn, pnpm, Poetry ou Cargo ne sont pas tous inventoriés. Les marqueurs d’environnement Python ne sont pas évalués. Un statut OSV « terminé » ne concerne que les coordonnées inventoriées, **pas toutes les dépendances possibles**. Les avis sont de gravité inconnue tant qu’ils ne sont pas examinés.

## Confidentialité et sortie

Le scan ne transmet pas le code et ne modifie pas volontairement les fichiers analysés ; écrire un rapport à l’intérieur du projet est une exception explicite. Les noms de projets, chemins et coordonnées de paquets du rapport peuvent eux-mêmes être sensibles. **Vérifiez le rapport avant de le partager** ; un secret peut exceptionnellement figurer dans un nom de fichier ou de paquet.

Le marqueur `repoguard:ignore` ne masque rien par défaut. L’option `--respect-inline-ignores` ignore toute ligne qui contient ce marqueur : elle peut donc cacher un vrai secret. En cas de vraie fuite, révoquez ou faites tourner d’abord la clé, puis retirez-la des fichiers et de l’historique. Réécrire l’historique ne révoque pas la clé.

Codes de sortie : **0** si l’exécution est terminée dans le périmètre choisi, **1** si un seuil `--fail-on` demandé est atteint, **2** en cas d’erreur ou d’analyse/consultation OSV incomplète. Les informations publiques ne déclenchent pas `--fail-on`. Des exclusions prévues restent possibles même avec le code 0. Une gravité d’avis inconnue compte comme élevée pour `--fail-on high`, par prudence.

## Tests et licence

```bash
python3 -m unittest discover -s tests -v
python3 -m repoguard demo --lang fr --format html -o ~/demo-repoguard.html
```

La démonstration utilise des données fictives. Licence [MIT](LICENSE). Le nom RepoGuard est aussi utilisé par d’autres projets indépendants.
