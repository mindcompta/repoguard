# RepoGuard — guide en français

RepoGuard est un outil libre pour examiner **localement** les fichiers texte d’un projet. Il cherche certains secrets possibles, inventorie certaines versions de dépendances et peut, si vous le demandez, consulter les avis de sécurité d’OSV. Il affiche séparément quelques informations de configuration publiques, comme un identifiant AdSense ou une clé API Google au format reconnaissable.

[Documentation en anglais](README.md) · [Site de présentation](https://mindcompta.github.io/repoguard/) · [Rapport de démonstration fictif](https://mindcompta.github.io/repoguard/demo/)

> **Important :** RepoGuard n’est pas un audit complet. Il peut manquer des problèmes ou signaler des exemples inoffensifs. **Un rapport vide ne garantit pas la sécurité d’un projet.** Une clé API cliente, un domaine Firebase ou un identifiant AdSense visible ne prouve pas automatiquement une fuite ou une faille.

## Ouvrir l’interface depuis un terminal

Comme pour un serveur de développement, on démarre RepoGuard dans le terminal, puis **on utilise l’interface dans le navigateur**. Python 3.10 ou plus récent doit être installé. Après avoir téléchargé et extrait l’archive source, ouvrez un terminal dans le dossier extrait et lancez :

```bash
python3 -m repoguard web --no-browser
```

Sur Windows, remplacez `python3` par `py -3` (ou `python`) ; sur Termux, `python` fonctionne également. Aucune bibliothèque tierce ni commande `npm install` n’est nécessaire pour utiliser le code directement depuis ce dossier.

Le terminal affiche **votre lien local privé**, par exemple une adresse qui commence par `http://127.0.0.1:`. Ouvrez le lien **complet**, y compris la partie après `#`, sur le même appareil. L’adresse et le jeton changent à chaque démarrage ; ne les partagez pas. Laissez le terminal ouvert pendant l’utilisation. Vous pouvez retirer `--no-browser` pour essayer d’ouvrir automatiquement le navigateur.

Dans la page, choisissez ou collez le chemin d’un dossier local, choisissez le périmètre et **oui ou non pour OSV**, puis consultez les résultats. Téléchargez le rapport si vous souhaitez le conserver. Le bouton « Quitter » arrête le programme. Le sélecteur de dossier peut être indisponible sur certaines plateformes, notamment Termux : dans ce cas, collez le chemin et vérifiez que le système autorise l’accès au dossier.

Une installation facultative du paquet est possible depuis le dossier source avec `python3 -m pip install .` (des outils de construction peuvent alors être téléchargés) ; l’interface se démarre ensuite avec `python3 -m repoguard web --no-browser`. L’extraction et le lancement direct ci-dessus évitent cette étape.

## Autre option : version portable Windows sans commande

1. Téléchargez l’archive **`RepoGuard-Windows-v0.3.0.zip`** qui accompagne cette version, ou consultez la [liste des versions publiées](https://github.com/mindcompta/repoguard/releases). Elle est portable pour **Windows 10/11 64 bits x86-64** et inclut Python 3.14.10 : aucune installation séparée de Python n’est nécessaire. Windows peut avertir que le logiciel n’est pas signé ; vérifiez sa provenance.
2. Faites un clic droit sur l’archive, puis **Extraire tout**, dans un dossier séparé de vos projets. Ne lancez pas le programme directement dans le ZIP.
3. Dans le dossier extrait, double-cliquez sur **`Ouvrir-RepoGuard.bat`**. Si Windows masque les extensions, le fichier s’appelle simplement « Ouvrir-RepoGuard ». Le navigateur s’ouvre sur une adresse privée de cet ordinateur.
4. Choisissez le dossier du projet ou collez son chemin, choisissez l’analyse standard ou approfondie, puis choisissez **oui ou non** pour OSV et lancez l’analyse. Si le sélecteur de dossier n’est pas disponible, copiez son chemin depuis l’explorateur et collez-le ; un chemin copié entre guillemets est accepté.
5. Les résultats s’affichent dans la page. Cliquez sur **Télécharger le rapport HTML** pour le conserver, et sur **Quitter** pour arrêter RepoGuard.

Fermer l’onglet ne ferme pas immédiatement le programme. Sans communication de la page, il s’arrête automatiquement après **30 minutes d’inactivité**, mais pas pendant une analyse ou une sélection de dossier. Un onglet suspendu par le navigateur peut être considéré comme inactif. Le rapport non téléchargé est perdu à l’arrêt. Ne partagez pas l’adresse locale : elle contient un jeton privé à l’ouverture. Le rapport téléchargé peut contenir des chemins ou noms de paquets sensibles.

Le programme écoute uniquement sur `127.0.0.1` avec un jeton de session et des vérifications Host/Origin : ce n’est pas une protection contre un logiciel malveillant ou un autre programme de votre compte. Le dossier choisi doit être **local** : les partages réseau Windows courants sont refusés, mais tous les montages ou dossiers synchronisés ne sont pas détectables et leur logiciel de synchronisation peut transmettre les fichiers indépendamment de RepoGuard.

Si le navigateur ne s’ouvre pas, double-cliquez sur `Diagnostic-RepoGuard.bat`, puis copiez l’adresse privée affichée dans la barre d’adresse. Le guide `LISEZ-MOI-WINDOWS.txt` est inclus. L’archive **source**, contrairement à l’archive portable, exige Python 3.10 ou plus récent. macOS, Linux et Termux peuvent utiliser la commande `python3 -m repoguard web` avec Python installé ; le lanceur double-clic inclus est destiné à Windows.

## Démarrer en ligne de commande

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
