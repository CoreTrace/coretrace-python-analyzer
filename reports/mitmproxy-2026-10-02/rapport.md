# Analyse de mitmproxy — 2 octobre 2026

L’analyse CoreTrace avec les plugins entreprise produit **87 résultats : 75 alertes et 12 diagnostics de couverture**. La revue conclut à **8 VP, 66 FP et 1 cas à double lecture : VP de présence d’un appel, FP d’exploitabilité pour le scénario CVE examiné**. Aucune exploitation distante n’a été démontrée dans cette revue.

Les huit VP sont six absences de timeout, une utilisation conditionnelle de SHA-1 pour des mots de passe et une dépendance vulnérable verrouillée. Ils ne représentent donc pas huit vulnérabilités distantes. Les deux alertes Werkzeug portent sur la même CVE.

## Périmètre et reproduction

| Élément | Valeur |
| --- | --- |
| Projet | `tests-project/mitmproxy` |
| Commit mitmproxy | `be758251c42116a17a1d7236d020af603fd82ef7` |
| Moteur | CoreTrace Python Analyzer **0.21.0** |
| Commit moteur | `4365d6e808769a7649e5726fe33cd2864c8e5816` |
| Plugins supplémentaires | `../coretrace-python-analyzer-plugins/plugins` |
| Commit plugins | `ac35460dc206eda1d81828b85a1e2bf6d1edc048` |
| Intelligence CVE | `curated-advisories@2026.09.27` |
| Chargement confirmé | 37 plugins intégrés + 7 plugins entreprise, versions et empreintes dans `findings.json` |
| Interpréteur | Python 3.14.5 |
| Mode | Analyse statique du dépôt complet, tests, exemples et scripts inclus ; sans cache ni baseline |
| Fin d’exécution | Code **1**, résultat normal lorsque des alertes existent ; stderr vide |

Commande exécutée depuis la racine du moteur :

```sh
PYTHONPATH=src .venv/bin/python -m coretrace_python \
  --check tests-project/mitmproxy \
  --plugins ../coretrace-python-analyzer-plugins/plugins \
  --format json \
  --sbom reports/mitmproxy-2026-10-02/sbom.json \
  --vex reports/mitmproxy-2026-10-02/vex.json \
  > reports/mitmproxy-2026-10-02/findings.json \
  2> reports/mitmproxy-2026-10-02/analysis.stderr
```

Les sept plugins supplémentaires sont `architecture-rules`, `curated-advisories`, `enterprise-validators`, `exposure-prioritization`, `frameworks-models`, `orm-n-plus-one` et `serverless-declarations`. Leur chargement ne signifie pas que chacun rencontre une configuration applicable. Aucun fichier de règles architecture/validateurs ni déclaration serverless reconnue n’a été relevé. PyYAML n’est pas installé dans l’environnement du moteur ; aucune alerte de template serverless non lu n’a été produite. L’intelligence CVE provient du catalogue local, sans actualisation générale des avis en ligne.

L’approche conserve le pipeline et les modèles natifs du moteur, puis ajoute une qualification humaine séparée : on peut reproduire les détections sans introduire d’exceptions spécifiques à mitmproxy dans les règles. Aucune modification du code ou des tests des trois dépôts. Aucun commit effectué.

## Synthèse de la qualification

VP signifie que le problème signalé est pertinent dans le périmètre indiqué ; FP signifie qu’il ne constitue pas la vulnérabilité suggérée dans l’application examinée. Un appel à une API sensible peut être réel tout en constituant un FP de vulnérabilité. Les diagnostics de couverture ne sont pas classés comme des failles.

| Règle | Nombre | Verdict | Motif |
| --- | ---: | --- | --- |
| `missing-timeout` | 6 | VP de robustesse | Appels `requests` sans timeout explicite, dans des extensions optionnelles ou un utilitaire de maintenance. |
| `weak-crypto` — htpasswd | 1 | VP conditionnel | Vérification de mots de passe avec SHA-1 non salé si l’opérateur choisit le format `{SHA}`. |
| `vulnerable-dependency` | 1 | VP d’inventaire | `uv.lock` verrouille Werkzeug 3.1.5, affecté selon le catalogue par CVE-2026-27199. |
| `reachable-vulnerability` | 1 | VP technique / FP d’exploitabilité | L’appel à `safe_join` existe, mais le découpage préalable bloque les chemins de périphériques Windows testés. |
| `command-injection` | 8 | FP | Exécutables fixes, listes d’arguments, pas de shell ; données de l’opérateur ou sortie locale de Git. |
| `high-entropy-string` | 46 | FP | Trames TLS/QUIC, données compressées, fixture de cookie et identifiants publics d’en-têtes HTTP. |
| `hardcoded-credential` | 6 | FP | Quatre valeurs de test et deux contraintes de version du paquet `js-tokens`. |
| `hardcoded-secret` | 4 | FP | Deux textes d’aide avec un token fictif et deux spécifications de proxy interprétées à tort comme des identifiants. |
| `weak-crypto` — Magisk | 1 | FP | MD5 sert à produire le nom de certificat imposé par Android/OpenSSL, pas à établir sa confiance. |
| `unsafe-xml` | 1 | FP dans le flux applicatif examiné | La méthode signalée n’a pas d’appel direct trouvé ; le visualiseur WBXML utilise une autre méthode. |
| `ambiguous-module` | 8 | Diagnostic | Collisions de noms de modules. |
| `syntax-error` | 4 | Diagnostic | Syntaxe Python valide `type ...` non prise en charge par le moteur. |

Sévérités brutes : **18 high, 51 medium, 6 low, 12 info**, aucune critical. Les 18 alertes high sont classées FP dans cette revue. Ces chiffres décrivent les résultats de ce scan, pas un taux de précision général du moteur.

## VP à traiter

### Six appels HTTP sans timeout

| Emplacement, relatif à mitmproxy | Usage et conséquence |
| --- | --- |
| `examples/contrib/jsondump.py:192` | `requests.post` dans le worker d’export ; un destinataire silencieux peut immobiliser le worker. |
| `examples/contrib/xss_scanner.py:141` | Requête du scanner sur le chemin de l’URL. |
| `examples/contrib/xss_scanner.py:152` | Requête du scanner avec un Referer de test. |
| `examples/contrib/xss_scanner.py:165` | Requête du scanner avec un User-Agent de test. |
| `examples/contrib/xss_scanner.py:185` | Requête du scanner sur les paramètres d’URL. |
| `mitmproxy/utils/emoji.py:1870` | Générateur de table d’emoji, uniquement sous `if __name__ == "__main__"`. |

Les fonctions du scanner préfixées `test_` sont bien appelées par son hook `response` (`xss_scanner.py:524` et suivantes) : ce sont des fonctions actives de l’extension, pas des tests unitaires. Les appels synchrones peuvent bloquer l’extension face à un serveur silencieux. L’utilitaire emoji peut bloquer sa propre exécution, mais cet appel ne s’exécute pas lors d’un simple import.

Priorité faible, portée conditionnelle à l’utilisation de ces extensions/utilitaires. Ajouter un timeout adapté aux appels et traiter les exceptions au niveau du worker ou du hook qui décide comment poursuivre. La politique `SECURITY.md:13` de mitmproxy considère les DoS comme des bugs ordinaires ; il ne faut pas transformer ces constats en six CVE.

### SHA-1 dans htpasswd

`mitmproxy/utils/htpasswd.py:77` calcule SHA-1 directement sur le mot de passe pour vérifier une entrée `{SHA}`. Le chemin applicatif existe : option `proxyauth` → `Htpasswd` (`addons/proxyauth.py:203`) → `check_password` (`:214`).

**VP de faiblesse cryptographique conditionnelle** : un fichier htpasswd en SHA-1 expose ses mots de passe à une recherche hors ligne rapide si ses empreintes sont obtenues. Cela ne démontre ni une fuite de ce fichier ni un contournement d’authentification. Le module reconnaît explicitement cette faiblesse et propose déjà bcrypt. L’action minimale est de migrer les entrées concernées vers bcrypt ; remplacer SHA-1 dans cette branche sans migration casserait la compatibilité du format.

### Werkzeug : dépendance vulnérable, scénario applicatif neutralisé

`uv.lock:1998–1999` fixe **Werkzeug 3.1.5**. Le plugin entreprise signale **CVE-2026-27199**, corrigée selon son catalogue en **3.1.6**, et relève l’appel `mitmproxy/addons/maplocal.py:47`.

La distinction est essentielle :

1. **VP d’inventaire** : la version vulnérable est réellement verrouillée. Une mise à jour du lock reste pertinente. La version effectivement déployée n’a pas été mesurée.
2. **VP de présence de l’appel** : `safe_join` est réellement utilisé sur des chemins dérivés des URL lorsque `map_local` est configuré.
3. **FP d’exploitabilité pour le scénario étudié** : `_safe_path_join` transforme d’abord le chemin en `Path(untrusted).parts`, puis appelle `safe_join(root, *parts)`. Chaque segment est donc contrôlé séparément, ce qui neutralise précisément l’absence de vérification des segments internes de Werkzeug 3.1.5.

Vérification sur le module `werkzeug/security.py` de la wheel officielle 3.1.5, téléchargée isolément sans installation :

```text
safe_join("C:/mapped", "reports/NUL")       -> "C:/mapped/reports/NUL"
_safe_path_join(root, "reports/NUL")       -> ValueError
_safe_path_join(root, "reports/CON")       -> ValueError
_safe_path_join(root, "reports/CON.txt.html") -> ValueError
_safe_path_join(root, "reports/NUL ")      -> ValueError
_safe_path_join(root, "reports/COM1")      -> ValueError
_safe_path_join(root, "reports/normal.txt") -> chemin accepté
```

Le corps exact de la fonction mitmproxy a été extrait par AST ; `PureWindowsPath`, `ntpath` et un contexte Windows isolé du module Werkzeug ont servi au contrôle. **Ce n’est pas une exécution native sous Windows ni une reproduction de DoS**. La sortie et le SHA-256 de la wheel sont dans `verification.txt`.

La CVE ne concerne que Windows : le contrôle des noms de périphériques de Werkzeug ne s’applique que si `os.name == "nt"`. Sur Linux et macOS, le scénario n’existe pas.

Le fichier VEX généré annonce `affected` parce que le moteur voit l’appel, et ce rapport conserve ce statut. Le statut `not_affected` avec la justification `inline_mitigations_already_exist` est une piste, pas un résultat établi : il ne pourrait être retenu qu’après une reproduction sous Windows natif, alors que la vérification ci-dessus est simulée. Le statut `affected` ne constitue pas non plus une preuve d’exploitation. La mention `exposure=unreached` du plugin ne prouve pas non plus l’inaccessibilité : ici le hook `MapLocal.request` fournit un chemin réel que le graphe ne représente pas entièrement.

## Principales familles de FP

### Huit injections de commande dans les scripts de release

`release/build.py:178,200` appelle `xcrun` avec des listes d’arguments. `release/release.py:104,108,132,137,153` appelle `git` ou `gh` de la même manière. La ligne 132 produit deux alertes, pour deux sources, d’où huit résultats pour sept appels.

Les exécutables sont fixes ; aucun de ces appels n’active `shell=True`. Les caractères de shell dans une valeur ne deviennent pas des commandes. La version de release est en outre contrôlée au début du script par `assert re.match(r"^\d+\.\d+\.\d+$", version)`, et la branche vient de Git. Ce contrôle n’est pas une validation robuste : `assert` disparaît sous `python -O`, et `$` accepte un saut de ligne final. Le verdict FP n’en dépend pas, puisqu’aucun shell n’interprète les arguments. Aucun passage d’une entrée distante à un interpréteur de commandes n’a été établi. Une validation d’arguments reste utile en général, mais ces traces ne démontrent pas l’injection annoncée. Les scripts de release n’ont pas été exécutés.

### Cinquante-six alertes de secrets

Les **46 chaînes à forte entropie** se répartissent en 13 valeurs dans du Python (F029–F033, F039–F045, F048) et 33 valeurs JSON (F052–F084). Les premières sont des trames TLS/QUIC, des buffers compressés et une fixture de parsing de cookie. Les 33 valeurs JSON ont été rapprochées de leurs noms d’en-têtes : `x-amz-cf-id`, `x-amz-id-2` et `x-client-data`. Ce sont des identifiants de requêtes ou des métadonnées de navigateur, pas des clés d’authentification AWS.

Les **six credentials** sont `dump_password` dans `examples/contrib/test_jsondump.py`, trois cas d’authentification de `test_webaddons.py`, et deux dépendances `js-tokens` dans `web/package-lock.json`. Les deux dernières sont des plages de versions npm, pas des tokens.

Les **quatre secrets URL** sont `?token=...` dans la documentation et le message d’aide de `gen_sample_flows.py`, puis deux syntaxes `reverse:udp://...@...` dans `test_mode_servers.py`. Dans ce dernier format, `@` sépare la destination et l’adresse d’écoute ; il ne sépare pas un mot de passe d’un serveur.

Le verdict ne repose donc pas uniquement sur le placement dans un répertoire de tests. Il repose sur l’usage et le contenu de chaque famille. Aucun credential de production exploitable n’a été établi ; aucune tentative d’authentification avec les valeurs relevées n’a été effectuée.

### MD5 pour le nom des certificats Android

`mitmproxy/utils/magisk.py:90` reproduit `openssl -subject_hash_old` pour nommer le fichier du certificat Android (`:102`). MD5 n’est ni la signature du certificat ni une empreinte utilisée pour décider de sa confiance. Le remplacer localement par un autre hash casserait le format attendu. **FP de faiblesse de sécurité dans cet usage.**

### XML dans le code WBXML embarqué

`mitmproxy/contrib/wbxml/ASWBXML.py:819` utilise bien `minidom.parseString`. Toutefois, aucune invocation directe de `loadXml` n’a été trouvée par recherche AST. Le chemin réel du visualiseur est `_view_wbxml.py:15` → `ASCommandResponse.decodeWBXML` → `loadBytes` → `getXml`, sans passer par `loadXml`.

**FP de vulnérabilité exposée dans le flux examiné**, avec confiance moyenne sur l’absence de tout appel dynamique externe. Ce verdict ne certifie pas que `loadXml` serait sûr pour une autre intégration acceptant du XML non fiable. Il ne faut pas non plus présenter un simple appel `minidom` comme une preuve d’XXE ou de lecture de fichiers.

## Couverture et limites

- **583 fichiers découverts**, dont **571 marqués analysés**, **8 ambigus** et **4 non traités à cause de `TypeAlias`**.
- **6 182 / 6 182 fonctions comptabilisées analysées**. Ce « 100 % » ne couvre pas les fonctions des quatre fichiers que le moteur n’a pas pu construire : leur compteur vaut zéro. Les huit fichiers ambigus ont tout de même des fonctions analysées, avec une résolution de noms limitée.
- Les quatre fichiers non pris en charge sont `mitmproxy/contentviews/_api.py`, `mitmproxy/contentviews/_utils.py`, `mitmproxy/contentviews/_view_image/image_parser.py` et `mitmproxy/net/dns/https_records.py`.
- Aucun résultat n’a été supprimé par baseline ou suppression dans le rapport.
- La revue vérifie les résultats obtenus, pas l’exhaustivité des vulnérabilités du projet. Les hooks mitmproxy, appels dynamiques et dépendances natives peuvent dépasser les modèles disponibles. L’analyse Python n’est pas un audit du frontend JavaScript/TypeScript.
- Les métadonnées `exposure` restent indicatives. Par exemple les appels du scanner XSS sont marqués `unreached`, alors que son hook `response` les appelle réellement.
- Certaines positions de configuration sont approximatives : les valeurs HAR sont toutes rattachées au premier champ `headers`, le second `js-tokens` est rattaché à la première occurrence, et l’alerte Werkzeug pointe une référence transitive dans le lock. L’inventaire ci-dessous et `triage.csv` donnent des positions vérifiées lorsque possible, sans modifier le JSON brut.
- Aucun test existant n’a été modifié ou exécuté ; la vérification ciblée porte sur le contournement allégué de `safe_join` et sur les appels directs de `loadXml`.

Pour améliorer l’architecture du moteur, les pistes pertinentes seraient la modélisation de `subprocess` selon le shell, l’exécutable et la position des arguments ; la qualification sémantique des valeurs détectées comme secrets ; et la représentation des préconditions et gardes des advisories. Des exclusions codées en dur pour les chemins de mitmproxy masqueraient ces causes générales. Aucune de ces évolutions n’est implémentée dans cette analyse.

Les défauts du moteur relevés par cette revue sont suivis dans des issues :

- [#206](https://github.com/CoreTrace/coretrace-python-analyzer/issues/206) : chemins des fichiers de dépendances et de configuration relatifs au répertoire courant, et non à la racine analysée (F052–F087 ici).
- [#207](https://github.com/CoreTrace/coretrace-python-analyzer/issues/207) : position et message de `vulnerable-dependency` pour un paquet verrouillé (F085).
- [#208](https://github.com/CoreTrace/coretrace-python-analyzer/issues/208) : `command-injection` sans distinction entre shell et liste d’arguments (F019–F026).
- [#209](https://github.com/CoreTrace/coretrace-python-analyzer/issues/209) : motif `url` de `hardcoded-secret` appliqué aux placeholders et aux paires `hôte:port@` (F027, F028, F046, F047).
- [#210](https://github.com/CoreTrace/coretrace-python-analyzer/issues/210) : positions et analyse des fichiers structurés (F052–F084, F086, F087).
- [#211](https://github.com/CoreTrace/coretrace-python-analyzer/issues/211) : hash de mots de passe signalés comme mots de passe (F050, F051).

Les gains attendus de ces corrections restent à mesurer par un nouveau scan avec les mêmes paramètres.

## Fichiers livrés

- [Résultats bruts](findings.json), [SBOM](sbom.json), [VEX automatique](vex.json).
- [Qualification ligne par ligne](triage.csv), [preuves ciblées](verification.txt).
- Les identifiants `F001` à `F087` ci-dessous correspondent à l’ordre des résultats dans `findings.json`.

## Inventaire exhaustif

| ID | Règle | Position vérifiée | Verdict | Justification |
| --- | --- | --- | --- | --- |
| F001 | `ambiguous-module` | [docs/build.py:1](https://github.com/mitmproxy/mitmproxy/blob/be758251c42116a17a1d7236d020af603fd82ef7/docs/build.py#L1) | Diagnostic | docs/build.py is the module 'build' like release/build.py: a symbol python.build.* may name a function of either, and an import of 'build' resolves only from its own root |
| F002 | `ambiguous-module` | [examples/addons/shutdown.py:1](https://github.com/mitmproxy/mitmproxy/blob/be758251c42116a17a1d7236d020af603fd82ef7/examples/addons/shutdown.py#L1) | Diagnostic | examples/addons/shutdown.py is the module 'shutdown' like test/mitmproxy/data/addonscripts/shutdown.py: a symbol python.shutdown.* may name a function of either, and an import of 'shutdown' resolves only from its own root |
| F003 | `missing-timeout` | [examples/contrib/jsondump.py:192](https://github.com/mitmproxy/mitmproxy/blob/be758251c42116a17a1d7236d020af603fd82ef7/examples/contrib/jsondump.py#L192) | VP | Appel requests sans timeout ; robustesse de l’extension optionnelle. |
| F004 | `hardcoded-credential` | [examples/contrib/test_jsondump.py:65](https://github.com/mitmproxy/mitmproxy/blob/be758251c42116a17a1d7236d020af603fd82ef7/examples/contrib/test_jsondump.py#L65) | FP | Valeur explicitement utilisée par un test d’authentification/export ; aucune configuration de production. |
| F005 | `missing-timeout` | [examples/contrib/xss_scanner.py:141](https://github.com/mitmproxy/mitmproxy/blob/be758251c42116a17a1d7236d020af603fd82ef7/examples/contrib/xss_scanner.py#L141) | VP | Appel requests sans timeout ; robustesse de l’extension optionnelle. |
| F006 | `missing-timeout` | [examples/contrib/xss_scanner.py:152](https://github.com/mitmproxy/mitmproxy/blob/be758251c42116a17a1d7236d020af603fd82ef7/examples/contrib/xss_scanner.py#L152) | VP | Appel requests sans timeout ; robustesse de l’extension optionnelle. |
| F007 | `missing-timeout` | [examples/contrib/xss_scanner.py:165](https://github.com/mitmproxy/mitmproxy/blob/be758251c42116a17a1d7236d020af603fd82ef7/examples/contrib/xss_scanner.py#L165) | VP | Appel requests sans timeout ; robustesse de l’extension optionnelle. |
| F008 | `missing-timeout` | [examples/contrib/xss_scanner.py:185](https://github.com/mitmproxy/mitmproxy/blob/be758251c42116a17a1d7236d020af603fd82ef7/examples/contrib/xss_scanner.py#L185) | VP | Appel requests sans timeout ; robustesse de l’extension optionnelle. |
| F009 | `reachable-vulnerability` | [mitmproxy/addons/maplocal.py:47](https://github.com/mitmproxy/mitmproxy/blob/be758251c42116a17a1d7236d020af603fd82ef7/mitmproxy/addons/maplocal.py#L47) | VP technique / FP exploitabilité | Appel réel à safe_join 3.1.5 ; Path(untrusted).parts neutralise le scénario de périphérique Windows testé. Pas de DoS natif reproduit. |
| F010 | `syntax-error` | [mitmproxy/contentviews/_api.py:1](https://github.com/mitmproxy/mitmproxy/blob/be758251c42116a17a1d7236d020af603fd82ef7/mitmproxy/contentviews/_api.py#L1) | Diagnostic | mitmproxy/contentviews/_api.py:20:1: unsupported syntax: TypeAlias |
| F011 | `syntax-error` | [mitmproxy/contentviews/_utils.py:1](https://github.com/mitmproxy/mitmproxy/blob/be758251c42116a17a1d7236d020af603fd82ef7/mitmproxy/contentviews/_utils.py#L1) | Diagnostic | mitmproxy/contentviews/_utils.py:19:1: unsupported syntax: TypeAlias |
| F012 | `syntax-error` | [mitmproxy/contentviews/_view_image/image_parser.py:1](https://github.com/mitmproxy/mitmproxy/blob/be758251c42116a17a1d7236d020af603fd82ef7/mitmproxy/contentviews/_view_image/image_parser.py#L1) | Diagnostic | mitmproxy/contentviews/_view_image/image_parser.py:10:1: unsupported syntax: TypeAlias |
| F013 | `unsafe-xml` | [mitmproxy/contrib/wbxml/ASWBXML.py:819](https://github.com/mitmproxy/mitmproxy/blob/be758251c42116a17a1d7236d020af603fd82ef7/mitmproxy/contrib/wbxml/ASWBXML.py#L819) | FP | loadXml sans appel direct trouvé ; le visualiseur utilise loadBytes/getXml. Appels dynamiques externes non exclus. |
| F014 | `syntax-error` | [mitmproxy/net/dns/https_records.py:1](https://github.com/mitmproxy/mitmproxy/blob/be758251c42116a17a1d7236d020af603fd82ef7/mitmproxy/net/dns/https_records.py#L1) | Diagnostic | mitmproxy/net/dns/https_records.py:35:1: unsupported syntax: TypeAlias |
| F015 | `missing-timeout` | [mitmproxy/utils/emoji.py:1870](https://github.com/mitmproxy/mitmproxy/blob/be758251c42116a17a1d7236d020af603fd82ef7/mitmproxy/utils/emoji.py#L1870) | VP | VP de robustesse du générateur lancé explicitement ; appel sous __main__, absent au simple import. |
| F016 | `weak-crypto` | [mitmproxy/utils/htpasswd.py:77](https://github.com/mitmproxy/mitmproxy/blob/be758251c42116a17a1d7236d020af603fd82ef7/mitmproxy/utils/htpasswd.py#L77) | VP | SHA-1 non salé pour mots de passe uniquement si un htpasswd {SHA} est choisi ; bcrypt est déjà supporté. |
| F017 | `weak-crypto` | [mitmproxy/utils/magisk.py:90](https://github.com/mitmproxy/mitmproxy/blob/be758251c42116a17a1d7236d020af603fd82ef7/mitmproxy/utils/magisk.py#L90) | FP | MD5 utilisé pour le nom Android/OpenSSL subject_hash_old, pas pour une décision de confiance. |
| F018 | `ambiguous-module` | [release/build.py:1](https://github.com/mitmproxy/mitmproxy/blob/be758251c42116a17a1d7236d020af603fd82ef7/release/build.py#L1) | Diagnostic | release/build.py is the module 'build' like docs/build.py: a symbol python.build.* may name a function of either, and an import of 'build' resolves only from its own root |
| F019 | `command-injection` | [release/build.py:178](https://github.com/mitmproxy/mitmproxy/blob/be758251c42116a17a1d7236d020af603fd82ef7/release/build.py#L178) | FP | Exécutable fixe, liste d’arguments sans shell ; entrée opérateur ou sortie locale Git, aucun interpréteur de commandes démontré. |
| F020 | `command-injection` | [release/build.py:200](https://github.com/mitmproxy/mitmproxy/blob/be758251c42116a17a1d7236d020af603fd82ef7/release/build.py#L200) | FP | Exécutable fixe, liste d’arguments sans shell ; entrée opérateur ou sortie locale Git, aucun interpréteur de commandes démontré. |
| F021 | `command-injection` | [release/release.py:104](https://github.com/mitmproxy/mitmproxy/blob/be758251c42116a17a1d7236d020af603fd82ef7/release/release.py#L104) | FP | Exécutable fixe, liste d’arguments sans shell ; entrée opérateur ou sortie locale Git, aucun interpréteur de commandes démontré. |
| F022 | `command-injection` | [release/release.py:108](https://github.com/mitmproxy/mitmproxy/blob/be758251c42116a17a1d7236d020af603fd82ef7/release/release.py#L108) | FP | Exécutable fixe, liste d’arguments sans shell ; entrée opérateur ou sortie locale Git, aucun interpréteur de commandes démontré. |
| F023 | `command-injection` | [release/release.py:132](https://github.com/mitmproxy/mitmproxy/blob/be758251c42116a17a1d7236d020af603fd82ef7/release/release.py#L132) | FP | Exécutable fixe, liste d’arguments sans shell ; entrée opérateur ou sortie locale Git, aucun interpréteur de commandes démontré. |
| F024 | `command-injection` | [release/release.py:132](https://github.com/mitmproxy/mitmproxy/blob/be758251c42116a17a1d7236d020af603fd82ef7/release/release.py#L132) | FP | Exécutable fixe, liste d’arguments sans shell ; entrée opérateur ou sortie locale Git, aucun interpréteur de commandes démontré. |
| F025 | `command-injection` | [release/release.py:137](https://github.com/mitmproxy/mitmproxy/blob/be758251c42116a17a1d7236d020af603fd82ef7/release/release.py#L137) | FP | Exécutable fixe, liste d’arguments sans shell ; entrée opérateur ou sortie locale Git, aucun interpréteur de commandes démontré. |
| F026 | `command-injection` | [release/release.py:153](https://github.com/mitmproxy/mitmproxy/blob/be758251c42116a17a1d7236d020af603fd82ef7/release/release.py#L153) | FP | Exécutable fixe, liste d’arguments sans shell ; entrée opérateur ou sortie locale Git, aucun interpréteur de commandes démontré. |
| F027 | `hardcoded-secret` | [test/helper_tools/gen_sample_flows.py:2](https://github.com/mitmproxy/mitmproxy/blob/be758251c42116a17a1d7236d020af603fd82ef7/test/helper_tools/gen_sample_flows.py#L2) | FP | Texte d’aide/docstring contenant ?token=... comme placeholder, pas un vrai token. |
| F028 | `hardcoded-secret` | [test/helper_tools/gen_sample_flows.py:271](https://github.com/mitmproxy/mitmproxy/blob/be758251c42116a17a1d7236d020af603fd82ef7/test/helper_tools/gen_sample_flows.py#L271) | FP | Texte d’aide/docstring contenant ?token=... comme placeholder, pas un vrai token. |
| F029 | `high-entropy-string` | [test/mitmproxy/addons/test_next_layer.py:40](https://github.com/mitmproxy/mitmproxy/blob/be758251c42116a17a1d7236d020af603fd82ef7/test/mitmproxy/addons/test_next_layer.py#L40) | FP | Trame TLS/QUIC hexadécimale utilisée dans les tests protocolaires, pas un secret. |
| F030 | `high-entropy-string` | [test/mitmproxy/addons/test_next_layer.py:65](https://github.com/mitmproxy/mitmproxy/blob/be758251c42116a17a1d7236d020af603fd82ef7/test/mitmproxy/addons/test_next_layer.py#L65) | FP | Trame TLS/QUIC hexadécimale utilisée dans les tests protocolaires, pas un secret. |
| F031 | `high-entropy-string` | [test/mitmproxy/addons/test_next_layer.py:97](https://github.com/mitmproxy/mitmproxy/blob/be758251c42116a17a1d7236d020af603fd82ef7/test/mitmproxy/addons/test_next_layer.py#L97) | FP | Trame TLS/QUIC hexadécimale utilisée dans les tests protocolaires, pas un secret. |
| F032 | `high-entropy-string` | [test/mitmproxy/addons/test_next_layer.py:128](https://github.com/mitmproxy/mitmproxy/blob/be758251c42116a17a1d7236d020af603fd82ef7/test/mitmproxy/addons/test_next_layer.py#L128) | FP | Trame TLS/QUIC hexadécimale utilisée dans les tests protocolaires, pas un secret. |
| F033 | `high-entropy-string` | [test/mitmproxy/addons/test_next_layer.py:976](https://github.com/mitmproxy/mitmproxy/blob/be758251c42116a17a1d7236d020af603fd82ef7/test/mitmproxy/addons/test_next_layer.py#L976) | FP | Trame TLS/QUIC hexadécimale utilisée dans les tests protocolaires, pas un secret. |
| F034 | `ambiguous-module` | [test/mitmproxy/data/addonscripts/addon.py:1](https://github.com/mitmproxy/mitmproxy/blob/be758251c42116a17a1d7236d020af603fd82ef7/test/mitmproxy/data/addonscripts/addon.py#L1) | Diagnostic | test/mitmproxy/data/addonscripts/addon.py is the module 'addon' like test/mitmproxy/data/addonscripts/same_filename/addon.py: a symbol python.addon.* may name a function of either, and an import of 'addon' resolves only from its own root |
| F035 | `ambiguous-module` | [test/mitmproxy/data/addonscripts/same_filename/addon.py:1](https://github.com/mitmproxy/mitmproxy/blob/be758251c42116a17a1d7236d020af603fd82ef7/test/mitmproxy/data/addonscripts/same_filename/addon.py#L1) | Diagnostic | test/mitmproxy/data/addonscripts/same_filename/addon.py is the module 'addon' like test/mitmproxy/data/addonscripts/addon.py: a symbol python.addon.* may name a function of either, and an import of 'addon' resolves only from its own root |
| F036 | `ambiguous-module` | [test/mitmproxy/data/addonscripts/shutdown.py:1](https://github.com/mitmproxy/mitmproxy/blob/be758251c42116a17a1d7236d020af603fd82ef7/test/mitmproxy/data/addonscripts/shutdown.py#L1) | Diagnostic | test/mitmproxy/data/addonscripts/shutdown.py is the module 'shutdown' like examples/addons/shutdown.py: a symbol python.shutdown.* may name a function of either, and an import of 'shutdown' resolves only from its own root |
| F037 | `ambiguous-module` | [test/mitmproxy/data/servercert/generate.py:1](https://github.com/mitmproxy/mitmproxy/blob/be758251c42116a17a1d7236d020af603fd82ef7/test/mitmproxy/data/servercert/generate.py#L1) | Diagnostic | test/mitmproxy/data/servercert/generate.py is the module 'generate' like test/mitmproxy/net/data/verificationcerts/generate.py: a symbol python.generate.* may name a function of either, and an import of 'generate' resolves only from its own root |
| F038 | `ambiguous-module` | [test/mitmproxy/net/data/verificationcerts/generate.py:1](https://github.com/mitmproxy/mitmproxy/blob/be758251c42116a17a1d7236d020af603fd82ef7/test/mitmproxy/net/data/verificationcerts/generate.py#L1) | Diagnostic | test/mitmproxy/net/data/verificationcerts/generate.py is the module 'generate' like test/mitmproxy/data/servercert/generate.py: a symbol python.generate.* may name a function of either, and an import of 'generate' resolves only from its own root |
| F039 | `high-entropy-string` | [test/mitmproxy/net/http/test_cookies.py:21](https://github.com/mitmproxy/mitmproxy/blob/be758251c42116a17a1d7236d020af603fd82ef7/test/mitmproxy/net/http/test_cookies.py#L21) | FP | Fixture de parsing de cookies, utilisée comme donnée attendue ; pas de credential de production établi. |
| F040 | `high-entropy-string` | [test/mitmproxy/net/test_encoding.py:79](https://github.com/mitmproxy/mitmproxy/blob/be758251c42116a17a1d7236d020af603fd82ef7/test/mitmproxy/net/test_encoding.py#L79) | FP | Buffer compressé hexadécimal dans un test de décodage, pas un secret. |
| F041 | `high-entropy-string` | [test/mitmproxy/net/test_encoding.py:85](https://github.com/mitmproxy/mitmproxy/blob/be758251c42116a17a1d7236d020af603fd82ef7/test/mitmproxy/net/test_encoding.py#L85) | FP | Buffer compressé hexadécimal dans un test de décodage, pas un secret. |
| F042 | `high-entropy-string` | [test/mitmproxy/proxy/layers/quic/test__stream_layers.py:114](https://github.com/mitmproxy/mitmproxy/blob/be758251c42116a17a1d7236d020af603fd82ef7/test/mitmproxy/proxy/layers/quic/test__stream_layers.py#L114) | FP | Trame TLS/QUIC hexadécimale utilisée dans les tests protocolaires, pas un secret. |
| F043 | `high-entropy-string` | [test/mitmproxy/proxy/layers/quic/test__stream_layers.py:147](https://github.com/mitmproxy/mitmproxy/blob/be758251c42116a17a1d7236d020af603fd82ef7/test/mitmproxy/proxy/layers/quic/test__stream_layers.py#L147) | FP | Trame TLS/QUIC hexadécimale utilisée dans les tests protocolaires, pas un secret. |
| F044 | `high-entropy-string` | [test/mitmproxy/proxy/layers/quic/test__stream_layers.py:179](https://github.com/mitmproxy/mitmproxy/blob/be758251c42116a17a1d7236d020af603fd82ef7/test/mitmproxy/proxy/layers/quic/test__stream_layers.py#L179) | FP | Trame TLS/QUIC hexadécimale utilisée dans les tests protocolaires, pas un secret. |
| F045 | `high-entropy-string` | [test/mitmproxy/proxy/layers/test_tls.py:46](https://github.com/mitmproxy/mitmproxy/blob/be758251c42116a17a1d7236d020af603fd82ef7/test/mitmproxy/proxy/layers/test_tls.py#L46) | FP | Trame TLS/QUIC hexadécimale utilisée dans les tests protocolaires, pas un secret. |
| F046 | `hardcoded-secret` | [test/mitmproxy/proxy/test_mode_servers.py:352](https://github.com/mitmproxy/mitmproxy/blob/be758251c42116a17a1d7236d020af603fd82ef7/test/mitmproxy/proxy/test_mode_servers.py#L352) | FP | La syntaxe reverse:udp://destination@écoute contient des adresses locales de test, pas des identifiants URL. |
| F047 | `hardcoded-secret` | [test/mitmproxy/proxy/test_mode_servers.py:356](https://github.com/mitmproxy/mitmproxy/blob/be758251c42116a17a1d7236d020af603fd82ef7/test/mitmproxy/proxy/test_mode_servers.py#L356) | FP | La syntaxe reverse:udp://destination@écoute contient des adresses locales de test, pas des identifiants URL. |
| F048 | `high-entropy-string` | [test/mitmproxy/test_tls.py:4](https://github.com/mitmproxy/mitmproxy/blob/be758251c42116a17a1d7236d020af603fd82ef7/test/mitmproxy/test_tls.py#L4) | FP | Trame TLS/QUIC hexadécimale utilisée dans les tests protocolaires, pas un secret. |
| F049 | `hardcoded-credential` | [test/mitmproxy/tools/web/test_webaddons.py:26](https://github.com/mitmproxy/mitmproxy/blob/be758251c42116a17a1d7236d020af603fd82ef7/test/mitmproxy/tools/web/test_webaddons.py#L26) | FP | Valeur explicitement utilisée par un test d’authentification/export ; aucune configuration de production. |
| F050 | `hardcoded-credential` | [test/mitmproxy/tools/web/test_webaddons.py:37](https://github.com/mitmproxy/mitmproxy/blob/be758251c42116a17a1d7236d020af603fd82ef7/test/mitmproxy/tools/web/test_webaddons.py#L37) | FP | Valeur explicitement utilisée par un test d’authentification/export ; aucune configuration de production. |
| F051 | `hardcoded-credential` | [test/mitmproxy/tools/web/test_webaddons.py:48](https://github.com/mitmproxy/mitmproxy/blob/be758251c42116a17a1d7236d020af603fd82ef7/test/mitmproxy/tools/web/test_webaddons.py#L48) | FP | Valeur explicitement utilisée par un test d’authentification/export ; aucune configuration de production. |
| F052 | `high-entropy-string` | [test/mitmproxy/data/har_files/charles.json:128](https://github.com/mitmproxy/mitmproxy/blob/be758251c42116a17a1d7236d020af603fd82ef7/test/mitmproxy/data/har_files/charles.json#L128) | FP | En-tête X-Amz-Cf-Id : identifiant de requête/métadonnée publique, pas une clé d’authentification. |
| F053 | `high-entropy-string` | [test/mitmproxy/data/har_files/chrome.json:188](https://github.com/mitmproxy/mitmproxy/blob/be758251c42116a17a1d7236d020af603fd82ef7/test/mitmproxy/data/har_files/chrome.json#L188) | FP | En-tête x-amz-cf-id : identifiant de requête/métadonnée publique, pas une clé d’authentification. |
| F054 | `high-entropy-string` | [test/mitmproxy/data/har_files/chrome.json:498](https://github.com/mitmproxy/mitmproxy/blob/be758251c42116a17a1d7236d020af603fd82ef7/test/mitmproxy/data/har_files/chrome.json#L498) | FP | En-tête x-client-data : identifiant de requête/métadonnée publique, pas une clé d’authentification. |
| F055 | `high-entropy-string` | [test/mitmproxy/data/har_files/firefox.json:176](https://github.com/mitmproxy/mitmproxy/blob/be758251c42116a17a1d7236d020af603fd82ef7/test/mitmproxy/data/har_files/firefox.json#L176) | FP | En-tête x-amz-cf-id : identifiant de requête/métadonnée publique, pas une clé d’authentification. |
| F056 | `high-entropy-string` | [test/mitmproxy/data/har_files/firefox.json:847](https://github.com/mitmproxy/mitmproxy/blob/be758251c42116a17a1d7236d020af603fd82ef7/test/mitmproxy/data/har_files/firefox.json#L847) | FP | En-tête x-amz-cf-id : identifiant de requête/métadonnée publique, pas une clé d’authentification. |
| F057 | `high-entropy-string` | [test/mitmproxy/data/har_files/firefox.json:1023](https://github.com/mitmproxy/mitmproxy/blob/be758251c42116a17a1d7236d020af603fd82ef7/test/mitmproxy/data/har_files/firefox.json#L1023) | FP | En-tête x-amz-cf-id : identifiant de requête/métadonnée publique, pas une clé d’authentification. |
| F058 | `high-entropy-string` | [test/mitmproxy/data/har_files/firefox.json:1199](https://github.com/mitmproxy/mitmproxy/blob/be758251c42116a17a1d7236d020af603fd82ef7/test/mitmproxy/data/har_files/firefox.json#L1199) | FP | En-tête x-amz-cf-id : identifiant de requête/métadonnée publique, pas une clé d’authentification. |
| F059 | `high-entropy-string` | [test/mitmproxy/data/har_files/firefox.json:1386](https://github.com/mitmproxy/mitmproxy/blob/be758251c42116a17a1d7236d020af603fd82ef7/test/mitmproxy/data/har_files/firefox.json#L1386) | FP | En-tête x-amz-cf-id : identifiant de requête/métadonnée publique, pas une clé d’authentification. |
| F060 | `high-entropy-string` | [test/mitmproxy/data/har_files/firefox.json:1573](https://github.com/mitmproxy/mitmproxy/blob/be758251c42116a17a1d7236d020af603fd82ef7/test/mitmproxy/data/har_files/firefox.json#L1573) | FP | En-tête x-amz-cf-id : identifiant de requête/métadonnée publique, pas une clé d’authentification. |
| F061 | `high-entropy-string` | [test/mitmproxy/data/har_files/firefox.json:1708](https://github.com/mitmproxy/mitmproxy/blob/be758251c42116a17a1d7236d020af603fd82ef7/test/mitmproxy/data/har_files/firefox.json#L1708) | FP | En-tête x-amz-id-2 : identifiant de requête/métadonnée publique, pas une clé d’authentification. |
| F062 | `high-entropy-string` | [test/mitmproxy/data/har_files/firefox.json:1919](https://github.com/mitmproxy/mitmproxy/blob/be758251c42116a17a1d7236d020af603fd82ef7/test/mitmproxy/data/har_files/firefox.json#L1919) | FP | En-tête x-amz-cf-id : identifiant de requête/métadonnée publique, pas une clé d’authentification. |
| F063 | `high-entropy-string` | [test/mitmproxy/data/har_files/firefox.json:2099](https://github.com/mitmproxy/mitmproxy/blob/be758251c42116a17a1d7236d020af603fd82ef7/test/mitmproxy/data/har_files/firefox.json#L2099) | FP | En-tête x-amz-cf-id : identifiant de requête/métadonnée publique, pas une clé d’authentification. |
| F064 | `high-entropy-string` | [test/mitmproxy/data/har_files/head-content-length.json:100](https://github.com/mitmproxy/mitmproxy/blob/be758251c42116a17a1d7236d020af603fd82ef7/test/mitmproxy/data/har_files/head-content-length.json#L100) | FP | En-tête x-amz-id-2 : identifiant de requête/métadonnée publique, pas une clé d’authentification. |
| F065 | `high-entropy-string` | [test/mitmproxy/data/har_files/insomnia.json:129](https://github.com/mitmproxy/mitmproxy/blob/be758251c42116a17a1d7236d020af603fd82ef7/test/mitmproxy/data/har_files/insomnia.json#L129) | FP | En-tête X-Amz-Cf-Id : identifiant de requête/métadonnée publique, pas une clé d’authentification. |
| F066 | `high-entropy-string` | [test/mitmproxy/data/har_files/safari.json:132](https://github.com/mitmproxy/mitmproxy/blob/be758251c42116a17a1d7236d020af603fd82ef7/test/mitmproxy/data/har_files/safari.json#L132) | FP | En-tête x-amz-cf-id : identifiant de requête/métadonnée publique, pas une clé d’authentification. |
| F067 | `high-entropy-string` | [test/mitmproxy/data/har_files/safari.json:260](https://github.com/mitmproxy/mitmproxy/blob/be758251c42116a17a1d7236d020af603fd82ef7/test/mitmproxy/data/har_files/safari.json#L260) | FP | En-tête x-amz-cf-id : identifiant de requête/métadonnée publique, pas une clé d’authentification. |
| F068 | `high-entropy-string` | [test/mitmproxy/data/har_files/safari.json:392](https://github.com/mitmproxy/mitmproxy/blob/be758251c42116a17a1d7236d020af603fd82ef7/test/mitmproxy/data/har_files/safari.json#L392) | FP | En-tête x-amz-cf-id : identifiant de requête/métadonnée publique, pas une clé d’authentification. |
| F069 | `high-entropy-string` | [test/mitmproxy/data/har_files/safari.json:520](https://github.com/mitmproxy/mitmproxy/blob/be758251c42116a17a1d7236d020af603fd82ef7/test/mitmproxy/data/har_files/safari.json#L520) | FP | En-tête x-amz-cf-id : identifiant de requête/métadonnée publique, pas une clé d’authentification. |
| F070 | `high-entropy-string` | [test/mitmproxy/data/har_files/safari.json:648](https://github.com/mitmproxy/mitmproxy/blob/be758251c42116a17a1d7236d020af603fd82ef7/test/mitmproxy/data/har_files/safari.json#L648) | FP | En-tête x-amz-cf-id : identifiant de requête/métadonnée publique, pas une clé d’authentification. |
| F071 | `high-entropy-string` | [test/mitmproxy/data/har_files/safari.json:776](https://github.com/mitmproxy/mitmproxy/blob/be758251c42116a17a1d7236d020af603fd82ef7/test/mitmproxy/data/har_files/safari.json#L776) | FP | En-tête x-amz-cf-id : identifiant de requête/métadonnée publique, pas une clé d’authentification. |
| F072 | `high-entropy-string` | [test/mitmproxy/data/har_files/safari.json:900](https://github.com/mitmproxy/mitmproxy/blob/be758251c42116a17a1d7236d020af603fd82ef7/test/mitmproxy/data/har_files/safari.json#L900) | FP | En-tête x-amz-cf-id : identifiant de requête/métadonnée publique, pas une clé d’authentification. |
| F073 | `high-entropy-string` | [test/mitmproxy/data/har_files/safari.json:1028](https://github.com/mitmproxy/mitmproxy/blob/be758251c42116a17a1d7236d020af603fd82ef7/test/mitmproxy/data/har_files/safari.json#L1028) | FP | En-tête x-amz-cf-id : identifiant de requête/métadonnée publique, pas une clé d’authentification. |
| F074 | `high-entropy-string` | [test/mitmproxy/data/har_files/safari.json:1156](https://github.com/mitmproxy/mitmproxy/blob/be758251c42116a17a1d7236d020af603fd82ef7/test/mitmproxy/data/har_files/safari.json#L1156) | FP | En-tête x-amz-cf-id : identifiant de requête/métadonnée publique, pas une clé d’authentification. |
| F075 | `high-entropy-string` | [test/mitmproxy/data/har_files/safari.json:1296](https://github.com/mitmproxy/mitmproxy/blob/be758251c42116a17a1d7236d020af603fd82ef7/test/mitmproxy/data/har_files/safari.json#L1296) | FP | En-tête x-amz-cf-id : identifiant de requête/métadonnée publique, pas une clé d’authentification. |
| F076 | `high-entropy-string` | [test/mitmproxy/data/har_files/safari.json:1436](https://github.com/mitmproxy/mitmproxy/blob/be758251c42116a17a1d7236d020af603fd82ef7/test/mitmproxy/data/har_files/safari.json#L1436) | FP | En-tête x-amz-cf-id : identifiant de requête/métadonnée publique, pas une clé d’authentification. |
| F077 | `high-entropy-string` | [test/mitmproxy/data/har_files/safari.json:1576](https://github.com/mitmproxy/mitmproxy/blob/be758251c42116a17a1d7236d020af603fd82ef7/test/mitmproxy/data/har_files/safari.json#L1576) | FP | En-tête x-amz-cf-id : identifiant de requête/métadonnée publique, pas une clé d’authentification. |
| F078 | `high-entropy-string` | [test/mitmproxy/data/har_files/safari.json:1716](https://github.com/mitmproxy/mitmproxy/blob/be758251c42116a17a1d7236d020af603fd82ef7/test/mitmproxy/data/har_files/safari.json#L1716) | FP | En-tête x-amz-cf-id : identifiant de requête/métadonnée publique, pas une clé d’authentification. |
| F079 | `high-entropy-string` | [test/mitmproxy/data/har_files/safari.json:1848](https://github.com/mitmproxy/mitmproxy/blob/be758251c42116a17a1d7236d020af603fd82ef7/test/mitmproxy/data/har_files/safari.json#L1848) | FP | En-tête x-amz-cf-id : identifiant de requête/métadonnée publique, pas une clé d’authentification. |
| F080 | `high-entropy-string` | [test/mitmproxy/data/har_files/safari.json:1976](https://github.com/mitmproxy/mitmproxy/blob/be758251c42116a17a1d7236d020af603fd82ef7/test/mitmproxy/data/har_files/safari.json#L1976) | FP | En-tête x-amz-cf-id : identifiant de requête/métadonnée publique, pas une clé d’authentification. |
| F081 | `high-entropy-string` | [test/mitmproxy/data/har_files/safari.json:2104](https://github.com/mitmproxy/mitmproxy/blob/be758251c42116a17a1d7236d020af603fd82ef7/test/mitmproxy/data/har_files/safari.json#L2104) | FP | En-tête x-amz-cf-id : identifiant de requête/métadonnée publique, pas une clé d’authentification. |
| F082 | `high-entropy-string` | [test/mitmproxy/data/har_files/safari.json:2228](https://github.com/mitmproxy/mitmproxy/blob/be758251c42116a17a1d7236d020af603fd82ef7/test/mitmproxy/data/har_files/safari.json#L2228) | FP | En-tête x-amz-cf-id : identifiant de requête/métadonnée publique, pas une clé d’authentification. |
| F083 | `high-entropy-string` | [test/mitmproxy/data/har_files/safari.json:2399](https://github.com/mitmproxy/mitmproxy/blob/be758251c42116a17a1d7236d020af603fd82ef7/test/mitmproxy/data/har_files/safari.json#L2399) | FP | En-tête x-amz-id-2 : identifiant de requête/métadonnée publique, pas une clé d’authentification. |
| F084 | `high-entropy-string` | [test/mitmproxy/data/har_files/safari.json:2538](https://github.com/mitmproxy/mitmproxy/blob/be758251c42116a17a1d7236d020af603fd82ef7/test/mitmproxy/data/har_files/safari.json#L2538) | FP | En-tête x-amz-cf-id : identifiant de requête/métadonnée publique, pas une clé d’authentification. |
| F085 | `vulnerable-dependency` | [uv.lock:1998](https://github.com/mitmproxy/mitmproxy/blob/be758251c42116a17a1d7236d020af603fd82ef7/uv.lock#L1998) | VP | Werkzeug 3.1.5 verrouillé ; CVE-2026-27199 au niveau inventaire, même CVE que F009. Version déployée non mesurée. |
| F086 | `hardcoded-credential` | [web/package-lock.json:71](https://github.com/mitmproxy/mitmproxy/blob/be758251c42116a17a1d7236d020af603fd82ef7/web/package-lock.json#L71) | FP | js-tokens est un nom de dépendance npm ; valeur = contrainte de version, pas un secret. |
| F087 | `hardcoded-credential` | [web/package-lock.json:9468](https://github.com/mitmproxy/mitmproxy/blob/be758251c42116a17a1d7236d020af603fd82ef7/web/package-lock.json#L9468) | FP | js-tokens est un nom de dépendance npm ; valeur = contrainte de version, pas un secret. |
