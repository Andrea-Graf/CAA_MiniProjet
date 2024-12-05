# Rapport de Projet

## Introduction
Ce rapport décrit l'architecture cryptographique et les choix effectués pour le projet. L'objectif du projet est de concevoir une application permettant aux utilisateurs d'envoyer des messages qui ne peuvent être déchiffrés qu'après une date spécifique dans le futur.

## Objectifs du Projet
- Permettre aux utilisateurs de se connecter avec un nom d'utilisateur et un mot de passe.
- Permettre aux utilisateurs de se connecter à leur compte depuis n'importe quel appareil.
- Permettre aux utilisateurs de changer leur mot de passe.
- Permettre aux utilisateurs d'envoyer des messages confidentiels à d'autres utilisateurs.
- Les messages doivent être lisibles par le destinataire uniquement après une date définie par l'expéditeur.
- Assurer que l'expéditeur du message soit authentifié et ne puisse pas répudier le message.
- Considérer des adversaires actifs et un serveur honnête mais curieux.

## Architecture Cryptographique
### Gestion des Clés
- 2 paires de clé asymétrique généré par le user à la création du compte.  
	- Une paires pour les chiffrements
	- Une paires pour les signatures
- 1 clé symétrique dérivée du mot de passe avec Argon2

### Paramètres de Sécurité
Basé sur les recommandation du NIST 
https://www.keylength.com/en/4/

- **Niveau de sécurité** : 2019 -2030
- **Taille des clés** :  
  - symétrique : 256 bits
  - Asymétrique : 512 bits
  - Hash : 512 bits
- **Vecteurs d'initialisation (IVs)** : 128 bits

### Confidentialité Réseau

Pour gérer la confidentialité des discussions qui transitent sur le réseau entre le serveur et le client, l'application utilisera TLS 1.3.

## Fonctionnalités de l'Application
### Création d'un compte
1. L'utilisateur entre un nom d'utilisateur et un mot de passe.
2. Le client génère un sel aléatoire (fonction à implémenter).
3. Le mot de passe et le sel sont hachés avec Argon2, ce qui retourne une sortie de 768 bits :

$$

K_{0->768} = Argon2id(\text{sel} || \text{MotDePasse})

$$

4. Les 512 premiers bits de $K$ ($K_{0-512}$) sont envoyés au serveur. Ils seront utilisés comme hash du mot de passe pour la vérification de connexion.
5. Les 256 bits restants de $K$ ($K_{512-768}$) sont utilisés comme clé AES-GCM pour chiffrer les clés privées générées précédemment.
6. Enfin, le client envoie ses deux paires de clés asymétriques, dont les clés privées ont été chiffrées, au serveur.
### Connexion
1. L'application demande le sel au serveur.
2. L'utilisateur entre ses identifiants dans l'application.
3. Le mot de passe et le sel sont hachés avec Argon2, ce qui retourne une sortie de 768 bits :

$$

K_{0->768} = Argon2id(\text{sel} || \text{MotDePasse})

$$

4. Les 512 premiers bits de $K$ ($K_{0-512}$) sont envoyés au serveur pour l'authentification.
5. Si l'authentification réussit, le serveur envoie les clés privées de l'utilisateur ; sinon, un message d'erreur est retourné.
6. Une fois les clés privées récupérées, l'application utilise les 256 bits restants de $K$ ($K_{512-768}$) pour déchiffrer les clés privées avec AES-GCM.

AES-GCM est utilisé car il permet en plus du chiffrement de générer un tag d'authentification, permettant de vérifier que les clés privées n'ont pas été modifiées sur le serveur.
### Changement de Mot de Passe
1. L'application demande le sel actuel au serveur ($OldSel$).
2. Le client entre son nom d'utilisateur, son ancien mot de passe et son nouveau mot de passe.
3. Le client génère un nouveau sel aléatoire ($NewSel$) (fonction à implémenter).
4. Le client génère ensuite les deux sorties Argon2 suivantes :

$$

K1_{0-512} = Argon2id(\text{OldSel} || \text{OldMotDePasse})

$$

$$

K2_{0-512} = Argon2id(\text{NewSel} || \text{NewMotDePasse})

$$

5. Si ce n'est pas déjà fait, le client s'authentifie auprès du serveur pour récupérer ses clés privées.
6. Le client déchiffre les clés privées avec $K1_{512-768}$ et les chiffre à nouveau avec $K2_{512-768}$.
7. Enfin, le client envoie une requête de modification de mot de passe au serveur, incluant son nom d'utilisateur, $K1_{0-512}$, $K2_{0-512}$ et les clés privées chiffrées avec le nouveau mot de passe.
8. Le serveur vérifie les informations reçues, notamment si $K1_{0-512}$ correspond à celui stocké sur le serveur, puis met à jour les informations de l'utilisateur.
### Envoi de Messages
1. Le client demande au serveur la clé publique de chiffrement du récepteur.
2. Ensuite, il chiffre le message avec ECIES, obtenant ainsi :

$$

R || C || \tau = ECIES(\text{message})

$$

3. Le client crée ensuite le message $Receiver || R || C || \tau || Date$, puis le signe avec sa clé privée de signature. Ce message signé est ensuite envoyé au serveur.
4. Le serveur reconstruit un message $Receiver || C || \tau || Date$ que le récepteur peut récupérer à tout moment.
5. Le serveur conserve $R$ jusqu'à la date prévue par l'expéditeur. Une fois cette date dépassée, il met $R$ à disposition du récepteur, permettant ainsi à ce dernier de reconstruire la clé symétrique utilisée pour chiffrer le message.

### Lecture de Messages
1. Le client peut télécharger à tout moment $C || \tau || Date$.
2. Pour télécharger le message, le client doit signer un message envoyé par le serveur avec sa clé privée de signature. Si le serveur approuve le challenge en vérifiant la signature, il autorise le téléchargement du message.
3. Les mêmes étapes sont suivies pour le téléchargement de $R$, mais le serveur vérifie également la date établie par l'expéditeur. Si cette date n'est pas dépassée, il n'envoie pas $R$. En même temps, le serveur envoie la clé publique de signature de l'expéditeur pour que le récepteur puisse vérifier la signature de l'expéditeur.
4. Le récepteur dispose désormais de tout ce qui est nécessaire pour déchiffrer le message avec ECIES.

## Considérations de Sécurité
- **Adversaires Actifs** : 
	- **Signatures Numériques** : Les messages sont signés avec les clés privées des utilisateurs, empêchant ainsi la répudiation et garantissant l'authenticité des messages.
	- **Utilisation de TLS 1.3** : Toutes les communications entre le client et le serveur sont sécurisées avec TLS 1.3, protégeant les données en transit contre les interceptions et les modifications.
- **Serveur Honnête mais Curieux** : 
	-  **Chiffrement de Bout en Bout** : Les messages sont chiffrés de bout en bout avec ECIES, garantissant que seuls les destinataires prévus peuvent les déchiffrer.
	- **Stockage Sécurisé des Clés** : Les clés privées des utilisateurs sont stockées chiffrées sur le serveur, empêchant l'accès non autorisé même en cas de compromission du serveur
	- **Authentification Forte** : Utilisation de Argon2 pour le hachage des mots de passe, garantissant une résistance aux attaques par force brute.
	

## Conclusion
Résumé des points clés et des choix effectués pour assurer la sécurité et la fonctionnalité de l'application.

## Code Source
Incluez un lien vers le dépôt de code source ou des instructions pour accéder au code.

## Fonctionnalités Supplémentaires (Bonus)
### Utilisation de Time-Lock Puzzles
Les Time-Lock Puzzles sont des mécanismes cryptographiques qui permettent de chiffrer des données de manière à ce qu'elles ne puissent être déchiffrées qu'après un certain temps, sans avoir besoin d'un serveur pour gérer la disponibilité des clés.
### Étapes pour Implémenter un Time-Lock Puzzle

1. **Chiffrement du Message** :
    
    - Le chiffrement du message reste inchangé par rapport au système initial.
2. **Génération du Puzzle** :
    
    - Si le client décide de télécharger le message avant la date de déchiffrement, le serveur envoie toutes les informations nécessaires, mais génère un puzzle temporel qui prendra le temps nécessaire en fonction du temps restant avant la date prévue. Le serveur chiffre $R$ avec ce puzzle.
3. **Création du Puzzle** :
    
    - Le serveur génère un puzzle temporel $P$ qui nécessite un certain temps de calcul pour être résolu.
    - Le serveur chiffre $R$ avec ce puzzle pour obtenir $P(R)$.
4. **Envoi du Message** :
    
    - Le serveur envoie au récepteur le message suivant : $$ C || \tau || P(R) || \text{Date} $$
5. **Résolution du Puzzle** :
    
    - Le récepteur peut télécharger le message à tout moment, mais il ne pourra pas déchiffrer $R$ avant d'avoir résolu le puzzle temporel $P$.
    - Si la date prévue est atteinte, il pourra soit récupérer $R$ en ayant résolu le puzzle s'il est hors ligne, soit le récupérer directement sur le serveur.
6. **Déchiffrement du Message** :
    
    - Après avoir résolu le puzzle et obtenu $R$, le récepteur peut utiliser $R$ pour déchiffrer le message.

#### Inconvénients

- Le temps de calcul pour résoudre le puzzle doit être soigneusement choisi pour correspondre à la date prévue.
- Peut nécessiter des ressources de calcul importantes pour résoudre le puzzle.
- La puissance de calcul varie d'un client à l'autre, donc le programme doit s'adapter en fonction de la machine du client.


Signature choix d'algorithme
Specifier plus les IV
Specifier la fonction pour la generation de l'aleatoire 
~~Modifier Argon pour hash 512bits~~ 
Specifiqueation Argon2
utilisation de Opaques 

