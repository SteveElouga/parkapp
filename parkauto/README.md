# 🚗 ParkApp – Documentation Technique & Utilisateur

Application de gestion de parking automobile.

Cette documentation présente l’architecture, les fonctionnalités et l’API REST. Elle est destinée aux développeurs et aux utilisateurs techniques.  
> Ce document est évolutif et sera mis à jour au fil du développement du projet.

---

## 🏗️ Vue d’ensemble

- **Backend** : Django + Django REST Framework
- **Modules principaux** :
  - Authentification & gestion des utilisateurs
  - Gestion des véhicules
  - Gestion des places de parking
  - Réservations & tickets

---

## 📦 Installation & Démarrage

```bash
git clone https://github.com/SteveElouga/parkapp.git
cd parkapp
pip install -r requirements.txt
python manage.py migrate
python manage.py runserver
```

---

## 🧩 Modules & Fonctionnalités

### 1. Authentification & Utilisateurs

- Inscription, activation de compte (code reçu par email)
- Connexion/Déconnexion (JWT)
- Rafraîchissement de token
- Mise à jour et suppression du profil utilisateur
- Changement de mot de passe
- Reset du mot de passe (email)
- Upload photo de profil
- Listing/admin des utilisateurs (rôle admin)
- Rôles gérés : client, admin de parking

### 2. Gestion du Parking

- Véhicules : création, édition, suppression, listing
- Places de parking : gestion des disponibilités, désactivation
- Réservations : pour un véhicule, une place et une plage horaire
- Tickets de réservation : QR code, statuts (généré, payé, utilisé, annulé)

---

## 🗂️ API Reference

> Toutes les routes API sont préfixées par `/api/`.  
> Authentification requise pour la plupart des endpoints (header `Authorization: Bearer <token>`).

### 🔑 Authentification & Utilisateurs

| Endpoint                           | Méthode | Serializer                         | Description                                              |
|-------------------------------------|---------|------------------------------------|----------------------------------------------------------|
| `/api/register/`                    | POST    | RegisterSerializer                 | Inscription d’un utilisateur                             |
| `/api/activate/`                    | POST    | ActivationSerializer               | Activation du compte via code                            |
| `/api/login/`                       | POST    | MyTokenObtainPairSerializer        | Connexion, JWT, accès/refresh token                      |
| `/api/logout/`                      | POST    | LogoutSerializer                   | Déconnexion, blacklist du refresh token                  |
| `/api/token/refresh/`               | POST    | Simple JWT                         | Rafraîchir le token d’accès                              |
| `/api/profile/`                     | PUT     | ProfileSerializer                  | Mise à jour/consultation du profil utilisateur           |
| `/api/change-password/`             | POST    | ChangePasswordSerializer           | Changement de mot de passe                               |
| `/api/delete-account/`              | DELETE  | AccountDeleteSerializer            | Suppression du compte utilisateur                        |
| `/profile/upload-photo/`            | POST    | ProfilePictureSerializer           | Upload de la photo de profil                             |
| `/api/password-reset-request/`      | POST    | PasswordResetRequestSerializer     | Demande de reset du mot de passe (envoi email)           |
| `/api/password-reset-confirm/`      | POST    | PasswordResetConfirmSerializer     | Confirmation du reset du mot de passe                    |
| `/api/users/`                       | GET/POST| UserSerializer / RegisterSerializer| Gestion admin des utilisateurs (listing, création, etc.) |
| `/api/users/<id>/`                  | GET/PUT/DELETE | UserSerializer           | Gestion admin (détail, édition, suppression)             |
| `/api/current-user/`                | GET     | UserSerializer                     | Récupérer le profil de l'utilisateur connecté            |

#### Serializers Authentification

- **RegisterSerializer** : Inscription, création admin
- **ActivationSerializer** : Activation compte
- **MyTokenObtainPairSerializer** : Login JWT
- **LogoutSerializer** : Logout JWT
- **ProfileSerializer** : Profil utilisateur
- **ChangePasswordSerializer** : Changement mot de passe
- **AccountDeleteSerializer** : Suppression compte
- **ProfilePictureSerializer** : Photo de profil
- **PasswordResetRequestSerializer** : Demande reset mot de passe
- **PasswordResetConfirmSerializer** : Confirmation reset mot de passe
- **UserSerializer** : Consultation, édition, listing (admin)

---

### 🚙 Gestion des véhicules

| Endpoint               | Méthode | Serializer        | Description                     |
|------------------------|---------|------------------|---------------------------------|
| `/api/vehicles/`       | GET/POST| VehicleSerializer | Liste/Ajout des véhicules       |
| `/api/vehicles/<id>/`  | GET/PUT/DELETE | VehicleSerializer | Détail/Mise à jour/Suppression |

#### VehicleSerializer

- Champs : `plate_number`, `model`, `brand`, `color`, `owner`, `created_at`
- Validation : unicité `plate_number`, format des champs

---

### 🅿️ Gestion des places de parking

| Endpoint                      | Méthode | Serializer            | Description                       |
|-------------------------------|---------|----------------------|-----------------------------------|
| `/api/parking-slots/`         | GET/POST| ParkingSlotSerializer | Liste/Ajout des places            |
| `/api/parking-slots/<id>/`    | GET/PUT/DELETE | ParkingSlotSerializer | Détail/Mise à jour/Suppression |
| `/api/parking-slots/<id>/disable/` | POST | - | Désactivation de la place (action personnalisée) |

#### ParkingSlotSerializer

- Champs : `code`, `is_available`, `location_description`
- Validation : unicité du code, format du lieu

---

### 📅 Réservations

| Endpoint                  | Méthode | Serializer           | Description                       |
|---------------------------|---------|---------------------|-----------------------------------|
| `/api/reservations/`      | GET/POST| ReservationSerializer| Liste/Ajout de réservations       |
| `/api/reservations/<id>/` | GET/PUT/DELETE | ReservationSerializer | Détail/Mise à jour/Suppression |

#### ReservationSerializer

- Champs : `user`, `vehicle`, `parking_slot`, `start_time`, `end_time`, `created_at`
- Validation : cohérence des horaires, disponibilité de la place

---

### 🎟️ Tickets de réservation

| Endpoint                         | Méthode | Serializer                | Description                         |
|-----------------------------------|---------|--------------------------|-------------------------------------|
| `/api/reservation-tickets/`       | GET/POST| ReservationTicketSerializer| Liste/Ajout des tickets             |
| `/api/reservation-tickets/<id>/`  | GET/PUT/DELETE | ReservationTicketSerializer | Détail/Mise à jour/Suppression  |

#### ReservationTicketSerializer

- Champs : `ticket_number`, `reservation`, `issued_at`, `is_paid`, `status`, `validated_at`, `qr_code_image`
- Validation : unicité du ticket, gestion automatique du QR code, statut conforme

---

## 🔍 Exemples de requêtes

```bash
# Inscription
curl -X POST https://MON_DOMAINE/api/register/ \
  -H "Content-Type: application/json" \
  -d '{"email": "user@exemple.com", "username": "username", "password": "MotDePasse123", "password_confirm": "MotDePasse123"}'

# Connexion
curl -X POST https://MON_DOMAINE/api/login/ \
  -H "Content-Type: application/json" \
  -d '{"email": "user@exemple.com", "password": "MotDePasse123"}'

# Ajouter un véhicule
curl -X POST https://MON_DOMAINE/api/vehicles/ \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"plate_number": "AA-123-BB", "model": "Clio", "brand": "Renault", "color": "Bleu"}'

# Réserver une place
curl -X POST https://MON_DOMAINE/api/reservations/ \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"vehicle_id": 1, "parking_slot_id": 3, "start_time": "2025-07-27T10:00:00", "end_time": "2025-07-27T12:00:00"}'
```

---

## ⚙️ Serializers – Bonnes pratiques

- Chaque endpoint dispose de son propre serializer, assurant la validation des données et le formatage des réponses.
- Toute modification (ajout de champ, changement de validation) doit être répercutée ici pour garantir la cohérence de l’API et de la documentation.

---

## 📌 Évolutions futures

- Ajout de la gestion des paiements
- Notifications (email/SMS) pour les réservations et validations
- Tableau de bord utilisateur et admin
- Documentation interactive (Swagger/OpenAPI)
- Intégration d’un frontend (web/mobile)

---

## 🤝 Contribuer

- Forker le projet, créer une branche, proposer une PR.
- Ouvrir une issue sur GitHub pour toute suggestion, bug, ou amélioration.
- Respecter les conventions de code, la documentation et la structure des serializers.

---

## 📝 Licence

À définir.

---

## 📚 Liens utiles

- [Django REST Framework](https://www.django-rest-framework.org/)
- [JWT](https://jwt.io/)
- [Documentation Django](https://docs.djangoproject.com/fr/4.2/)