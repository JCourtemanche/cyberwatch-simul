"""
Deterministic security issues catalog for the Cyberwatch simulator.
Matches the shape returned by /api/v3/security_issues.
"""
import random
from datetime import timedelta

from .base import iso_z, past_date


SECURITY_ISSUE_SEED = [
    ('PENTEST-2024-REF-1', 'level_critical',
     "Résultat d'un test d'intrusion — accès admin sans authentification",
     'Une interface d\'administration est accessible sans authentification depuis le réseau interne. '
     'Un attaquant peut prendre le contrôle complet de l\'application.'),
    ('PENTEST-2024-REF-2', 'level_high',
     'Injection SQL sur formulaire de recherche',
     'Le paramètre "q" du formulaire de recherche est vulnérable à une injection SQL, '
     'permettant l\'extraction de la base de données.'),
    ('MISC-TLS-001', 'level_medium',
     'TLS 1.0 / 1.1 encore acceptés',
     'Le serveur accepte des connexions TLS 1.0 et 1.1 en plus de TLS 1.2/1.3. '
     'Recommandation : désactiver les versions obsolètes.'),
    ('MISC-SSH-001', 'level_medium',
     'Authentification SSH par mot de passe autorisée',
     'Le serveur SSH accepte l\'authentification par mot de passe. '
     'Recommandation : forcer l\'authentification par clé.'),
    ('WEB-HDR-001', 'level_low',
     'En-tête de sécurité HSTS manquant',
     'L\'en-tête Strict-Transport-Security n\'est pas défini sur les réponses HTTPS.'),
    ('WEB-HDR-002', 'level_low',
     'En-tête X-Frame-Options manquant',
     'L\'en-tête X-Frame-Options n\'est pas défini, exposant à des attaques clickjacking.'),
    ('CIS-2.2.1', 'level_medium',
     'Service Telnet installé sur un serveur Linux',
     'Le paquet telnet est installé. Recommandation : le désinstaller au profit de SSH uniquement.'),
    ('CIS-5.2.5', 'level_high',
     'Compte root autorisé à se connecter en SSH',
     'Le paramètre PermitRootLogin est à yes dans /etc/ssh/sshd_config.'),
    ('ANSSI-R2', 'level_high',
     'Partitionnement disque non conforme',
     'Les répertoires /tmp, /var et /home ne sont pas sur des partitions dédiées.'),
    ('ANSSI-R7', 'level_medium',
     'Compte utilisateur avec UID 0 autre que root',
     'Un compte utilisateur non standard possède l\'UID 0, contournant les mécanismes d\'audit.'),
    ('PENTEST-2023-REF-3', 'level_critical',
     'Élévation de privilèges via service Windows mal configuré',
     'Le service "AcmeUpdater" possède des permissions modifiables par tout utilisateur authentifié, '
     'permettant une élévation vers SYSTEM.'),
    ('MISC-SMB-001', 'level_high',
     'SMBv1 activé sur poste Windows',
     'Le protocole SMBv1 obsolète est activé, exposant aux attaques type EternalBlue.'),
    ('PWD-POL-001', 'level_medium',
     'Politique de mot de passe insuffisante',
     'La longueur minimale des mots de passe est fixée à 6 caractères. '
     'Recommandation : 12 caractères minimum.'),
    ('AUDIT-LOG-001', 'level_low',
     'Audit des tentatives de connexion échouées désactivé',
     'La stratégie d\'audit "Ouverture de session — Échecs" n\'est pas activée.'),
    ('MISC-USB-001', 'level_medium',
     'Périphériques USB non filtrés',
     'Aucune restriction ne s\'applique aux périphériques USB de stockage sur les postes utilisateurs.'),
]


def build_security_issues_catalog(count=15):
    """Build the deterministic security issues catalog."""
    catalog = []
    r = random.Random(4711)
    seed = SECURITY_ISSUE_SEED[:count]
    for idx, (sid, level, title, description) in enumerate(seed, start=1):
        detected = past_date(min_days=5, max_days=200)
        catalog.append({
            'id': 40 + idx,
            'sid': sid,
            'level': level,
            'title': title,
            'description': description,
            'editable': r.choice([True, False]),
            'detected_at': iso_z(detected),
        })
    return catalog
