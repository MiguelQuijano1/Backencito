SERVICE_CATALOG = [
    {
        "id": "ec2",
        "name": "EC2",
        "category": "Cómputo",
        "description": "Servidores virtuales en la nube. Ejecuta aplicaciones con capacidad de cómputo escalable.",
        "mainFunction": "Ejecutar aplicaciones",
        "icon": "Server",
        "global": False,
    },
    {
        "id": "s3",
        "name": "S3",
        "category": "Almacenamiento",
        "description": "Almacenamiento de objetos diseñado para guardar y recuperar cualquier cantidad de datos.",
        "mainFunction": "Almacenar objetos",
        "icon": "HardDrive",
        "global": False,
    },
    {
        "id": "rds",
        "name": "RDS",
        "category": "Bases de datos",
        "description": "Bases de datos relacionales administradas (MySQL, PostgreSQL, etc.).",
        "mainFunction": "Bases de datos administradas",
        "icon": "Database",
        "global": False,
    },
    {
        "id": "iam",
        "name": "IAM",
        "category": "Seguridad",
        "description": "Gestión de identidades y accesos.",
        "mainFunction": "Control de acceso",
        "icon": "Shield",
        "global": True,
    },
    {
        "id": "vpc",
        "name": "VPC",
        "category": "Redes",
        "description": "Red virtual privada aislada en la nube.",
        "mainFunction": "Aislamiento de red",
        "icon": "Network",
        "global": False,
    },
    {
        "id": "route53",
        "name": "Route 53",
        "category": "Redes",
        "description": "DNS escalable.",
        "mainFunction": "Enrutamiento DNS",
        "icon": "Globe",
        "global": True,
    },
    {
        "id": "cloudfront",
        "name": "CloudFront",
        "category": "Redes",
        "description": "CDN para entrega de contenido.",
        "mainFunction": "Entrega de contenido",
        "icon": "Cloud",
        "global": True,
    },
]

SERVICE_CATEGORIES = ["Todos", "Cómputo", "Almacenamiento", "Bases de datos", "Redes", "Seguridad"]

# Tarifas de referencia (estimación pública; no es tu factura AWS)
PRICING_OPTIONS = [
    {"name": "EC2", "rate": 0.0528, "hours": 730},
    {"name": "RDS", "rate": 0.0704, "hours": 730},
    {"name": "S3", "rate": 0.023, "hours": 1},
    {"name": "CloudFront", "rate": 0.0274, "hours": 1},
    {"name": "Route 53", "rate": 17.12, "hours": 1},
    {"name": "IAM", "rate": 0.0, "hours": 1},
    {"name": "VPC", "rate": 0.0, "hours": 1},
]

COMPLIANCE_FRAMEWORKS = ["ISO 27001", "SOC 2", "GDPR", "HIPAA"]
