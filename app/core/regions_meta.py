"""Catálogo público de regiones AWS (no requiere cuenta)."""

REGION_CATALOG: dict[str, dict] = {
    "us-east-1": {
        "id": "us-east-1",
        "name": "EE. UU. Este",
        "location": "N. Virginia",
        "lat": 38.9,
        "lon": -77.5,
        "az_sites": [
            {"city": "Ashburn", "lat": 39.04, "lon": -77.49},
            {"city": "Manassas", "lat": 38.75, "lon": -77.47},
            {"city": "Sterling", "lat": 39.0, "lon": -77.43},
        ],
    },
    "us-west-2": {
        "id": "us-west-2",
        "name": "EE. UU. Oeste",
        "location": "Oregón",
        "lat": 45.8,
        "lon": -119.7,
        "az_sites": [
            {"city": "Boardman", "lat": 45.84, "lon": -119.7},
            {"city": "Hillsboro", "lat": 45.52, "lon": -122.99},
        ],
    },
    "sa-east-1": {
        "id": "sa-east-1",
        "name": "Sudamérica",
        "location": "São Paulo",
        "lat": -23.55,
        "lon": -46.63,
        "az_sites": [
            {"city": "Vinhedo", "lat": -23.03, "lon": -46.98},
            {"city": "Osasco", "lat": -23.53, "lon": -46.79},
            {"city": "Campinas", "lat": -22.91, "lon": -47.06},
        ],
    },
    "eu-west-1": {
        "id": "eu-west-1",
        "name": "Europa",
        "location": "Irlanda",
        "lat": 53.35,
        "lon": -6.26,
        "az_sites": [
            {"city": "Dublín", "lat": 53.35, "lon": -6.26},
            {"city": "Clonee", "lat": 53.41, "lon": -6.44},
        ],
    },
    "eu-central-1": {
        "id": "eu-central-1",
        "name": "Europa Central",
        "location": "Fráncfort",
        "lat": 50.1,
        "lon": 8.7,
        "az_sites": [
            {"city": "Fráncfort", "lat": 50.11, "lon": 8.68},
            {"city": "Hanau", "lat": 50.13, "lon": 8.92},
        ],
    },
    "ap-southeast-1": {
        "id": "ap-southeast-1",
        "name": "Asia Pacífico",
        "location": "Singapur",
        "lat": 1.35,
        "lon": 103.8,
        "az_sites": [
            {"city": "Jurong", "lat": 1.34, "lon": 103.72},
            {"city": "Changi", "lat": 1.36, "lon": 103.99},
        ],
    },
}


def region_meta(region_id: str) -> dict:
    return REGION_CATALOG.get(
        region_id,
        {"id": region_id, "name": region_id, "location": region_id, "lat": 0.0, "lon": 0.0, "az_sites": []},
    )


def region_label(meta: dict) -> str:
    return f"{meta['name']} ({meta['location']})"
