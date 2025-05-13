import os

DIR_PATH = os.path.dirname(os.path.abspath(__file__))
MAXMIND_DIR = os.path.join(DIR_PATH, "maxmind")
GEOLITE_ASN_DB = os.path.join(MAXMIND_DIR, "GeoLite2-ASN.mmdb")
GEOLITE_COUNTRY_DB = os.path.join(MAXMIND_DIR, "GeoLite2-Country.mmdb")
