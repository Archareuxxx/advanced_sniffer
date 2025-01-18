import pygeoip

# Use a GeoIP database (download from MaxMind or similar sources)
GEOIP_DB = "GeoLiteCity.dat"
geoip = pygeoip.GeoIP(GEOIP_DB)

def get_geoip_info(ip_address):
    """Get GeoIP information for an IP address."""
    try:
        record = geoip.record_by_addr(ip_address)
        return {
            "Country": record.get("country_name", "Unknown"),
            "City": record.get("city", "Unknown"),
            "Latitude": record.get("latitude", "Unknown"),
            "Longitude": record.get("longitude", "Unknown")
        }
    except Exception:
        return "GeoIP lookup failed"
      
