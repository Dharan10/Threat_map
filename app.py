# threat_map_final.py
import os
import time
import json
import requests
import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import datetime, timedelta
from dotenv import load_dotenv
from streamlit_autorefresh import st_autorefresh
import pytz

# -------------------------
# Config / Load keys
# -------------------------
load_dotenv()
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")  # optional
OTX_API_KEY = os.getenv("OTX_API_KEY")              # optional

st.set_page_config(page_title="Real-Time Cyber Threat Map", layout="wide", initial_sidebar_state="expanded")

# -------------------------
# Helpers
# -------------------------
@st.cache_data(ttl=3600)
def geolocate_ip(ip: str):
    """Use ip-api.com as a free geolocation fallback. Cached for 1 hour."""
    if not ip or ip in ("0.0.0.0", "127.0.0.1"):
        return 0.0, 0.0, "Unknown"
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,lat,lon", timeout=5)
        j = r.json()
        if j.get("status") == "success":
            return float(j.get("lat", 0.0)), float(j.get("lon", 0.0)), j.get("country", "Unknown")
    except Exception:
        pass
    return 0.0, 0.0, "Unknown"

def to_utc_series(series):
    """Convert a Series of datetimes to tz-aware UTC safely."""
    # pd.to_datetime(..., utc=True) returns tz-aware datetimes
    return pd.to_datetime(series, utc=True, errors="coerce")

# -------------------------
# Sample fallback data (realistic)
# -------------------------
@st.cache_data(ttl=3600)
def load_sample_data():
    sample = [
        {"IP":"176.65.148.240","Country":"DE","Attack Type":"Unknown","Severity":"High","Latitude":51.1657,"Longitude":10.4515,"Last Reported":"2025-08-16T12:17:01Z"},
        {"IP":"14.103.120.147","Country":"CN","Attack Type":"DDoS","Severity":"High","Latitude":35.8617,"Longitude":104.1954,"Last Reported":"2025-08-16T12:17:01Z"},
        {"IP":"3.134.100.58","Country":"US","Attack Type":"Malware","Severity":"High","Latitude":37.0902,"Longitude":-95.7129,"Last Reported":"2025-08-16T12:17:01Z"},
        {"IP":"162.244.31.243","Country":"DE","Attack Type":"Phishing","Severity":"Medium","Latitude":51.1657,"Longitude":10.4515,"Last Reported":"2025-08-16T12:17:00Z"},
        {"IP":"192.42.116.211","Country":"NL","Attack Type":"Botnet","Severity":"High","Latitude":52.1326,"Longitude":5.2913,"Last Reported":"2025-08-16T12:17:00Z"},
        {"IP":"47.83.170.6","Country":"HK","Attack Type":"Proxy","Severity":"Medium","Latitude":22.3193,"Longitude":114.1694,"Last Reported":"2025-08-16T12:17:00Z"},
        {"IP":"201.48.22.10","Country":"BR","Attack Type":"DDoS","Severity":"High","Latitude":-14.2350,"Longitude":-51.9253,"Last Reported":"2025-08-15T18:05:00Z"},
        {"IP":"41.77.112.34","Country":"ZA","Attack Type":"Malware","Severity":"Medium","Latitude":-30.5595,"Longitude":22.9375,"Last Reported":"2025-08-15T17:45:00Z"},
        {"IP":"77.88.55.66","Country":"RU","Attack Type":"Phishing","Severity":"High","Latitude":61.5240,"Longitude":105.3188,"Last Reported":"2025-08-15T17:30:00Z"},
        {"IP":"203.0.113.1","Country":"JP","Attack Type":"Botnet","Severity":"Medium","Latitude":36.2048,"Longitude":138.2529,"Last Reported":"2025-08-15T17:15:00Z"},
        {"IP":"102.165.35.12","Country":"NG","Attack Type":"Proxy","Severity":"High","Latitude":9.0820,"Longitude":8.6753,"Last Reported":"2025-08-15T17:00:00Z"},
        {"IP":"8.8.8.8","Country":"US","Attack Type":"DDoS","Severity":"Medium","Latitude":37.3861,"Longitude":-122.0839,"Last Reported":"2025-08-15T16:45:00Z"},
        {"IP":"185.199.108.153","Country":"GB","Attack Type":"Malware","Severity":"High","Latitude":55.3781,"Longitude":-3.4360,"Last Reported":"2025-08-15T16:30:00Z"},
        {"IP":"139.130.4.5","Country":"AU","Attack Type":"Phishing","Severity":"Medium","Latitude":-25.2744,"Longitude":133.7751,"Last Reported":"2025-08-15T16:15:00Z"},
        {"IP":"196.25.1.200","Country":"ZA","Attack Type":"Botnet","Severity":"High","Latitude":-30.5595,"Longitude":22.9375,"Last Reported":"2025-08-15T16:00:00Z"},
        {"IP":"123.45.67.89","Country":"IN","Attack Type":"Proxy","Severity":"Medium","Latitude":20.5937,"Longitude":78.9629,"Last Reported":"2025-08-15T15:45:00Z"}
    ]
    df = pd.DataFrame(sample)
    df["Last Reported"] = to_utc_series(df["Last Reported"])
    return df

# -------------------------
# AbuseIPDB fetch (optional)
# -------------------------
@st.cache_data(ttl=300)
def fetch_abuseipdb(limit=100):
    if not ABUSEIPDB_API_KEY:
        return pd.DataFrame()
    url = "https://api.abuseipdb.com/api/v2/blacklist"
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"limit": limit, "confidenceMinimum": 50}
    try:
        r = requests.get(url, headers=headers, params=params, timeout=10)
        if r.status_code != 200:
            return pd.DataFrame()
        data = r.json().get("data", [])
    except Exception:
        return pd.DataFrame()

    rows = []
    for ip_info in data:
        ip = ip_info.get("ipAddress")
        last = ip_info.get("lastReportedAt")
        last_ts = pd.to_datetime(last, utc=True, errors="coerce")
        lat = ip_info.get("latitude", 0) or 0
        lon = ip_info.get("longitude", 0) or 0
        country = ip_info.get("countryCode") or "Unknown"
        if lat == 0 and lon == 0:
            lat, lon, country = geolocate_ip(ip)
        usage = ip_info.get("usageType") or "Unknown"
        severity = "High" if (ip_info.get("abuseConfidenceScore") or 0) > 75 else "Medium"
        rows.append({
            "IP": ip, "Country": country, "Attack Type": usage,
            "Severity": severity, "Latitude": lat, "Longitude": lon,
            "Last Reported": last_ts
        })
    return pd.DataFrame(rows)

# -------------------------
# OTX fetch (optional)
# -------------------------
@st.cache_data(ttl=300)
def fetch_otx(limit=100):
    if not OTX_API_KEY:
        return pd.DataFrame()
    url = "https://otx.alienvault.com/api/v1/indicators/IPv4/last"
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    params = {"limit": limit}
    try:
        r = requests.get(url, headers=headers, params=params, timeout=10)
        if r.status_code != 200:
            return pd.DataFrame()
        data = r.json().get("results", [])
    except Exception:
        return pd.DataFrame()

    rows = []
    for item in data:
        ip = item.get("indicator") or "Unknown"
        last = item.get("last_seen") or item.get("modified") or None
        last_ts = pd.to_datetime(last, utc=True, errors="coerce") if last else pd.Timestamp.now(tz=pytz.UTC)
        geo = item.get("geo", {}) or {}
        lat = geo.get("latitude") or 0
        lon = geo.get("longitude") or 0
        country = geo.get("country_name") or "Unknown"
        if lat == 0 and lon == 0:
            lat, lon, country = geolocate_ip(ip)
        attack_type = item.get("type") or "Unknown"
        rows.append({
            "IP": ip, "Country": country, "Attack Type": attack_type,
            "Severity": "Medium", "Latitude": lat, "Longitude": lon,
            "Last Reported": last_ts
        })
    return pd.DataFrame(rows)

# -------------------------
# Combine and prepare
# -------------------------
@st.cache_data(ttl=300)
def build_dataset():
    # attempt to fetch from both APIs (if keys present)
    df_abuse = fetch_abuseipdb(limit=150)
    df_otx = fetch_otx(limit=150)

    # If both failed, return sample data
    if df_abuse.empty and df_otx.empty:
        return load_sample_data(), True  # second value means 'using_sample'

    # Combine available frames
    frames = []
    if not df_abuse.empty:
        frames.append(df_abuse)
    if not df_otx.empty:
        frames.append(df_otx)

    combined = pd.concat(frames, ignore_index=True)
    # normalize timestamps - ensure UTC tz-aware (pd.to_datetime with utc=True)
    combined["Last Reported"] = to_utc_series(combined["Last Reported"])
    # Fill missing 'Attack Type' or 'Country'
    combined["Attack Type"] = combined["Attack Type"].fillna("Unknown").replace("", "Unknown")
    combined["Country"] = combined["Country"].fillna("Unknown").replace("", "Unknown")
    # Geolocate any 0,0 coordinates
    for i, row in combined.loc[(combined["Latitude"].fillna(0) == 0) & (combined["Longitude"].fillna(0) == 0)].iterrows():
        ip = row["IP"]
        lat, lon, country = geolocate_ip(ip)
        combined.at[i, "Latitude"] = lat
        combined.at[i, "Longitude"] = lon
        if combined.at[i, "Country"] in ("Unknown", "") and country:
            combined.at[i, "Country"] = country
    # dedupe by IP
    combined = combined.drop_duplicates(subset=["IP"])
    return combined, False

# -------------------------
# UI: Sidebar controls
# -------------------------
st.sidebar.title("Filters & Settings")
time_filter_days = st.sidebar.slider("Show attacks from last X days", min_value=1, max_value=30, value=7, step=1)
attack_type_filter = st.sidebar.multiselect("Attack types", ["DDoS","Malware","Phishing","Botnet","Proxy","Unknown"], default=["Unknown","Malware","DDoS"])
severity_filter = st.sidebar.multiselect("Severity", ["Medium","High"], default=["Medium","High"])
country_search = st.sidebar.text_input("Filter by country code/name (leave blank for all)")
refresh_interval = st.sidebar.number_input("Auto-refresh every X seconds", min_value=10, max_value=600, value=120, step=10)
st.sidebar.markdown("---")
st.sidebar.write("Data sources: AbuseIPDB (optional), AlienVault OTX (optional), IP geolocation (ip-api.com), sample fallback")

# enable auto-refresh
st_autorefresh(interval=refresh_interval * 1000, key="autorefresh")

# -------------------------
# Build dataset (live if possible, otherwise sample)
# -------------------------
with st.spinner("Fetching threat data (APIs or fallback)..."):
    df_all, using_sample = build_dataset()
    time.sleep(0.2)

if using_sample:
    st.warning("APIs returned no data or no API keys provided — using sample dataset for demo. (You can add keys to .env to fetch live data.)")
else:
    st.success("Loaded live threat data (where available).")

# -------------------------
# Filter dataset
# -------------------------
# Ensure datetime tz-aware
df_all["Last Reported"] = to_utc_series(df_all["Last Reported"])

time_threshold = pd.Timestamp.now(tz=pytz.UTC) - pd.Timedelta(days=time_filter_days)
df = df_all[df_all["Last Reported"] >= time_threshold].copy()

# Apply filters
if attack_type_filter:
    df = df[df["Attack Type"].isin(attack_type_filter)]
if severity_filter:
    df = df[df["Severity"].isin(severity_filter)]
if country_search and country_search.strip():
    cs = country_search.strip().lower()
    df = df[df["Country"].astype(str).str.lower().str.contains(cs)]

# Remove invalid coordinates (0,0)
df = df[(df["Latitude"].fillna(0) != 0) & (df["Longitude"].fillna(0) != 0)].copy()

# -------------------------
# Top metrics + UI header
# -------------------------
st.title("🌐 Real-Time Cyber Attack Threat Map")
col1, col2, col3, col4 = st.columns([1.5,1,1,1])

col1.metric("Total attacks (shown)", len(df))
col2.metric("High severity", int((df["Severity"] == "High").sum()))
col3.metric("Unique countries", int(df["Country"].nunique()))
col4.metric("Using sample data?", "Yes" if using_sample else "No")

st.markdown("---")

# -------------------------
# Map visualization (Plotly Mapbox)
# -------------------------
if not df.empty:
    # size by recency (newer -> bigger)
    now = pd.Timestamp.now(tz=pytz.UTC)
    df["age_minutes"] = (now - df["Last Reported"]).dt.total_seconds() / 60.0
    # invert age to size: recent smaller age -> larger size
    df["size"] = df["age_minutes"].apply(lambda x: max(6, 18 - min(16, x/10)))  # heuristic: recent bigger
    fig_map = px.scatter_mapbox(
        df,
        lat="Latitude",
        lon="Longitude",
        color="Severity",
        size="size",
        size_max=18,
        hover_name="IP",
        hover_data=["Country","Attack Type","Severity","Last Reported"],
        zoom=1,
        mapbox_style="carto-positron",
        color_discrete_map={"High":"red","Medium":"orange"}
    )
    fig_map.update_layout(margin={"r":0,"t":0,"l":0,"b":0}, height=600)
    st.plotly_chart(fig_map, use_container_width=True)
else:
    st.warning("No data to show on the map after applying filters.")

# -------------------------
# Charts: distribution + top countries
# -------------------------
st.markdown("### Attack Type Distribution & Top Attacked Countries")
c1, c2 = st.columns(2)
with c1:
    if not df.empty:
        type_counts = df["Attack Type"].value_counts().reset_index()
        type_counts.columns = ["Attack Type","Count"]
        fig_type = px.pie(type_counts, names="Attack Type", values="Count", color="Attack Type",
                          color_discrete_sequence=px.colors.qualitative.Set3)
        st.plotly_chart(fig_type, use_container_width=True)
    else:
        st.info("No attack type data")

with c2:
    if not df.empty:
        country_counts = df["Country"].value_counts().reset_index()
        country_counts.columns = ["Country", "Count"]
        fig_country = px.bar(country_counts, x="Country", y="Count", text="Count",
                             color="Country", color_discrete_sequence=px.colors.qualitative.Set2)
        fig_country.update_layout(xaxis_tickangle=-45)
        st.plotly_chart(fig_country, use_container_width=True)
    else:
        st.info("No country data")

st.markdown("---")

# -------------------------
# Data table + export
# -------------------------
if not df.empty:
    st.subheader("Full attack table (filtered)")
    display_df = df[["IP","Country","Attack Type","Severity","Latitude","Longitude","Last Reported"]].sort_values("Last Reported", ascending=False)
    st.dataframe(display_df.reset_index(drop=True))

    csv = display_df.to_csv(index=False)
    st.download_button("Download CSV of filtered results", csv, file_name="threats_filtered.csv", mime="text/csv")
else:
    st.info("No rows to display in table.")

# -------------------------
# Footer / notes
# -------------------------
st.markdown("---")
st.markdown("""
**Notes:**  
- This app attempts to use AbuseIPDB and OTX if API keys are present in `.env`.  
- When keys are not present or APIs return empty, the app uses a realistic sample dataset so the dashboard remains functional for portfolio/demo.  
- IP geolocation uses the free `ip-api.com` service and is cached for one hour.  
- If you add valid API keys in `.env`, the app will pull live data when available.
""")
