import streamlit as st
import requests
import re
import pandas as pd

# Page setup
st.set_page_config(
    page_title="Threat Intel & IOC Reputation Engine",
    page_icon="🛡️",
    layout="wide"
)

# Custom header styling
st.markdown("""
    <style>
    .metric-card {
        background-color: #f8f9fa;
        border: 1px solid #e9ecef;
        padding: 15px;
        border-radius: 8px;
        margin-bottom: 10px;
    }
    </style>
""", unsafe_allow_html=True)

st.title("🛡️ Threat Intelligence & IOC Reputation Engine")
st.markdown(
    "Automated Open Source Intelligence (OSINT) enrichment engine designed for SOC triage. "
    "Classifies artifacts and correlates threat reputation against **AbuseIPDB** and **VirusTotal**."
)

# Load API credentials from Streamlit Secrets
ABUSEIPDB_API_KEY = st.secrets.get("ABUSEIPDB_API_KEY", "")
VIRUSTOTAL_API_KEY = st.secrets.get("VIRUSTOTAL_API_KEY", "")

# Sidebar status
with st.sidebar:
    st.header("🔑 Telemetry Feeds")
    if ABUSEIPDB_API_KEY:
        st.success("AbuseIPDB Feed: Active")
    else:
        st.error("AbuseIPDB Feed: Missing API Key")
        
    if VIRUSTOTAL_API_KEY:
        st.success("VirusTotal Feed: Active")
    else:
        st.error("VirusTotal Feed: Missing API Key")
        
    st.markdown("---")
    st.caption("SOC Analyst Toolkit | Project 08")

# Helper: Detect IOC Type
def identify_ioc_type(ioc: str) -> str:
    ioc = ioc.strip()
    # IPv4 Pattern
    ipv4_pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    # MD5 (32 hex) / SHA256 (64 hex)
    md5_pattern = r"^[a-fA-F0-9]{32}$"
    sha256_pattern = r"^[a-fA-F0-9]{64}$"
    # Domain Pattern
    domain_pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"

    if re.match(ipv4_pattern, ioc):
        return "IPv4"
    elif re.match(md5_pattern, ioc) or re.match(sha256_pattern, ioc):
        return "File Hash"
    elif re.match(domain_pattern, ioc):
        return "Domain"
    return "Unknown"

# AbuseIPDB Query
def query_abuseipdb(ip: str):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Accept": "application/json",
        "Key": ABUSEIPDB_API_KEY
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": "90",
        "verbose": True
    }
    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        if response.status_code == 200:
            return response.json().get("data", {})
        else:
            st.error(f"AbuseIPDB API error: Status {response.status_code} ({response.text})")
            return None
    except Exception as e:
        st.error(f"Error querying AbuseIPDB: {e}")
        return None

# VirusTotal Query
def query_virustotal(ioc: str, ioc_type: str):
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }
    endpoint_map = {
        "IPv4": f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}",
        "Domain": f"https://www.virustotal.com/api/v3/domains/{ioc}",
        "File Hash": f"https://www.virustotal.com/api/v3/files/{ioc}"
    }
    url = endpoint_map.get(ioc_type)
    if not url:
        return None

    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            return response.json().get("data", {}).get("attributes", {})
        elif response.status_code == 404:
            return {"not_found": True}
        else:
            st.error(f"VirusTotal API error: Status {response.status_code} ({response.text})")
            return None
    except Exception as e:
        st.error(f"Error querying VirusTotal: {e}")
        return None

# User Input Form
user_ioc = st.text_input("Enter Indicator of Compromise (IP, Domain, or SHA-256 / MD5 Hash):", placeholder="e.g. 185.220.101.5, example.com, or hash")

if st.button("🚀 Analyze Indicator", type="primary"):
    if not user_ioc.strip():
        st.warning("Please provide an IOC to begin triage.")
    else:
        ioc_clean = user_ioc.strip().lower()
        detected_type = identify_ioc_type(ioc_clean)
        
        st.markdown(f"### Target Artifact: `{ioc_clean}` (Detected: **{detected_type}**)")
        
        if detected_type == "Unknown":
            st.error("Unrecognized format. Please submit a valid IPv4 address, domain, MD5, or SHA-256 hash.")
        else:
            col1, col2 = st.columns(2)
            
            # --- AbuseIPDB Section (IPv4 only) ---
            if detected_type == "IPv4":
                with col1:
                    st.subheader("🌐 AbuseIPDB Intel")
                    if not ABUSEIPDB_API_KEY:
                        st.info("AbuseIPDB API key not configured in secrets.")
                    else:
                        with st.spinner("Querying AbuseIPDB..."):
                            ip_data = query_abuseipdb(ioc_clean)
                            
                        if ip_data:
                            score = ip_data.get("abuseConfidenceScore", 0)
                            reports = ip_data.get("totalReports", 0)
                            country = ip_data.get("countryCode", "N/A")
                            isp = ip_data.get("isp", "N/A")
                            domain = ip_data.get("domain", "N/A")
                            is_tor = ip_data.get("isTor", False)

                            # Risk presentation
                            if score >= 50:
                                st.error(f"Abuse Confidence Score: {score}% (High Risk)")
                            elif score > 0:
                                st.warning(f"Abuse Confidence Score: {score}% (Suspicious)")
                            else:
                                st.success(f"Abuse Confidence Score: {score}% (Clean / Benign)")

                            st.write(f"**Country:** {country} | **Total Reports:** {reports}")
                            st.write(f"**ISP:** {isp}")
                            st.write(f"**Associated Domain:** {domain}")
                            st.write(f"**Tor Exit Node:** {'Yes' if is_tor else 'No'}")

                            # Show recent reports snippet
                            recent_reports = ip_data.get("reports", [])
                            if recent_reports:
                                with st.expander("View Recent Abuse Reports"):
                                    report_rows = []
                                    for r in recent_reports[:5]:
                                        report_rows.append({
                                            "Reported At": r.get("reportedAt", "N/A")[:10],
                                            "Categories": str(r.get("categories", [])),
                                            "Comment": r.get("comment", "")[:80] + "..."
                                        })
                                    st.dataframe(pd.DataFrame(report_rows), use_container_width=True)

            # --- VirusTotal Section ---
            vt_target_col = col2 if detected_type == "IPv4" else st.container()
            with vt_target_col:
                st.subheader("🦠 VirusTotal Telemetry")
                if not VIRUSTOTAL_API_KEY:
                    st.info("VirusTotal API key not configured in secrets.")
                else:
                    with st.spinner("Querying VirusTotal..."):
                        vt_data = query_virustotal(ioc_clean, detected_type)
                        
                    if vt_data:
                        if vt_data.get("not_found"):
                            st.info("No prior telemetry found in VirusTotal database for this indicator.")
                        else:
                            stats = vt_data.get("last_analysis_stats", {})
                            malicious = stats.get("malicious", 0)
                            suspicious = stats.get("suspicious", 0)
                            harmless = stats.get("harmless", 0)
                            undetected = stats.get("undetected", 0)
                            
                            c1, c2, c3, c4 = st.columns(4)
                            c1.metric("Malicious", malicious, delta_color="inverse")
                            c2.metric("Suspicious", suspicious, delta_color="inverse")
                            c3.metric("Harmless", harmless)
                            c4.metric("Undetected", undetected)
                            
                            if malicious > 0:
                                st.error(f"Flagged as malicious by {malicious} security engine(s).")
                            else:
                                st.success("Zero security engines flagged this artifact as malicious.")

                            # Engine breakdown expander
                            results = vt_data.get("last_analysis_results", {})
                            if results:
                                with st.expander("Inspect Antivirus Engine Detections"):
                                    rows = []
                                    for engine, det in results.items():
                                        cat = det.get("category")
                                        if cat in ["malicious", "suspicious"]:
                                            rows.append({
                                                "Engine": engine,
                                                "Verdict": cat.upper(),
                                                "Result": det.get("result", "Flagged")
                                            })
                                    if rows:
                                        st.dataframe(pd.DataFrame(rows), use_container_width=True)
                                    else:
                                        st.write("All reporting engines evaluated this artifact as clean.")