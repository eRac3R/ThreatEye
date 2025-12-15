from flask import Flask, request, render_template, jsonify
from elasticsearch import Elasticsearch
from thehive4py.api import TheHiveApi
import requests
import json
from datetime import datetime
from apscheduler.schedulers.background import BackgroundScheduler
import requests
import re



app = Flask(__name__)
es = Elasticsearch("http://192.168.1.7:9200")  # Update to your ES URL

THEHIVE_URL = "http://localhost:9000"  # Update this to your actual TheHive URL if different
#THEHIVE_API_KEY = "wPioRkl91ROl7ud5ELLcaPkczNyFFehd"  # Replace with your TheHive API key
THEHIVE_API_KEY = "i7DdxDQ4ZXmG4P1MFkNQwq02lPhvCOQt"
thehive_api = TheHiveApi(THEHIVE_URL, THEHIVE_API_KEY)


#new1
MISP_URL = "https://localhost"
MISP_API_KEY = "qIJIs8oyusAdUh7VTQVr3cHpUGV7Ua6pQEkx36Rr"
MISP_VERIFY_SSL = False
#new1

severity_map = {
    "whoami": 2,
    "id": 2,
    "hostname": 1,
    "uname": 1,
    "ps": 3
}

@app.route('/')
@app.route('/dashboard')
def dashboard():
    # Combined auditbeat + filebeat counts]
    auditbeat_count = es.count(index="auditbeat-*")['count']
    filebeat_count = es.count(index="filebeat-*")['count']
    stats = {
        "auditbeat_docs": auditbeat_count,
        "filebeat_docs": filebeat_count,
    }
    return render_template('dashboard.html', stats=stats)

@app.template_filter('datetimeformat')
def datetimeformat(value):
    # The timestamp appears to be in milliseconds
    dt = datetime.fromtimestamp(value / 1000)
    return dt.strftime('%Y-%m-%d %H:%M:%S')


@app.route('/thehive/cases')
def thehive_cases():
    url = f"{THEHIVE_URL}/api/case"
    headers = {
        'Authorization': f'Bearer {THEHIVE_API_KEY}',
        'Accept': 'application/json'
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        cases = response.json()
        print("Cases JSON pretty:", json.dumps(cases, indent=2))
        return render_template('thehive_cases.html', cases=cases)
    else:
        return render_template('error.html', message="Failed to fetch TheHive cases")




@app.route('/networks')
def networks():
    networks_data = [
        {"network": "192.168.1.0/24", "blocked_attempts": 10, "last_blocked": "2025-09-23 14:32:00"},
        {"network": "10.0.0.0/8", "blocked_attempts": 25, "last_blocked": "2025-09-23 13:10:10"}
    ]
    return render_template('networks.html', networks=networks_data)

@app.route('/threats')
def threats():
    threats_data = [
        {"site": "malicious-site.com", "flag": "High", "source": "MISP", "detected_on": "2025-09-22"},
        {"site": "phishing-site.net", "flag": "Medium", "source": "External Feed", "detected_on": "2025-09-21"}
    ]
    return render_template('threats.html', threats=threats_data)


@app.route('/simulations')
def simulations():
    simulations_data = [
        {"simulation": "Phishing Email Test", "status": "Complete", "date": "2025-09-20", "alerts_triggered": 3},
        {"simulation": "Ransomware Drill", "status": "In Progress", "date": "2025-09-22", "alerts_triggered": 5}
    ]
    return render_template('simulations.html', simulations=simulations_data)


@app.route('/anomalies')
def anomalies():
    data = [
        {"id": 1, "type": "Login Anomaly", "user": "admin", "date": "2025-09-22", "action_taken": "Account Locked"},
        {"id": 2, "type": "Data Exfiltration", "user": "user01", "date": "2025-09-21", "action_taken": "Session Terminated"},
    ]
    return render_template('anomalies.html', anomalies=data)



@app.route('/alerts-viz')
def alerts_viz():
    return render_template('alerts_viz.html')

@app.route('/api/alerts')
def api_alerts():
    body = {
        "size": 30,
        "sort": [{ "@timestamp": { "order": "desc" }}]
    }
    # Query both auditbeat and filebeat indices for alerts
    res = es.search(index=[".alerts-*", "auditbeat-*", "filebeat-*"], body=body)
    hits = res.get('hits', {}).get('hits', [])
    alerts = []
    for hit in hits:
        source = hit['_source']
        alerts.append({
            "timestamp": source.get('@timestamp', ''),
            "alert_name": source.get('alert', {}).get('action_group', ''),
            "severity": source.get('event', {}).get('severity', ''),
            "message": source.get('message', '')
        })
    return jsonify(alerts)

def create_thehive_case(title, description, severity=2, tags=None):
    if tags is None:
        tags = []
    url = f"{THEHIVE_URL}/api/case"
    headers = {
        "Authorization": f"Bearer {THEHIVE_API_KEY}",
        "Content-Type": "application/json"
    }
    body = {
        "title": title,
        "description": description,
        "severity": severity,
        "tags": tags
    }
    try:
        response = requests.post(url, headers=headers, json=body)
        response.raise_for_status()  # Raises HTTPError for bad responses
        print(f"Created TheHive case: {title}")
        return True
    except requests.exceptions.RequestException as err:
        print(f"Failed to create TheHive case: {err} - Response: {response.text if response else 'No response'}")
        return False
    
def get_severity_for_command(args_list):
    severities_found = []
    for cmd, severity in severity_map.items():
        if any(cmd in arg for arg in args_list):
            severities_found.append(severity)
    return max(severities_found) if severities_found else 1

    
def sync_alerts_to_thehive_logic():
    query = {
        "query": {
            "bool": {
                "should": [
                    {"match_phrase": {"process.args": "whoami"}},
                    {"match_phrase": {"process.args": "id"}},
                    {"match_phrase": {"process.args": "hostname"}},
                    {"match_phrase": {"process.args": "uname"}},
                    {"match_phrase": {"process.args": "ps"}}
                ],
                "minimum_should_match": 1,
                "filter": [
                    {"term": {"event.action": "executed"}},
                    {"range": {"@timestamp": {"gte": "now-10m"}}}
                ]
            }
        },
        "size": 20,
        "sort": [{"@timestamp": {"order": "desc"}}]
    }

    res = es.search(index=["auditbeat-*", "filebeat-*"], body=query)
    hits = res.get('hits', {}).get('hits', [])
    created = 0

    for hit in hits:
        source = hit.get('_source', {})
        args_list = source.get('process', {}).get('args', [])
        command_str = ' '.join(args_list)

        # Extract and send indicators to MISP
        for arg in args_list:
            if arg.startswith("http://") or arg.startswith("https://"):
                add_misp_indicator(arg)
            elif re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", arg):
                add_misp_indicator(arg)
            elif re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", arg):
                add_misp_indicator(arg)
            elif re.match(r"^[a-fA-F0-9]{32}$", arg):
                add_misp_indicator(arg)
            elif re.match(r"^[a-fA-F0-9]{40}$", arg):
                add_misp_indicator(arg)
            elif re.match(r"^[a-fA-F0-9]{64}$", arg):
                add_misp_indicator(arg)

        severity = get_severity_for_command(args_list)
        title = f"Alert: Suspicious command '{command_str}' detected"
        description = json.dumps(source, indent=2)

        if create_thehive_case(title, description, severity=severity, tags=["auditbeat", "auto"]):
            created += 1

    print(f"{datetime.now()}: Created {created} new TheHive cases.")
    return created


@app.route('/sync-alerts-to-thehive')
def sync_alerts_to_thehive_route():
    created = sync_alerts_to_thehive_logic()
    return f"Created {created} new TheHive cases."

@app.route('/misp_alerts')
def misp_alerts():
    url = f"{MISP_URL}/events/restSearch"
    headers = {
        "Authorization": MISP_API_KEY,
        "Accept": "application/json"
    }
    response = requests.post(url, headers=headers, verify=False)
    alerts = response.json()
    return render_template('misp_alerts.html', alerts=alerts)




def sync_job():
    with app.app_context():
        print("Running scheduled alert sync to TheHive...")
        sync_alerts_to_thehive_logic()


def search_misp(query):
    url = "https://localhost/events/restSearch"
    headers = {
        "Authorization": MISP_API_KEY,
        "Accept": "application/json"
    }
    data = {
        "value": query
    }
    response = requests.post(url, headers=headers, json=data, verify=False)
    return response.json()


def sync_misp_job():
    with app.app_context():
        print("Running scheduled MISP sync...")
        # Example: Search for malware events
        results = search_misp("malware")
        print("MISP search results:", results)
        # Example: Add a new indicator
        result = add_misp_indicator("abc123def456ghi789")
        print("MISP add indicator result:", result)


def parse_indicator(value):
    # Detect indicator type and assign category
    if re.match(r"^[a-fA-F0-9]{32}$", value):  # MD5 hash
        return "md5", "Payload delivery"
    elif re.match(r"^[a-fA-F0-9]{40}$", value):  # SHA1 hash
        return "sha1", "Payload delivery"
    elif re.match(r"^[a-fA-F0-9]{64}$", value):  # SHA256 hash
        return "sha256", "Payload delivery"
    elif re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", value):  # IP address
        return "ip-dst", "Network activity"
    elif re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", value):  # Domain
        return "domain", "Network activity"
    elif re.match(r"^https?://", value):  # URL
        return "url", "Network activity"
    else:
        return "other", "Other"


def add_misp_indicator(value):
    type, category = parse_indicator(value)
    url = f"{MISP_URL}/attributes/add"
    headers = {
        "Authorization": MISP_API_KEY,
        "Accept": "application/json"
    }
    data = {
        "event_id": 1,  # Use an existing event ID or create a new one
        "category": category,
        "type": type,
        "value": value
    }
    response = requests.post(url, headers=headers, json=data, verify=False)
    return response.json()




if __name__ == "__main__":
    scheduler = BackgroundScheduler()
    scheduler.add_job(sync_job, 'interval', seconds=30)
    scheduler.add_job(sync_misp_job, 'interval', seconds=30)
    scheduler.start()
    app.run(host="0.0.0.0", port=5000, debug=True)
