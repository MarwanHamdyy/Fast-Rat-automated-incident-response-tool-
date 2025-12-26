"""
FAST RAT - API Server
Flask-based REST API serving the dashboard and data.
"""
from flask import Flask, jsonify, request, render_template, send_file
from flask_cors import CORS
from ir_core import FastRATEngine
from log_generator import LogGenerator
import pandas as pd
import io
import os
import json
import smtplib
import threading
import schedule
import time
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email.mime.text import MIMEText
from email import encoders
from datetime import datetime

app = Flask(__name__)
CORS(app)

# Email configuration file
EMAIL_CONFIG_FILE = "data/email_config.json"

# Initialize engine and generator
engine = FastRATEngine()
generator = LogGenerator(engine)

def load_email_config():
    """Load email configuration from file."""
    if os.path.exists(EMAIL_CONFIG_FILE):
        with open(EMAIL_CONFIG_FILE, 'r') as f:
            return json.load(f)
    return {'enabled': False, 'email': '', 'smtp_server': 'smtp.gmail.com', 'smtp_port': 587, 'smtp_user': '', 'smtp_pass': ''}

def save_email_config(config):
    """Save email configuration to file."""
    os.makedirs('data', exist_ok=True)
    with open(EMAIL_CONFIG_FILE, 'w') as f:
        json.dump(config, f)

def send_email_report():
    """Send hourly Excel report via email."""
    config = load_email_config()
    if not config.get('enabled') or not config.get('email'):
        return
    
    try:
        # Generate Excel report
        incidents = engine.storage.get_all_incidents()
        df = pd.DataFrame(incidents)
        
        output = io.BytesIO()
        df.to_excel(output, index=False, engine='openpyxl')
        output.seek(0)
        
        # Create email
        msg = MIMEMultipart()
        msg['From'] = config.get('smtp_user', 'fastrat@security.local')
        msg['To'] = config['email']
        msg['Subject'] = f"FAST RAT - Hourly Security Report - {datetime.now().strftime('%Y-%m-%d %H:%M')}"
        
        body = f"""
FAST RAT Security Report
========================
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Summary:
- Total Incidents: {len(incidents)}
- Critical: {len([i for i in incidents if i.get('severity') == 'CRITICAL'])}
- High: {len([i for i in incidents if i.get('severity') == 'HIGH'])}
- Medium: {len([i for i in incidents if i.get('severity') == 'MEDIUM'])}

See attached Excel file for details.
"""
        msg.attach(MIMEText(body, 'plain'))
        
        # Attach Excel file
        attachment = MIMEBase('application', 'vnd.openxmlformats-officedocument.spreadsheetml.sheet')
        attachment.set_payload(output.read())
        encoders.encode_base64(attachment)
        attachment.add_header('Content-Disposition', f'attachment; filename="fast_rat_report_{datetime.now().strftime("%Y%m%d_%H%M")}.xlsx"')
        msg.attach(attachment)
        
        # Send email
        if config.get('smtp_server'):
            server = smtplib.SMTP(config['smtp_server'], config.get('smtp_port', 587))
            server.starttls()
            if config.get('smtp_user') and config.get('smtp_pass'):
                server.login(config['smtp_user'], config['smtp_pass'])
            server.send_message(msg)
            server.quit()
            print(f"📧 Email report sent to {config['email']}")
    except Exception as e:
        print(f"❌ Failed to send email: {e}")

def run_scheduler():
    """Run the scheduler in a background thread."""
    schedule.every(1).hours.do(send_email_report)
    while True:
        schedule.run_pending()
        time.sleep(60)

# ============ API ROUTES ============

@app.route('/')
def home():
    """Serve the dashboard."""
    return render_template('dashboard.html')

@app.route('/api/dashboard', methods=['GET'])
def get_dashboard():
    """Get dashboard stats and recent incidents."""
    stats = engine.storage.get_stats()
    incidents = engine.storage.get_all_incidents()
    
    # Sort by created_at desc and take top 10
    sorted_incidents = sorted(incidents, key=lambda x: x.get('created_at', ''), reverse=True)[:10]
    
    return jsonify({
        'stats': stats,
        'recent_incidents': sorted_incidents
    })

@app.route('/api/incidents', methods=['GET'])
def get_incidents():
    """Get all incidents."""
    incidents = engine.storage.get_all_incidents()
    return jsonify({'incidents': incidents})

@app.route('/api/incidents/<incident_id>', methods=['GET'])
def get_incident(incident_id):
    """Get single incident details."""
    incident = engine.storage.get_incident(incident_id)
    if incident:
        return jsonify(incident)
    return jsonify({'error': 'Not found'}), 404

@app.route('/api/events/recent', methods=['GET'])
def get_recent_events():
    """Get recent events for live traffic monitor."""
    limit = request.args.get('limit', 15, type=int)
    events = engine.storage.get_recent_events(limit)
    return jsonify({'events': events})

@app.route('/api/analytics', methods=['GET'])
def get_analytics():
    """Get analytics data for charts."""
    range_type = request.args.get('range', 'daily')
    data = engine.storage.get_analytics_data(range_type)
    return jsonify(data)

@app.route('/api/reports/download', methods=['GET'])
def download_report():
    """Download incident report as Excel."""
    try:
        incidents = engine.storage.get_all_incidents()
        
        if not incidents:
            # Create empty report with headers
            df = pd.DataFrame(columns=['Incident ID', 'Title', 'Severity', 'Status', 
                                       'Source IP', 'Actions Taken', 'Created At'])
        else:
            df = pd.DataFrame(incidents)
            # Rename columns for better readability
            df = df.rename(columns={
                'incident_id': 'Incident ID',
                'title': 'Title',
                'severity': 'Severity',
                'status': 'Status',
                'source_ip': 'Source IP',
                'actions_taken': 'Actions Taken',
                'created_at': 'Created At',
                'description': 'Description'
            })
        
        output = io.BytesIO()
        
        # Create Excel with formatting
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            df.to_excel(writer, sheet_name='Incidents', index=False)
            
            # Auto-adjust column widths
            worksheet = writer.sheets['Incidents']
            for idx, col in enumerate(df.columns):
                max_length = max(df[col].astype(str).map(len).max(), len(col)) + 2
                worksheet.column_dimensions[chr(65 + idx)].width = min(max_length, 50)
        
        output.seek(0)
        
        # Include timestamp in filename
        from datetime import datetime
        filename = f'fast_rat_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.xlsx'
        
        return send_file(
            output,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            as_attachment=True,
            download_name=filename
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/health', methods=['GET'])
def health():
    """Health check."""
    return jsonify({'status': 'healthy', 'name': 'FAST RAT'})

@app.route('/api/actions', methods=['GET'])
def get_actions():
    """Get all containment actions."""
    actions = engine.storage.get_all_actions()
    return jsonify({'actions': actions})

@app.route('/api/actions/block-ip', methods=['POST'])
def block_ip():
    """Manually block an IP address."""
    data = request.json
    ip = data.get('ip', '')
    
    if not ip:
        return jsonify({'error': 'IP address required'}), 400
    
    # Store the action
    engine.storage.store_action({
        'action_type': 'Block IP',
        'target': ip,
        'status': 'active',
        'performed_by': 'Manual'
    })
    
    # Log the containment
    engine.containment.block_ip(ip)
    
    return jsonify({'success': True, 'message': f'Blocked IP {ip}'})

@app.route('/api/actions/quarantine', methods=['POST'])
def quarantine_file():
    """Manually quarantine a file."""
    data = request.json
    filepath = data.get('path', '')
    
    if not filepath:
        return jsonify({'error': 'File path required'}), 400
    
    engine.storage.store_action({
        'action_type': 'Quarantine File',
        'target': filepath,
        'status': 'active',
        'performed_by': 'Manual'
    })
    
    engine.containment.quarantine_file(filepath)
    
    return jsonify({'success': True, 'message': f'Quarantined {filepath}'})

@app.route('/api/email/config', methods=['GET'])
def get_email_config():
    """Get email configuration (hides password)."""
    config = load_email_config()
    # Don't expose password
    safe_config = {k: v for k, v in config.items() if k != 'smtp_pass'}
    safe_config['has_password'] = bool(config.get('smtp_pass'))
    return jsonify(safe_config)

@app.route('/api/email/config', methods=['POST'])
def set_email_config():
    """Set email configuration."""
    data = request.json
    config = load_email_config()
    
    config['email'] = data.get('email', config.get('email', ''))
    config['enabled'] = data.get('enabled', config.get('enabled', False))
    config['smtp_server'] = data.get('smtp_server', config.get('smtp_server', 'smtp.gmail.com'))
    config['smtp_port'] = data.get('smtp_port', config.get('smtp_port', 587))
    config['smtp_user'] = data.get('smtp_user', config.get('smtp_user', ''))
    
    if data.get('smtp_pass'):
        config['smtp_pass'] = data['smtp_pass']
    
    save_email_config(config)
    
    # Send immediate email if enabled
    if config.get('enabled') and config.get('email'):
        try:
            send_email_report()
            return jsonify({'success': True, 'message': f'Configuration saved. First report sent to {config["email"]}!'})
        except Exception as e:
            return jsonify({'success': True, 'message': f'Configuration saved, but email failed: {str(e)}'})
    
    return jsonify({'success': True, 'message': 'Email configuration saved'})

@app.route('/api/email/test', methods=['POST'])
def test_email():
    """Send a test email."""
    config = load_email_config()
    if not config.get('email'):
        return jsonify({'error': 'No email configured'}), 400
    
    try:
        send_email_report()
        return jsonify({'success': True, 'message': f'Test email sent to {config["email"]}'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============ MAIN ============

if __name__ == '__main__':
    print("""
    ╔═══════════════════════════════════════════════════╗
    ║                                                   ║
    ║   ███████╗ █████╗ ███████╗████████╗              ║
    ║   ██╔════╝██╔══██╗██╔════╝╚══██╔══╝              ║
    ║   █████╗  ███████║███████╗   ██║                 ║
    ║   ██╔══╝  ██╔══██║╚════██║   ██║                 ║
    ║   ██║     ██║  ██║███████║   ██║                 ║
    ║   ╚═╝     ╚═╝  ╚═╝╚══════╝   ╚═╝                 ║
    ║                                                   ║
    ║           R A T  -  Response & Analysis Tool      ║
    ║                                                   ║
    ║   Dashboard: http://localhost:5000                ║
    ║                                                   ║
    ╚═══════════════════════════════════════════════════╝
    """)
    
    # Start log generator
    generator.start()
    
    # Start email scheduler in background
    scheduler_thread = threading.Thread(target=run_scheduler, daemon=True)
    scheduler_thread.start()
    print("📧 Email scheduler started (hourly reports)")
    
    # Run Flask
    app.run(host='0.0.0.0', port=5000, debug=False)
