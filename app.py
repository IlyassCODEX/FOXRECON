from flask import Flask, render_template, request, jsonify, session
import uuid
import threading
import time
from datetime import datetime
from modules.subdomains import SubdomainEnumerator
from modules.ai import FastSecurityAnalyst  # Updated import
from utils.reporting import ReportGenerator
from utils.helpers import validate_domain, sanitize_domain
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)

scan_results = {}
scan_status = {}

@app.context_processor
def inject_now():
    return {'now': datetime.now}

@app.route('/')
def index():
    return render_template('scan.html')

@app.route('/start_scan', methods=['POST'])
def start_scan():
    data = request.get_json()
    domain = data.get('domain', '').strip()
    
    if not validate_domain(domain):
        return jsonify({'error': 'Invalid domain format'}), 400
    
    domain = sanitize_domain(domain)
    scan_id = str(uuid.uuid4())
    
    # Initialize scan status
    scan_status[scan_id] = {
        'status': 'running',
        'progress': 0,
        'current_task': 'Initializing scan...',
        'start_time': datetime.now(),
        'domain': domain
    }
    
    # Initialize results
    scan_results[scan_id] = {
        'domain': domain,
        'subdomains': [],
        'security_analysis': {},  # Updated key name for clarity
        'scan_id': scan_id,
        'timestamp': datetime.now().isoformat()
    }
    
    # Start background scan
    thread = threading.Thread(target=run_scan, args=(scan_id, domain))
    thread.daemon = True
    thread.start()
    
    return jsonify({'scan_id': scan_id})

def run_scan(scan_id, domain):
    try:
        # Create application context for the background thread
        with app.app_context():
            # Update status
            scan_status[scan_id]['current_task'] = 'Enumerating subdomains...'
            scan_status[scan_id]['progress'] = 10
            
            # Run subdomain enumeration
            subdomain_enum = SubdomainEnumerator()
            subdomains = subdomain_enum.enumerate(domain)
            
            scan_results[scan_id]['subdomains'] = subdomains
            scan_status[scan_id]['progress'] = 60
            scan_status[scan_id]['current_task'] = 'Running security analysis...'  # Updated message
            
            # Run security analysis (much faster than AI)
            security_analyst = FastSecurityAnalyst()  # Updated class name
            security_analysis = security_analyst.analyze_subdomains(domain, subdomains)
            
            scan_results[scan_id]['security_analysis'] = security_analysis  # Updated key
            # Also keep the old key for backward compatibility with templates
            scan_results[scan_id]['ai_analysis'] = security_analysis
            
            scan_status[scan_id]['progress'] = 100
            scan_status[scan_id]['status'] = 'completed'
            scan_status[scan_id]['current_task'] = 'Security analysis completed'
            scan_status[scan_id]['end_time'] = datetime.now()
            
    except Exception as e:
        scan_status[scan_id]['status'] = 'error'
        scan_status[scan_id]['error'] = str(e)
        scan_status[scan_id]['progress'] = 0
        print(f"Scan error for {scan_id}: {e}")  # Add logging for debugging

@app.route('/scan_status/<scan_id>')
def get_scan_status(scan_id):
    if scan_id not in scan_status:
        return jsonify({'error': 'Scan not found'}), 404
    
    status = scan_status[scan_id].copy()
    
    # Convert datetime objects to strings
    if 'start_time' in status:
        status['start_time'] = status['start_time'].isoformat()
    if 'end_time' in status:
        status['end_time'] = status['end_time'].isoformat()
    
    return jsonify(status)

@app.route('/results/<scan_id>')
def get_results(scan_id):
    if scan_id not in scan_results:
        return jsonify({'error': 'Results not found'}), 404
    
    return render_template('results.html', 
                         results=scan_results[scan_id], 
                         scan_id=scan_id)

@app.route('/api/results/<scan_id>')
def api_results(scan_id):
    if scan_id not in scan_results:
        return jsonify({'error': 'Results not found'}), 404
    
    return jsonify(scan_results[scan_id])

@app.route('/export/<scan_id>')
def export_results(scan_id):
    if scan_id not in scan_results:
        return jsonify({'error': 'Results not found'}), 404
    
    format_type = request.args.get('format', 'json')
    
    report_gen = ReportGenerator()
    
    if format_type == 'pdf':
        pdf_content = report_gen.generate_pdf(scan_results[scan_id])
        return pdf_content, 200, {
            'Content-Type': 'application/pdf',
            'Content-Disposition': f'attachment; filename=security_report_{scan_id}.pdf'
        }
    else:
        json_content = report_gen.generate_json(scan_results[scan_id])
        return json_content, 200, {
            'Content-Type': 'application/json',
            'Content-Disposition': f'attachment; filename=security_report_{scan_id}.json'
        }

# Optional: Add a health check endpoint
@app.route('/health')
def health_check():
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'analysis_type': 'Fast Rule-based Security Analysis'
    })

# Optional: Add endpoint to get analysis capabilities
@app.route('/api/capabilities')
def get_capabilities():
    return jsonify({
        'analysis_type': 'Rule-based Security Analysis',
        'features': [
            'Fast subdomain analysis',
            'Security risk assessment',
            'Attack surface mapping',
            'Vulnerability categorization',
            'Testing recommendations',
            'High-value target identification'
        ],
        'no_dependencies': True,
        'instant_results': True
    })

if __name__ == '__main__':
    print("🌐 Server: http://127.0.0.1:5000")
    print("-" * 50)
    
    app.run(debug=True, host='127.0.0.1', port=5000)