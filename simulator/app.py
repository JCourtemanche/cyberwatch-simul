"""Cyberwatch API simulator — Flask entrypoint."""
import logging

from flask import Flask, jsonify

from config import Config
from routes.assets import assets_bp
from routes.compliance import compliance_bp
from routes.cves import cves_bp
from routes.declarative import declarative_v2_bp, declarative_v3_bp
from routes.ping import ping_bp
from routes.security_issues import security_issues_bp
from routes.sysadmin import sysadmin_bp


def create_app():
    app = Flask(__name__)

    logging.basicConfig(
        level=logging.INFO if Config.DEBUG else logging.WARNING,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    )
    logger = logging.getLogger(__name__)
    logger.info('Starting Cyberwatch API Simulator')

    app.register_blueprint(ping_bp)
    app.register_blueprint(cves_bp)
    app.register_blueprint(assets_bp)
    app.register_blueprint(sysadmin_bp)
    app.register_blueprint(compliance_bp)
    app.register_blueprint(security_issues_bp)
    app.register_blueprint(declarative_v2_bp)
    app.register_blueprint(declarative_v3_bp)

    @app.route('/health', methods=['GET'])
    def health():
        return jsonify({
            'status': 'healthy',
            'service': 'Cyberwatch API Simulator',
            'version': '1.0.0',
        }), 200

    @app.route('/', methods=['GET'])
    def root():
        return jsonify({
            'service': 'Cyberwatch API Simulator',
            'version': '1.0.0',
            'auth': 'HTTP Basic Auth (username=access_key, password=secret_key)',
            'endpoints': {
                'GET /api/v3/ping': 'Health & auth check',
                'GET /api/v3/vulnerabilities/cve_announcements': 'List CVEs (paginated, filterable)',
                'GET /api/v3/vulnerabilities/cve_announcements/<cve_code>': 'Fetch a CVE with servers/refs',
                'GET /api/v3/vulnerabilities/servers': 'List vulnerability assets (paginated, filterable)',
                'GET /api/v3/vulnerabilities/servers/<id>': 'Fetch a vulnerability asset (full)',
                'GET /api/v3/assets/servers': 'Sysadmin assets list',
                'GET /api/v3/assets/servers/<id>': 'Sysadmin asset detail',
                'GET /api/v3/compliance/assets': 'Compliance assets list',
                'GET /api/v3/compliance/servers/<id>': 'Compliance asset detail',
                'GET /api/v3/security_issues': 'List security issues',
                'GET /api/v3/security_issues/<id>': 'Fetch a security issue',
                'POST /api/v2/cbw_scans/scripts': 'Upload Declarative Data (airgap)',
                'GET /api/v3/servers/<id>/info': 'Read Declarative Data (plain text)',
                'GET /health': 'Health check',
            },
        }), 200

    @app.errorhandler(404)
    def not_found(_):
        return jsonify({'error': 'Endpoint not found'}), 404

    @app.errorhandler(500)
    def internal_error(error):
        logger.error(f'Internal server error: {error}')
        return jsonify({'error': 'Internal server error'}), 500

    return app


app = create_app()

if __name__ == '__main__':
    app.run(host=Config.HOST, port=Config.PORT, debug=Config.DEBUG)
