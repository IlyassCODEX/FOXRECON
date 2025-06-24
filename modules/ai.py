import os
import json
from datetime import datetime
from flask import current_app
import logging

class FastSecurityAnalyst:
    def __init__(self):
        """Initialize with rule-based analysis only - no AI dependencies"""
        # Configure logger
        self.logger = logging.getLogger(__name__)
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)
        
        # Security patterns and risk scoring
        self.security_patterns = self._load_security_patterns()
        self.vulnerability_indicators = self._load_vulnerability_indicators()

    def _load_security_patterns(self):
        """Load security-focused subdomain patterns with risk scoring"""
        return {
            'critical': {
                'admin': ['admin', 'administrator', 'cpanel', 'whm', 'plesk', 'directadmin'],
                'database': ['db', 'database', 'mysql', 'phpmyadmin', 'adminer', 'mongodb', 'redis'],
                'backup': ['backup', 'bak', 'old', 'archive', 'dump'],
                'internal': ['internal', 'intranet', 'private', 'corp', 'employee']
            },
            'high': {
                'development': ['dev', 'devel', 'development', 'test', 'testing', 'qa', 'staging', 'stage'],
                'api': ['api', 'rest', 'graphql', 'service', 'webservice', 'ws'],
                'config': ['config', 'configuration', 'setup', 'install'],
                'auth': ['auth', 'authentication', 'login', 'sso', 'oauth', 'ldap']
            },
            'medium': {
                'mail': ['mail', 'email', 'smtp', 'imap', 'pop', 'webmail', 'exchange'],
                'monitoring': ['monitor', 'nagios', 'zabbix', 'grafana', 'kibana'],
                'file': ['files', 'upload', 'download', 'ftp', 'sftp'],
                'vpn': ['vpn', 'remote', 'access', 'gateway']
            },
            'info': {
                'cdn': ['cdn', 'static', 'assets', 'media', 'img', 'images'],
                'blog': ['blog', 'news', 'www', 'site'],
                'support': ['help', 'support', 'docs', 'documentation'],
                'social': ['social', 'community', 'forum']
            }
        }

    def _load_vulnerability_indicators(self):
        """Load vulnerability indicators and common attack patterns"""
        return {
            'admin_panels': {
                'patterns': ['admin', 'panel', 'control', 'manage', 'dashboard'],
                'risk_score': 50,
                'description': 'Administrative interfaces often have authentication bypasses'
            },
            'dev_environments': {
                'patterns': ['dev', 'test', 'beta', 'demo', 'sandbox'],
                'risk_score': 45,
                'description': 'Development environments may expose debug information'
            },
            'database_interfaces': {
                'patterns': ['phpmyadmin', 'adminer', 'mysql', 'db'],
                'risk_score': 60,
                'description': 'Database management interfaces are high-value targets'
            },
            'backup_systems': {
                'patterns': ['backup', 'bak', 'dump', 'archive'],
                'risk_score': 55,
                'description': 'Backup systems may contain sensitive data'
            },
            'api_endpoints': {
                'patterns': ['api', 'rest', 'graphql', 'service'],
                'risk_score': 40,
                'description': 'APIs vulnerable to IDOR, injection, and data exposure'
            }
        }

    def analyze_subdomains(self, domain, subdomains):
        """Fast rule-based analysis without AI dependencies"""
        try:
            analysis_data = self._prepare_analysis_data(domain, subdomains)
            
            # Generate insights using rule-based logic
            insights = self._generate_security_insights(domain, analysis_data)

            return {
                'summary': {
                    'total_subdomains': len(subdomains),
                    'active_subdomains': len([s for s in subdomains if s.get('http_status') or s.get('https_status')]),
                    'https_enabled': len([s for s in subdomains if s.get('https_status')]),
                    'analysis_timestamp': datetime.now().isoformat(),
                    'analysis_type': 'Rule-based Security Analysis'
                },
                'insights': insights,
                'risk_assessment': self._assess_security_risk(analysis_data),
                'attack_surface': self._analyze_attack_surface(analysis_data),
                'recommendations': self._generate_security_recommendations(domain, analysis_data),
                'high_value_targets': self._identify_security_targets(subdomains),
                'vulnerability_summary': self._generate_vulnerability_summary(analysis_data)
            }
        except Exception as e:
            self.logger.error(f"Analysis failed: {e}")
            return self._minimal_analysis(domain, subdomains)

    def _generate_security_insights(self, domain, analysis_data):
        """Generate security-focused insights using rule-based logic"""
        insights = []
        
        # Critical findings
        if analysis_data['categories']['critical']:
            critical_count = sum(len(v) for v in analysis_data['categories']['critical'].values())
            insights.append(f"🚨 CRITICAL: Found {critical_count} high-risk subdomains (admin panels, databases, internal systems)")
        
        # High-risk findings
        if analysis_data['categories']['high']:
            high_count = sum(len(v) for v in analysis_data['categories']['high'].values())
            insights.append(f"⚠️ HIGH RISK: Discovered {high_count} development/API endpoints requiring immediate testing")
        
        # HTTPS adoption analysis
        https_rate = analysis_data['https_adoption']
        if https_rate < 0.3:
            insights.append(f"🔓 SSL RISK: Very low HTTPS adoption ({https_rate:.1%}) - major security concern")
        elif https_rate < 0.7:
            insights.append(f"🔒 SSL WARNING: Moderate HTTPS adoption ({https_rate:.1%}) - some subdomains unencrypted")
        
        # Response code analysis for potential issues
        suspicious_codes = self._analyze_suspicious_responses(analysis_data['response_codes'])
        if suspicious_codes:
            insights.append(f"🔍 RESPONSE CODES: Found {len(suspicious_codes)} potentially interesting response patterns")
        
        # Attack surface assessment
        if analysis_data['active_subdomains'] > 50:
            insights.append(f"📊 LARGE SURFACE: {analysis_data['active_subdomains']} active subdomains create extensive attack surface")
        elif analysis_data['active_subdomains'] > 20:
            insights.append(f"📊 MODERATE SURFACE: {analysis_data['active_subdomains']} active subdomains provide good testing scope")
        
        # Specific vulnerability patterns
        vuln_patterns = self._detect_vulnerability_patterns(analysis_data)
        for pattern in vuln_patterns:
            insights.append(f"🎯 {pattern}")
        
        return insights[:8]  # Limit to most important insights

    def _detect_vulnerability_patterns(self, data):
        """Detect specific vulnerability patterns"""
        patterns = []
        
        if data['categories']['critical']['admin']:
            patterns.append(f"Admin panel exposure: {len(data['categories']['critical']['admin'])} administrative interfaces found")
        
        if data['categories']['critical']['database']:
            patterns.append(f"Database exposure: {len(data['categories']['critical']['database'])} database management systems detected")
        
        if data['categories']['high']['development']:
            patterns.append(f"Dev environment leak: {len(data['categories']['high']['development'])} development systems exposed")
        
        if data['categories']['critical']['backup']:
            patterns.append(f"Backup system exposure: {len(data['categories']['critical']['backup'])} backup systems accessible")
        
        return patterns

    def _prepare_analysis_data(self, domain, subdomains):
        """Prepare and categorize subdomain data for security analysis"""
        active_subdomains = [s for s in subdomains if s.get('http_status') or s.get('https_status')]
        
        # Initialize security-focused categories
        categories = {
            'critical': {'admin': [], 'database': [], 'backup': [], 'internal': []},
            'high': {'development': [], 'api': [], 'config': [], 'auth': []},
            'medium': {'mail': [], 'monitoring': [], 'file': [], 'vpn': []},
            'info': {'cdn': [], 'blog': [], 'support': [], 'social': []},
            'uncategorized': []
        }

        # Categorize subdomains based on security patterns
        for subdomain in active_subdomains:
            name = subdomain['subdomain'].lower()
            categorized = False
            
            for risk_level, risk_categories in self.security_patterns.items():
                for category, keywords in risk_categories.items():
                    if any(keyword in name for keyword in keywords):
                        categories[risk_level][category].append(subdomain)
                        categorized = True
                        break
                if categorized:
                    break
            
            if not categorized:
                categories['uncategorized'].append(subdomain)

        return {
            'domain': domain,
            'total_subdomains': len(subdomains),
            'active_subdomains': len(active_subdomains),
            'categories': categories,
            'https_adoption': len([s for s in active_subdomains if s.get('https_status')]) / max(len(active_subdomains), 1),
            'response_codes': self._analyze_response_codes(active_subdomains)
        }

    def _assess_security_risk(self, data):
        """Calculate security risk score using rule-based assessment"""
        score = 0
        risk_factors = []
        
        # Critical risk factors
        critical_total = sum(len(v) for v in data['categories']['critical'].values())
        if critical_total > 0:
            score += critical_total * 15
            risk_factors.append(f"Critical systems exposed: {critical_total}")
        
        # High risk factors
        high_total = sum(len(v) for v in data['categories']['high'].values())
        if high_total > 0:
            score += high_total * 10
            risk_factors.append(f"High-risk endpoints: {high_total}")
        
        # HTTPS adoption risk
        if data['https_adoption'] < 0.3:
            score += 25
            risk_factors.append(f"Very low HTTPS adoption: {data['https_adoption']:.1%}")
        elif data['https_adoption'] < 0.7:
            score += 15
            risk_factors.append(f"Moderate HTTPS adoption: {data['https_adoption']:.1%}")
        
        # Large attack surface
        if data['active_subdomains'] > 100:
            score += 20
            risk_factors.append(f"Very large attack surface: {data['active_subdomains']} subdomains")
        elif data['active_subdomains'] > 50:
            score += 10
            risk_factors.append(f"Large attack surface: {data['active_subdomains']} subdomains")
        
        # Suspicious response codes
        suspicious_responses = self._count_suspicious_responses(data['response_codes'])
        if suspicious_responses > 5:
            score += 12
            risk_factors.append(f"Multiple suspicious response codes: {suspicious_responses}")
        
        # Determine risk level
        if score >= 80:
            level = "Critical"
        elif score >= 50:
            level = "High"
        elif score >= 25:
            level = "Medium"
        else:
            level = "Low"
        
        return {
            'level': level,
            'score': min(score, 100),
            'factors': risk_factors,
            'critical_assets': critical_total,
            'total_risk_assets': critical_total + high_total
        }

    def _analyze_attack_surface(self, data):
        """Analyze potential attack vectors and entry points"""
        attack_vectors = []
        
        # Critical attack vectors
        for category, subdomains in data['categories']['critical'].items():
            if subdomains:
                attack_vectors.append({
                    'type': f'Critical - {category.title()}',
                    'count': len(subdomains),
                    'risk': 'Critical',
                    'description': self._get_attack_description(category, 'critical'),
                    'priority': 1
                })
        
        # High-risk attack vectors
        for category, subdomains in data['categories']['high'].items():
            if subdomains:
                attack_vectors.append({
                    'type': f'High Risk - {category.title()}',
                    'count': len(subdomains),
                    'risk': 'High',
                    'description': self._get_attack_description(category, 'high'),
                    'priority': 2
                })
        
        # Medium-risk attack vectors
        for category, subdomains in data['categories']['medium'].items():
            if subdomains:
                attack_vectors.append({
                    'type': f'Medium Risk - {category.title()}',
                    'count': len(subdomains),
                    'risk': 'Medium',
                    'description': self._get_attack_description(category, 'medium'),
                    'priority': 3
                })
        
        return {
            'total_vectors': len(attack_vectors),
            'vectors': sorted(attack_vectors, key=lambda x: x['priority']),
            'surface_size': data['active_subdomains'],
            'critical_entry_points': sum(len(v) for v in data['categories']['critical'].values())
        }

    def _get_attack_description(self, category, risk_level):
        """Get attack description for specific category and risk level"""
        descriptions = {
            'admin': 'Administrative interfaces - test for default credentials, auth bypass, privilege escalation',
            'database': 'Database management systems - SQL injection, credential attacks, data exposure',
            'backup': 'Backup systems - may contain sensitive data, configuration files, credentials',
            'internal': 'Internal systems - corporate access, employee data, business intelligence',
            'development': 'Development environments - debug info, source code, staging data exposure',
            'api': 'API endpoints - IDOR, injection attacks, rate limiting bypass, data leakage',
            'config': 'Configuration interfaces - system settings, credentials, infrastructure details',
            'auth': 'Authentication systems - SSO bypass, credential harvesting, session management',
            'mail': 'Email services - user enumeration, credential attacks, mail server exploitation',
            'monitoring': 'Monitoring systems - infrastructure details, performance data, alerts',
            'file': 'File services - directory traversal, file upload, sensitive document access',
            'vpn': 'VPN services - remote access exploitation, credential attacks'
        }
        return descriptions.get(category, 'Security testing recommended')

    def _generate_security_recommendations(self, domain, data):
        """Generate prioritized security testing recommendations"""
        recommendations = []
        
        # Critical priority recommendations
        critical_total = sum(len(v) for v in data['categories']['critical'].values())
        if critical_total > 0:
            recommendations.append({
                'priority': 'Critical',
                'category': 'Immediate Security Assessment',
                'action': f'Urgent testing required for {critical_total} critical systems (admin panels, databases, internal systems)',
                'tools': ['Burp Suite Professional', 'OWASP ZAP', 'SQLMap', 'Hydra'],
                'timeline': 'Within 24 hours',
                'count': critical_total
            })
        
        # High priority recommendations
        if data['categories']['critical']['admin']:
            recommendations.append({
                'priority': 'High',
                'category': 'Admin Panel Security',
                'action': 'Test administrative interfaces for authentication bypass, default credentials, and privilege escalation',
                'tools': ['Burp Suite', 'DirSearch', 'Hydra', 'Custom Scripts'],
                'timeline': 'Within 48 hours',
                'count': len(data['categories']['critical']['admin'])
            })
        
        if data['categories']['critical']['database']:
            recommendations.append({
                'priority': 'High',
                'category': 'Database Security',
                'action': 'Immediate testing of database interfaces for SQL injection and unauthorized access',
                'tools': ['SQLMap', 'Burp Suite', 'Manual Testing'],
                'timeline': 'Within 48 hours',
                'count': len(data['categories']['critical']['database'])
            })
        
        if data['categories']['high']['development']:
            recommendations.append({
                'priority': 'High',
                'category': 'Development Environment',
                'action': 'Check development systems for exposed source code, debug information, and configuration files',
                'tools': ['DirBuster', 'GitDumper', 'Google Dorking', 'Wayback Machine'],
                'timeline': 'Within 72 hours',
                'count': len(data['categories']['high']['development'])
            })
        
        # Medium priority recommendations
        if data['https_adoption'] < 0.7:
            recommendations.append({
                'priority': 'Medium',
                'category': 'SSL/TLS Security',
                'action': f'SSL/TLS assessment for {data["https_adoption"]:.1%} HTTPS adoption rate',
                'tools': ['SSLScan', 'TestSSL.sh', 'SSL Labs', 'Nmap SSL Scripts'],
                'timeline': 'Within 1 week',
                'count': f"{data['https_adoption']:.1%} adoption"
            })
        
        if data['categories']['high']['api']:
            recommendations.append({
                'priority': 'Medium',
                'category': 'API Security Testing',
                'action': 'Comprehensive API security assessment for identified endpoints',
                'tools': ['Postman', 'Burp Suite', 'FFUF', 'API Security Scanner'],
                'timeline': 'Within 1 week',
                'count': len(data['categories']['high']['api'])
            })
        
        return recommendations[:6]  # Limit to top 6 recommendations

    def _identify_security_targets(self, subdomains):
        """Identify high-value security testing targets"""
        security_targets = []
        
        # Enhanced scoring for security-focused assessment
        scoring_keywords = {
            # Critical targets (50+ points)
            'admin': 60, 'administrator': 65, 'cpanel': 70, 'whm': 65, 'plesk': 60,
            'phpmyadmin': 75, 'adminer': 70, 'mysql': 50, 'database': 55, 'db': 50,
            'backup': 55, 'internal': 60, 'intranet': 65, 'private': 55,
            
            # High-value targets (30-49 points)
            'dev': 45, 'devel': 40, 'development': 45, 'test': 35, 'testing': 40,
            'staging': 45, 'stage': 40, 'beta': 35, 'demo': 30,
            'api': 40, 'rest': 35, 'graphql': 45, 'service': 30,
            'config': 45, 'configuration': 50, 'setup': 40,
            
            # Medium targets (15-29 points)
            'mail': 25, 'webmail': 30, 'smtp': 20, 'auth': 35, 'login': 30,
            'monitor': 25, 'vpn': 30, 'remote': 25, 'ftp': 25
        }
        
        for subdomain in subdomains:
            # Only consider active subdomains
            if not (subdomain.get('http_status') or subdomain.get('https_status')):
                continue
            
            name = subdomain['subdomain'].lower()
            score = 0
            reasons = []
            risk_level = "Low"
            
            # Calculate base score from keywords
            for keyword, points in scoring_keywords.items():
                if keyword in name:
                    score += points
                    reasons.append(f"{keyword.title()} system")
            
            # Response code analysis for security relevance
            http_status = subdomain.get('http_status')
            https_status = subdomain.get('https_status')
            
            # High-value response codes
            if http_status == 401 or https_status == 401:
                score += 25
                reasons.append("Authentication required")
            elif http_status == 403 or https_status == 403:
                score += 20
                reasons.append("Access forbidden")
            elif http_status == 200 or https_status == 200:
                score += 10
                reasons.append("Accessible content")
            elif http_status in [500, 502, 503] or https_status in [500, 502, 503]:
                score += 15
                reasons.append("Server error (potential info disclosure)")
            
            # HTTPS bonus for secure testing
            if https_status:
                score += 5
            
            # Determine risk level based on score
            if score >= 60:
                risk_level = "Critical"
            elif score >= 40:
                risk_level = "High"
            elif score >= 25:
                risk_level = "Medium"
            
            # Only include meaningful targets
            if score >= 20:
                security_targets.append({
                    'subdomain': subdomain['subdomain'],
                    'security_score': score,
                    'risk_level': risk_level,
                    'reasons': reasons,
                    'ip': subdomain.get('ip', 'N/A'),
                    'title': subdomain.get('title', 'N/A'),
                    'https_status': https_status,
                    'http_status': http_status,
                    'testing_priority': self._calculate_testing_priority(score, reasons)
                })
        
        # Sort by security score (highest first) and return top 15
        return sorted(security_targets, key=lambda x: x['security_score'], reverse=True)[:15]

    def _calculate_testing_priority(self, score, reasons):
        """Calculate testing priority based on score and indicators"""
        if score >= 60:
            return "Immediate"
        elif score >= 40:
            return "High"
        elif score >= 25:
            return "Medium"
        else:
            return "Low"

    def _analyze_response_codes(self, subdomains):
        """Analyze HTTP response codes for security insights"""
        response_codes = {}
        
        for subdomain in subdomains:
            for status_type in ['http_status', 'https_status']:
                code = subdomain.get(status_type)
                if code:
                    response_codes[code] = response_codes.get(code, 0) + 1
        
        return response_codes

    def _analyze_suspicious_responses(self, response_codes):
        """Identify suspicious response code patterns"""
        suspicious = {}
        
        # Response codes that might indicate interesting content
        interesting_codes = {
            401: "Authentication required",
            403: "Forbidden access",
            500: "Internal server error",
            502: "Bad gateway",
            503: "Service unavailable"
        }
        
        for code, description in interesting_codes.items():
            if code in response_codes:
                suspicious[code] = {
                    'count': response_codes[code],
                    'description': description
                }
        
        return suspicious

    def _count_suspicious_responses(self, response_codes):
        """Count total suspicious responses"""
        suspicious_codes = [401, 403, 500, 502, 503]
        return sum(response_codes.get(code, 0) for code in suspicious_codes)

    def _generate_vulnerability_summary(self, data):
        """Generate a summary of potential vulnerabilities"""
        summary = {
            'critical_findings': [],
            'high_risk_findings': [],
            'recommendations_count': 0,
            'immediate_action_required': False
        }
        
        # Critical findings
        critical_total = sum(len(v) for v in data['categories']['critical'].values())
        if critical_total > 0:
            summary['critical_findings'].append(f"{critical_total} critical systems exposed")
            summary['immediate_action_required'] = True
        
        # High-risk findings
        high_total = sum(len(v) for v in data['categories']['high'].values())
        if high_total > 0:
            summary['high_risk_findings'].append(f"{high_total} high-risk endpoints identified")
        
        # HTTPS issues
        if data['https_adoption'] < 0.5:
            summary['high_risk_findings'].append(f"Poor HTTPS adoption ({data['https_adoption']:.1%})")
        
        summary['recommendations_count'] = len(self._generate_security_recommendations(data['domain'], data))
        
        return summary

    def _minimal_analysis(self, domain, subdomains):
        """Minimal analysis for fallback scenarios"""
        active_subdomains = [s for s in subdomains if s.get('http_status') or s.get('https_status')]
        
        return {
            'summary': {
                'total_subdomains': len(subdomains),
                'active_subdomains': len(active_subdomains),
                'https_enabled': len([s for s in subdomains if s.get('https_status')]),
                'analysis_timestamp': datetime.now().isoformat(),
                'analysis_type': 'Minimal Rule-based Analysis'
            },
            'insights': [
                f"Found {len(subdomains)} total subdomains for {domain}",
                f"Active subdomains: {len(active_subdomains)}",
                f"HTTPS enabled: {len([s for s in subdomains if s.get('https_status')])}",
                "Basic security analysis completed",
                "Full analysis may require additional processing"
            ],
            'risk_assessment': {
                'level': 'Unknown',
                'score': 0,
                'factors': ['Minimal analysis mode - manual review recommended']
            },
            'attack_surface': {
                'total_vectors': 0,
                'vectors': [],
                'surface_size': len(active_subdomains)
            },
            'recommendations': [{
                'priority': 'Medium',
                'category': 'Manual Review',
                'action': 'Perform manual security assessment of identified subdomains',
                'tools': ['Manual Testing', 'Burp Suite', 'OWASP ZAP'],
                'count': 'Fallback analysis'
            }],
            'high_value_targets': [],
            'vulnerability_summary': {
                'critical_findings': [],
                'high_risk_findings': [],
                'recommendations_count': 1,
                'immediate_action_required': False
            }
        }
