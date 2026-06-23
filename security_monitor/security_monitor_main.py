# coding: utf-8
import glob
import ipaddress
import json
import os
import re
import shutil
import sqlite3
import subprocess
import time
from datetime import datetime

PLUGIN_NAME = 'security_monitor'
PLUGIN_PATH = os.path.dirname(os.path.abspath(__file__))
DATA_PATH = os.path.join(PLUGIN_PATH, 'data')
DB_PATH = os.path.join(DATA_PATH, 'security_monitor.db')
RULES_PATH = os.path.join(DATA_PATH, 'rules.json')
SETTINGS_PATH = os.path.join(DATA_PATH, 'settings.json')

DEFAULT_SETTINGS = {
    'log_paths': ['/www/wwwlogs/*.log'],
    'enabled': True,
    'dry_run': True,
    'auto_ban': False,
    'default_ban_seconds': 3600,
    'scan_limit_lines': 5000,
    'waf_enabled': False,
    'whitelist_ips': ['127.0.0.1', '::1'],
    'whitelist_paths': [],
    'whitelist_user_agents': [],
    'private_ip_whitelist': True,
    'firewall_backend': 'auto'
}

NGINX_COMBINED = re.compile(r'^(?P<ip>\S+)\s+-\s+(?P<user>\S+)\s+\[(?P<time>[^\]]+)\]\s+"(?P<method>\S+)\s+(?P<uri>\S+)\s+(?P<proto>[^"]+)"\s+(?P<status>\d{3})\s+(?P<size>\S+)\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)"')

class security_monitor_main:
    def __init__(self):
        ensure_dirs()
        init_db()
        seed_rules()
        seed_settings()

    def get_overview(self, args=None):
        conn = db()
        now = int(time.time())
        total = conn.execute('select count(*) from events').fetchone()[0]
        recent = conn.execute('select count(*) from events where ts > ?', (now - 86400,)).fetchone()[0]
        banned = conn.execute('select count(*) from bans where active=1 and (expires_at=0 or expires_at>?)', (now,)).fetchone()[0]
        top_ips = query_dicts(conn, 'select ip,count(*) as count,max(ts) as last_seen from events group by ip order by count desc limit 10')
        risks = query_dicts(conn, 'select severity,count(*) as count from events group by severity order by count desc')
        return ok({'total_events': total, 'events_24h': recent, 'active_bans': banned, 'top_ips': top_ips, 'risks': risks})

    def get_events(self, args=None):
        limit = int(getattr(args, 'limit', 100) if args else 100)
        conn = db()
        rows = query_dicts(conn, 'select * from events order by ts desc limit ?', (limit,))
        return ok(rows)

    def get_rules(self, args=None):
        return ok(load_rules())

    def save_rules(self, args):
        rules = json.loads(args.rules) if isinstance(args.rules, str) else args.rules
        save_json(RULES_PATH, rules)
        return ok(True)

    def get_settings(self, args=None):
        return ok(load_settings())

    def save_settings(self, args):
        settings = load_settings()
        data = json.loads(args.settings) if isinstance(args.settings, str) else args.settings
        settings.update(data)
        save_json(SETTINGS_PATH, settings)
        return ok(settings)

    def scan(self, args=None):
        settings = load_settings()
        if not settings.get('enabled', True):
            return ok({'scanned': 0, 'matched': 0, 'banned': 0})
        rules = compile_rules(load_rules())
        conn = db()
        scanned = matched = banned = 0
        for path in expand_logs(settings.get('log_paths', [])):
            for line in read_new_lines(conn, path, int(settings.get('scan_limit_lines', 5000))):
                scanned += 1
                event = parse_log_line(line, path)
                if not event or is_whitelisted(event, settings):
                    continue
                hits = match_rules(event, rules)
                for rule in hits:
                    matched += 1
                    save_event(conn, event, rule)
                    if should_ban(conn, event['ip'], rule):
                        result = ban_ip(event['ip'], rule['id'], rule.get('ban_seconds', settings.get('default_ban_seconds', 3600)), settings)
                        if result.get('success'):
                            banned += 1
        unban_expired(settings)
        return ok({'scanned': scanned, 'matched': matched, 'banned': banned, 'dry_run': settings.get('dry_run', True)})

    def get_bans(self, args=None):
        conn = db()
        return ok(query_dicts(conn, 'select * from bans order by created_at desc limit 200'))

    def ban(self, args):
        settings = load_settings()
        seconds = int(getattr(args, 'seconds', settings.get('default_ban_seconds', 3600)))
        return ok(ban_ip(args.ip, getattr(args, 'reason', 'manual'), seconds, settings))

    def unban(self, args):
        settings = load_settings()
        return ok(unban_ip(args.ip, settings))

    def generate_waf(self, args=None):
        path = os.path.join(DATA_PATH, 'nginx-security-monitor.conf')
        content = build_nginx_waf(load_rules())
        with open(path, 'w') as f:
            f.write(content)
        return ok({'path': path})

    def export_config(self, args=None):
        return ok({'settings': load_settings(), 'rules': load_rules()})

    def export_report(self, args=None):
        conn = db()
        now = int(time.time())
        report = {
            'generated_at': datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'),
            'settings': load_settings(),
            'summary': {
                'total_events': conn.execute('select count(*) from events').fetchone()[0],
                'events_24h': conn.execute('select count(*) from events where ts > ?', (now - 86400,)).fetchone()[0],
                'active_bans': conn.execute('select count(*) from bans where active=1 and (expires_at=0 or expires_at>?)', (now,)).fetchone()[0]
            },
            'risks': query_dicts(conn, 'select severity,count(*) as count from events group by severity order by count desc'),
            'top_ips': query_dicts(conn, 'select ip,count(*) as count,max(ts) as last_seen from events group by ip order by count desc limit 20'),
            'recent_events': query_dicts(conn, 'select * from events order by ts desc limit 200'),
            'bans': query_dicts(conn, 'select * from bans order by created_at desc limit 200')
        }
        conn.close()
        path = os.path.join(DATA_PATH, 'security-monitor-report-%s.json' % datetime.utcnow().strftime('%Y%m%d-%H%M%S'))
        with open(path, 'w') as f:
            json.dump(report, f, indent=2, sort_keys=True)
        report['path'] = path
        return ok(report)

    def import_config(self, args):
        data = json.loads(args.config) if isinstance(args.config, str) else args.config
        if 'settings' in data:
            save_json(SETTINGS_PATH, data['settings'])
        if 'rules' in data:
            save_json(RULES_PATH, data['rules'])
        return ok(True)

    def reset_rules(self, args=None):
        save_json(RULES_PATH, default_rules())
        return ok(load_rules())

    def test_match(self, args):
        uri = getattr(args, 'uri', '/')
        ua = getattr(args, 'user_agent', 'test')
        event = {'uri': uri, 'user_agent': ua}
        hits = match_rules(event, compile_rules(load_rules()))
        for hit in hits:
            hit.pop('_regex', None)
        return ok(hits)

def ensure_dirs():
    if not os.path.isdir(DATA_PATH):
        os.makedirs(DATA_PATH)

def db():
    return sqlite3.connect(DB_PATH)

def init_db():
    conn = db()
    conn.execute('create table if not exists events (id integer primary key autoincrement, ts integer, ip text, domain text, method text, uri text, status integer, user_agent text, rule_id text, rule_name text, category text, severity text, source_log text)')
    conn.execute('create table if not exists bans (id integer primary key autoincrement, ip text, reason text, backend text, created_at integer, expires_at integer, active integer, dry_run integer)')
    conn.execute('create table if not exists log_offsets (path text primary key, inode integer, offset integer)')
    conn.commit()
    conn.close()

def seed_settings():
    if not os.path.exists(SETTINGS_PATH):
        save_json(SETTINGS_PATH, DEFAULT_SETTINGS)

def seed_rules():
    if os.path.exists(RULES_PATH):
        return
    save_json(RULES_PATH, default_rules())

def default_rules():
    return [
        rule('dotfiles', 'Dotfile and secret file probe', 'secrets', 'high', r'(?i)(^|/)\.(env|git|svn|hg|bzr|htaccess|htpasswd|npmrc|netrc|pypirc|DS_Store)(/|$|[.?\s])', 2, 600, 3600),
        rule('cloud-secrets', 'Cloud credential probe', 'secrets', 'critical', r'(?i)(\.aws/(credentials|config)|\.kube/(config|token)|terraform\.tfstate|service-account.*\.json|private.*\.(pem|key)|fullchain\.pem)', 1, 600, 86400),
        rule('wp-sensitive', 'WordPress sensitive path probe', 'cms', 'medium', r'(?i)(wp-config\.php|xmlrpc\.php|wp-content/(backup|backups|debug\.log)|wp-json/wp/v2/users|readme\.html|license\.txt)', 5, 600, 3600),
        rule('admin-panels', 'Admin panel scanner', 'scanner', 'medium', r'(?i)(^|/)(phpmyadmin|phpMyAdmin|pma|myadmin|mysqladmin|adminer|administrator|adminpanel|admincp|manager/html|cpanel|whm)(/|$|[.?])', 5, 600, 3600),
        rule('backup-files', 'Backup or database dump probe', 'leak', 'high', r'(?i)(backup|dump|database|db|www|html|site|web|archive).*(\.(sql|zip|tar|tar\.gz|tgz|gz|rar|7z|bz2))($|[?])|\.(bak|old|orig|save|backup|swp|swo|tmp)($|[?])', 2, 600, 7200),
        rule('config-files', 'Config file probe', 'leak', 'high', r'(?i)(^|/)(config|configuration|settings|localconfig|database|db|appsettings|parameters|connection|dbconfig|bootstrap|constants|init|common)\.(php|inc|json|ya?ml|xml|ini|cfg|properties|groovy)($|[?])|web\.config', 2, 600, 7200),
        rule('traversal-lfi', 'Traversal or local file inclusion', 'lfi', 'critical', r'(?i)(\.\./|\.\.%2f|%2e%2e|%252e%252e|/etc/(passwd|shadow|hosts|fstab)|/proc/self/(environ|cmdline|fd)|php://|file://|expect://|data://)', 1, 600, 86400),
        rule('webshell', 'Webshell or upload probe', 'rce', 'critical', r'(?i)(c99|r57|wso|b374k|indoxploit|phpspy|webshell|shell|cmd|exec|uploadshell|eval-stdin)\.php|vendor/phpunit/.*/eval-stdin\.php', 1, 600, 86400),
        rule('rce-params', 'RCE parameter probe', 'rce', 'critical', r'(?i)([?&](cmd|exec|command|system|shell|passthru|proc_open|popen)=|base64_decode|eval\(|assert\(|Runtime\.getRuntime|jndi:(ldap|rmi|dns))', 1, 600, 86400),
        rule('sqli', 'SQL injection probe', 'sqli', 'high', r'(?i)(union(\+|%20|\s)+select|information_schema|sleep\s*\(|benchmark\s*\(|or(\+|%20|\s)+1=1|waitfor(\+|%20|\s)+delay|extractvalue\s*\(|updatexml\s*\()', 2, 600, 7200),
        rule('xss', 'XSS payload probe', 'xss', 'high', r'(?i)(<script|%3cscript|javascript:|onerror\s*=|onload\s*=|document\.cookie|alert\s*\(|<svg|%3csvg|<iframe|%3ciframe)', 2, 600, 7200),
        rule('framework-debug', 'Framework debug endpoint probe', 'framework', 'high', r'(?i)(_profiler|_wdt|_ignition|actuator/(env|heapdump|shutdown|loggers)|jolokia|__debug__|elmah\.axd|WEB-INF|META-INF|app/etc/local\.xml)', 2, 600, 7200),
        rule('api-docs', 'API documentation probe', 'api', 'low', r'(?i)(swagger\.json|swagger-ui|swagger-resources|api-docs|openapi\.(json|ya?ml)|graphql|graphiql)', 20, 600, 1800),
        rule('bad-bot', 'Bad bot or generic scanner pattern', 'scanner', 'medium', r'(?i)(nikto|sqlmap|acunetix|nessus|nmap|masscan|zgrab|dirbuster|gobuster|wpscan|whatweb|python-requests|curl/|wget/)', 10, 600, 3600)
    ]

def rule(id, name, category, severity, pattern, threshold, window, ban_seconds):
    return {'id': id, 'name': name, 'category': category, 'severity': severity, 'pattern': pattern, 'threshold': threshold, 'window_seconds': window, 'ban_seconds': ban_seconds, 'enabled': True}

def load_settings():
    return load_json(SETTINGS_PATH, DEFAULT_SETTINGS)

def load_rules():
    return load_json(RULES_PATH, [])

def load_json(path, default):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return default

def save_json(path, data):
    with open(path, 'w') as f:
        json.dump(data, f, indent=2, sort_keys=True)

def compile_rules(rules):
    out = []
    for item in rules:
        if item.get('enabled', True):
            item = dict(item)
            item['_regex'] = re.compile(item['pattern'])
            out.append(item)
    return out

def expand_logs(patterns):
    paths = []
    for pattern in patterns:
        paths.extend(glob.glob(pattern))
    return sorted(set(paths))

def read_new_lines(conn, path, limit):
    try:
        stat = os.stat(path)
        row = conn.execute('select inode, offset from log_offsets where path=?', (path,)).fetchone()
        offset = row[1] if row and row[0] == stat.st_ino and row[1] <= stat.st_size else 0
        with open(path, 'r', errors='ignore') as f:
            f.seek(offset)
            lines = f.readlines()[-limit:]
            new_offset = f.tell()
        conn.execute('insert or replace into log_offsets(path,inode,offset) values(?,?,?)', (path, stat.st_ino, new_offset))
        conn.commit()
        return lines
    except Exception:
        return []

def parse_log_line(line, source_log):
    m = NGINX_COMBINED.match(line)
    if not m:
        return None
    d = m.groupdict()
    return {'ts': int(time.time()), 'ip': d['ip'], 'domain': os.path.basename(source_log).replace('.log', ''), 'method': d['method'], 'uri': d['uri'], 'status': int(d['status']), 'user_agent': d['ua'], 'source_log': source_log, 'raw': line}

def is_whitelisted(event, settings):
    ip = event['ip']
    try:
        addr = ipaddress.ip_address(ip)
        if settings.get('private_ip_whitelist', True) and (addr.is_private or addr.is_loopback):
            return True
    except Exception:
        pass
    if ip in settings.get('whitelist_ips', []):
        return True
    if any(event['uri'].startswith(p) for p in settings.get('whitelist_paths', [])):
        return True
    user_agent = event.get('user_agent', '').lower()
    return any(pattern.lower() in user_agent for pattern in settings.get('whitelist_user_agents', []) if pattern)

def match_rules(event, rules):
    target = event['uri'] + ' ' + event.get('user_agent', '')
    return [r for r in rules if r['_regex'].search(target)]

def save_event(conn, event, rule):
    conn.execute('insert into events(ts,ip,domain,method,uri,status,user_agent,rule_id,rule_name,category,severity,source_log) values(?,?,?,?,?,?,?,?,?,?,?,?)', (event['ts'], event['ip'], event['domain'], event['method'], event['uri'], event['status'], event['user_agent'], rule['id'], rule['name'], rule['category'], rule['severity'], event['source_log']))
    conn.commit()

def should_ban(conn, ip, rule):
    since = int(time.time()) - int(rule.get('window_seconds', 600))
    count = conn.execute('select count(*) from events where ip=? and rule_id=? and ts>?', (ip, rule['id'], since)).fetchone()[0]
    return count >= int(rule.get('threshold', 1))

def ban_ip(ip, reason, seconds, settings):
    now = int(time.time())
    conn = db()
    row = conn.execute('select * from bans where ip=? and active=1 and (expires_at=0 or expires_at>?) order by created_at desc limit 1', (ip, now)).fetchone()
    if row:
        conn.close()
        return {'success': True, 'ip': ip, 'skipped': True, 'output': 'already active'}
    expires = 0 if int(seconds) <= 0 else now + int(seconds)
    backend = detect_backend(settings.get('firewall_backend', 'auto'))
    dry = bool(settings.get('dry_run', True) or not settings.get('auto_ban', False))
    success = True
    output = 'dry-run'
    if not dry:
        success, output = firewall_ban(ip, backend)
    conn.execute('insert into bans(ip,reason,backend,created_at,expires_at,active,dry_run) values(?,?,?,?,?,?,?)', (ip, reason, backend, now, expires, 1 if success else 0, 1 if dry else 0))
    conn.commit()
    conn.close()
    return {'success': success, 'ip': ip, 'backend': backend, 'expires_at': expires, 'dry_run': dry, 'output': output}

def unban_expired(settings):
    conn = db()
    now = int(time.time())
    rows = query_dicts(conn, 'select * from bans where active=1 and expires_at>0 and expires_at<=?', (now,))
    conn.close()
    for row in rows:
        unban_ip(row['ip'], settings)

def unban_ip(ip, settings):
    backend = detect_backend(settings.get('firewall_backend', 'auto'))
    dry = bool(settings.get('dry_run', True) or not settings.get('auto_ban', False))
    success = True
    output = 'dry-run'
    if not dry:
        success, output = firewall_unban(ip, backend)
    conn = db()
    conn.execute('update bans set active=0 where ip=?', (ip,))
    conn.commit()
    conn.close()
    return {'success': success, 'ip': ip, 'backend': backend, 'dry_run': dry, 'output': output}

def detect_backend(value):
    if value and value != 'auto':
        return value
    if shutil.which('ufw'):
        return 'ufw'
    if shutil.which('firewall-cmd'):
        return 'firewalld'
    if shutil.which('iptables'):
        return 'iptables'
    return 'none'

def run(cmd):
    try:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = p.communicate(timeout=20)
        return p.returncode == 0, (out + err).decode(errors='ignore')
    except Exception as e:
        return False, str(e)

def firewall_ban(ip, backend):
    if backend == 'ufw':
        return run(['ufw', 'deny', 'from', ip, 'to', 'any'])
    if backend == 'firewalld':
        return run(['firewall-cmd', '--permanent', '--add-rich-rule=rule family="ipv4" source address="%s" drop' % ip])
    if backend == 'iptables':
        return run(['iptables', '-I', 'INPUT', '-s', ip, '-j', 'DROP'])
    return False, 'no firewall backend'

def firewall_unban(ip, backend):
    if backend == 'ufw':
        return run(['ufw', 'delete', 'deny', 'from', ip, 'to', 'any'])
    if backend == 'firewalld':
        return run(['firewall-cmd', '--permanent', '--remove-rich-rule=rule family="ipv4" source address="%s" drop' % ip])
    if backend == 'iptables':
        return run(['iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'])
    return False, 'no firewall backend'

def build_nginx_waf(rules):
    return '''# generated by security_monitor\nlocation ~* /(\\.env|\\.git|\\.svn|\\.hg|\\.bzr|\\.htaccess|\\.htpasswd) { return 403; }\nlocation ~* \\.(sql|bak|old|orig|save|backup|swp|swo|tmp)(\\?|$) { return 403; }\nlocation ~* /(wp-config\\.php|composer\\.(json|lock)|package(-lock)?\\.json|web\\.config) { return 403; }\nif ($request_uri ~* "(\\.\\./|%2e%2e|/etc/passwd|php://|file://|expect://|data://)") { return 403; }\n'''

def query_dicts(conn, sql, params=()):
    cur = conn.execute(sql, params)
    cols = [c[0] for c in cur.description]
    return [dict(zip(cols, row)) for row in cur.fetchall()]

def ok(data):
    return {'status': True, 'msg': data}

if __name__ == '__main__':
    print(json.dumps(security_monitor_main().scan(), indent=2))
