from src.security_core import extract_iocs, mitre_mapping, create_alert

def test_iocs():
    x=extract_iocs('bad@example.com https://login-example.com/a 192.168.1.10')
    assert x['domains']==['login-example.com']; assert x['ip_addresses']==['192.168.1.10']

def test_mitre():
    ids={x['id'] for x in mitre_mapping('Credential Phishing')}
    assert {'T1566','T1566.002'} <= ids

def test_alert():
    a=create_alert(source='Email Analyzer', threat_type='Credential Phishing', confidence=94.2, risk_score=90, indicators=['URL'], summary='Test')
    assert a['severity']=='CRITICAL' and a['priority']=='P1' and a['status']=='OPEN'
