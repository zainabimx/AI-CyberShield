# Apply these changes to app.py.
# 1) Add import:
from src.security_core import extract_iocs, create_alert
# 2) Add session state:
if 'alerts' not in st.session_state: st.session_state.alerts=[]
def add_security_alert(source, threat_type, confidence, risk_score, indicators, summary):
    alert=create_alert(source=source, threat_type=threat_type, confidence=confidence,
                       risk_score=risk_score, indicators=indicators, summary=summary)
    st.session_state.alerts.append(alert); return alert
# 3) Add sidebar options:
# '🚨 SOC Alert Queue', '🔎 Incident Investigation'
# 4) After email prediction:
iocs=extract_iocs(email_text)
ioc_labels=[f'{k}: {len(v)}' for k,v in iocs.items() if v]
if prediction == 1:
    add_security_alert('Email Analyzer','Credential Phishing',confidence,int(confidence),
                       matched_words + ioc_labels,'ML phishing detection triggered a SOC alert.')
# 5) After URL score:
if score >= 50:
    add_security_alert('Domain Integrity Scanner','Phishing Website',score,int(score),reasons,
                       'Heuristic URL analysis identified a potentially malicious website.')
# 6) Add SOC Alert Queue page:
elif app_mode == '🚨 SOC Alert Queue':
    st.markdown('## 🚨 SOC Alert Queue')
    if st.session_state.alerts:
        df=pd.DataFrame(st.session_state.alerts)
        st.dataframe(df[['alert_id','timestamp','source','threat_type','severity','priority','confidence','risk_score','status']].iloc[::-1], use_container_width=True, hide_index=True)
        a,b,c,d=st.columns(4); a.metric('Total Alerts',len(df)); b.metric('Critical',int((df.severity=='CRITICAL').sum())); c.metric('High',int((df.severity=='HIGH').sum())); d.metric('Open',int((df.status=='OPEN').sum()))
    else: st.info('No SOC alerts yet. Run an email or URL analysis first.')
# 7) Add Incident Investigation page:
elif app_mode == '🔎 Incident Investigation':
    st.markdown('## 🔎 Incident Investigation')
    if not st.session_state.alerts: st.info('Generate a phishing or high-risk URL alert first.')
    else:
        choices={a['alert_id']:a for a in reversed(st.session_state.alerts)}
        selected=st.selectbox('Select Incident',list(choices)); incident=choices[selected]
        a,b,c,d=st.columns(4); a.metric('Severity',incident['severity']); b.metric('Priority',incident['priority']); c.metric('Risk Score',f"{incident['risk_score']}/100"); d.metric('Confidence',f"{incident['confidence']}%")
        st.write('**Source:**',incident['source']); st.write('**Threat Type:**',incident['threat_type']); st.write('**Summary:**',incident['summary'])
        st.markdown('### Indicators of Compromise'); st.write(incident['indicators'] or 'None recorded')
        st.markdown('### MITRE ATT&CK Mapping'); st.dataframe(pd.DataFrame(incident['mitre_techniques']),use_container_width=True,hide_index=True)
        statuses=['OPEN','INVESTIGATING','CONTAINED','RESOLVED','CLOSED']; new=st.selectbox('Update Incident Status',statuses,index=statuses.index(incident['status']))
        if st.button('Update Status'):
            incident['status']=new; st.success(f'{selected} updated to {new}.')
