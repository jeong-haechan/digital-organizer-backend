import os
import re
import requests
import traceback # traceback 추가
from flask import Flask, redirect, url_for, session, request, jsonify
from flask_cors import CORS
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from deep_translator import GoogleTranslator

app = Flask(__name__)
app.secret_key = 'digital_organizer_secret'
CORS(app, supports_credentials=True, origins=["https://digital-organizer-frontend.vercel.app"])

CLIENT_SECRETS_FILE = "credentials.json"
SCOPES = [
    'https://www.googleapis.com/auth/gmail.readonly',
    'https://www.googleapis.com/auth/userinfo.profile'
]
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

# 1. 포함할 키워드 (가입 시그널)
KEYWORDS = ['가입', '환영', 'welcome', 'verify', 'confirm', '인증', '구독', 'registration', 'account', 'created', 'started']

# 2. [강화됨] 제외할 키워드 (가입인 척하는 알림들)
EXCLUDE_KEYWORDS = [
    'password', 'reset', 'change', 'alert', 'security', 'code', # 보안 알림
    'login', 'sign-in', '로그인', '접속', # 로그인 알림
    'update', '업데이트', '변경', # 정보 변경
    'expires', 're-verify', '만료', '갱신', # 기간 만료
    'ready', '준비', 'receipt', 'invoice', 'payment', '결제', # 단순 알림
    'comment', 'reply', 'news', 'newsletter', 'digest' # 뉴스레터/댓글
]

def get_root_domain(domain):
    """서브도메인을 제거하고 메인 도메인만 추출 (예: mail.nexon.com -> nexon.com)"""
    parts = domain.split('.')
    # co.kr, go.kr 등 국가 도메인 처리 (뒤에서 3개 유지)
    if len(parts) >= 3 and parts[-2] in ['co', 'go', 'ac', 'ne', 'or', 're']:
        return '.'.join(parts[-3:])
    # 일반 도메인 처리 (뒤에서 2개 유지)
    elif len(parts) >= 2:
        return '.'.join(parts[-2:])
    return domain

def analyze_email_header(headers):
    subject = ""
    sender = ""
    date = ""
    
    for h in headers:
        if h['name'] == 'Subject':
            subject = h['value']
        if h['name'] == 'From':
            sender = h['value']
        if h['name'] == 'Date':
            date = h['value']

    # 키워드 필터링 (대소문자 무시)
    subject_lower = subject.lower()
    
    # 가입 키워드가 없으면 탈락
    if not any(k in subject_lower for k in KEYWORDS):
        return None
        
    # [핵심] 제외 키워드가 하나라도 있으면 탈락
    if any(e in subject_lower for e in EXCLUDE_KEYWORDS):
        return None

    # 이메일 추출
    match = re.search(r'<(.+?)>', sender)
    email_address = match.group(1) if match else sender.strip()
            
    # 도메인 추출 및 정규화
    try:
        raw_domain = email_address.split('@')[-1].lower()
        root_domain = get_root_domain(raw_domain) # 뿌리 도메인 추출
    except:
        raw_domain = "unknown"
        root_domain = "unknown"

    # 서비스 이름 추출
    service_name = sender.split('<')[0].strip().replace('"', '')
    if not service_name or '@' in service_name:
        service_name = root_domain

    # 구글/유튜브/개인메일 필터링
    if "google.com" in root_domain or "youtube.com" in root_domain or "gmail.com" in root_domain: 
         return None 

    try:
        year = re.search(r'\d{4}', date).group(0)
    except:
        year = "Unknown"

    return {
        "name": service_name, 
        "domain": raw_domain,
        "root_domain": root_domain, # 중복 제거용 키
        "year": year, 
        "subject": subject
    }

@app.route('/')
def index():
    return "Server Running (Optimized Filter)"

@app.route('/login')
def login():
    flow = Flow.from_client_secrets_file(CLIENT_SECRETS_FILE, scopes=SCOPES)
    flow.redirect_uri = url_for('callback', _external=True)
    authorization_url, state = flow.authorization_url(access_type='offline', include_granted_scopes='true')
    session['state'] = state
    return redirect(authorization_url)

@app.route('/callback')
def callback():
    state = session['state']
    flow = Flow.from_client_secrets_file(CLIENT_SECRETS_FILE, scopes=SCOPES, state=state)
    flow.redirect_uri = url_for('callback', _external=True)
    authorization_response = request.url
    flow.fetch_token(authorization_response=authorization_response)
    credentials = flow.credentials
    
    # 사용자 정보 가져오기
    userinfo_service = build('oauth2', 'v2', credentials=credentials)
    user_info = userinfo_service.userinfo().get().execute()
    
    session['credentials'] = {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes
    }
    session['user_info'] = {
        'name': user_info.get('name'),
        'picture': user_info.get('picture')
    }
    
    return redirect('https://digital-organizer-frontend.vercel.app?auth=success')

@app.route('/logout')
def logout():
    session.clear()
    return jsonify({"status": "success"})

@app.route('/scan_gmail')
def scan_gmail():
    if 'credentials' not in session:
        return jsonify({"error": "Login required"}), 401

    try:
        creds = Credentials(**session['credentials'])
        service = build('gmail', 'v1', credentials=creds)

        messages = []
        page_token = None
        # 쿼리도 강화 (제외 키워드 -word 문법 사용)
        query = 'subject:(가입 OR 환영 OR welcome OR verify OR 인증) -subject:(reset OR login OR alert OR code OR update OR 변경 OR 로그인)'
        
        for _ in range(5): 
            results = service.users().messages().list(
                userId='me', q=query, maxResults=200, pageToken=page_token
            ).execute()
            messages.extend(results.get('messages', []))
            page_token = results.get('nextPageToken')
            if not page_token: break

        found_services = []
        for msg in messages:
            try:
                txt = service.users().messages().get(userId='me', id=msg['id'], format='metadata').execute()
                headers = txt['payload'].get('headers')
                result = analyze_email_header(headers)
                if result:
                    found_services.append(result)
            except: continue

        # [핵심] 중복 제거 로직 (Root Domain 기준)
        # 딕셔너리를 사용하여 같은 뿌리 도메인은 하나만 남김
        unique_services_map = {}
        
        # 최신 메일이 먼저 오므로, 리스트를 뒤집어서(오래된 순) 넣으면 -> 최신 메일이 덮어씀 (최신 상태 반영)
        # 반대로 최초 가입일을 알고 싶다면 오래된 것을 유지해야 함.
        # 여기서는 "가장 명확한 이름"을 남기기 위해 단순히 도메인 기준으로 합치겠습니다.
        
        for service in found_services:
            key = service['root_domain'] # nvidia.com으로 통일됨
            
            if key not in unique_services_map:
                unique_services_map[key] = service
            else:
                # 이미 있는 서비스면, 연도가 더 오래된 것을 '가입 시점'으로 보존 (선택사항)
                # 여기서는 기존(먼저 발견된 최신 메일) 정보를 유지합니다.
                pass

        final_services = list(unique_services_map.values())

        # 차트 데이터
        year_stats = {}
        for s in final_services:
            y = s['year']
            year_stats[y] = year_stats.get(y, 0) + 1
        
        chart_data = [{"year": k, "count": v} for k, v in year_stats.items()]
        chart_data.sort(key=lambda x: x['year'])

        return jsonify({
            "total_count": len(final_services),
            "services": final_services,
            "chart_data": chart_data
        })

    except Exception as e:
        print(f"Error: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/check_breach', methods=['POST'])
def check_breach():
    """XposedOrNot API의 키 없는 'breach-analytics' 경로를 사용하여 실제 유출 사이트 목록을 가져옵니다."""
    
    email = request.json.get('email')
    
    if not email:
        return jsonify({"error": "이메일 주소를 입력해주세요."}), 400
    
    # [핵심 변경] 키가 필요 없는 breach-analytics 엔드포인트 사용
    XPOSED_API_URL = f"https://api.xposedornot.com/v1/breach-analytics?email={email}"
    
    headers = {
        'User-Agent': 'DigitalOrganizerProject - Final University Project (Contact: abcdabcd6169@gmail.com)',
    }

    try:
        response = requests.get(XPOSED_API_URL, headers=headers, timeout=15)

        # 429 Rate Limit, 401 Unauthorized 등 오류 처리
        response.raise_for_status() 

        # 응답 데이터 (JSON)
        data = response.json()
        
        # XposedOrNot 응답 구조 확인: data['results'] 리스트에 유출 정보가 담겨 있음
        exposed_breaches = data.get('ExposedBreaches')
        if exposed_breaches:
            breach_results = exposed_breaches.get('breaches_details', [])
        else:
            breach_results = []
        
        if not breach_results:
            # results 리스트가 비어있으면 안전함
            return jsonify({"status": "safe", "breaches": []})

        # 유출 정보 가공
        breaches_list = []
        for breach in breach_results:
            # 유출 항목 (DataClasses) 정리
            data_classes_str = breach.get('xposed_data', '')
            
            # 위험도 판단
            risk_level = 'Medium'
            if 'Passwords' in data_classes_str or 'Credit' in data_classes_str:
                risk_level = 'High'
            
            breaches_list.append({
                "site": breach.get('domain', 'Unknown Site'),
                "date": breach.get('xposed_date', 'Unknown Date'),
                "risk": risk_level,
                "details": breach.get('details', ''),
                "data_classes": data_classes_str.replace(';', ', '),
                "industry": breach.get('industry', 'N/A'),
                "records": breach.get('xposed_records', 0)
            })

        return jsonify({"status": "leaked", "breaches": breaches_list})

    except requests.exceptions.HTTPError as e:
        print(f"XPOSED HTTP Error: {e}")
        status_code = e.response.status_code
        if status_code == 429:
            error_msg = "요청 횟수 초과(Rate Limit). 잠시 후 다시 시도해주세요."
        elif status_code == 401:
            error_msg = "API 인증 오류. 유효한 이메일인지 확인해주세요."
        else:
            error_msg = f"API 요청 오류 ({status_code}). 서버 상태를 확인해주세요."
            
        return jsonify({"error": error_msg}), 500
    except requests.exceptions.RequestException as e:
        print(f"XPOSED Network Error: {e}")
        return jsonify({"error": f"네트워크 연결 오류: {str(e)}"}), 500
    except Exception as e:
        print(f"\n--- CRITICAL TRACEBACK START: Unhandled Error ---\n{e}")
        traceback.print_exc()
        return jsonify({"error": "처리 중 알 수 없는 내부 오류 발생"}), 500


@app.route('/api/check_login')
def check_login():
    if 'credentials' in session and 'user_info' in session:
        return jsonify({"logged_in": True, "name": session['user_info'].get('name')})
    else:
        return jsonify({"logged_in": False})


@app.route('/api/translate', methods=['POST'])
def translate_text():
    try:
        data = request.get_json()
        text_to_translate = data.get('text')

        if not text_to_translate:
            return jsonify({"error": "No text provided"}), 400

        translated = GoogleTranslator(source='en', target='ko').translate(text_to_translate)
        
        return jsonify({"translated_text": translated})
    except Exception as e:
        print(f"Translation Error: {e}")
        traceback.print_exc()
        return jsonify({"error": "Translation failed"}), 500


if __name__ == '__main__':
    app.run('localhost', 5000, debug=True)