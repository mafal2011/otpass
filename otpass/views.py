from django.shortcuts import render, HttpResponse
from django.http import JsonResponse
from django.db import transaction
from django.views.decorators.csrf import csrf_exempt
from .models import *

import imapclient
from email.parser import Parser
import email.policy

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
import base64
import hashlib


EMAIL = GlobalVar.objects.get(var_nm='EMAIL').var_val
PASSWORD = GlobalVar.objects.get(var_nm='PASSWORD').var_val

# # with imapclient.IMAPClient('imap.gmail.com', ssl=True) as imap_obj:
imap_obj = imapclient.IMAPClient('imap.gmail.com', ssl=True)
imap_obj.login(EMAIL, PASSWORD)
# # imap_obj.logout() [주기적으로 로그아웃 해줘야함]
# # 'INBOX' 폴더를 선택합니다 
imap_obj.select_folder('INBOX', readonly=True)

# Create your views here.

def test_func(request):
    return HttpResponse("OK")

def req_otpass_pubkey(request):
    """
    퍼블릭키를 출력하는 api
    """
    if request.method == 'GET':
        keystore_inst = KeyStore.objects.get(name='default_key')
        pubkey = keystore_inst.pubkey
        return HttpResponse(pubkey)
    else:
        return HttpResponse("not support method")

@csrf_exempt
def req_otpass_mail(request):
    """otp가 전달된 메일을 값을 받음
    1. 요청 주요 데이터(이메일, 패스워드 등)들은 pubkey로 암호화
    2. 메일은 요청된 이메일을 검색하여 가장 최근에 받은 메일을 통으로 전달
    3. 전달된 메일은 클라이언트단에서 디코딩해서 사용해야함
    4. otp 인증 전 해당 함수를 통해서 데이터를 받고, 주기적으로 요청을 통해서 메일 내용이 변경 되었다면 가져오기
    """
    global EMAIL, PASSWORD, imap_obj
    # 0. GET User-Agent
    user_agent = request.headers.get('User-Agent', 'dgnit-version231018')
    
    # 1. GET ip
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]  # 프록시를 거쳤을 경우 여러 IP 주소 중 가장 왼쪽 IP를 선택
    else:
        ip = request.META.get('REMOTE_ADDR')  # 직접 연결된 경우 사용
    
    # 2. GET mail_idx
    mail_idx = request.POST.get('mail_idx', '')
    if mail_idx == '':
        mail_idx = 0
    
    # 3. GET ip
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]  # 프록시를 거쳤을 경우 여러 IP 주소 중 가장 왼쪽 IP를 선택
    else:
        ip = request.META.get('REMOTE_ADDR')  # 직접 연결된 경우 사용

    # 4. GET email --> 매칭되는거 없으면 FAILED 리턴
    try:
        requested_email = request.POST.get('email', 'none@nonemail.com')
        # 2-1. userpwd Instance 가져오기
        userpwd_inst = UserPwd.objects.get(email=requested_email)
    except:
        answer = '등록되지 않는 이메일이거나 비밀번호가 일치하지 않습니다.'
        with transaction.atomic():
            new_otp_request = RequestOtp(
                ipaddr=ip,
                email=requested_email,
                pwd='',
                mail_idx=mail_idx,
                answer=answer,
            )
            new_otp_request.save()
            
        response_DICT = {'result':'FAILED',
                        'answer':answer}
        return JsonResponse(response_DICT, json_dumps_params={'ensure_ascii': False})
    
    # 5. GET pwd & 복호화 디코딩 포함(DB에는 sha516적용된 상태로)
    pwd = request.POST.get('pwd', '')
    
    # 5-1. 키 인스턴스 생성
    keystore_inst = userpwd_inst.key_pair # 할당된 키페어
    prikey = keystore_inst.prikey
    prikey_inst = serialization.load_pem_private_key(
        prikey.encode('utf-8'),
        password=None,
        backend=default_backend()
    )
    # 5-2. 패스워드 디코딩(base64 --> rsa --> sha512해시화 된 암호)
    pwd = prikey_inst.decrypt(
        base64.b64decode(pwd),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    ).decode('utf-8')
    salted_pwd = pwd.encode() + userpwd_inst.salt # salt 적용
    pwd = hashlib.sha512(salted_pwd).hexdigest() 
    
    # 6. 데이터 유효성 검증 및 로그저장
    # ! <데이터 로그 저장 및 유효성 검증>
    a = 0
    if request.method != "POST":
        a += 1
        answer = '지원하지 않는 방식입니다.'
    # elif user_agent != 'dgnit-version231018': # 브라우저에서 접속 막기 & 라이센스처리 등을 위해서 활용
    #     a += 1
    #     answer = '라이센스가 없습니다.'
    elif pwd != userpwd_inst.pwd:
        a += 1
        answer = '등록되지 않는 이메일이거나 비밀번호가 일치하지 않습니다.'
    if a > 0: # 에러가 하나 있는 경우
        with transaction.atomic():
            new_otp_request = RequestOtp(
                ipaddr=ip,
                email=requested_email,
                pwd=pwd,
                mail_idx=mail_idx,
                answer=answer,
            )
            new_otp_request.save()
        response_DICT = {'result':'FAILED',
                        'answer':answer}
        return JsonResponse(response_DICT, json_dumps_params={'ensure_ascii': False})
    # ! </데이터 유효성 검증>
    
    # 7. 이메일 가져와서 answer 생성(세션이 만료되었으면 자동으로 다시 로그인해서 진행할 수 있도록)
    try:
        message_id = imap_obj.search(['FROM', requested_email])[-1] # 보낸 것을 확인해서 가장 최근에것 하나 들고오기
        raw_message = imap_obj.fetch([message_id], ['BODY[]', 'FLAGS'])
        mail_Str = raw_message[message_id][b'BODY[]'].decode('utf-8')
        parsed_mail = Parser(policy=email.policy.default).parsestr(mail_Str)
    except:
        del imap_obj
        imap_obj = imapclient.IMAPClient('imap.gmail.com', ssl=True)
        imap_obj.login(EMAIL, PASSWORD)
        imap_obj.select_folder('INBOX', readonly=True)
        message_id = imap_obj.search(['FROM', requested_email])[-1] # 보낸 것을 확인해서 가장 최근에것 하나 들고오기
        raw_message = imap_obj.fetch([message_id], ['BODY[]', 'FLAGS'])
        mail_Str = raw_message[message_id][b'BODY[]'].decode('utf-8')
        parsed_mail = Parser(policy=email.policy.default).parsestr(mail_Str)
        
    answer = 'no otp massage'
    for i, body in enumerate(parsed_mail.walk()):
        body_type = body["Content-Type"]
        if ("TEXT/PLAIN" in body_type.upper() and
            "UTF-8" in body_type.upper()):
            answer = body.get_content()
            break
                
    # 8. db에 저장하고 응답하기(정상완료)
    with transaction.atomic():
        new_otp_request = RequestOtp(
            ipaddr=ip,
            email=requested_email,
            pwd=pwd,
            mail_idx=mail_idx,
            answer=answer,
        )
        new_otp_request.save()
        
    response_DICT = {'result':'SUCCESS',
                     'answer':answer}
    return JsonResponse(response_DICT, json_dumps_params={'ensure_ascii': False})

def otp_requests_check_page(request):
    if request.method == "GET":
        return render(request, "otpass/otp_request_check.html")