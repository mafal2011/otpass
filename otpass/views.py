from django.shortcuts import render, HttpResponse
from django.http import JsonResponse
from django.db import transaction
from .models import *

import imapclient
from email.parser import Parser
import email.policy

EMAIL = 'mafal201121@gmail.com' 
PASSWORD = 'goyqgwyjnmprnigo'

# Create your views here.

def test_func(request):
    return HttpResponse("OK")

def req_otpass_pubkey(request):
    return HttpResponse("req_pubkey")

def req_otpass_mail(request):
    """otp가 전달된 메일을 값을 받음
    1. 요청 주요 데이터(이메일, 패스워드 등)들은 pubkey로 암호화
    2. 메일은 요청된 이메일을 검색하여 가장 최근에 받은 메일을 통으로 전달
    3. 전달된 메일은 클라이언트단에서 디코딩해서 사용해야함
    4. otp 인증 전 해당 함수를 통해서 데이터를 받고, 주기적으로 요청을 통해서 메일 내용이 변경 되었다면 가져오기
    """
    #! 일단은 암호화시키지않고 진행
    if request.method != "POST":
        return HttpResponse('wow!')
    # 1. GET ip
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]  # 프록시를 거쳤을 경우 여러 IP 주소 중 가장 왼쪽 IP를 선택
    else:
        ip = request.META.get('REMOTE_ADDR')  # 직접 연결된 경우 사용
    print(f"ip주소: {ip}")
    
    # 2. GET email(추후 디코딩 포함)
    requested_email = request.POST['email']
    print(f'requested_email: {requested_email}')
    
    # 3. GET pwd(추후 디코딩 포함)
    pwd = request.POST['pwd']
    mail_idx = request.POST['mail_idx']
    if mail_idx == '':
        mail_idx = 0
    print(f"pwd: {pwd} {type(pwd)} {pwd == ''}")
    print(f"mail_idx: {mail_idx}")
    
    # 4. 해당 이메일에 대해서 pwd가 매칭이 되는지 확인 후 다음단계
    # 4. 일정시간동안 여러번 오류가 발생했다면 해당 계정에 대해서 잠금 진행
    
    
    # 5. 이메일 가져와서 answer 생성
    # IMAP 서버에 연결하고 로그인합니다
    with imapclient.IMAPClient('imap.gmail.com', ssl=True) as imap_obj:
        # imap_obj = imapclient.IMAPClient('imap.gmail.com', ssl=True)
        imap_obj.login(EMAIL, PASSWORD)
        # 'INBOX' 폴더를 선택합니다 
        imap_obj.select_folder('INBOX', readonly=True)
        message_id = imap_obj.search(['FROM', 'mafal2011@naver.com'])[-1] # 보낸 것을 확인해서 가장 최근에것 하나 들고오기
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
                
    # 6. db에 저장하기
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