from django.shortcuts import render, HttpResponse

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
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]  # 프록시를 거쳤을 경우 여러 IP 주소 중 가장 왼쪽 IP를 선택
    else:
        ip = request.META.get('REMOTE_ADDR')  # 직접 연결된 경우 사용
    
    print(f"ip주소: {ip}")
    return HttpResponse(ip)