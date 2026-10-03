import json, urllib.request, urllib.error, random
BASE="http://localhost:3001"
UAS={"browser":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
     "curl":"curl/8.7.1"}
TERMS=["apple","juice","banana","orange","lemon","melon","carrot","raspberry","eggfruit","strawberry","green smoothie","fruit press","apple juice","best seller","lemon juice","pomegranate","kiwi","mango","water","tea"]
EMAILS=["alice@example.com","bob.smith@example.org","carol@shop.test","dave123@mail.com","erin@company.io","frank@example.net"]
def reqs():
    r=[]
    for t in TERMS: r.append(("GET","/rest/products/search?q="+urllib.request.quote(t),None))
    r.append(("GET","/rest/products/search?q=",None))
    for i in range(1,21): r.append(("GET",f"/rest/products/{i}/reviews",None))
    r.append(("GET","/api/Products",None))
    for i in range(1,16): r.append(("GET",f"/api/Products/{i}",None))
    for p in ["/rest/user/whoami","/rest/languages","/rest/admin/application-version","/rest/admin/application-configuration","/rest/captcha","/rest/image-captcha","/api/Challenges","/api/Quantitys","/api/SecurityQuestions","/api/Feedbacks","/api/Deliverys","/rest/memories","/rest/country-mapping","/rest/deluxe-membership","/rest/basket/1","/rest/order-history","/rest/wallet/balance","/api/Addresss","/api/Cards","/rest/user/security-question?email=alice@example.com"]:
        r.append(("GET",p,None))
    for i in range(1,6): r.append(("GET",f"/rest/track-order/{i}abc-def{i}",None))
    for e in EMAILS:
        r.append(("POST","/rest/user/login",{"email":e,"password":"Passw0rd!23"}))
        r.append(("POST","/api/Users",{"email":e,"password":"Passw0rd!23","passwordRepeat":"Passw0rd!23","securityQuestion":{"id":1},"securityAnswer":"blue"}))
    for i in range(1,6):
        r.append(("PUT",f"/rest/products/{i}/reviews",{"message":"Really tasty and fresh, would buy again","author":"alice@example.com"}))
        r.append(("POST","/api/Feedbacks",{"comment":"Great shop, fast delivery","rating":5,"captchaId":1,"captcha":"12"}))
    return r
def send(method,path,body,ua):
    data=None; h={"User-Agent":ua,"Accept":"application/json, text/plain, */*"}
    if body is not None: data=json.dumps(body).encode(); h["Content-Type"]="application/json"
    req=urllib.request.Request(BASE+path,data=data,method=method,headers=h)
    try: return urllib.request.urlopen(req,timeout=10).status
    except urllib.error.HTTPError as e: return e.code
    except Exception as e: return 0
n=0
for ua_name,ua in UAS.items():
    for rep in range(3):
        for m,p,b in reqs(): send(m,p,b,ua); n+=1
print("sent",n)
