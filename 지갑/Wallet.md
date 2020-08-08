> 지갑
> ----------------
>   > ### 3.1. 키와 지갑 주소
>   > ### 3.2. 개인 키(Private Key)
>   > ### 3.3. 공개 키(Public Key)
>   > ### 3.4. 지갑 주소(Address)
>   > ### 3.5. 지갑 주소 관리
>   > ### 3.6. 지갑 백업 및 관리
>   > ### 3.7. 지갑의 유형과 키 관리

### 3.1. 키와 지갑 주소
비트코인에서 지갑은 사용자의 개인 키(Private Key)와 공개 키(Public Key), 지갑 주소(Address)를 관리하며, 트랜잭션을 생성하고 확인하는 기능을 수행한다.
지갑은 키와 트랜잭션을 관리하는 것이 주된 기능이다.  

특히, 키 관리 기능에 있어, 개인 키와 공개 키는 ECC 기술을 사용하고, 사용자 인증에는 개인 키를, 다른 사람이 검증하는 경우에는 공개 키를 사용한다.
비대칭 암호화 기법에 근거하기 때문에, 개인 키의 분실은 소유한 코인을 모두 분실하는 것을 의미한다.  
따라서, 키 관리 기능은 비트코인 네트워크에서 매우 중요하다.


#### 비트코인 지갑 주소
지갑은 비트코인 잔액 자체를 보관하는 것이 아닌, 잔액에 대한 권한을 가진 키와 주소를 관리한다.
이 때, 비트코인 지갑은 고유 주소를 가지며 이 지갑의 주소는 개인 키와 공개 키로 만들어진다.

#### 지갑 주소가 생성되는 과정
1. 개인 키(256bits)로 ECC 암호를 통해 공개 키(512bits)를 생성
2. Double SHA-256과 RIPEMD160으로 공개 키 Hash(160bits) 게산
3. Hash를 Base58Check Encoding하여 지갑 주소(160bits) 생성

생성 구조 상 공개 키 Hash와 지갑 주소 사이에서만 역변환이 가능하고, 나머지 과정에 대해서는 역변환이 불가능하다.  

### 3.2. Private Key
주소의 시작점이고, 소유권을 보증하는 핵심 역할  
ECC의 표준 문서에 정의된 secp256k1 규격에 근거해 생성하며, 사용할 함수식과 순환군 내 점의 개수가 사전 정의되어 있다.  
여기서 개인 키는 점의 개수(n)보다 약간 작으며, 2^256(약 10^77) 개에 달해 무작위 생성을 통한 해킹은 어렵다.

#### Random Number Generator(RNG)
개인 키는 랜덤한 숫자로, 이를 위해 난수(Random Number)가 필요하다. 일반적인 프로그래밍 언어에 사전 정의된 난수 발생 함수는 
완전히 불규칙한 난수를 생성하지 못하는 의사 난수 생성기(Pseudo-RNG, PRNG)이다. 난수 생성기는 다음과 같은 것이 존재한다.

[1] True Random Number Generator(TRNG)  
물리적 난수 생성 방식으로, 주사위 던지기, 반도체 노이즈, 클럭의 지터 등에 기반한다. 완전한 무작위다.

[2] Pseudo-random Number Generator(PRNG)  
Seed 값에 근거해 난수를 생성하며, 프로그래밍 언어의 사전 정의 함수들이 주로 이러한 방식을 사용한다.

[3] Crtyptographically Secure Pseudo-random Number Generator(CSPRNG)  
다양한 곳에서 발생하는 노이즈를 모아 그것을 Seed로 사용하는 방식으로, 몇몇 함수들이 존재한다.


### 3.3. 개인 키 생성하기
~~~
import os
import random
import time
import hashlib

# secp256k1의 Domain parameter 
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# CSPRNG, os.urandom()와 random()를 조합해하고 sha-256을 사용해 256bit 생성
def random_key():
    r = str(os.urandom(32)) \
        + str(random.randrange(2**256)) \
        + str(int(time.time() * 1000000))
    r = bytes(r, 'utf-8')
    h = hashlib.sha256(r).digest()
    key = ''.join('{:02x}'.format(y) for y in h)
    return key

# secp256k1의 n값보다 "작게"
while (1):
    privKey = random_key()
    if int(privKey, 16) < N:
        break

print("PrivKey (Hex) : ", privKey)
print("PrivKey (Dec) : ", int(privKey, 16))
~~~

#### Base58Check Encoding
개인 키, 공개 키, 지갑 주소 생성 과정에서 사용하는 문자열 변환 알고리즘으로, 58개의 문자열로 구성되어 있으며,
혼동하기 쉬운 문자는 사용하지 않고 변환을 수행한다.

#### Wallet Import Format(WIF)
긴 길이의 숫자로 구성된 개인 키는 읽기 쉬운 형태인 WIF 포맷으로 변환한다. WIF에는 checksum같은 것들이 포함되어 있어, 오류 검출이 가능하다.
개인 키의 앞부분에 버전 정보를 붙이고, SHA-256 Hash를 두 번 적용해 Hash를 생성하여 앞부분의 4bytes를 checksum으로 사용한다.
이와 같이 구성한 버전 정보, 개인 키, checksum을 합쳐 Base58Check를 수행하면 개인 키의 WIF가 된다.

~~~
import hashlib
import binascii

# https://en.bitcoin.it/wiki/Wallet_import_format의 예제로 제시된 개인키를 WIF 형태로 변환한다.
privKey = '0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D'

# Base58 Encoding에 사용되는 문자열
s = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

# version prefix를 추가
# 0x80 ~ Private key WIF
# 공개키를 compressed form으로 사용할 때는 이 뒤에 '01'을 추가
prefixPayload = '80' + privKey

# Checksum 계산
# version + payload에 double-SHA256을 수행하고, 앞 부분의 4 bytes를 prefixPayload 뒤에 추가
versionPayload = binascii.unhexlify(prefixPayload)
h = hashlib.sha256(hashlib.sha256(versionPayload).digest()).digest()
h = ''.join('{:02x}'.format(y) for y in h)
versionPayloadChecksum = prefixPayload + h[0:8]

# Base58Check encoding
eKey = int(versionPayloadChecksum, 16)
base58 = ''
while(1):
    m, r = divmod(eKey, 58)
    base58 += s[r]
    if m == 0:
        break
    eKey = m

wif = base58[::-1]
print("\n개인키 (Hex): ", privKey.lower())
print("개인키 (WIF): ", wif)
~~~

#### 개인 키 & 공개 키 생성하기
공개 키는 개인 키의 ECC로 생성되며, 트랜잭션 입력부에 전자서명과 함께 기록되며, 이 기록을 다른 사람들이 검증할 수 있다.  
공개 키는 타원곡선식과 곡선 상 점인 베이스 포인트(G)를 바탕으로 생성하며, 개인 키의 개수만큼 더해서 키를 생성한다. 이 때,
곡선 상 한 점이므로 G(x,y)의 구조에서 x, y값을 concatenate하여 512bits의 공개 키를 생성할 수 있다.
~~~
import os
import math
import random
import time
import hashlib

# Additive Operation
def addOperation(a, b, p, q, m):
    if q == (math.inf, math.inf):
        return p
    
    x1 = p[0]
    y1 = p[1]
    x2 = q[0]
    y2 = q[1]
    
    if p == q:
        # Doubling
        # slope (s) = (3 * x1 ^ 2 + a) / (2 * y1) mod m
        # 페르마 소정리를 바탕으로 분모의 역원부터 계산
        # pow() 함수로 Square-and-Multiply 알고리즘 수행
        r = 2 * y1
        rInv = pow(r, m-2, m)   # Fermat's Little Theorem
        s = (rInv * (3 * (x1 ** 2) + a)) % m
    else:
        r = x2 - x1
        rInv = pow(r, m-2, m)   # Fermat's Little Theorem
        s = (rInv * (y2 - y1)) % m
    x3 = (s ** 2 - x1 - x2) % m
    y3 = (s * (x1 - x3) - y1) % m
    return x3, y3

# CSPRNG 방식
def random_key():
    r = str(os.urandom(32)) \
        + str(random.randrange(2**256)) \
        + str(int(time.time() * 1000000))
    r = bytes(r, 'utf-8')
    h = hashlib.sha256(r).digest()
    key = ''.join('{:02x}'.format(y) for y in h)
    return key

# secp256k1의 Domain parameters
# y^2 = x^3 + 7 mod m
a = 0
b = 7
m = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# 개인키를 생성
while(1):
    d = int(random_key(), 16)
    if d > 0 & d < n:
        break

# Double-and-Add 알고리즘으로 공개키를 생성
bits = bin(d)
bits = bits[2:len(bits)]

# initialize. bits[0] = 1 (always)
K = G

# 두 번째 비트부터 Double-and-Add 알고리즘을적용
bits = bits[1:len(bits)]
for bit in bits:
    # Double
    K = addOperation(a, b, K, K, m)
    
    # Multiply
    if bit == '1':
        K = addOperation(a, b, K, G, m)

privKey = d
pubKey = K
print("\nPrivate Key : ", hex(privKey))
print("\n Public Key : (%s,\n               %s)" % (hex(pubKey[0]), hex(pubKey[1])))
~~~

#### 공개 키의 유형들
- 비압축포맷(Uncompressed Format)  
x, y 모두 사용(512bits)
0x04를 포맷 앞에 붙여 비압축 포맷임을 명시하여, 총 길이는 520bits

- 압축 포맷(Compressed Format)
x만 사용(256bits)  
0x02나 0x03을 포맷 앞에 붙여 압축 포맷임을 명시한다. 이 때, y좌표가 홀수면 0x02, 짝수이면 0x03을 사용하며, 총 길이는 264bits

####포맷 변환
~~~
privKey = '3ba54c096fbb082b2af8efdfd92f886350a36c806296199234d338e8d81b456d'
pubKey = ('484ec026a5a371a4e99cd2258760be98f9662c95b94a49706735e62a1a128855',
          'c7f3b6a8e049d54ab99414b2245fd45bbf5d916a97e56bdd87f7110c95f7bde8')

# secp256k1에 정의된 domain parameter p
p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F

# 공개키를 Uncompressed format으로 표시.
uPubKey = '04' + pubKey[0] + pubKey[1]

# 공개키를 Compressed format으로 표시
if int(pubKey[1], 16) % 2 == 0:
    cPubKey = '02' + pubKey[0]
else:
    cPubKey = '03' + pubKey[0]

# Compressed Format을 (x, y) Format으로 변환
# p % 4 = 3 mod 4 이므로 아래 공식을 적용
x = int(cPubKey[2:], 16)
a = (pow(x, 3, p) + 7) % p  # y^2
y = pow(a, (p+1)//4, p)     # y

prefix = int(cPubKey[:2], 16)
if (prefix == 2 and y & 1) or (prefix == 3 and not y & 1):
    y = (-y) % p

# 공개키
print("\n Public Key : (%s,\n               %s)" % (pubKey[0], pubKey[1]))

# Uncompressed format
print("\nUncompressed (size = %d):\n%s" % (len(uPubKey)*4, uPubKey))

# Compressed format
print("\nCompressed (size = %d):\n%s" % (len(cPubKey)*4, cPubKey))

print("\nCompressed format --> Public key :")
print("\n Public Key : (%s,\n               %s)" % (hex(x)[2:], hex(y)[2:]))
~~~

### 3.4. 지갑 주소(Address)
공개 정보이면서, 거래에 있어 핵심적인 요소이다. 개인 키와 공개 키, 공개 키 Hash 과정을 거쳐 주소를 생성한다.

#### 생성 과정
1. 개인 키로 비 압축 포맷의 공개 키 생성
2. double-SHA-256, RIPEMD160으로 공개 키 Hash 생성
3. Version Prefix 추가 후, Base58Check를 통해 주소 생성

공개 키 Hash를 통해 주소가 생성되므로, 사실상 같은 존재라고 볼 수 있으며, 따라서 비트코인 트랜잭션에서는 공개 키 해시가 기록된다.

#### Version Prefix
지갑의 용도를 구분한다.
- 0x00(메인넷의 일반 지갑), 0x6f(테스트넷의 시험용 지갑), 0x05(P2SH)

#### 주소 생성
~~~
# pybitcointools를 설치하지 않고 배포용 실습 코드의 bitcoin 폴더가 있는 곳에서 실행한다.
import bitcoin.main as btc

# 개인키를 생성
while (1):
    privKey = btc.random_key()                      # 256 bit Random number
    dPrivKey = btc.decode_privkey(privKey, 'hex')   # 10진수 숫자
    if dPrivKey < btc.N:                            # secp256k1 의 N 보다 작으면 OK
        break

# 개인키로 공개키를 생성
pubKey = btc.privkey_to_pubkey(privKey)

# 공개키로 지갑 주소를 생성(mainnet)
address1 = btc.pubkey_to_address(pubKey, 0)

# 공개키로 160-bit public key hash를 생성한다
pubHash160 = btc.hash160(btc.encode_pubkey(pubKey, 'bin'))

# 160-bit public key hash로 지갑 주소 생성(위의 address와 동일)
address2 = btc.hex_to_b58check(pubHash160, 0)

# 지갑 주소를 160-bit public key hash로 변환(위의 pubHash160과 동일)
pubHash1601 = btc.b58check_to_hex(address2)

# 공개키로 testnet용 지갑 주소를 생성
address3 = btc.pubkey_to_address(pubKey, 0x6f)

print("\n\n개인키 : ", privKey)
print("개인키 --> 공개키 : ", pubKey)
print("\n공개키 --> 지갑주소 (1. mainet 용) : ", address1)
print("공개키 --> 공개키 해시 : ", pubHash160)
print("\n공개키 해시 --> 지갑주소 (2. mainet 용) : ", address2)
print("지갑주소 --> 공개키 해시 : ", pubHash1601)
print("지갑주소 (Testnet 용) :", address3)
~~~

### 3.5. 지갑 주소 관리
지갑 어플리케이션은 개인 키와 지갑 주소를 하나만 운영하는 것이 아니라 여러 개를 운용하기도 하며,
일종의 OTP(One Time Password)처럼 사용하여, 보안상 안전을 확보한다.  
지갑 어플리케이션은 키의 생성과 백업을 담당해 키 관리가 가능하다.  

### 3.6. 지갑 백업 및 관리
지갑의 백업은 개인 키의 백업을 의미하는 것과 동일하다. 개인 키는 네트워크에서 모든 것들의 기본이 되기 때문에,
개인 키의 안전한 백업은 자신의 지갑을 안전하게 백업하는 것을 의미한다.  
개인 키는 자신의 지갑에 접근할 수 있는 고유한 키이기 때문에, 이를 분실하는 경우 해당 지갑의 UTXO는 아무도 사용할 수 없으며,
이를 보관하기 위해서는 다음의 백업 방식을 고려한다.

- Warm Storage  
전자 장치에 백업하는 기존의 백업 방식으로, 1차적 방식
- Cold Storage  
전자장치의 안정성을 고려해 전자정치에 백업에만 의존하지 않고, 물리적인 기록도 진행하는 것
- Paper Wallet  
개인 키를 화폐나 증권형태로 만들어 보관하는 방식, 개인 키 자체를 그대로 기록할 수도 있고, 개인 키를 암호화하여 보관하기도 한다.

#### 브레인 지갑(Brain Wallet)
개인 키를 난수가 아닌 특정 문장이나, 단어 구성으로 만드는 방식으로, 개인 키 자체를 보관할 필요를 없앨 수 있다.
~~~
# pybitcointools (https://github.com/vbuterin/pybitcointools)
# pybitcointools를 설치하지 않고 배포용 실습 코드의 bitcoin 폴더가 있는 곳에서 실행
import bitcoin.main as btc

# 특정 문자열로 256-bit 개인키를 생성(long brain wallet passphrase).
passphrase = 'Brain Wallet 시험용 개인키'
privKey = btc.sha256(passphrase)
dPrivKey = btc.decode_privkey(privKey, 'hex')   # 10진수 숫자
if dPrivKey < btc.N:                            # secp256k1 의 N 보다 작으면 OK
    # 개인키로 공개키를 생성
    pubKey = btc.privkey_to_pubkey(privKey)
    
    # 공개키로 지갑 주소를 생성(mainnet)
    address = btc.pubkey_to_address(pubKey, 0)
    print("\n\nPassphrase :", passphrase)
    print("\n개인키 :", privKey)
    print("개인키 --> 공개키 :", pubKey)
    print("\n공개키 --> 지갑주소 :", address)
else:
    print("요청하신 Passphrase로 개인키를 만들었으나, 유효하지 않습니다.")
    print("다른 Passphrase로 다시 시도해 주세요.")
~~~

#### 베니티 지갑(Vanity Wallet)
지갑 주소의 특정 위치에 사용자가 원하는 문자열을 나타나게 한 것으로, 자신과 타인이 개인 키를 알아보기 쉽게 하는 가독성을 
확보할 수 있다. 법인명, 개인별명 등을 기록할 수 있다. 다만, Base58Check 인코딩에서 사용할 수 있는 문자열만 사용 가능하다.
~~~
# pybitcointools (https://github.com/vbuterin/pybitcointools)
# pybitcointools를 설치하지 않고 배포용 실습 코드의 bitcoin 폴더가 있는 곳에서 실행
import bitcoin.main as btc

bFound = False
for i in range(10000):
    # 개인키를 생성
    while (1):
        privKey = btc.random_key()                      # 256 bit Random number
        dPrivKey = btc.decode_privkey(privKey, 'hex')   # 10진수 숫자
        if dPrivKey < btc.N:                            # secp256k1 의 N 보다 작으면 OK
            break
    
    # 개인키로 공개키를 생성
    pubKey = btc.privkey_to_pubkey(privKey)
    
    # 공개키로 지갑 주소를 생성(mainnet)
    address = btc.pubkey_to_address(pubKey, 0)
    
    # 지갑 주소 앞 부분 원하는 문자열인지 확인
    if address[1:4] == 'ABC':
        bFound = True
        break

if bFound:
    print("\n\n개인키 : ", privKey)
    print("\n개인키 --> 공개키 : ", pubKey)
    print("\n공개키 --> 지갑주소 : ", address)
else:
    print("찾지 못했습니다. 다시 시도해 주세요")
~~~

### 3.7. 지갑의 유형과 키 관리
지갑은 키 관리 방식에 따라 크게 두 가지로 나눌 수 있다.

- 비결정적 방식 지갑(Non-deterministic Wallet, Type-0)  
여러 키를 랜덤하게 만드는 방식으로 키를 독립적으로 여러 개 생성하며, 상호 간 연관성이 없게 한다. 안전한 방식이지만, 백업에
신경써야 하는 방식이다.

- 결정적 방식 지갑(Deterministic Walle, Type-1 or Type-2)  
같은 상태에서 같은 입력에 대해 같은 결과가 항상 보장되는 것으로, Seed와 Hash Function을 통해 연쇄적으로 키를 생성한다.
각각의 키는 비결정적 방식과 다르게 상호 연관성을 갖는 키 체인(Key Chain)을 이루며, 초기 Seed는 문장이나 단어들로 구성한다.
     1. Type -1  
     초기 Seed의 Hash로 마스터 키(Master Key) 생성 후, 키의 Hash로 다음 키를 연쇄적으로 생성하는 방식으로, 초기 Seed만 
     확보하고 있으면, 언제든지 다른 키를 구성할 수 있어 백업이 쉽다.
     2. Type-2  
     HD Wallet(Hierarchical Deterministic Wallet)은 키와 지갑 주소를 계층적 구조로 관리한다. 마스터 Seed로 마스터 개인 키와 공개 키를 생성하고,
     마스터 키로 하위 계층의 키와 주소를 생성하는 방식이다. 하위 계층의 지갑 주소를 생성할 때 상위 계층의 공개 키를 이용하므로,
     개인 키 없이 생성이 가능하다는 장점을 가지고 있으며, 시드 값만 보관하면 모든 키와 주소를 원래 상태로 복원이 가능하다.

### 3.8. 메인넷(Mainnet), 테스트넷(Testnet)
메인넷은 실제 운영되는 비트코인 네트워크, 테스트넷은 개발용 네트워크를 의미한다. 관련 서비스를 개발하는 사람은 테스트넷에서
기능을 시험하고, 서비스를 준비한다.
