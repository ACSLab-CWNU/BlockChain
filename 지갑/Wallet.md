> 지갑
> ----------------
>   > ### 1.1 현대대수 학습
>   > ### 1.2 유한체 
>   > ### 1.3 유한집합 정의하기
>   >   > #### 1.3.1 파이썬으로 유한체 코딩하기

### 지갑 주소
비트코인에서 지갑은 사용자의 개인 키(Private Key)와 공개 키(Public Key), 지갑 주소(Address)를 관리하며, 트랜잭션을 생성하고 확인하는 기능을 수행한다.
지갑은 키와 트랜잭션을 관리하는 것이 주된 기능이다.  

특히, 키 관리 기능에 있어, 개인 키와 공개 키는 ECC 기술을 사용하고, 사용자 인증에는 개인 키를, 다른 사람이 검증하는 경우에는 공개 키를 사용한다.
비대칭 암호화 기법에 근거하기 때문에, 개인 키의 분실은 소유한 코인을 모두 분실하는 것을 의미한다.  
따라서, 키 관리 기능은 비트코인 네트워크에서 매우 중요하다.


### 비트코인 지갑 주소
지갑은 비트코인 잔액 자체를 보관하는 것이 아닌, 잔액에 대한 권한을 가진 키와 주소를 관리한다.
이 때, 비트코인 지갑은 고유 주소를 가지며 이 지갑의 주소는 개인 키와 공개 키로 만들어진다.

####지갑 주소가 생성되는 과정
1. 개인 키(256bits)로 ECC 암호를 통해 공개 키(512bits)를 생성
2. Double SHA-256과 RIPEMD160으로 공개 키 Hash(160bits) 게산
3. Hash를 Base58Check Encoding하여 지갑 주소(160bits) 생성

생성 구조 상 공개 키 Hash와 지갑 주소 사이에서만 역변환이 가능하고, 나머지 과정에 대해서는 역변환이 불가능하다.  

### Private Key
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


### 개인 키 생성하기
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

### Base58Check Encoding
개인 키, 공개 키, 지갑 주소 생성 과정에서 사용하는 문자열 변환 알고리즘으로, 58개의 문자열로 구성되어 있으며,
혼동하기 쉬운 문자는 사용하지 않고 변환을 수행한다.

### Wallet Import Format(WIF)
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

### 개인 키 & 공개 키 생성하기
공개 키는 개인 키의 ECC로 생성되며, 트랜잭션 입력부에 전자서명과 함께 기록되며, 이 기록을 다른 사람들이 검증할 수 있다.  
공개 키는 타원곡선식과 곡선 상 점인 베이스 포인트(G)를 바탕으로 생성하며, 개인 키의 개수만큼 더해서 키를 생성한다. 이 때,
곡선 상 한 점이므로 G(x,y)의 구조에서 x, y값을 concatenate하여 512bits의 공개 키를 생성할 수 있다.
~~~
# 파이썬 실습 파일: 3-3.공개키(생성).py
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

- 압축 포맷(Compressed Format)
x만 사용(256bits)