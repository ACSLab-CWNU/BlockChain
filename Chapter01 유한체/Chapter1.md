# 1.1 현대대수 학습
타원 곡선 암호를 파악하기 위해 필요.   
타원곡선 암호는 비트코인의 핵심인 전자서명과 서명 검증 알고리즘을 이해하는 데 필수적임.   
슈노어 서명, 기밀 트랜잭션 등의 이해를 위해 학습 필요   

# 1.2 유한체 정의
수학에서 유한체는 다음 성질들을 만족하는 2개의 연산자를 가진 집합이며 그 집합의 원소 수가 유한함.
<pre>
  1. a와 b가 집합에 속해 있으면, a+b와 a•b도 집합 안에 있다.   
     (집합 위에 두 연산 +, • 이 닫혀 있음)
  2. 집합에 0으로 표기하는 원소가 존재하고 집합 내 다른 원소 a와 +연산 결과는 a다.   
     즉 a+0=a (+ 연산에 대한 항등원 존재)
  3. 집합에 1로 표기하는 원소가 존재하고 집합 내 다른 원소 a와 •연산 결과는 a다.
     즉 a와 •연산 결관는 a다. 즉 a•1=a (•연산에 대한 항등원 존재)
  4. 집합의 원소 a와 +연산 결과가 0이 되게 하는 원소 b가 역시 집합에 속해 있고 이러한 b를 -a로 표기한다.
     (+연산에 대한 a의 역원 -a존재)
  5. 0이 아닌 집합의 원소 a에 대해 a•b=1이 되게 하는 원소 b가 역시 집합에 속해 있고 이러한 b를 a¯¹로 표기한다.
     (•연산에 대한 a의 역원a¯¹존재)
</pre>
유한 개수의 숫자를 원소로하는 집합이 존재.   
집합의 원소 개수가 유한하므로 집합의 크기를 어떤값 p라고 표현.  
어떤값 p를 위수(order)라고 함.
    
1번 성질에 의해 집합 원소들간의 덧셈과 곱셈 연산의 결과가 집합의 원소여야 함.
```
{0, 1, 2}에서 1+2=3, 2+2=4 이기 때문에 덧셈에 닫혀있지 않음.
{-1, 0, 1}은 곱셈에 닫혀있지만 덧셈에 대해 닫혀있지 않음.
```
예시의 두 집합을 덧셈과 곱셉에 대해 닫히도록 덧셈과 곱셈을 새로 정의해야 할 필요가 있음.
   
2번과 3번 성질을 만족하기위해 덧셈과 곱셈에 대한 항등원이 집합내에 존재해야함.   
```
덧셈에 대한 항등원 : 0
곱셉에 대한 항등원 : 1
```
   
4번 성질을 만족하기 위해 덧셈에 대한 역원이 존재해야 함.
```
집합내의 원소 a가 존재 -> -a 또한 집합내에 존재
{3, -3}
```
   
5번 성질을 만족하기 위해 곱셈에 대한 역원이 존재
```
집합내의 원소 a가 존재 -> a¯¹이 존재
{3, 1/3}
```

# 1.3 유한집합 정의하기
집합의 위수가 p이면 집합의 원소는 0, 1, 2, ··· p-1 로 쓸 수 있음   
여기서 원소들은 일반적인 숫자가 아님   
일반 숫자의 성질이 있지만 덧셈, 뺄셈, 곱셈에 대한 정의에 있어 차이가 있음
```
유한체 집합 표기
Fp = {0, 1, 2, ... p-1}
```
중괄호 안에 있는 것은 집합의 원소   
Fp는 위수 p의 유한체(p는 집합의 위수. 집합 안의 원소 개수)   
중괄호 안의 0, 1, 2는 유한체 안의 서로 다른 원소   
```
위수 11의 유한체
F₁₁ = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10}

위수 17의 유한체
F₁₇ = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,}

위수 983의 유한체
F₉₈₃ = {0, 1, 2, ... 982}
```
유한체는 반드시 소수이거나 소수의 거듭제곱을 위수로 가져야 함.

## 1.3.1 파이썬으로 유한체 
유한체 원소 1개를 표현하는 클래스를 정의. 클래스 이름은 FieldElement.
```
class FieldElement:
  
    def __init__(self, num, prime):
        if num >= prime or num < 0:  ➊
            error = 'Num {} not in field range 0 to {}'.format(
                num, prime - 1)
            raise ValueError(error)
        self.num = num  ➋
        self.prime = prime
  
    def __repr__(self):
        return 'FieldElement_{}({})'.format(self.prime, self.num)
        
    def __eq__(self, other):
        if other is None:
            return False
        return self.num == other.num and self.prime == other.prime  ➌
```
> ➊ num과 prime을 인수로 받은 후 num 값이 경곗값을 포함하여 0과 prime-1 사이 값인지조사   
> 그렇지 않은 경우 유효하지 않은 FieldElement를 얻게 되므로 ValueError를 발생    
> ➋ __init__ 메서드의 나머지 부분에서 조사된 인수 값으로 객체를 초기화   
> ➌ __eq__ 메서드는 FieldElement 클래스의 두 개체가 같은지 검사   
> 객체의 num과 prime 속성이 서로 같은 경우에만 True 값을 반환

```
>>> from FieldElement import FieldElement
>>> a = FieldElement(7, 13)
>>> b = FieldElement(6, 13)
>>> print(a == b)
False
>>> print(a == a)
True
```
### 연습문제 1.1
FieldElement의 두 객체가 서로 다른지 검사하는 != 연산자를 재정의하도록 FieldElement 클래스의 __ne__ 메서드를 작성.
```
    def __ne__(self, other):
        if other is None:
            print('other is none')
            return False
        return not(self == other)
```

```
>>> print(a != b)
True
>>> print(a != a)
False
```
# 1.4 나머지 연산
나머지 연산을 이용해 덧셈, 뺄셈, 곱셈, 나눗셈에 대해 닫혀 있는 유한체를 만들 수 있음.
```
7 % 3 = 1
1747 % 231 = 60

현재 시간이 3시 일때, 16시간전은 몇시였는가?
(3-16) % 12 = 11

현재 시간은이 12분일 때, 843분 후는 몇분인가?
(12 + 843) % 60 = 15
```
분에 대한 나머지연산(%) 결과는 항상 0 ~ 59의 범위를 가짐.   
아무리 큰 숫자라도 나머지 연산 후 에는 유한한 범위의 숫자로 변환되기 때문에 숫자 개수가 한정되어야 하는 유한체에 매우 적절한 속성임.   

## 1.4.1 파이썬으로 나머지 연산 코딩
```
print(7 % 3)
1

print(-27 % 13)
12
```

# 1.5 유한체 덧셈과 뺄셈
유한체에서의 덧셈을 정의할 때 그 결과가 유한체에 속해 있도록 해야함.   
즉, 유한체가 덧셈에 닫혀있도록 해야함.   
나머지 연산을 이용하여 덧셈을 정의하면 유한체가 덛셈에 닫혀 있도록 할 수 있음.   
   
19를 위수로 하는 유한체에서
<pre>
F₁₉ = {0, 1, 2, ... 18}
</pre>   
덧셈에 대해 닫혀있음 정의
<pre>
a +<sub>f</sub> b ∊ F₁₉
(일반 정수에서의 덧셈과 구별하기 위해 +가 아닌 +<sub>f</sub>로 표시.)
</pre>   
   
유한체 덧셈 일반화 정의
<pre>
a +<sub>f</sub> b = (a + b)%p, (p는 위수. a, b ∊ F<sub>p</sub>)
</pre>   

유한체 덧셈은 유한체에서 임의의 수 2개를 꺼내서 더하고 그 수를 위수로 나눈 나머지를 구함.   
<pre>
19를 위수로 하는 유한체 F₁₉에서,
7 +<sub>f</sub> 8 = (7+8)%19 = 15
11 +<sub>f</sub> 17 = (11+17)%19 = 9
</pre>   
   
덧셈에 대한 역원도 동일한 방식으로 정의.   
a ∊ F<sub>p</sub>이면 -<sub>f</sub>a ∊ F<sub>p</sub>가 성립.   

유한체 덧셈 역원 일반화 정의
<pre>
-<sub>f</sub>a = (-a) % p
(일반 정수에서의 뺄셈과 구별하기 위해 -가 아닌 -<sub>f</sub>로 표시.)
</pre>  

19를 위수로 하는 유한체 F₁₉에서
<pre>
-<sub>f</sub>9 = (-9)%19 = 10
</pre>
-<sub>f</sub>9는 9의 역원이므로
<pre>
9+<sub>f</sub>10 = 0
</pre>
10은 9의 덧셈에 대한 역원임을 알 수 있음.   
   
유한체의 뺄셈도 덧셈과 동일한 방식으로 정의 가능.
<pre>
a-<sub>f</sub>b = (a-b)%p, (a, b ∊ F<sub>p</sub>)
</pre>
   
19를 위수로 하는 유한체 F₁₉에서
<pre>
11-<sub>f</sub>9=(11-9)%19=2
6-<sub>f</sub>13=(6-13)%19 = 12
</pre>

### 연습문제 1.2
유한체 F<sub>57</sub>에서 다음 연산의 결과를 구하시오.
* 44 +<sub>f</sub> 33
<pre>
>>> prime = 57
>>> print((44+33)%prime)
20
</pre>
* 9 -<sub>f</sub> 29
<pre>
>>> print((9-29)%prime)
37
</pre>
* 17 +<sub>f</sub> 42 +<sub>f</sub> 49
<pre>
>>> print((17+42+49)%prime)
51
</pre>
* 52 -<sub>f</sub> 30 -<sub>f</sub> 38
<pre>
print((52-30-38)%prime)
41
</pre>

# 1.5.1 파이썬으로 유한체 덧셈과 뺄셈  코딩하기
FieldElement 클래스에서 __add__와 __sub__ 메서드를 정의.
```
    def __add__(self, other):
        if self.prime != other.prime: ➊
            raise TypeError('Cannot add two numbers in different Fields')
        num = (self.num + other.num) % self.prime ➋
        return self.__class__(num, self.prime) ➌
```
> ➊ 더하는 수와 더해지는 수의 위수가 동일한지 확인. 서로 위수가 다르면 계산은 무의미함.   
> ➋ 나머지 연산을 통해 유한체 덧셈을 정의.   
> ➌ 자기 자신 클래스의 인스턴스를 반환.   

```
>>> from FieldElement import FieldElement
>>> a = FieldElement(7, 13)
>>> b = FieldElement(12, 13)
>>> c = FieldElement(6, 13)
>>> print(a+b==c)
True
```

### 연습문제 1.3
2개의 FieldElement 객체의 뺄셈을 정의하는 __sub__ 메서드를 작성.
```
    def __sub__(self, other):
        if self.prime != other.prime: 
            raise TypeError('Cannot add two numbers in different Fields')
        num = (self.num - other.num) % self.prime 
        return self.__class__(num, self.prime) 
```
# 1.6 유한체 곱셈과 거듭제곱
유한체에서 닫혀 있는 덧셈(+<sub>f</sub>)을 새롭게 정의한것처럼 곱셈에 대해서도 정의.
정수집합에서의 곱셈은 '여러번 더하기'를 의미
```
5 • 3 = 5 + 5 + 5 = 15
8 • 17 = 8 + 8 + 8 + ... + 8 = 136
```
유한체에서 곱셈도 동일한 방법으로 계산 가능
<pre>
5 •<sub>f</sub> 3 = 5 +<sub>f</sub> 5 +<sub>f</sub> 5
8 •<sub>f</sub> 17 = 8 +<sub>f</sub> 8 +<sub>f</sub> 8 +<sub>f</sub> ... +<sub>f</sub> 8
</pre>

위수가 19인 유한체 F<sub>19</sub>에서
<pre>
5 •<sub>f</sub> 3 = 5 +<sub>f</sub> 5 +<sub>f</sub> 5 = 15 % 19 = 15
8 •<sub>f</sub> 17 = 8 +<sub>f</sub> 8 +<sub>f</sub> 8 +<sub>f</sub> ... +<sub>f</sub> 8 = (8•17) % 19 = 3
</pre>
계산은 정수집합의 곱셈을 유한체의 위수로 나눈 나머지와 동일하며, 결과는 F<sub>19</sub>에 속함.   
즉, 결과는 항상 집합 {0, 1, ..p-1}에 속함.   
   
거듭제곱은 한 숫자를 '여러번 곱하기'를 의미
<pre>
7<sup>3</sup> = 7 • 7 • 7 = 343
</pre>

위수가 19인 유한체 F<sub>19</sub>에서
<pre>
7<sup>3</sup> = 343 % 19 = 1
9<sup>12</sup> = 7
</pre>

### 연습문제 1.4
유한체 F<sub>97</sub>에서 다음 곱셈과 거듭제곱을 구하시오.
* 95 •<sub>f</sub> 45 •<sub>f</sub> 31
```
>>> prime = 97
>>> print(95*45*31 % prime)
23
```
* 17 •<sub>f</sub> 13 •<sub>f</sub> 19 •<sub>f</sub> 44
```
>>> print(17*13*19*44 % prime)
68
```
* 127 •<sub>f</sub> 77<sup>49</sup>
```
>>> print(12**7*77**49 % prime)
63
```

### 연습문제 1.5
k가 각각 1, 3, 7, 13, 18인 경우 F<sub>19</sub>에서 다음 집합을 구하고, 구한 집합에서 어떤 규칙성이 있는지 찾으시오.
* {k •<sub>f</sub> 0, k •<sub>f</sub> 1, k •<sub>f</sub> 2, k •<sub>f</sub> 3, ... k •<sub>f</sub> 18}
```
>>> prime = 19
>>> for k in (1, 3, 7, 13, 18):
...     print([k*i % prime for i in range(prime)])
[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18]
[0, 3, 6, 9, 12, 15, 18, 2, 5, 8, 11, 14, 17, 1, 4, 7, 10, 13, 16]
[0, 7, 14, 2, 9, 16, 4, 11, 18, 6, 13, 1, 8, 15, 3, 10, 17, 5, 12]
[0, 13, 7, 1, 14, 8, 2, 15, 9, 3, 16, 10, 4, 17, 11, 5, 18, 12, 6]
[0, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1]

>>> for k in (1, 3, 7, 13, 18):
...     print(sorted([k*i % prime for i in range(prime)]))
[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18]
[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18]
[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18]
[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18]
[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18]
```
결과를 정렬하면, 모두 같은 집합임

## 1.6.1 파이썬으로 곱셉 코딩하기
FieldElement 클래스에서 __mul__ 메서드를 정의

### 연습문제 1.6
2개의 유한체 원소 곱셈을 정의하는 __mul__ 메서드를 작성.
```
    def __mul__(self, other):
        if self.prime != other.prime: 
            raise TypeError('Cannot add two numbers in different Fields')
        num = (self.num * other.num) % self.prime 
        return self.__class__(num, self.prime) 
```
```
>>> from FieldElement
>>> a = FieldElement(3, 13)
>>> b = FieldElement(12, 13)
>>> c = FieldElement(10, 13)
>>> print(a*b==c)
True
```
## 1.6.2 파이썬으로 거듭제곱 코딩하기
FielElement 클래스에서 __pow__ 메서드를 정의
```
    def __pow__(self, exponent):
        num = self.num ** exponent) % self.prime ➊
        return self.__class__(num, self.prime) ➋
```
```
>>> from ecc import FieldElement
>>> a = FieldElement(3, 13)
>>> b = FieldElement(1, 13)
>>> print(a**3==b)
True
```
지수가 유한체 원소일 경우 지수 관련 성질 (예 7<sup>a</sup> • 7<sup>b</sup> = 7<sup>a+b</sup>)이 성립하지 않으므로 지수는 유한체로 한정하지 않음.

### 연습문제 1.7
7, 11, 17, 31인 p값에 대해 유한체 F<sub>p</sub>에서 다음 집합을 구하시오.
* {1<sup>(p-1)</sup>, 2<sup>(p-1)</sup>, 3<sup>(p-1)</sup>, 4<sup>(p-1)</sup>, ... (p-1)<sup>(p-1)</sup>}
```
>>> for prime in (7, 11, 17, 31):
...     print([pow(i, prime-1, prime) for i in range(1, prime)])
[1, 1, 1, 1, 1, 1]
[1, 1, 1, 1, 1, 1, 1, 1, 1, 1]
[1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]
[1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]
```
# 1.7 유한체 나눗셈
유한체에서 나눗셈은 일반대수에서의 나눗셈과 비교하는 방법을 이용   
일반대수에서 나눗셈은 곱셈의 역연산   
```
7 • 8 = 56은 56/8 = 7을 의미
12 • 2 = 23는 24/12 = 2를 의미
```
일반대수에서와 마찬가지로 유한체의 나눗셈에서도 0으로 어떤 값을 나눌 수 없음   
F<sub>19</sub>에 이를 적용하면 다음과 같음
<pre>
3 •<sub>f</sub>7 = 21%19 = 2로부터 2/<sub>f</sub>7 = 3이라는 등식이 성립
9 •<sub>f</sub>5 = 45%19 = 7로부터 7/<sub>f</sub>5 = 9이라는 등식이 성립
</pre>
어떤 유한체 원소를 0이 아닌 원소로 나눈 결과는 유한체 소속의 원소가 됨.   
3 •<sub>f</sub> 7 = 2를 모르는 경우 2/<sub>f</sub>7을 계산하는 방법은 연습문제 1.7을 활용하여 해결 가능함   
소수인 p와 0보다 큰 n에 대해 n<sup>(p-1)</sup>는 항상 1임을 알 수 있음   
페르마의 소정리라고도 불리는 정수론의 결과로 다음과 같이 일반화 할 수 있음
<pre>
n<sup>(p-1)</sup>%p = 1
</pre>
