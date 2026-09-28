# 第2章 第7节配套：gcd、辗转相除与扩展欧几里得（Bézout 系数）
import math


def euclid_steps(x, y):
    while y:
        print('   %d = %d * %d + %d' % (x, x // y, y, x % y))
        x, y = y, x % y
    return x


def egcd(x, y):
    if y == 0:
        return x, 1, 0
    g, a, b = egcd(y, x % y)
    return g, b, a - (x // y) * b


print('=== 1. gcd：能同时整除两数的最大正整数，=1 叫“互素” ===')
print('math.gcd(12, 18)   =', math.gcd(12, 18), ' -> 不互素，逆元不存在')
print('math.gcd(65537, 17) =', math.gcd(65537, 17), '-> 互素，逆元存在')

print()
print('=== 2. 辗转相除：反复“大数除以小数取余”，直到余数为 0 ===')
print('求 gcd(65537, 17) 的每一步：')
print('  gcd(65537, 17) =', euclid_steps(65537, 17))

print()
print('=== 3. 扩展欧几里得：顺带求出 Bézout 系数 a, b，使 x*a + y*b = g ===')
g, a, b = egcd(65537, 17)
print('扩展欧几里得(65537, 17) -> g =', g, ', a =', a, ', b =', b)
print('验证 65537*%d + 17*%d = %d' % (a, b, 65537 * a + 17 * b))

print()
print('=== 4. 逆元：g = 1 时，Bézout 系数就是模逆元 ===')
print('17*%d = 1 (mod 65537)  -> 17 模 65537 的逆元是 %d' % (b, b % 65537))
print('RSA 里同一个道理：pow(17, -1, 3120) =', pow(17, -1, 3120))
print('验证 (17*2753) % 3120 =', (17 * 2753) % 3120)