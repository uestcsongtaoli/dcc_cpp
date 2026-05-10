"""
Generate 300,000 rows of fake but realistic CSV test data.
Format mirrors samples.csv from the dcc project.
"""
import random
import string
import csv
import os

random.seed(42)

# ── Chinese names ─────────────────────────────────────────────────────────────

SURNAMES = [
    '王','李','张','刘','陈','杨','赵','黄','周','吴',
    '徐','孙','胡','朱','高','林','何','郭','马','罗',
    '梁','宋','郑','谢','韩','唐','冯','于','董','萧',
    '程','曹','袁','邓','许','傅','沈','曾','彭','吕',
    '苏','卢','蒋','蔡','贾','丁','魏','薛','叶','阎',
]

GIVEN1 = [
    '秀','娟','敏','静','丽','强','磊','军','洋','勇',
    '艳','杰','涛','明','超','霞','平','刚','桂','芳',
    '凤','华','建','伟','宏','文','波','宁','飞','海',
    '云','珍','清','燕','鹏','辉','倩','雪','雷','冬',
    '志','峰','斌','康','晨','浩','鑫','龙','达','成',
]

GIVEN2 = [
    '英','兰','花','红','芹','春','萍','莉','梅','慧',
    '玲','美','岩','云','阳','东','江','生','浩','欣',
    '婷','萌','娜','悦','婧','雯','菲','彤','薇','瑶',
    '翔','睿','博','轩','宇','昊','泽','熙','祺','凯',
]

def gen_name():
    s = random.choice(SURNAMES)
    if random.random() < 0.55:
        return s + random.choice(GIVEN1)
    return s + random.choice(GIVEN1) + random.choice(GIVEN2)

# ── ID card ───────────────────────────────────────────────────────────────────
# 6-digit region + 8-digit birth + 3-digit seq + 1 check (digit or X)

REGION_PREFIXES = [
    '110','120','130','140','150','210','220','230',
    '310','320','330','340','350','360','370','410',
    '420','430','440','450','460','500','510','520',
    '530','540','610','620','630','640','650',
]

def gen_id_card():
    prefix = random.choice(REGION_PREFIXES)
    suffix = f"{random.randint(100, 999):03d}{random.randint(10, 99):02d}"
    year   = random.randint(1955, 2005)
    month  = random.randint(1, 12)
    day    = random.randint(1, 28)
    seq    = random.randint(100, 999)
    check  = random.choice('0123456789X')
    return f"{prefix}{suffix}{year}{month:02d}{day:02d}{seq}{check}"

# ── Phone ─────────────────────────────────────────────────────────────────────

PHONE_PREFIXES = [
    '130','131','132','133','134','135','136','137','138','139',
    '150','151','152','153','155','156','157','158','159',
    '176','177','178','180','181','182','183','185','186','187','188','189',
]

def gen_phone():
    return random.choice(PHONE_PREFIXES) + ''.join(random.choices(string.digits, k=8))

# ── Email ─────────────────────────────────────────────────────────────────────

EMAIL_DOMAINS = ['qq.com','163.com','126.com','cmbchina.com','sina.com',
                 'gmail.com','outlook.com','139.com','sohu.com','yeah.net']

_LC  = string.ascii_lowercase
_DIG = string.digits

def gen_email():
    style = random.randint(0, 3)
    if style == 0:          # letters only
        local = ''.join(random.choices(_LC, k=random.randint(4, 10)))
    elif style == 1:        # letters + digits
        local = ''.join(random.choices(_LC + _DIG, k=random.randint(5, 12)))
    elif style == 2:        # short + digits suffix
        local = ''.join(random.choices(_LC, k=random.randint(3, 7))) \
              + str(random.randint(1, 9999))
    else:                   # digits + letters mixed
        local = ''.join(random.choices(_LC + _DIG, k=random.randint(6, 14)))
    return local + '@' + random.choice(EMAIL_DOMAINS)

# ── Other fields ──────────────────────────────────────────────────────────────

_BK_SPECIAL = '!%^&*@#'
_BK_CHARS   = string.ascii_letters + string.digits + _BK_SPECIAL

def gen_user_code():
    return ''.join(random.choices(string.ascii_uppercase, k=4))

def gen_business_key():
    n = random.randint(8, 16)
    # Guarantee at least one special char (matching sample pattern)
    base = random.choices(_BK_CHARS, k=n - 1)
    base.append(random.choice(_BK_SPECIAL))
    random.shuffle(base)
    return ''.join(base)

def gen_mac():
    return ':'.join(f'{random.randint(0,255):02X}' for _ in range(6))

def gen_secret_code():
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))

# ── Main ──────────────────────────────────────────────────────────────────────

N       = 300_000
OUT     = os.path.join(os.path.dirname(__file__), 'table_data.csv')
HEADER  = ['user_id','serial_no','user_code','business_key',
           'id_card','phone','name','email',
           'device_id','trans_id','secret_code']

print(f"Generating {N:,} rows → {OUT}")

with open(OUT, 'w', newline='', encoding='utf-8') as f:
    w = csv.writer(f)
    w.writerow(HEADER)
    for _ in range(N):
        w.writerow([
            random.randint(10_000,    99_999),               # user_id      5-digit
            random.randint(1_000_000_000_000,
                           9_999_999_999_999),               # serial_no   13-digit
            gen_user_code(),                                  # user_code    4 uppercase
            gen_business_key(),                               # business_key 8-16 mixed
            gen_id_card(),                                    # id_card      18-char
            gen_phone(),                                      # phone        11-digit
            gen_name(),                                       # name         2-3 CJK
            gen_email(),                                      # email
            gen_mac(),                                        # device_id    MAC format
            random.randint(100_000_000_000_000_000,
                           999_999_999_999_999_999),          # trans_id    18-digit
            gen_secret_code(),                                # secret_code  6 alphanum
        ])

size_mb = os.path.getsize(OUT) / 1024 / 1024
print(f"Done. File size: {size_mb:.1f} MB")

# Quick sanity check
with open(OUT, encoding='utf-8') as f:
    lines = f.readlines()
print(f"Lines (incl header): {len(lines):,}")
print("Sample rows:")
for row in lines[1:4]:
    print(" ", row.rstrip())
