import hashlib
import hmac
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import random
import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import jwt
import json
import os
import threading
import time

# ==== Đọc proxy từ file ====
with open("live.txt", "r") as f:
    proxy_list = [line.strip() for line in f if line.strip()]

def get_random_proxy():
    proxy = random.choice(proxy_list)
    return {
        "http": f"http://{proxy}",
        "https": f"http://{proxy}"
    }

class GarenaGuestAuth:
    def __init__(self, name, filename):
        self.name = name
        self.filename = filename
        self.secretKey = b'2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3'
        self.superscript_digits = ['⁰', '¹', '²', '³', '⁴', '⁵', '⁶', '⁷', '⁸', '⁹']
        random_num = random.randint(1, 99999)
        self.passwordRaw = f"{self.name}{''.join(self.superscript_digits[int(d)] for d in str(random_num))}"
        self.actual_password = f"c25tool{random.randint(1000000000, 9999999999)}"

        # mỗi lần reg 1 acc thì random proxy mới
        self.session = requests.Session()
        self.session.proxies.update(get_random_proxy())

    def hashPassword(self):
        return hashlib.sha256(self.actual_password.encode()).hexdigest().upper()

    def enc_var(self, number):
        encoded_bytes = []
        while True:
            byte = number & 0x7F
            number >>= 7
            encoded_bytes.append(byte | (0x80 if number else 0))
            if not number:
                break
        return bytes(encoded_bytes)

    def vfield(self, field_number, value):
        return self.enc_var((field_number << 3) | 0) + self.enc_var(value)

    def ldf(self, field_number, value):
        encoded_value = value.encode() if isinstance(value, str) else value
        return self.enc_var((field_number << 3) | 2) + self.enc_var(len(encoded_value)) + encoded_value

    def taopack(self, fields):
        packet = bytearray()
        for field in sorted(fields.keys()):
            value = fields[field]
            if isinstance(value, dict):
                packet.extend(self.ldf(field, self.taopack(value)))
            elif isinstance(value, int):
                packet.extend(self.vfield(field, value))
            elif isinstance(value, (str, bytes)):
                packet.extend(self.ldf(field, value))
        return packet

    def enc_api(self, plain_text):
        plain_text = bytes.fromhex(plain_text)
        key = b"Yg&tc%DEuh6%Zc^8"
        iv = b"6oyZDr22E3ychjM%"
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return cipher.encrypt(pad(plain_text, AES.block_size)).hex()

    def taoSGT(self, data):
        return hmac.new(self.secretKey, data.encode(), hashlib.sha256).hexdigest()

    def enc_field_3(self, openId):
        key = [0, 0, 0, 2, 0, 1, 7, 0, 0, 0, 0, 0, 2, 0, 1, 7, 0, 0, 0, 0, 0, 2, 0, 1, 7, 0, 0, 0, 0, 0, 2, 0]
        return bytes(b ^ key[i % len(key)] ^ 48 for i, b in enumerate(openId.encode()))

    def decode_jwt(self, token):
        try:
            return jwt.decode(token, options={"verify_signature": False})
        except jwt.InvalidTokenError:
            return None

    def luuvaofile(self, data):
        filee = f"{self.filename}.json"
        try:
            with lockk:
                existing_data = []
                if os.path.exists(filee):
                    with open(filee, "r", encoding="utf-8") as f:
                        existing_data = json.load(f)
                uid = data["uid"]
                updated = False
                for i, entry in enumerate(existing_data):
                    if entry.get("uid") == uid:
                        existing_data[i] = data
                        updated = True
                        break
                if not updated:
                    existing_data.append(data)
                with open(filee, "w", encoding="utf-8") as f:
                    json.dump(existing_data, f, ensure_ascii=False, indent=2)
        except Exception:
            pass
    
    def run(self):
        try:
            hashedPassword = self.hashPassword()
            payloadRegister = {
                'password': hashedPassword,
                'client_type': '2',
                'source': '2',
                'app_id': '100067'
            }
            bodyRegister = '&'.join(f'{k}={v}' for k, v in payloadRegister.items())
            headersRegister = {
                'User-Agent': 'GarenaMSDK/4.0.19P9(SM-S908E ;Android 11;vi;VN;)',
                'Authorization': f'Signature {self.taoSGT(bodyRegister)}',
                'Content-Type': 'application/x-www-form-urlencoded',
                'Connection': 'Keep-Alive',
                'Accept-Encoding': 'gzip'
            }
            resRegister = self.session.post('https://100067.connect.garena.com/oauth/guest/register',
                                         data=payloadRegister, headers=headersRegister, timeout=10)
            resRegister.raise_for_status()
            uid = str(resRegister.json()['uid'])

            payloadToken = {
                'uid': uid,
                'password': hashedPassword,
                'response_type': 'token',
                'client_type': '2',
                'client_secret': '2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3',
                'client_id': '100067'
            }
            headersToken = {
                'User-Agent': 'GarenaMSDK/4.0.19P9(SM-S908E ;Android 11;vi;VN;)',
                'Content-Type': 'application/x-www-form-urlencoded',
                'Connection': 'Keep-Alive',
                'Accept-Encoding': 'gzip'
            }
            resToken = self.session.post('https://100067.connect.garena.com/oauth/guest/token/grant',
                                       data=payloadToken, headers=headersToken, timeout=10)
            resToken.raise_for_status()
            tokenData = resToken.json()
            accessToken = tokenData['access_token']
            openId = tokenData['open_id']
            encrypted_field_3 = self.enc_field_3(openId)
            payload = {
                1: self.passwordRaw,
                2: accessToken,
                3: openId,
                5: 102000007,
                6: 4,
                7: 1,
                13: 1,
                14: encrypted_field_3,
                15: "vn",
                16: 1
            }
            payload_encrypted = self.enc_api(self.taopack(payload).hex())
            headersMajor = {
                "Authorization": f"Bearer {accessToken}",
                "X-Unity-Version": "2018.4.11f1",
                "X-GA": "v1 1",
                "ReleaseVersion": "OB50",
                "Content-Type": "application/octet-stream",
                "Content-Length": str(len(bytes.fromhex(payload_encrypted))),
                "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 10; RMX1821 Build/QP1A.190711.020)",
                "Host": "loginbp.ggblueshark.com",
                "Connection": "Keep-Alive",
                "Accept-Encoding": "gzip"
            }
            resMajor = self.session.post('https://loginbp.ggblueshark.com/MajorRegister',
                                       data=bytes.fromhex(payload_encrypted), headers=headersMajor, timeout=10)
            if resMajor.status_code != 200:
                if resMajor.status_code == 400:
                    print("\033[39mĐã Bị \033[31mBlock\033[32m IP\033[39m, Vui Lòng \033[33mFake\033[32m IP\033[39m Mới. Đổi \033[32mIP\033[39m Xong Thì Bấm \033[35mENTER\033[39m!!!")
                    input()
                else:
                    print("\033[31mLỗi Reg Vui Lòng Kiểm Tra Lại!!")
                return None
            account_data = {
                "access_token": accessToken,
                "open_id": openId,
                "name": self.passwordRaw,
                "uid": uid,
                "password": self.actual_password
            }
            self.luuvaofile({
                "uid": account_data['uid'],
                "password": hashedPassword
            })
            return account_data
        except Exception as e:
            return None
        finally:
            self.session.close()

lockk = threading.Lock()
registered_count = 0
count_lock = threading.Lock()

def startreg(target_count, name, filename):
    global registered_count
    auth = GarenaGuestAuth(name, filename)
    result = auth.run()
    
    if result:
        with count_lock:
            registered_count += 1
            current_count = registered_count
        print(f"\033[39m╭Đang Reg \033[31m{current_count}\033[39m/\033[32m{target_count}\n"
              f"\033[39m╰─➤Name: \033[35m{result['name']:<8} \033[39m│ "
              f"Uid: \033[33m{result['uid']:<10} \033[39m│ "
              f"Password: \033[34m{result['password']}\033[39m")
        return True
    return False

def autoregluong(soaccreg=1000, soluong=50, name="", filename=""):
    global registered_count
    registered_count = 0
    print(f"\033[39mBắt Đầu \033[32mAuto Reg \033[31m{soaccreg} \033[39mAcc Với \033[31m{soluong} \033[39mLuồng...")
    start_time = time.time()
    successful_registrations = 0
    
    with ThreadPoolExecutor(max_workers=soluong) as executor:
        futures = []
        while successful_registrations < soaccreg:
            remaining = soaccreg - successful_registrations
            batch_size = min(remaining, soluong)
            futures = [executor.submit(startreg, soaccreg, name, filename) for _ in range(batch_size)]
            for future in as_completed(futures):
                try:
                    if future.result():
                        successful_registrations += 1
                    if successful_registrations >= soaccreg:
                        break
                except Exception as e:
                    print(f"\033[31mThread error: {str(e)}\033[39m")
        for future in futures:
            if not future.done():
                future.cancel()
    
    end_time = time.time()
    elapsed_time = end_time - start_time
    
    print(f"\n\033[39m╭─────────────────────────────────────╮")
    print(f"│ Thành Công: \033[32m{successful_registrations:<3} \033[39mTài Khoản           │")
    print(f"│ Thời Gian: \033[35m{elapsed_time:.2f}\033[39m Giây               │")
    print(f"╰─────────────────────────────────────╯")

def regnhurua(soaccreg=1000, name="", filename=""):
    global registered_count
    registered_count = 0
    start_time = time.time()
    
    while registered_count < soaccreg:
        if startreg(soaccreg, name, filename):
            registered_count += 1
    
    end_time = time.time()
    elapsed_time = end_time - start_time
    print(f"\n\033[39m╭─────────────────────────────────────╮")
    print(f"│ Thành Công: \033[32m{registered_count:<3} \033[39mTài Khoản           │")
    print(f"│ Thời Gian: \033[35m{elapsed_time:.2f}\033[39m Giây               │")
    print(f"╰─────────────────────────────────────╯")

if __name__ == '__main__':
    while True:
        n = input("\033[39mNhập Tên Acc Reg (\033[31mMax 8 Kí Tự\033[39m):\033[36m ").strip()
        if len(n) <= 7:
            name = n
            break
        else:
            print("\033[39mTên Không Được Vượt Quá 7 Ký Tự. Vui Lòng Nhập Lại.")
    
    f = input("\033[39mNhập Tên File Lưu Acc Reg:\033[36m ").strip()
    filename = f
    print("\033[33m1. \033[39mĐa Luồng (\033[32mNhanh\033[39m)")
    print("\033[33m2. \033[39mTuần Tự (\033[31mChậm\033[39m)")
    choice = input("\033[39mChọn Phương Thức Số:\033[36m ").strip()
    
    try:
        soaccreg = int(input("\033[39mNhập Số Lượng Cần Reg:\033[36m "))
    except ValueError:
        soaccreg = 100
        print("\033[39mMặc Định: \033[33m100 \033[39mTài Khoản")
    
    if choice == "1":
        try:
            soluong = int(input("\033[39mNhập Số Luồng (Nên Để \033[33m20\033[39m-\033[33m50\033[39m):\033[36m "))
        except ValueError:
            soluong = 50
            print("\033[39mMặc Định Luồng Là: \033[33m50")
        
        autoregluong(soaccreg=soaccreg, soluong=soluong, name=name, filename=filename)
    else:
        regnhurua(soaccreg=soaccreg, name=name, filename=filename)