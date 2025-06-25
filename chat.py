import os
import json
import base64
import time
import asyncio
from pathlib import Path

import discord
from discord.ext import commands

import libpx  # importuje px.py (jako knihovnu libpx)

# --- KONSTANTY ---

BOT_TOKEN = "Mtoken"            # Zde vložte svůj Discord bot token (Alice)
FRIEND_USER_ID = id      # Discord User ID příjemce (Boba)
KEY_PATH = "key1.bin"
CHUNK_SIZE = 4096

# --- UŽIVATELSKÝ PROFIL ---

USERNAME = "alice"

# --- ŠIFROVACÍ STAV A KLÍČE ---
dh = None
session_keys = None  # bude dict s 'k_enc_msg', 'k_enc_files', 'k_hmac'
friend_dh_pub = None

# --- DISCORD BOT ---

intents = discord.Intents.default()
intents.messages = True
intents.dm_messages = True

bot = commands.Bot(command_prefix="!", intents=intents)

# --- RSA KLÍČE (autentizace, podpis) ---

def load_or_generate_rsa_key():
    if Path(KEY_PATH).is_file():
        with open(KEY_PATH, "rb") as f:
            n, e, d = [int.from_bytes(f.read(256), "big") for _ in range(3)]
            return libpx.RSAKeyPair(n, e, d)
    else:
        key = libpx.RSAKeyPair.generate()
        with open(KEY_PATH, "wb") as f:
            f.write(key.n.to_bytes(256, "big"))
            f.write(key.e.to_bytes(256, "big"))
            f.write(key.d.to_bytes(256, "big"))
        return key

rsa_key = load_or_generate_rsa_key()

# --- PING-PONG/ONLINE TEST ---

async def ping_peer():
    # Pošle ping zprávu, čeká na pong
    ping_msg = {
        "type": "ping",
        "from": USERNAME,
        "timestamp": int(time.time())
    }
    # Podepiš ping
    token = f"{ping_msg['timestamp']}|{USERNAME}".encode()
    signature = rsa_key.sign(token)
    ping_msg["signature"] = [int(x) for x in signature]

    user = await bot.fetch_user(FRIEND_USER_ID)
    await user.send(json.dumps(ping_msg))
    print("Ping sent to peer, waiting for pong...")

    # Čekej na pong max 5 sekund
    for _ in range(5):
        await asyncio.sleep(1)
        if session_keys is not None:
            return True
    print("Peer isn't online, test another time!")
    return False

# --- KEY EXCHANGE ---

async def start_session():
    # Inicializace DH, pošle veřejný DH klíč
    global dh
    dh = libpx.DH2048()
    dh_pub_bytes = dh.get_public_bytes()
    msg = {
        "type": "dh_public",
        "from": USERNAME,
        "payload": base64.b64encode(dh_pub_bytes).decode()
    }
    user = await bot.fetch_user(FRIEND_USER_ID)
    await user.send(json.dumps(msg))
    print("Sent DH public key, wait for peer...")

def derive_session_keys(shared_secret: int):
    # Derivace klíčů: 32B pro AES msg, 32B pro AES files, 32B pro HMAC
    k_enc_msg = libpx.DH2048.kdf_hkdf_sha256(shared_secret, info=b"AES256-CBC msg", length=32)
    k_enc_files = libpx.DH2048.kdf_hkdf_sha256(shared_secret, info=b"AES256-CTR file", length=32)
    k_hmac = libpx.DH2048.kdf_hkdf_sha256(shared_secret, info=b"HMAC-SHA256", length=32)
    return {"k_enc_msg": k_enc_msg, "k_enc_files": k_enc_files, "k_hmac": k_hmac}

# --- ŠIFROVÁNÍ/DEŠIFROVÁNÍ ZPRÁV ---

def encrypt_message(plaintext: str):
    # AES-256-CBC + HMAC-SHA256
    iv = libpx.get_random_bytes(16)
    aes = libpx.AESModeOfOperationCBC(session_keys["k_enc_msg"], iv)
    ciphertext = aes.encrypt(plaintext.encode("utf-8"))
    hmac_tag = libpx.hmac_sha256(session_keys["k_hmac"], iv + ciphertext)
    return {
        "iv": base64.b64encode(iv).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "hmac": base64.b64encode(hmac_tag).decode()
    }

def decrypt_message(msg_obj):
    iv = base64.b64decode(msg_obj["iv"])
    ciphertext = base64.b64decode(msg_obj["ciphertext"])
    expected_hmac = base64.b64decode(msg_obj["hmac"])
    if libpx.hmac_sha256(session_keys["k_hmac"], iv + ciphertext) != expected_hmac:
        raise Exception("HMAC verification failed!")
    aes = libpx.AESModeOfOperationCBC(session_keys["k_enc_msg"], iv)
    plaintext = aes.decrypt(ciphertext).decode("utf-8")
    return plaintext

# --- ŠIFROVÁNÍ/DEŠIFROVÁNÍ SOUBORŮ ---

def encrypt_file_chunk(chunk: bytes, ctr: int):
    nonce = ctr.to_bytes(16, "big")  # 16B nonce/counter
    aes = libpx.AESModeOfOperationCTR(session_keys["k_enc_files"], counter=libpx.Counter(int.from_bytes(nonce, "big")))
    ciphertext = aes.encrypt(chunk)
    hmac_tag = libpx.hmac_sha256(session_keys["k_hmac"], ciphertext)
    return ciphertext, hmac_tag

def decrypt_file_chunk(ciphertext: bytes, hmac_tag: bytes, ctr: int):
    if libpx.hmac_sha256(session_keys["k_hmac"], ciphertext) != hmac_tag:
        raise Exception("HMAC verification failed on file chunk!")
    nonce = ctr.to_bytes(16, "big")
    aes = libpx.AESModeOfOperationCTR(session_keys["k_enc_files"], counter=libpx.Counter(int.from_bytes(nonce, "big")))
    chunk = aes.decrypt(ciphertext)
    return chunk

# --- UPLOAD / DOWNLOAD SOUBORŮ ---

async def upload_file(filepath: str, friend_username: str):
    # Posílá chunk po chunku
    filename = os.path.basename(filepath)
    user = await bot.fetch_user(FRIEND_USER_ID)
    with open(filepath, "rb") as f:
        ctr = 0
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            ciphertext, hmac_tag = encrypt_file_chunk(chunk, ctr)
            msg = {
                "type": "file_chunk",
                "from": USERNAME,
                "to": friend_username,
                "filename": filename,
                "chunk_index": ctr,
                "payload": base64.b64encode(ciphertext).decode(),
                "hmac": base64.b64encode(hmac_tag).decode(),
                "is_last_chunk": False
            }
            await user.send(json.dumps(msg))
            ctr += 1
        # Pošle end_of_file
        msg = {
            "type": "file_chunk",
            "from": USERNAME,
            "to": friend_username,
            "filename": filename,
            "chunk_index": ctr,
            "payload": "",
            "hmac": "",
            "is_last_chunk": True
        }
        await user.send(json.dumps(msg))
    print(f"File {filename} upload complete.")

async def download_file(friend_username: str, save_path: str):
    # Přijímá chunk zprávy, skládá do souboru
    received_chunks = {}
    filename = None
    last_index = None
    save_full_path = None
    while True:
        await asyncio.sleep(0.5)
        # Kontroluje frontu zpráv (v reálné integraci udělej v on_message)
        if "file_chunk_queue" in globals() and file_chunk_queue:
            msg = file_chunk_queue.pop(0)
            if msg["from"] != friend_username:
                continue
            if filename is None:
                filename = msg["filename"]
                save_full_path = os.path.join(save_path, filename)
                f = open(save_full_path, "wb")
            if msg["is_last_chunk"]:
                f.close()
                print(f"File {filename} download complete.")
                break
            ctr = msg["chunk_index"]
            ciphertext = base64.b64decode(msg["payload"])
            hmac_tag = base64.b64decode(msg["hmac"])
            chunk = decrypt_file_chunk(ciphertext, hmac_tag, ctr)
            f.write(chunk)

# --- DISCORD EVENT HANDLERY ---

file_chunk_queue = []

@bot.event
async def on_ready():
    print(f"{USERNAME} bot is ready and online!")
    await ping_peer()
    await start_session()

@bot.event
async def on_message(message):
    global session_keys, friend_dh_pub

    if message.author.id == bot.user.id:
        return  # ignore itself

    try:
        data = json.loads(message.content)
    except Exception:
        return

    if data.get("type") == "pong":
        print("Peer is online, initiating key exchange...")
        # Pokračuj v key exchange, pokud potřeba

    elif data.get("type") == "dh_public":
        friend_dh_pub_bytes = base64.b64decode(data["payload"])
        friend_dh_pub = int.from_bytes(friend_dh_pub_bytes, "big")
        # Odpověz vlastním DH pub pokud nemáš session key
        if session_keys is None:
            await start_session()
        # Spočítej shared secret
        shared_secret = dh.compute_shared_secret(friend_dh_pub)
        session_keys = derive_session_keys(shared_secret)
        print("Session keys derived. Secure chat ready.")

    elif data.get("type") == "msg":
        # Přijmi šifrovanou zprávu, dešifruj a zobraz
        plaintext = decrypt_message(data)
        print(f"[{data['from']}] {plaintext}")

    elif data.get("type") == "file_chunk":
        file_chunk_queue.append(data)
        # GUI: signalizuj progress atd.

# --- ODESÍLÁNÍ ZPRÁV ---

async def send_message(text, friend_username):
    obj = encrypt_message(text)
    obj.update({
        "type": "msg",
        "from": USERNAME,
        "to": friend_username
    })
    user = await bot.fetch_user(FRIEND_USER_ID)
    await user.send(json.dumps(obj))

def display_pyidenticon(username):
    # (Pseudo) pyidenticon generátor
    import hashlib
    import pyidenticon
    hash_bytes = hashlib.sha256(username.encode()).digest()
    pyidenticon.draw(hash_bytes, 5, 120, f"{username}_identicon.png")
    # GUI: zobraz obrázek

# --- MAIN ---

if __name__ == "__main__":
    bot.run(BOT_TOKEN)
