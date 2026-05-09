import os
import stoat
import requests
import asyncio
from dotenv import load_dotenv

# ======================
# CONFIG ENV
# ======================
load_dotenv()

TOKEN = os.getenv("STOAT_TOKEN")
CHANNEL_ID = os.getenv("CHANNEL_ID")

client = stoat.Client()

seen = set()

API_URL = "https://api.osv.dev/v1/query"


# ======================
# LOOP PRINCIPALE
# ======================
async def check_linux_vulns():
    # petite pause au démarrage pour laisser le client se connecter
    await asyncio.sleep(3)

    channel = await client.fetch_channel(CHANNEL_ID)

    while True:
        try:
            response = requests.post(
                API_URL,
                json={"query": "linux kernel"},
                timeout=10
            )

            data = response.json()
            vulns = data.get("vulns", [])

            for vuln in vulns[:10]:
                vuln_id = vuln.get("id")

                if not vuln_id or vuln_id in seen:
                    continue

                seen.add(vuln_id)

                summary = vuln.get("summary", "Pas de résumé disponible")

                severity = "Inconnue"
                try:
                    severity = vuln["severity"][0].get("score", "Inconnue")
                except Exception:
                    pass

                message = (
                    "🚨 **Nouvelle faille Linux détectée**\n\n"
                    f"🆔 ID : {vuln_id}\n"
                    f"⚠️ Sévérité : {severity}\n"
                    f"📄 Résumé : {summary}"
                )

                await channel.send(message)

        except Exception as e:
            print(f"[Erreur] {e}")

        await asyncio.sleep(300)


# ======================
# EVENT READY
# ======================
@client.on(stoat.ReadyEvent)
async def ready(event):
    print("✅ Bot connecté")

    # IMPORTANT : pas de wait_until_ready, pas de loop client
    asyncio.create_task(check_linux_vulns())


# ======================
# RUN BOT
# ======================
client.run(TOKEN)