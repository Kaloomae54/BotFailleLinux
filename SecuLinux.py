import os
import stoat
import requests
import asyncio

from dotenv import load_dotenv

# Charge les variables d'environnement
load_dotenv()

TOKEN = os.getenv("STOAT_TOKEN")
CHANNEL_ID = os.getenv("CHANNEL_ID")

client = stoat.Client()

# Stocke les failles déjà envoyées (reset si redémarrage)
seen = set()

API_URL = "https://api.osv.dev/v1/query"


async def check_linux_vulns():
    await client.wait_until_ready()

    channel = await client.fetch_channel(CHANNEL_ID)

    while True:
        try:
            payload = {
                "query": "linux kernel"
            }

            response = requests.post(API_URL, json=payload, timeout=10)
            data = response.json()

            vulns = data.get("vulns", [])

            for vuln in vulns[:10]:
                vuln_id = vuln.get("id")

                if not vuln_id or vuln_id in seen:
                    continue

                seen.add(vuln_id)

                summary = vuln.get("summary", "Pas de résumé disponible")

                # Sévérité si dispo
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
            print(f"[Erreur API] {e}")

        await asyncio.sleep(300)  # 5 minutes


@client.on(stoat.ReadyEvent)
async def ready(event):
    print("✅ Bot Stoat connecté")

    # IMPORTANT : nouvelle méthode compatible asyncio
    asyncio.create_task(check_linux_vulns())


client.run(TOKEN)