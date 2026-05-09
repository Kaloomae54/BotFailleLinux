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

            response = requests.post(API_URL, json=payload)
            data = response.json()

            vulns = data.get("vulns", [])

            for vuln in vulns[:5]:
                vuln_id = vuln["id"]

                if vuln_id not in seen:
                    seen.add(vuln_id)

                    summary = vuln.get(
                        "summary",
                        "Pas de résumé disponible"
                    )

                    severity = "Inconnue"

                    if "severity" in vuln:
                        severity = vuln["severity"][0].get(
                            "score",
                            "Inconnue"
                        )

                    message = (
                        f"🚨 Nouvelle faille Linux détectée\n\n"
                        f"🔹 ID : {vuln_id}\n"
                        f"🔹 Sévérité : {severity}\n"
                        f"🔹 Résumé : {summary}"
                    )

                    await channel.send(message)

        except Exception as e:
            print(f"Erreur : {e}")

        # Attend 5 minutes
        await asyncio.sleep(300)

@client.on(stoat.ReadyEvent)
async def ready(event):
    print("✅ Bot connecté")
    client.loop.create_task(check_linux_vulns())

client.run(TOKEN)