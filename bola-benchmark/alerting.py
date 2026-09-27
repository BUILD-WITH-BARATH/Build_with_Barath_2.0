"""
Multi-channel alerting system: Email, Slack, Webhooks
Dispatches security events, quota warnings, compliance alerts.
"""
import json
import os
import smtplib
import asyncio
import httpx
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Optional

# Email configuration (defaults can be overridden via env)
SMTP_HOST = os.environ.get("SMTP_HOST", "localhost")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "noreply@cyberaccess.io")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
SMTP_ENABLED = os.environ.get("SMTP_ENABLED", "false").lower() == "true"

# Slack configuration
SLACK_TIMEOUT = 5  # seconds


class AlertDispatcher:
    """Dispatch alerts to configured channels."""

    @staticmethod
    async def send_email_alert(
        recipient: str,
        subject: str,
        body: str,
        alert_type: str = "security"
    ) -> bool:
        """Send email alert (async-compatible)."""
        if not SMTP_ENABLED or not SMTP_PASSWORD:
            return False

        try:
            msg = MIMEMultipart()
            msg["From"] = SMTP_USER
            msg["To"] = recipient
            msg["Subject"] = subject

            # HTML email
            html = f"""
            <html>
              <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                <div style="max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #ddd; border-radius: 8px;">
                  <h2 style="color: #e74c3c;">CyberAccess Security Alert</h2>
                  <p><strong>Alert Type:</strong> {alert_type.upper()}</p>
                  <hr style="border: none; border-top: 1px solid #ddd; margin: 20px 0;">
                  <div>{body}</div>
                  <hr style="border: none; border-top: 1px solid #ddd; margin: 20px 0;">
                  <p style="font-size: 12px; color: #666;">
                    This is an automated alert from CyberAccess BOLA Defense System.
                    <br>Do not reply to this email.
                  </p>
                </div>
              </body>
            </html>
            """
            msg.attach(MIMEText(html, "html"))

            # Send (non-blocking via thread pool)
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(
                None,
                lambda: smtplib.SMTP(SMTP_HOST, SMTP_PORT).starttls()
                or smtplib.SMTP(SMTP_HOST, SMTP_PORT).sendmail(SMTP_USER, recipient, msg.as_string())
            )
            return True
        except Exception as e:
            print(f"[alerting] Email failed: {e}")
            return False

    @staticmethod
    async def send_slack_alert(
        webhook_url: str,
        title: str,
        message: str,
        severity: str = "info",
        tenant_id: str = "unknown"
    ) -> bool:
        """Send Slack webhook alert."""
        try:
            # Color based on severity
            colors = {
                "critical": "#e74c3c",  # Red
                "warning": "#f39c12",   # Orange
                "info": "#3498db"       # Blue
            }
            color = colors.get(severity, "#3498db")

            payload = {
                "attachments": [
                    {
                        "fallback": title,
                        "color": color,
                        "title": title,
                        "text": message,
                        "fields": [
                            {"title": "Severity", "value": severity.upper(), "short": True},
                            {"title": "Tenant", "value": tenant_id, "short": True}
                        ],
                        "footer": "CyberAccess BOLA Defense",
                        "ts": int(time.time())
                    }
                ]
            }

            async with httpx.AsyncClient(timeout=SLACK_TIMEOUT) as client:
                response = await client.post(webhook_url, json=payload)
                return response.status_code == 200
        except Exception as e:
            print(f"[alerting] Slack failed: {e}")
            return False

    @staticmethod
    async def send_webhook_alert(
        webhook_url: str,
        event: dict
    ) -> bool:
        """Send generic webhook POST."""
        try:
            async with httpx.AsyncClient(timeout=SLACK_TIMEOUT) as client:
                response = await client.post(webhook_url, json=event)
                return response.status_code in [200, 201, 202]
        except Exception as e:
            print(f"[alerting] Webhook failed: {e}")
            return False


async def dispatch_alerts(
    tenant_id: str,
    alert_type: str,  # "quota_warning", "security_event", "compliance_alert"
    title: str,
    message: str,
    severity: str = "info",
    db=None
):
    """
    Load alert channels from DB and dispatch to all active channels.
    Non-blocking (async).
    """
    if not db:
        return

    try:
        with db() as c:
            channels = c.execute(
                "SELECT id, channel_type, channel_config FROM alert_channels "
                "WHERE tenant_id = %s AND is_active = true",
                (tenant_id,)
            ).fetchall()

        tasks = []
        for channel in channels:
            ch_type = channel["channel_type"]
            config = json.loads(channel["channel_config"])

            if ch_type == "email" and "address" in config:
                tasks.append(
                    AlertDispatcher.send_email_alert(
                        config["address"], title, message, alert_type
                    )
                )
            elif ch_type == "slack" and "url" in config:
                tasks.append(
                    AlertDispatcher.send_slack_alert(
                        config["url"], title, message, severity, tenant_id
                    )
                )
            elif ch_type == "webhook" and "url" in config:
                tasks.append(
                    AlertDispatcher.send_webhook_alert(
                        config["url"],
                        {
                            "tenant_id": tenant_id,
                            "alert_type": alert_type,
                            "title": title,
                            "message": message,
                            "severity": severity
                        }
                    )
                )

        # Fire all alerts concurrently
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
    except Exception as e:
        print(f"[alerting] dispatch failed: {e}")


import time
