"""
Slack notification integration — SEV-1 incidents only.
Posts a rich block message to the configured channel.
"""
import os
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
from backend.models.schemas import EnsembleOutput, Severity

SEVERITY_EMOJI = {
    Severity.SEV1: "🔴",
    Severity.SEV2: "🟠",
    Severity.SEV3: "🟡",
    Severity.SEV4: "🟢",
}


def notify(alert_text: str, result: EnsembleOutput) -> bool:
    """Post a SEV-1 incident classification notification to Slack. Returns True on success."""
    token = os.getenv("SLACK_BOT_TOKEN")
    channel = os.getenv("SLACK_CHANNEL_ID")

    if not token or not channel:
        return False

    final = result.final_decision

    # Only notify for SEV-1
    if final.severity != Severity.SEV1:
        return False

    client = WebClient(token=token)
    emoji = SEVERITY_EMOJI.get(final.severity, "⚪")

    # Truncate alert_text for display
    display_title = alert_text[:120] + "..." if len(alert_text) > 120 else alert_text

    blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"{emoji} SEV-1 INCIDENT — Immediate Action Required",
            },
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Alert:*\n{display_title}"},
                {"type": "mrkdwn", "text": f"*Category:*\n`{final.category.value}`"},
                {"type": "mrkdwn", "text": f"*Severity:*\n*{final.severity.value}*"},
                {"type": "mrkdwn", "text": f"*Confidence:*\n{final.confidence:.0%}"},
                {"type": "mrkdwn", "text": f"*Route To:*\n{final.route_to}"},
                {"type": "mrkdwn", "text": f"*Escalation Required:*\n{'Yes ⚠️' if final.escalation_required else 'No'}"},
            ],
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Recommended Action:*\n{final.recommended_action}",
            },
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "*Runbook:*\n" + "\n".join(f"• {a}" for a in final.runbook),
            },
        },
    ]

    if final.reasoning:
        blocks.append({
            "type": "context",
            "elements": [{"type": "mrkdwn", "text": f"_AI Reasoning: {final.reasoning}_"}],
        })

    if result.agreement:
        blocks.append({
            "type": "context",
            "elements": [{"type": "mrkdwn", "text": "✅ ML and LLM models agreed on this classification"}],
        })

    try:
        client.chat_postMessage(channel=channel, blocks=blocks, text=f"SEV-1: {display_title}")
        return True
    except SlackApiError:
        return False
