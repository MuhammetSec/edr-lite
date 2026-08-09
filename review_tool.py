#!/usr/bin/env python3
"""Review Tool - triage MEDIUM-severity detections the monitor set aside.

The monitor writes findings scored 40-69 to logs/review_queue.jsonl instead of
alerting on them. This tool walks that queue so each one can be whitelisted or
promoted to a confirmed threat.

Usage:
    python3 review_tool.py           # Interactively review pending records
    python3 review_tool.py --all     # Show all records (including reviewed)
    python3 review_tool.py --stats   # Show statistics
"""
import argparse
import sys
from typing import Dict, List

from logger import read_jsonl, rewrite_jsonl, write_jsonl

REVIEW_QUEUE = "logs/review_queue.jsonl"
WHITELIST = "logs/whitelist.jsonl"
CONFIRMED_THREATS = "logs/alerts.jsonl"


def show_review_item(item: Dict, index: int) -> None:
    """Display a single review item."""
    event = item.get("event", {})
    print(f"\n{'=' * 80}")
    print(
        f"#{index + 1} - Severity: {item['severity']} | "
        f"Score: {item['risk_score']} | PID: {item['pid']}"
    )
    print(f"{'=' * 80}")
    print(f"Command: {event.get('cmdline', 'N/A')}")
    print(f"Executable: {event.get('exe', 'N/A')}")
    print(f"User: {event.get('username', 'N/A')}")
    print(f"Matches: {', '.join(item.get('matches', []))}")
    print(f"Time: {item['timestamp']}")
    print(f"Status: {'✓ Reviewed' if item.get('reviewed') else '⚠ Awaiting review'}")


def save_queue(items: List[Dict]) -> None:
    """Rewrite the review queue with updated review state."""
    rewrite_jsonl(REVIEW_QUEUE, items)


def interactive_review() -> None:
    """Walk the pending queue and record a decision for each item."""
    items = read_jsonl(REVIEW_QUEUE)

    if not items:
        print("✓ Review queue is empty!")
        return

    unreviewed = [i for i in items if not i.get("reviewed", False)]

    if not unreviewed:
        print(f"✓ All records have been reviewed! (Total: {len(items)})")
        print("  To see all: python3 review_tool.py --all")
        return

    print(f"\n📋 Review Queue - {len(unreviewed)} pending records\n")

    for idx, item in enumerate(unreviewed):
        show_review_item(item, idx)

        print("\n" + "─" * 80)
        print("What would you like to do?")
        print("  [S] Safe (add to whitelist)")
        print("  [T] Threat (move to alerts)")
        print("  [I] Skip (do nothing for now)")
        print("  [Q] Quit")

        while True:
            choice = input("\nYour choice [s/t/i/q]: ").strip().lower()

            if choice == "s":
                # Mark as safe; the monitor reads this whitelist at startup
                item["reviewed"] = True
                item["review_decision"] = "SAFE"
                write_jsonl(
                    WHITELIST,
                    {
                        "cmdline_pattern": item["event"]["cmdline"][:100],
                        "name": item["event"].get("name"),
                        "reason": "User approved",
                        "timestamp": item["timestamp"],
                    },
                )
                print("✓ Marked as safe and added to whitelist.")
                break

            elif choice == "t":
                # Mark as threat and promote to the alert log
                item["reviewed"] = True
                item["review_decision"] = "THREAT"
                item["status"] = "THREAT"
                write_jsonl(CONFIRMED_THREATS, item)
                print("⚠ Marked as threat and moved to alerts.")
                break

            elif choice == "i":
                print("⏭ Skipped.")
                break

            elif choice == "q":
                print("\n👋 Exiting...")
                save_queue(items)
                sys.exit(0)

            else:
                print("❌ Invalid choice. Please enter s, t, i, or q.")

    save_queue(items)
    print(f"\n✓ Review completed! {len(unreviewed)} records processed.")


def show_stats() -> None:
    """Show statistics across the queue, alerts, and whitelist."""
    review_items = read_jsonl(REVIEW_QUEUE)
    alerts = read_jsonl(CONFIRMED_THREATS)
    whitelist = read_jsonl(WHITELIST)

    unreviewed = [i for i in review_items if not i.get("reviewed", False)]
    reviewed_safe = [i for i in review_items if i.get("review_decision") == "SAFE"]
    reviewed_threat = [i for i in review_items if i.get("review_decision") == "THREAT"]

    print("\n" + "=" * 80)
    print("📈 STATISTICS")
    print("=" * 80)
    print("\n📋 Review Queue (MEDIUM, score 40-69):")
    print(f"   - Awaiting review: {len(unreviewed)}")
    print(f"   - Marked as safe: {len(reviewed_safe)}")
    print(f"   - Marked as threat: {len(reviewed_threat)}")
    print(f"   - Total: {len(review_items)}")

    print(f"\n🚨 Alerts (HIGH/CRITICAL, score >=70): {len(alerts)}")
    for severity in ("CRITICAL", "HIGH"):
        count = sum(1 for a in alerts if a.get("severity") == severity)
        print(f"   - {severity}: {count}")
    print(f"\n✅ Whitelist: {len(whitelist)} records")

    if unreviewed:
        print(f"\n⚠  {len(unreviewed)} records awaiting review!")
        print("   To review: python3 review_tool.py")
    else:
        print("\n✓ All records reviewed!")


def show_all() -> None:
    """Show all review items, reviewed or not."""
    items = read_jsonl(REVIEW_QUEUE)

    if not items:
        print("📋 Review queue is empty!")
        return

    print(f"\n📋 All Records ({len(items)} total)\n")

    for idx, item in enumerate(items):
        show_review_item(item, idx)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Triage MEDIUM-severity detections from the monitor's review queue."
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--stats", action="store_true", help="Show statistics")
    group.add_argument(
        "--all", action="store_true", help="Show all records, including reviewed ones"
    )
    args = parser.parse_args()

    if args.stats:
        show_stats()
    elif args.all:
        show_all()
    else:
        interactive_review()


if __name__ == "__main__":
    main()
