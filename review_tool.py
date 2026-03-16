#!/usr/bin/env python3
"""
Review Tool - Simple CLI tool to review processes requiring inspection.

Usage:
    python3 review_tool.py           # List all unreviewed records
    python3 review_tool.py --all     # Show all records (including reviewed)
    python3 review_tool.py --stats   # Show statistics
"""
import json
import sys
from typing import List, Dict
from pathlib import Path


REVIEW_QUEUE = "logs/review_queue.jsonl"
WHITELIST = "logs/whitelist.jsonl"
CONFIRMED_THREATS = "logs/alerts.jsonl"


def load_jsonl(path: str) -> List[Dict]:
    """Load all records from a JSONL file."""
    if not Path(path).exists():
        return []
    
    records = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                records.append(json.loads(line))
    return records


def append_jsonl(path: str, obj: Dict) -> None:
    """Append a record to JSONL file."""
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(obj, ensure_ascii=False) + "\n")


def show_review_item(item: Dict, index: int) -> None:
    """Display a single review item."""
    print(f"\n{'='*80}")
    print(f"#{index + 1} - Severity: {item['severity']} | Score: {item['risk_score']} | PID: {item['pid']}")
    print(f"{'='*80}")
    print(f"Command: {item['event']['cmdline']}")
    print(f"Executable: {item['event'].get('exe', 'N/A')}")
    print(f"User: {item['event'].get('username', 'N/A')}")
    print(f"Matches: {', '.join(item['matches'])}")
    print(f"Time: {item['timestamp']}")
    print(f"Status: {'✓ Reviewed' if item.get('reviewed') else '⚠ Awaiting review'}")


def interactive_review() -> None:
    """Interactive review mode."""
    items = load_jsonl(REVIEW_QUEUE)
    
    if not items:
        print("✓ Review queue is empty!")
        return
    
    unreviewed = [i for i in items if not i.get("reviewed", False)]
    
    if not unreviewed:
        print(f"✓ All records have been reviewed! (Total: {len(items)})")
        print(f"  To see all: python3 review_tool.py --all")
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
            
            if choice == 's':
                # Mark as safe and add to whitelist
                item["reviewed"] = True
                item["review_decision"] = "SAFE"
                append_jsonl(WHITELIST, {
                    "cmdline_pattern": item["event"]["cmdline"][:100],
                    "name": item["event"].get("name"),
                    "reason": "User approved",
                    "timestamp": item["timestamp"]
                })
                print("✓ Marked as safe and added to whitelist.")
                break
            
            elif choice == 't':
                # Mark as threat and move to alerts
                item["reviewed"] = True
                item["review_decision"] = "THREAT"
                item["status"] = "THREAT"
                append_jsonl(CONFIRMED_THREATS, item)
                print("⚠ Marked as threat and moved to alerts.")
                break
            
            elif choice == 'i':
                print("⏭ Skipped.")
                break
            
            elif choice == 'q':
                print("\n👋 Exiting...")
                # Save reviewed items back
                save_queue(items)
                sys.exit(0)
            
            else:
                print("❌ Invalid choice. Please enter s, t, i, or q.")
    
    # Save all changes
    save_queue(items)
    print(f"\n✓ Review completed! {len(unreviewed)} records processed.")


def save_queue(items: List[Dict]) -> None:
    """Save review queue back to file."""
    with open(REVIEW_QUEUE, "w", encoding="utf-8") as f:
        for item in items:
            f.write(json.dumps(item, ensure_ascii=False) + "\n")


def show_stats() -> None:
    """Show statistics."""
    review_items = load_jsonl(REVIEW_QUEUE)
    alerts = load_jsonl(CONFIRMED_THREATS)
    whitelist = load_jsonl(WHITELIST)
    
    unreviewed = [i for i in review_items if not i.get("reviewed", False)]
    reviewed_safe = [i for i in review_items if i.get("review_decision") == "SAFE"]
    reviewed_threat = [i for i in review_items if i.get("review_decision") == "THREAT"]
    
    print("\n" + "="*80)
    print("📈 STATISTICS")
    print("="*80)
    print(f"\n📋 Review Queue:")
    print(f"   - Awaiting review: {len(unreviewed)}")
    print(f"   - Marked as safe: {len(reviewed_safe)}")
    print(f"   - Marked as threat: {len(reviewed_threat)}")
    print(f"   - Total: {len(review_items)}")
    
    print(f"\n🚨 Confirmed Threats: {len(alerts)}")
    print(f"✅ Whitelist: {len(whitelist)} records")
    
    if unreviewed:
        print(f"\n⚠  {len(unreviewed)} records awaiting review!")
        print(f"   To review: python3 review_tool.py")
    else:
        print(f"\n✓ All records reviewed!")


def show_all() -> None:
    """Show all review items."""
    items = load_jsonl(REVIEW_QUEUE)
    
    if not items:
        print("📋 Review queue is empty!")
        return
    
    print(f"\n📋 All Records ({len(items)} total)\n")
    
    for idx, item in enumerate(items):
        show_review_item(item, idx)


def main():
    if len(sys.argv) > 1:
        arg = sys.argv[1]
        if arg == "--stats":
            show_stats()
        elif arg == "--all":
            show_all()
        elif arg in ["-h", "--help"]:
            print(__doc__)
        else:
            print(f"❌ Unknown parameter: {arg}")
            print(__doc__)
    else:
        interactive_review()


if __name__ == "__main__":
    main()