import json
import logging
import threading
import time

from src import config
from src.collectors import Collector
from src.engine import central_push
from src.engine.llm import analyze_daily_report, analyze_weekly_report
from src.engine.sanitizer import sanitize_dict
from src.engine.notifier import post_daily_report, post_weekly_report

logger = logging.getLogger(__name__)

# Serializes daily-report runs. The scheduler runs run_daily_report in a thread
# via run_in_executor with a wait_for timeout; on timeout the asyncio side gives
# up but the executor THREAD keeps running (threads can't be cancelled), so a
# retry — or a manual POST /report racing the scheduled run — could otherwise
# execute a second report concurrently (double LLM call, double Slack post). A
# non-blocking threading.Lock is what actually prevents that; an asyncio.Lock
# would not, since the worker isn't async-aware.
_daily_report_lock = threading.Lock()


def _save_report(collector_data, result, report_type: str = "daily"):
    """Best-effort save to SQLite. Never raises."""
    try:
        from src.handlers.startup import get_store
        store = get_store()
        rid = store.save_daily_report(
            cluster=config.CLUSTER_NAME,
            collector_data=collector_data,
            result=result,
            report_type=report_type,
        )
        logger.info("%s report saved (id=%d)", report_type.capitalize(), rid)
    except Exception:
        logger.warning("Failed to persist %s report", report_type, exc_info=True)


def run_daily_report(*, suppress_error_output: bool = False) -> bool:
    """Generate, persist and post the daily report.

    Returns True when the LLM produced a real report, False when the LLM call
    itself failed (provider outage / timeout). The scheduler uses this to
    decide whether to re-attempt the report later in the day.

    `suppress_error_output`: when True and the LLM call failed transiently,
    skip saving/posting the error placeholder — the caller is going to retry,
    and we don't want to spam Slack (or persist an error report row) on every
    intermediate attempt. The final attempt is run with this False so a
    genuine, sustained outage is still surfaced.
    """
    if not _daily_report_lock.acquire(blocking=False):
        logger.warning("Daily report already in progress — skipping concurrent run")
        return False
    try:
        logger.info("Generating daily report")
        collector = Collector()
        data = collector.collect_daily_data()
        result = analyze_daily_report(data)
        if result.llm_error and suppress_error_output:
            logger.warning("Daily report LLM call failed — suppressing output, caller will retry")
            return False
        _save_report(data, result)
        post_daily_report(result)
        central_push.push_report({
            "created_at": time.time(),
            "overall_status": result.parsed.get("overall_status", "") if result.parsed else "",
            "summary": result.parsed.get("summary", "") if result.parsed else "",
            "analysis_json": json.dumps(result.parsed) if result.parsed else "",
            "collector_data_json": json.dumps(sanitize_dict(data), default=str),
            "llm_model": result.model,
            "cost_usd": result.cost_usd or 0.0,
        })
        logger.info("Daily report sent (status=%s)",
                    result.parsed.get("overall_status", "?") if result.parsed else "error")
        return not result.llm_error
    finally:
        _daily_report_lock.release()


def run_weekly_report():
    logger.info("Generating weekly report")
    from src.collectors.daily import collect_weekly_data
    data = collect_weekly_data()
    result = analyze_weekly_report(data)
    _save_report(data, result, report_type="weekly")
    post_weekly_report(result)
    central_push.push_report({
        "created_at": time.time(),
        "report_type": "weekly",
        "overall_status": result.parsed.get("overall_trend", "") if result.parsed else "",
        "summary": result.parsed.get("summary", "") if result.parsed else "",
        "analysis_json": json.dumps(result.parsed) if result.parsed else "",
        "collector_data_json": json.dumps(sanitize_dict(data), default=str),
        "llm_model": result.model,
        "cost_usd": result.cost_usd or 0.0,
    })
    logger.info("Weekly report sent (trend=%s)",
                result.parsed.get("overall_trend", "?") if result.parsed else "error")
