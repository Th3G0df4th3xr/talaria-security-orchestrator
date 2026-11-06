"""TALARIA Security Command Center — Streamlit presentation layer."""


import pandas as pd
import plotly.express as px
import streamlit as st

from talaria.dashboard.client import (
    DashboardAPIError,
    TalariaAPIClient,
)

st.set_page_config(
    page_title="TALARIA | Security Command Center",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

client = TalariaAPIClient()

st.markdown(
    """
    <style>
    .block-container {padding-top: 1.8rem; padding-bottom: 2rem;}
    [data-testid="stMetric"] {
        background: rgba(128, 128, 128, 0.08);
        border: 1px solid rgba(128, 128, 128, 0.18);
        padding: 16px;
        border-radius: 10px;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


def load_data():
    """Retrieve dashboard data exclusively through the TALARIA API."""
    return {
        "health": client.health(),
        "summary": client.summary(),
        "repositories": client.repositories(),
        "scans": client.scans(),
        "severity": client.severity(),
        "trends": client.trends(days=30),
        "findings": client.findings(),
    }


def display_time(value):
    return value or "—"


st.sidebar.title("🛡️ TALARIA")
st.sidebar.caption("Security Orchestration Command Center")
st.sidebar.divider()

if st.sidebar.button("↻ Refresh dashboard", use_container_width=True):
    st.rerun()

st.sidebar.caption("Local-first • API-driven • Human-controlled")

st.title("Security Command Center")
st.caption("Repository intelligence · Scan operations · Finding lifecycle")

try:
    data = load_data()
except DashboardAPIError as exc:
    st.error(f"Backend unavailable: {exc}")
    st.info(
        "Start the FastAPI backend in another terminal:\n\n"
        "`uvicorn talaria.api:app --host 127.0.0.1 --port 8000`"
    )
    st.stop()

health = data["health"]
summary = data["summary"]
repositories = data["repositories"]
scans = data["scans"]
severity = data["severity"]
trends = data["trends"]
findings = data["findings"]

if health.get("status") == "ok":
    st.success(
        f"● Backend online  |  "
        f"{health.get('service', 'TALARIA')} "
        f"v{health.get('version', 'unknown')}"
    )
else:
    st.warning("Backend responded, but its health status is not OK.")

st.divider()

# Operational overview
st.subheader("Operational Overview")

scan_stats = summary.get("scans", {})
finding_stats = summary.get("findings", {})

metrics = st.columns(5)
metrics[0].metric("Repositories", summary.get("repositories", 0))
metrics[1].metric("Total scans", scan_stats.get("total", 0))
metrics[2].metric("Completed scans", scan_stats.get("completed", 0))
metrics[3].metric("Failed scans", scan_stats.get("failed", 0))
metrics[4].metric("Total findings", finding_stats.get("total", 0))

status_metrics = st.columns(5)
status_metrics[0].metric("Open", finding_stats.get("open", 0))
status_metrics[1].metric("Confirmed", finding_stats.get("confirmed", 0))
status_metrics[2].metric("Fixed", finding_stats.get("fixed", 0))
status_metrics[3].metric(
    "False positives",
    finding_stats.get("false_positive", 0),
)
status_metrics[4].metric(
    "Running scans",
    scan_stats.get("running", 0),
)

st.divider()

# Severity and trends
left, right = st.columns(2)

with left:
    st.subheader("Finding Severity")
    distribution = severity.get("distribution", {})
    severity_frame = pd.DataFrame(
        [
            {"Severity": name.title(), "Findings": count}
            for name, count in distribution.items()
        ]
    )

    if not severity_frame.empty and severity_frame["Findings"].sum():
        figure = px.pie(
            severity_frame,
            names="Severity",
            values="Findings",
            hole=0.58,
            title="Severity distribution",
        )
        figure.update_layout(
            legend_title_text="Severity",
            margin=dict(t=50, b=10, l=10, r=10),
        )
        st.plotly_chart(figure, use_container_width=True)
    else:
        st.info("No findings are available for severity analysis.")

with right:
    st.subheader("Finding Trends — 30 Days")
    trend_rows = trends.get("data", [])
    trend_frame = pd.DataFrame(trend_rows)

    if not trend_frame.empty:
        figure = px.line(
            trend_frame,
            x="date",
            y=["occurrences", "unique_findings"],
            markers=True,
            labels={
                "value": "Count",
                "date": "Date",
                "variable": "Metric",
            },
        )
        figure.update_layout(
            legend_title_text="Metric",
            margin=dict(t=30, b=10, l=10, r=10),
        )
        st.plotly_chart(figure, use_container_width=True)
    else:
        st.info("No finding occurrences recorded in this period.")

st.divider()

# Repository inventory
st.subheader("Repository Inventory")

if repositories:
    repository_frame = pd.DataFrame(repositories)
    visible_columns = [
        column
        for column in ("id", "name", "registered_at")
        if column in repository_frame.columns
    ]
    st.dataframe(
        repository_frame[visible_columns],
        use_container_width=True,
        hide_index=True,
    )
else:
    st.info("No repositories have been onboarded yet.")

with st.expander("＋ Register a Git repository"):
    with st.form("register_repository_form"):
        repository_path = st.text_input(
            "Local Git repository path",
            placeholder="/Users/you/Projects/example",
        )
        register_submitted = st.form_submit_button(
            "Register repository",
            type="primary",
        )

    if register_submitted:
        if not repository_path.strip():
            st.warning("Enter a repository path.")
        else:
            try:
                result = client.register_repository(
                    repository_path.strip()
                )
                st.success(
                    f"Repository registered: {result.get('name', 'success')}"
                )
                st.rerun()
            except DashboardAPIError as exc:
                st.error(str(exc))

st.divider()

# Scan history and execution
st.subheader("Scan Operations")

with st.expander("＋ Start a repository scan"):
    repository_options = {
        item.get("name", str(item.get("id"))): item.get("path")
        for item in repositories
        if item.get("path")
    }

    if repository_options:
        with st.form("start_scan_form"):
            selected_repository = st.selectbox(
                "Repository",
                options=list(repository_options),
            )
            scan_submitted = st.form_submit_button(
                "Run scan",
                type="primary",
            )

        if scan_submitted:
            try:
                result = client.run_scan(
                    repository_options[selected_repository]
                )
                st.success(
                    f"Scan finished with status: "
                    f"{result.get('status', 'submitted')}"
                )
                st.rerun()
            except DashboardAPIError as exc:
                st.error(str(exc))
    else:
        st.info("Register a repository before starting a scan.")

if scans:
    scan_frame = pd.DataFrame(scans)
    visible_columns = [
        column
        for column in (
            "id",
            "repository",
            "started_at",
            "completed_at",
            "status",
            "finding_count",
            "error_summary",
        )
        if column in scan_frame.columns
    ]
    st.dataframe(
        scan_frame[visible_columns],
        use_container_width=True,
        hide_index=True,
    )
else:
    st.info("No scans have been recorded yet.")

st.divider()

# Finding management
st.subheader("Finding Management")

if findings:
    filter_columns = st.columns(3)

    statuses = sorted(
        {str(item.get("status", "unknown")) for item in findings}
    )
    severities = sorted(
        {
            str(item.get("payload", {}).get("severity", "unknown")).lower()
            for item in findings
        }
    )

    selected_status = filter_columns[0].selectbox(
        "Status",
        ["All", *statuses],
    )
    selected_severity = filter_columns[1].selectbox(
        "Severity",
        ["All", *severities],
    )
    search_term = filter_columns[2].text_input(
        "Search findings",
        placeholder="Title, rule or fingerprint",
    )

    filtered_findings = []

    for item in findings:
        payload = item.get("payload") or {}
        item_status = str(item.get("status", "unknown"))
        item_severity = str(
            payload.get("severity", "unknown")
        ).lower()
        searchable = " ".join(
            str(payload.get(key, ""))
            for key in ("title", "rule_id", "description", "message")
        ) + " " + str(item.get("fingerprint", ""))

        if selected_status != "All" and item_status != selected_status:
            continue
        if (
            selected_severity != "All"
            and item_severity != selected_severity
        ):
            continue
        if search_term and search_term.lower() not in searchable.lower():
            continue

        filtered_findings.append(item)

    display_rows = []
    for item in filtered_findings:
        payload = item.get("payload") or {}
        display_rows.append(
            {
                "ID": item.get("id"),
                "Title": (
                    payload.get("title")
                    or payload.get("rule_id")
                    or payload.get("message")
                    or "Untitled finding"
                ),
                "Severity": str(
                    payload.get("severity", "unknown")
                ).upper(),
                "Status": item.get("status"),
                "First seen": item.get("first_seen_at"),
                "Last seen": item.get("last_seen_at"),
            }
        )

    st.caption(f"Showing {len(filtered_findings)} of {len(findings)} findings")
    st.dataframe(
        pd.DataFrame(display_rows),
        use_container_width=True,
        hide_index=True,
    )

    if filtered_findings:
        finding_ids = [item["id"] for item in filtered_findings]
        selected_id = st.selectbox(
            "Inspect finding",
            finding_ids,
            format_func=lambda value: f"Finding #{value}",
        )

        try:
            detail = client.finding(selected_id)
            payload = detail.get("payload") or {}

            with st.expander(
                f"Finding #{selected_id} — Details",
                expanded=True,
            ):
                st.write(
                    {
                        "Title": payload.get("title"),
                        "Rule": payload.get("rule_id"),
                        "Severity": payload.get("severity"),
                        "Status": detail.get("status"),
                        "Fingerprint": detail.get("fingerprint"),
                        "First seen": detail.get("first_seen_at"),
                        "Last seen": detail.get("last_seen_at"),
                    }
                )
                st.markdown("**Description**")
                st.write(
                    payload.get("description")
                    or payload.get("message")
                    or "No description supplied."
                )
                st.markdown("**Occurrences**")
                occurrences = detail.get("occurrences", [])
                if occurrences:
                    st.dataframe(
                        pd.DataFrame(occurrences),
                        use_container_width=True,
                        hide_index=True,
                    )
                else:
                    st.caption("No occurrence history available.")

            current_status = detail.get("status", "")
            all_statuses = [
                "open",
                "needs_review",
                "confirmed",
                "false_positive",
                "accepted_risk",
                "fixed",
                "reopened",
            ]

            with st.form(f"finding_status_form_{selected_id}"):
                target_status = st.selectbox(
                    "New lifecycle status",
                    all_statuses,
                    index=(
                        all_statuses.index(current_status)
                        if current_status in all_statuses
                        else 0
                    ),
                )
                update_submitted = st.form_submit_button(
                    "Update finding status"
                )

            if update_submitted:
                try:
                    result = client.update_finding_status(
                        selected_id,
                        target_status,
                    )
                    if result.get("changed"):
                        st.success(
                            f"Status updated to {target_status}."
                        )
                    else:
                        st.info("Finding already has that status.")
                    st.rerun()
                except DashboardAPIError as exc:
                    st.error(str(exc))
        except DashboardAPIError as exc:
            st.error(str(exc))
else:
    st.info("No findings are available yet.")

st.divider()
st.caption(
    "TALARIA local MVP · All dashboard data is retrieved through the "
    "FastAPI service. Lifecycle transitions are enforced by the backend."
)
