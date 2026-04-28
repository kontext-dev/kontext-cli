import React, { useEffect, useMemo, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import "./styles.css";

const API = import.meta.env.VITE_KONTEXT_API ?? "http://127.0.0.1:4765";

function App() {
  const [sessions, setSessions] = useState([]);
  const [selectedSessionID, setSelectedSessionID] = useState("");
  const [events, setEvents] = useState([]);
  const [bucket, setBucket] = useState("ask");
  const [selectedEventID, setSelectedEventID] = useState("");
  const [error, setError] = useState("");
  const selectedSessionRef = useRef("");

  useEffect(() => {
    refresh();
    const timer = setInterval(refresh, 3000);
    return () => clearInterval(timer);
  }, []);

  useEffect(() => {
    if (selectedSessionID) loadEvents(selectedSessionID);
    selectedSessionRef.current = selectedSessionID;
  }, [selectedSessionID]);

  function refresh() {
    fetch(`${API}/api/sessions`)
      .then((res) => res.ok ? res.json() : Promise.reject(new Error(res.statusText)))
      .then((nextSessions) => {
        const safeSessions = nextSessions ?? [];
        setSessions(safeSessions);
        setError("");
        const currentSessionID = selectedSessionRef.current;
        const sessionToLoad = safeSessions.some((session) => session.session_id === currentSessionID)
          ? currentSessionID
          : safeSessions[0]?.session_id;
        if (sessionToLoad) {
          if (sessionToLoad !== currentSessionID) setSelectedSessionID(sessionToLoad);
          loadEvents(sessionToLoad);
        }
      })
      .catch((err) => setError(err.message));
  }

  function loadEvents(sessionID) {
    fetch(`${API}/api/sessions/${encodeURIComponent(sessionID)}/events`)
      .then((res) => res.ok ? res.json() : Promise.reject(new Error(res.statusText)))
      .then((nextEvents) => {
        const safeEvents = nextEvents ?? [];
        setEvents(safeEvents);
        setError("");
        setSelectedEventID((current) => {
          if (current && safeEvents.some((event) => event.id === current)) return current;
          return firstEventForBucket(safeEvents, bucket)?.id ?? safeEvents[0]?.id ?? "";
        });
      })
      .catch((err) => setError(err.message));
  }

  function selectBucket(nextBucket) {
    setBucket(nextBucket);
    setSelectedEventID(firstEventForBucket(events, nextBucket)?.id ?? "");
  }

  const selectedSession = useMemo(
    () => sessions.find((session) => session.session_id === selectedSessionID),
    [sessions, selectedSessionID],
  );
  const counts = useMemo(() => bucketCounts(events), [events]);
  const visibleEvents = useMemo(() => eventsForBucket(events, bucket), [events, bucket]);
  const selectedEvent = useMemo(
    () => visibleEvents.find((event) => event.id === selectedEventID) ?? visibleEvents[0],
    [selectedEventID, visibleEvents],
  );

  return (
    <main>
      <nav className="topbar">
        <div>
          <strong>Kontext Guard</strong>
          <span>Observe mode · local only</span>
        </div>
        <div className="topActions">
          <SessionPicker
            sessions={sessions}
            value={selectedSessionID}
            onChange={(event) => {
              setSelectedSessionID(event.target.value);
              setSelectedEventID("");
            }}
          />
          <button onClick={refresh}>Refresh</button>
        </div>
      </nav>

      <section className="hero">
        <div>
          <p>Current Claude Code session</p>
          <h1>{selectedSession ? shortSession(selectedSession.session_id) : "No session yet"}</h1>
        </div>
        <span>{selectedSession ? `${selectedSession.actions} actions` : "Start Claude Code to capture tool calls"}</span>
      </section>

      <DecisionFunnel active={bucket} counts={counts} onSelect={selectBucket} />

      {error && <p className="error">{error}</p>}

      <section className="workspace">
        <ActionList
          bucket={bucket}
          events={visibleEvents}
          selectedEventID={selectedEvent?.id}
          onSelect={setSelectedEventID}
        />
        <EventInspector event={selectedEvent} />
      </section>
    </main>
  );
}

function SessionPicker({ sessions, value, onChange }) {
  if (sessions.length <= 1) return null;
  return (
    <select aria-label="Session" value={value} onChange={onChange}>
      {sessions.map((session) => (
        <option key={session.session_id} value={session.session_id}>
          {shortSession(session.session_id)}
        </option>
      ))}
    </select>
  );
}

function DecisionFunnel({ active, counts, onSelect }) {
  const items = [
    { id: "all", label: "All actions", value: counts.all, detail: "Everything Claude Code tried" },
    { id: "ask", label: "Needs ask", value: counts.ask, detail: "Review before enforcement" },
    { id: "deny", label: "Would deny", value: counts.deny, detail: "Future block queue" },
  ];

  return (
    <section className="funnel" aria-label="Decision funnel">
      {items.map((item) => (
        <button
          className={active === item.id ? `funnelStep ${item.id} active` : `funnelStep ${item.id}`}
          key={item.id}
          onClick={() => onSelect(item.id)}
          style={{ "--w": `${barWidth(item.value, counts.all)}%` }}
        >
          <span>{item.label}</span>
          <strong>{item.value}</strong>
          <small>{item.detail}</small>
        </button>
      ))}
    </section>
  );
}

function ActionList({ bucket, events, selectedEventID, onSelect }) {
  return (
    <section className="actionList">
      <div className="panelHeader">
        <div>
          <p>{bucketTitle(bucket)}</p>
          <h2>{events.length} actions</h2>
        </div>
      </div>
      <div className="rows">
        {events.length === 0 && <p className="empty">Nothing in this bucket.</p>}
        {events.map((event) => (
          <button
            className={event.id === selectedEventID ? `eventRow ${event.decision} active` : `eventRow ${event.decision}`}
            key={event.id}
            onClick={() => onSelect(event.id)}
          >
            <span className="toolName">{event.tool_name || event.risk_event?.type || "tool"}</span>
            <span className="eventReason">{humanReason(event)}</span>
            <span className="riskScore">{scoreLabel(event)}</span>
          </button>
        ))}
      </div>
    </section>
  );
}

function EventInspector({ event }) {
  if (!event) {
    return (
      <aside className="inspector emptyInspector">
        <h2>Select an action</h2>
        <p>Click a funnel bucket, then click an action.</p>
      </aside>
    );
  }

  const riskEvent = event.risk_event ?? {};
  const signals = riskEvent.signals ?? [];

  return (
    <aside className={`inspector ${event.decision}`}>
      <div className="decisionLine">
        <span>{decisionLabel(event.decision)}</span>
        <strong>{scoreLabel(event)}</strong>
      </div>

      <h2>{event.tool_name || riskEvent.type || "Tool call"}</h2>
      <p className="reason">{humanReason(event)}</p>

      <section>
        <h3>Why this is suspicious</h3>
        <p>{technicalExplanation(event)}</p>
      </section>

      <section>
        <h3>What it wanted to do</h3>
        <code>{actionSummary(event)}</code>
      </section>

      <dl className="facts">
        <div><dt>Decision source</dt><dd>{decisionSource(event)}</dd></div>
        <div><dt>Reason code</dt><dd>{event.reason_code || "none"}</dd></div>
        <div><dt>Operation</dt><dd>{riskEvent.operation || riskEvent.operation_class || "unknown"}</dd></div>
        <div><dt>Environment</dt><dd>{riskEvent.environment || "unknown"}</dd></div>
      </dl>

      <section>
        <h3>Signals</h3>
        <div className="signals">
          {signals.length === 0 && <span>none</span>}
          {signals.map((signal) => <span key={signal}>{signal}</span>)}
        </div>
      </section>
    </aside>
  );
}

function bucketCounts(events) {
  return {
    all: events.length,
    ask: events.filter((event) => event.decision === "ask").length,
    deny: events.filter((event) => event.decision === "deny").length,
  };
}

function eventsForBucket(events, bucket) {
  if (bucket === "ask") return events.filter((event) => event.decision === "ask");
  if (bucket === "deny") return events.filter((event) => event.decision === "deny");
  return events;
}

function firstEventForBucket(events, bucket) {
  return eventsForBucket(events, bucket)[0];
}

function bucketTitle(bucket) {
  if (bucket === "ask") return "Needs ask";
  if (bucket === "deny") return "Would deny";
  return "All actions";
}

function decisionLabel(decision) {
  if (decision === "allow") return "would allow";
  if (decision === "ask") return "would ask";
  if (decision === "deny") return "would deny";
  return decision || "unknown";
}

function humanReason(event) {
  if (event.reason_code === "async_telemetry") return "Recorded after execution";
  if (event.reason_code === "model_risk_threshold") return "Markov sequence risk crossed threshold";
  return event.reason || event.reason_code || "No explanation";
}

function technicalExplanation(event) {
  const riskEvent = event.risk_event ?? {};
  if (event.reason_code === "model_risk_threshold") {
    return `The Markov-chain model scored this normalized action at ${scoreLabel(event)}, at or above the local threshold ${thresholdLabel(event)}. In plain terms: actions like this are statistically closer to known unsafe sequences than normal coding flow.`;
  }
  if (event.reason_code === "async_telemetry") {
    return "This was not a live gate. It was recorded after execution so the session history can improve future model parameters.";
  }
  if (isDeterministicGuard(event)) {
    return `A deterministic guard fired before the model decision mattered. The Markov score is ${scoreLabel(event)} against threshold ${thresholdLabel(event)}, so this specific flag is rule-driven, not a sequence anomaly.`;
  }
  if (riskEvent.type === "normal_tool_call") {
    return `The model score is ${scoreLabel(event)} against threshold ${thresholdLabel(event)}. This currently looks like routine coding-agent behavior.`;
  }
  return `The action was normalized as ${riskEvent.type || "unknown"} with model score ${scoreLabel(event)} against threshold ${thresholdLabel(event)}.`;
}

function decisionSource(event) {
  if (event.reason_code === "model_risk_threshold") return "Markov-chain model";
  if (event.reason_code === "async_telemetry") return "Trace history";
  if (isDeterministicGuard(event)) return "Deterministic guard";
  return "Normal scoring";
}

function isDeterministicGuard(event) {
  return Boolean(event.risk_event?.guard_id) || [
    "production_mutation",
    "credential_access_without_intent",
    "destructive_operation_without_intent",
    "direct_infra_api_with_credential",
    "unknown_high_risk_command",
  ].includes(event.reason_code);
}

function actionSummary(event) {
  const riskEvent = event.risk_event ?? {};
  return riskEvent.command_summary || riskEvent.request_summary || riskEvent.path_class || "No command summary stored.";
}

function scoreLabel(event) {
  return event.risk_score == null ? "n/a" : event.risk_score.toFixed(3);
}

function thresholdLabel(event) {
  return event.threshold == null ? "n/a" : event.threshold.toFixed(3);
}

function shortSession(sessionID) {
  return sessionID ? sessionID.slice(0, 8) : "";
}

function barWidth(value, total) {
  if (!total) return 6;
  return Math.max(10, Math.round((value / total) * 100));
}

createRoot(document.getElementById("root")).render(<App />);
