import { useState, useEffect, useCallback } from 'react';
import { useAPI } from '../hooks/useAPI';
import SeverityBadge from '../components/SeverityBadge';

export default function AIInsights() {
  const { apiFetch } = useAPI();
  const [dailySummary, setDailySummary] = useState(null);
  const [summaryLoading, setSummaryLoading] = useState(false);
  const [queryText, setQueryText] = useState('');
  const [queryResult, setQueryResult] = useState(null);
  const [queryLoading, setQueryLoading] = useState(false);
  const [wafRecs, setWafRecs] = useState(null);
  const [wafLoading, setWafLoading] = useState(false);
  const [threatId, setThreatId] = useState('');
  const [threatAnalysis, setThreatAnalysis] = useState(null);
  const [threatLoading, setThreatLoading] = useState(false);
  const [actorIp, setActorIp] = useState('');
  const [actorAnalysis, setActorAnalysis] = useState(null);
  const [actorLoading, setActorLoading] = useState(false);
  const [aiAvailable, setAiAvailable] = useState(true);

  const loadDailySummary = useCallback(async () => {
    setSummaryLoading(true);
    try {
      const res = await apiFetch('/ai/daily-summary');
      if (res.message === 'AI not configured') {
        setAiAvailable(false);
        return;
      }
      setDailySummary(res.data);
    } catch {
      // ignore
    } finally {
      setSummaryLoading(false);
    }
  }, [apiFetch]);

  useEffect(() => { loadDailySummary(); }, [loadDailySummary]);

  const handleQuery = async () => {
    if (!queryText.trim()) return;
    setQueryLoading(true);
    setQueryResult(null);
    try {
      const res = await apiFetch('/ai/query', {
        method: 'POST',
        body: JSON.stringify({ query: queryText }),
      });
      setQueryResult(res.data);
    } catch {
      setQueryResult({ answer: 'Failed to get a response. Please try again.' });
    } finally {
      setQueryLoading(false);
    }
  };

  const handleWAFRecs = async () => {
    setWafLoading(true);
    setWafRecs(null);
    try {
      const res = await apiFetch('/ai/waf-recommendations');
      setWafRecs(res.data);
    } catch {
      // ignore
    } finally {
      setWafLoading(false);
    }
  };

  const handleAnalyzeThreat = async () => {
    if (!threatId.trim()) return;
    setThreatLoading(true);
    setThreatAnalysis(null);
    try {
      const res = await apiFetch(`/ai/analyze-threat/${threatId}`, { method: 'POST' });
      setThreatAnalysis(res.data);
    } catch (err) {
      setThreatAnalysis({ summary: 'Analysis failed: ' + (err.message || 'unknown error') });
    } finally {
      setThreatLoading(false);
    }
  };

  const handleAnalyzeActor = async () => {
    if (!actorIp.trim()) return;
    setActorLoading(true);
    setActorAnalysis(null);
    try {
      const res = await apiFetch(`/ai/analyze-actor/${actorIp}`);
      setActorAnalysis(res.data);
    } catch (err) {
      setActorAnalysis({ summary: 'Analysis failed: ' + (err.message || 'unknown error') });
    } finally {
      setActorLoading(false);
    }
  };

  if (!aiAvailable) {
    return (
      <div className="space-y-6">
        <h2 className="text-xl font-semibold text-[#e0e0e0]">AI Insights</h2>
        <div className="bg-[#0d1526] border border-[#1e2d4a] rounded-lg p-8 text-center">
          <div className="text-4xl mb-4">◈</div>
          <h3 className="text-[#e0e0e0] text-lg font-medium mb-2">AI Not Configured</h3>
          <p className="text-[#8892a0] text-sm max-w-md mx-auto">
            To enable AI-powered security analysis, configure an AI provider in your Sentinel config:
          </p>
          <pre className="mt-4 bg-[#0a0f1e] border border-[#1e2d4a] rounded p-4 text-xs text-[#00d4ff] text-left max-w-md mx-auto font-mono">
{`sentinel.Config{
  AI: &sentinel.AIConfig{
    Provider: sentinel.Claude,
    APIKey:   "your-api-key",
  },
}`}
          </pre>
        </div>
      </div>
    );
  }

  const statusColors = {
    secure: 'text-[#00ff88]',
    elevated: 'text-[#ff6b35]',
    concerning: 'text-[#ff6b35]',
    critical: 'text-[#ff2d55]',
  };

  return (
    <div className="space-y-6">
      <h2 className="text-xl font-semibold text-[#e0e0e0]">AI Insights</h2>

      {/* Daily Summary */}
      <div className="bg-[#0d1526] border border-[#1e2d4a] rounded-lg p-4">
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-sm uppercase tracking-wider text-[#8892a0]">Daily Security Summary</h3>
          <button
            onClick={loadDailySummary}
            disabled={summaryLoading}
            className="px-3 py-1 bg-[#1e2d4a] text-[#00d4ff] rounded text-xs hover:bg-[#2a3d5a] disabled:opacity-50"
          >
            {summaryLoading ? 'Generating...' : 'Refresh'}
          </button>
        </div>
        {summaryLoading && !dailySummary ? (
          <div className="text-[#8892a0] text-sm animate-pulse">Generating daily summary with AI...</div>
        ) : dailySummary ? (
          <div className="space-y-3">
            <div className="flex items-center gap-2">
              <span className="text-[#8892a0] text-xs">Status:</span>
              <span className={`font-medium text-sm ${statusColors[dailySummary.overall_status] || 'text-[#e0e0e0]'}`}>
                {dailySummary.overall_status?.toUpperCase()}
              </span>
            </div>
            <p className="text-[#e0e0e0] text-sm leading-relaxed">{dailySummary.summary}</p>
            {dailySummary.highlights?.length > 0 && (
              <div>
                <h4 className="text-[#8892a0] text-xs uppercase mb-1">Key Highlights</h4>
                <ul className="space-y-1">
                  {dailySummary.highlights.map((h, i) => (
                    <li key={i} className="text-[#e0e0e0] text-xs flex gap-2">
                      <span className="text-[#00d4ff]">-</span> {h}
                    </li>
                  ))}
                </ul>
              </div>
            )}
            {dailySummary.recommendations?.length > 0 && (
              <div>
                <h4 className="text-[#8892a0] text-xs uppercase mb-1">Recommendations</h4>
                <ul className="space-y-1">
                  {dailySummary.recommendations.map((r, i) => (
                    <li key={i} className="text-[#00ff88] text-xs flex gap-2">
                      <span className="text-[#00d4ff]">→</span> {r}
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        ) : (
          <p className="text-[#8892a0] text-sm">Click Refresh to generate a daily summary.</p>
        )}
      </div>

      {/* Natural Language Query */}
      <div className="bg-[#0d1526] border border-[#1e2d4a] rounded-lg p-4">
        <h3 className="text-sm uppercase tracking-wider text-[#8892a0] mb-3">Ask AI</h3>
        <div className="flex gap-2 mb-3">
          <input
            value={queryText}
            onChange={(e) => setQueryText(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleQuery()}
            placeholder="e.g., What was the most dangerous attack today?"
            className="bg-[#0a0f1e] border border-[#1e2d4a] rounded px-3 py-2 text-sm text-[#e0e0e0] focus:border-[#00d4ff] focus:outline-none flex-1"
          />
          <button
            onClick={handleQuery}
            disabled={queryLoading}
            className="px-4 py-2 bg-[#00d4ff] text-[#0a0f1e] rounded text-sm font-medium hover:bg-[#00bde0] disabled:opacity-50"
          >
            {queryLoading ? 'Thinking...' : 'Ask'}
          </button>
        </div>
        {queryResult && (
          <div className="bg-[#0a0f1e] border border-[#1e2d4a] rounded p-3 space-y-2">
            <p className="text-[#e0e0e0] text-sm leading-relaxed whitespace-pre-wrap">{queryResult.answer}</p>
            {queryResult.suggestions?.length > 0 && (
              <div className="pt-2 border-t border-[#1e2d4a]">
                <span className="text-[#8892a0] text-xs">Follow-up questions: </span>
                {queryResult.suggestions.map((s, i) => (
                  <button
                    key={i}
                    onClick={() => { setQueryText(s); }}
                    className="text-[#00d4ff] text-xs hover:underline mr-3"
                  >
                    {s}
                  </button>
                ))}
              </div>
            )}
          </div>
        )}
      </div>

      {/* Threat and Actor Analysis side by side */}
      <div className="grid grid-cols-2 gap-4">
        {/* Threat Analysis */}
        <div className="bg-[#0d1526] border border-[#1e2d4a] rounded-lg p-4">
          <h3 className="text-sm uppercase tracking-wider text-[#8892a0] mb-3">Threat Analysis</h3>
          <div className="flex gap-2 mb-3">
            <input
              value={threatId}
              onChange={(e) => setThreatId(e.target.value)}
              placeholder="Enter threat ID..."
              className="bg-[#0a0f1e] border border-[#1e2d4a] rounded px-3 py-1.5 text-sm text-[#e0e0e0] focus:border-[#00d4ff] focus:outline-none flex-1 font-mono"
            />
            <button
              onClick={handleAnalyzeThreat}
              disabled={threatLoading}
              className="px-3 py-1.5 bg-[#1e2d4a] text-[#00d4ff] rounded text-xs hover:bg-[#2a3d5a] disabled:opacity-50"
            >
              {threatLoading ? 'Analyzing...' : 'Analyze'}
            </button>
          </div>
          {threatAnalysis && (
            <div className="bg-[#0a0f1e] border border-[#1e2d4a] rounded p-3 space-y-2 text-xs">
              <p className="text-[#e0e0e0] text-sm">{threatAnalysis.summary}</p>
              {threatAnalysis.explanation && (
                <p className="text-[#8892a0]">{threatAnalysis.explanation}</p>
              )}
              {threatAnalysis.severity_assessment && (
                <div className="flex items-center gap-2">
                  <span className="text-[#8892a0]">Severity:</span>
                  <span className="text-[#e0e0e0]">{threatAnalysis.severity_assessment}</span>
                </div>
              )}
              {threatAnalysis.threat_category && (
                <div className="flex items-center gap-2">
                  <span className="text-[#8892a0]">Category:</span>
                  <span className="text-[#00d4ff]">{threatAnalysis.threat_category}</span>
                </div>
              )}
              {threatAnalysis.recommendations?.length > 0 && (
                <ul className="space-y-1 pt-1 border-t border-[#1e2d4a]">
                  {threatAnalysis.recommendations.map((r, i) => (
                    <li key={i} className="text-[#00ff88]">→ {r}</li>
                  ))}
                </ul>
              )}
            </div>
          )}
        </div>

        {/* Actor Analysis */}
        <div className="bg-[#0d1526] border border-[#1e2d4a] rounded-lg p-4">
          <h3 className="text-sm uppercase tracking-wider text-[#8892a0] mb-3">Actor Assessment</h3>
          <div className="flex gap-2 mb-3">
            <input
              value={actorIp}
              onChange={(e) => setActorIp(e.target.value)}
              placeholder="Enter IP address..."
              className="bg-[#0a0f1e] border border-[#1e2d4a] rounded px-3 py-1.5 text-sm text-[#e0e0e0] focus:border-[#00d4ff] focus:outline-none flex-1 font-mono"
            />
            <button
              onClick={handleAnalyzeActor}
              disabled={actorLoading}
              className="px-3 py-1.5 bg-[#1e2d4a] text-[#00d4ff] rounded text-xs hover:bg-[#2a3d5a] disabled:opacity-50"
            >
              {actorLoading ? 'Assessing...' : 'Assess'}
            </button>
          </div>
          {actorAnalysis && (
            <div className="bg-[#0a0f1e] border border-[#1e2d4a] rounded p-3 space-y-2 text-xs">
              <p className="text-[#e0e0e0] text-sm">{actorAnalysis.summary}</p>
              <div className="grid grid-cols-2 gap-2">
                {actorAnalysis.intent && (
                  <div>
                    <span className="text-[#8892a0]">Intent: </span>
                    <span className="text-[#ff6b35]">{actorAnalysis.intent}</span>
                  </div>
                )}
                {actorAnalysis.sophistication && (
                  <div>
                    <span className="text-[#8892a0]">Skill: </span>
                    <span className="text-[#e0e0e0]">{actorAnalysis.sophistication}</span>
                  </div>
                )}
                {actorAnalysis.risk_level && (
                  <div>
                    <span className="text-[#8892a0]">Risk: </span>
                    <span className={actorAnalysis.risk_level === 'critical' ? 'text-[#ff2d55]' : actorAnalysis.risk_level === 'high' ? 'text-[#ff6b35]' : 'text-[#e0e0e0]'}>
                      {actorAnalysis.risk_level}
                    </span>
                  </div>
                )}
              </div>
              {actorAnalysis.recommendations?.length > 0 && (
                <ul className="space-y-1 pt-1 border-t border-[#1e2d4a]">
                  {actorAnalysis.recommendations.map((r, i) => (
                    <li key={i} className="text-[#00ff88]">→ {r}</li>
                  ))}
                </ul>
              )}
            </div>
          )}
        </div>
      </div>

      {/* WAF Recommendations */}
      <div className="bg-[#0d1526] border border-[#1e2d4a] rounded-lg p-4">
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-sm uppercase tracking-wider text-[#8892a0]">AI WAF Recommendations</h3>
          <button
            onClick={handleWAFRecs}
            disabled={wafLoading}
            className="px-3 py-1 bg-[#1e2d4a] text-[#00d4ff] rounded text-xs hover:bg-[#2a3d5a] disabled:opacity-50"
          >
            {wafLoading ? 'Analyzing...' : 'Generate Recommendations'}
          </button>
        </div>
        {wafRecs?.length > 0 ? (
          <div className="space-y-2">
            {wafRecs.map((rec, i) => (
              <div key={i} className="bg-[#0a0f1e] border border-[#1e2d4a] rounded p-3">
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-3">
                    <span className="text-[#e0e0e0] text-sm font-medium">{rec.name}</span>
                    <SeverityBadge severity={rec.severity} />
                    <span className="text-[#8892a0] text-xs">{rec.rule_id}</span>
                  </div>
                  <span className="text-[#8892a0] text-xs">{(rec.applies_to || []).join(', ')}</span>
                </div>
                <div className="text-[#00d4ff] text-xs font-mono mb-1">{rec.pattern}</div>
                <p className="text-[#8892a0] text-xs">{rec.reason}</p>
              </div>
            ))}
          </div>
        ) : wafRecs && wafRecs.length === 0 ? (
          <p className="text-[#8892a0] text-sm">No recommendations at this time.</p>
        ) : (
          <p className="text-[#8892a0] text-sm">Click Generate Recommendations to analyze recent attacks and suggest WAF rules.</p>
        )}
      </div>
    </div>
  );
}
