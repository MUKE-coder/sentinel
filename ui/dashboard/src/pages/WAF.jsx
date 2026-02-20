import { useState, useEffect, useCallback } from 'react';
import { useAPI } from '../hooks/useAPI';
import SeverityBadge from '../components/SeverityBadge';

export default function WAF() {
  const { apiFetch } = useAPI();
  const [wafConfig, setWafConfig] = useState(null);
  const [customRules, setCustomRules] = useState([]);
  const [newRule, setNewRule] = useState({ id: '', name: '', pattern: '', applies_to: ['path', 'query', 'body'], severity: 'High', action: 'block', enabled: true });
  const [testPayload, setTestPayload] = useState('');
  const [testResults, setTestResults] = useState(null);
  const [ruleError, setRuleError] = useState('');

  const loadData = useCallback(async () => {
    try {
      const [rulesRes, customRes] = await Promise.all([
        apiFetch('/waf/rules'),
        apiFetch('/waf/custom-rules'),
      ]);
      setWafConfig(rulesRes.data);
      setCustomRules(customRes.data || []);
    } catch {
      // ignore
    }
  }, [apiFetch]);

  useEffect(() => { loadData(); }, [loadData]);

  const handleAddRule = async () => {
    setRuleError('');
    if (!newRule.id || !newRule.pattern) {
      setRuleError('ID and pattern are required');
      return;
    }
    try {
      await apiFetch('/waf/custom-rules', {
        method: 'POST',
        body: JSON.stringify(newRule),
      });
      setNewRule({ id: '', name: '', pattern: '', applies_to: ['path', 'query', 'body'], severity: 'High', action: 'block', enabled: true });
      loadData();
    } catch (err) {
      setRuleError(err.message || 'Failed to add rule');
    }
  };

  const handleDeleteRule = async (id) => {
    await apiFetch(`/waf/custom-rules/${id}`, { method: 'DELETE' });
    loadData();
  };

  const handleTest = async () => {
    if (!testPayload.trim()) return;
    try {
      const res = await apiFetch('/waf/test', {
        method: 'POST',
        body: JSON.stringify({ payload: testPayload }),
      });
      setTestResults(res.data);
    } catch {
      setTestResults(null);
    }
  };

  return (
    <div className="space-y-6">
      <h2 className="text-xl font-semibold text-[#e0e0e0]">WAF Configuration</h2>

      {/* WAF Status */}
      {wafConfig && (
        <div className="bg-[#0d1526] border border-[#1e2d4a] rounded-lg p-4">
          <h3 className="text-sm uppercase tracking-wider text-[#8892a0] mb-3">Built-in Rules</h3>
          <div className="flex items-center gap-4 mb-4">
            <span className="text-[#8892a0] text-sm">Mode:</span>
            <span className="text-[#00d4ff] font-medium">{wafConfig.mode || 'block'}</span>
          </div>
          <div className="grid grid-cols-4 gap-3">
            {wafConfig.rules && Object.entries(wafConfig.rules).map(([key, value]) => (
              <div key={key} className="bg-[#0a0f1e] border border-[#1e2d4a] rounded p-2 text-xs">
                <span className="text-[#8892a0]">{key}: </span>
                <span className="text-[#e0e0e0]">{value || 'strict'}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Custom Rules */}
      <div className="bg-[#0d1526] border border-[#1e2d4a] rounded-lg p-4">
        <h3 className="text-sm uppercase tracking-wider text-[#8892a0] mb-3">Custom Rules</h3>

        {/* Add rule form */}
        <div className="grid grid-cols-6 gap-2 mb-4">
          <input
            placeholder="Rule ID"
            value={newRule.id}
            onChange={(e) => setNewRule({ ...newRule, id: e.target.value })}
            className="bg-[#0a0f1e] border border-[#1e2d4a] rounded px-3 py-1.5 text-sm text-[#e0e0e0] focus:border-[#00d4ff] focus:outline-none"
          />
          <input
            placeholder="Rule name"
            value={newRule.name}
            onChange={(e) => setNewRule({ ...newRule, name: e.target.value })}
            className="bg-[#0a0f1e] border border-[#1e2d4a] rounded px-3 py-1.5 text-sm text-[#e0e0e0] focus:border-[#00d4ff] focus:outline-none"
          />
          <input
            placeholder="Regex pattern"
            value={newRule.pattern}
            onChange={(e) => setNewRule({ ...newRule, pattern: e.target.value })}
            className="bg-[#0a0f1e] border border-[#1e2d4a] rounded px-3 py-1.5 text-sm text-[#e0e0e0] focus:border-[#00d4ff] focus:outline-none col-span-2 font-mono"
          />
          <select
            value={newRule.severity}
            onChange={(e) => setNewRule({ ...newRule, severity: e.target.value })}
            className="bg-[#0a0f1e] border border-[#1e2d4a] rounded px-3 py-1.5 text-sm text-[#e0e0e0] focus:border-[#00d4ff] focus:outline-none"
          >
            <option value="Critical">Critical</option>
            <option value="High">High</option>
            <option value="Medium">Medium</option>
            <option value="Low">Low</option>
          </select>
          <button
            onClick={handleAddRule}
            className="px-4 py-1.5 bg-[#00d4ff] text-[#0a0f1e] rounded text-sm font-medium hover:bg-[#00bde0]"
          >
            Add Rule
          </button>
        </div>
        {ruleError && <p className="text-[#ff2d55] text-xs mb-3">{ruleError}</p>}

        {/* Rules list */}
        {customRules.length > 0 ? (
          <div className="space-y-2">
            {customRules.map((rule) => (
              <div key={rule.id} className="flex items-center justify-between bg-[#0a0f1e] border border-[#1e2d4a] rounded px-3 py-2">
                <div className="flex items-center gap-4 flex-1">
                  <span className={rule.enabled ? 'text-[#00ff88] text-xs' : 'text-[#8892a0] text-xs'}>
                    {rule.enabled ? 'ON' : 'OFF'}
                  </span>
                  <span className="text-[#e0e0e0] text-sm font-medium">{rule.name || rule.id}</span>
                  <span className="text-[#00d4ff] text-xs font-mono">{rule.pattern}</span>
                  <span className="text-[#8892a0] text-xs">{(rule.applies_to || []).join(', ')}</span>
                  <SeverityBadge severity={rule.severity} />
                </div>
                <button
                  onClick={() => handleDeleteRule(rule.id)}
                  className="px-3 py-1 bg-[#ff2d55] text-white rounded text-xs hover:bg-[#e0264d]"
                >
                  Delete
                </button>
              </div>
            ))}
          </div>
        ) : (
          <p className="text-[#8892a0] text-sm">No custom rules configured</p>
        )}
      </div>

      {/* Rule Tester */}
      <div className="bg-[#0d1526] border border-[#1e2d4a] rounded-lg p-4">
        <h3 className="text-sm uppercase tracking-wider text-[#8892a0] mb-3">Rule Tester</h3>
        <div className="flex gap-2 mb-4">
          <input
            placeholder="Paste a test payload..."
            value={testPayload}
            onChange={(e) => setTestPayload(e.target.value)}
            className="bg-[#0a0f1e] border border-[#1e2d4a] rounded px-3 py-1.5 text-sm text-[#e0e0e0] focus:border-[#00d4ff] focus:outline-none flex-1 font-mono"
          />
          <button
            onClick={handleTest}
            className="px-4 py-1.5 bg-[#1e2d4a] text-[#00d4ff] rounded text-sm font-medium hover:bg-[#2a3d5a]"
          >
            Test
          </button>
        </div>

        {testResults && (
          <div>
            <p className="text-[#e0e0e0] text-sm mb-2">
              {testResults.match_count > 0 ? (
                <span className="text-[#ff2d55]">{testResults.match_count} rule(s) triggered</span>
              ) : (
                <span className="text-[#00ff88]">No rules triggered</span>
              )}
            </p>
            {testResults.matches?.length > 0 && (
              <div className="space-y-1">
                {testResults.matches.map((m, i) => (
                  <div key={i} className="flex items-center gap-3 bg-[#0a0f1e] border border-[#1e2d4a] rounded px-3 py-2 text-xs">
                    <span className="text-[#00d4ff] font-medium">{m.pattern}</span>
                    <span className="text-[#8892a0]">{m.threat_type}</span>
                    <span className="text-[#ff2d55] font-mono">{m.matched}</span>
                    <span className="text-[#8892a0]">{m.location}</span>
                    <SeverityBadge severity={m.severity} />
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
