import { useEffect, useState } from 'react';
import {
  AlertTriangle,
  ArrowRight,
  Check,
  CreditCard,
  Download,
  ExternalLink,
  Layers,
  Lock,
  Server,
  Sparkles,
  X,
  Zap,
} from 'lucide-react';
import {
  PLAN_TIERS,
  getStoredPlan,
  setStoredPlan,
  type PlanTier,
} from '../../data/planTiering';
import { useAuth } from '../../../contexts/AuthContext';
import { billingService } from '../../../api/services/billingService';
import { isPublicDemo } from '../../utils/demoMode';

interface PlanUsageBannerProps {
  /** Count of active honeypots deployed */
  honeypotCount: number;
  /** Total events ingested in current period */
  eventCount: number;
  /** Optional callback when user clicks navigate to billing */
  onNavigateToBilling?: () => void;
}

export default function PlanUsageBanner({
  honeypotCount,
  eventCount,
  onNavigateToBilling,
}: PlanUsageBannerProps) {
  const [currentPlan, setCurrentPlan] = useState<PlanTier>(() => (isPublicDemo() ? 'pro' : getStoredPlan()));
  const [isBannerDismissed, setIsBannerDismissed] = useState(false);
  // Server-side plan and server usage (the source of truth, same as the header). Falls back to local values.
  const [serverUsage, setServerUsage] = useState<{ used: number; limit: number } | null>(null);

  useEffect(() => {
    if (isPublicDemo()) return;
    let mounted = true;
    billingService
      .getUsage()
      .then((d) => {
        if (!mounted || !d || d.platform) return;
        const id = d.plan?.id;
        if (id === 'basic' || id === 'pro' || id === 'enterprise') setCurrentPlan(id as PlanTier);
        const s = d.usage?.honeypots || d.usage?.servers;
        if (s && typeof s.used === 'number' && typeof s.limit === 'number') {
          setServerUsage({ used: s.used, limit: s.limit });
        }
      })
      .catch(() => {
        /* keep local fallback */
      });
    return () => {
      mounted = false;
    };
  }, []);

  const plan = PLAN_TIERS[currentPlan];
  const maxHoneypots = serverUsage?.limit ?? plan.maxHoneypots;
  const maxEvents = plan.maxEventsPerMonth;
  const honeypotUsed = serverUsage?.used ?? honeypotCount;

  // Usage ratios
  const honeypotRatio = Math.min(100, Math.round((honeypotUsed / maxHoneypots) * 100));
  const eventRatio = Math.min(100, Math.round((eventCount / maxEvents) * 100));

  const isNearLimit = honeypotRatio >= 75 || eventRatio >= 75;
  const isBasic = currentPlan === 'basic';
  // Changing the plan needs the same permission the server asks for (rbac.users.manage).
  const { permissions } = useAuth();
  const canChangePlan = permissions.includes('rbac.users.manage');
  const isPro = currentPlan === 'pro';

  const openUpgradeModal = () => {
    window.dispatchEvent(new CustomEvent('open-plan-upgrade'));
  };

  useEffect(() => {
    const handlePlanChanged = (e: Event) => {
      const custom = e as CustomEvent<{ plan: PlanTier }>;
      if (custom.detail?.plan) {
        setCurrentPlan(custom.detail.plan);
      }
    };
    window.addEventListener('plan-changed', handlePlanChanged);
    return () => window.removeEventListener('plan-changed', handlePlanChanged);
  }, []);

  return (
    <div className="at-plan-usage-section">
      {/* ── Top Upgrade Notice (for non-enterprise users) ── */}
      {isBasic && !isBannerDismissed && (
        <div className="at-plan-upgrade-banner" role="region" aria-label="Subscription upgrade notice">
          <div className="at-plan-upgrade-left">
            <span className="at-plan-upgrade-icon">
              <Sparkles size={16} />
            </span>
            <div className="at-plan-upgrade-copy">
              <strong>Unlock Pro Capabilities: JSON Exports &amp; 35 Honeypots</strong>
              <p>
                Your Basic plan includes CSV export only. Upgrade to Pro to enable automated JSON threat feeds,
                deploy up to 35 honeypots, and access automated MITRE ATT&amp;CK scoring.
              </p>
            </div>
          </div>

          <div className="at-plan-upgrade-actions">
            <button
              type="button"
              className="at-btn at-btn-primary at-btn-sm at-plan-upgrade-cta"
              onClick={openUpgradeModal}
            >
              <Zap size={13} />
              Upgrade to Pro — ${PLAN_TIERS.pro.priceMonthly}/mo
            </button>
            <button
              type="button"
              className="at-plan-banner-dismiss"
              onClick={() => setIsBannerDismissed(true)}
              aria-label="Dismiss banner"
            >
              <X size={14} />
            </button>
          </div>
        </div>
      )}

      {/* ── Main Plan & Usage Quota Card ── */}
      <div className="at-saas-panel at-plan-quota-card">
        <div className="at-plan-quota-header">
          <div className="at-plan-quota-title-wrap">
            <div className="at-plan-badge-group">
              <span className={`at-plan-tag at-plan-tag-${currentPlan}`}>
                <CreditCard size={12} />
                {plan.name} Plan
              </span>
              <span className="at-plan-sub-badge">{plan.badge}</span>
            </div>
            <h3 className="at-plan-heading">Resource Quotas &amp; Ingestion Limits</h3>
            <p className="at-plan-description">
              Current subscription entitlement and telemetry usage for this billing cycle.
            </p>
          </div>

          {canChangePlan && (<div className="at-plan-quota-actions">
            <button
              type="button"
              className="at-btn at-btn-secondary at-btn-sm"
              onClick={openUpgradeModal}
            >
              <Layers size={13} />
              Change Plan
            </button>
            {isBasic && (
              <button
                type="button"
                className="at-btn at-btn-primary at-btn-sm"
                onClick={openUpgradeModal}
              >
                <ArrowRight size={13} />
                Upgrade
              </button>
            )}
          </div>)}
        </div>

        <div className="at-plan-meters-grid">
          {/* Meter 1: Honeypots */}
          <div className="at-plan-meter-card">
            <div className="at-plan-meter-top">
              <span className="at-plan-meter-label">
                <Server size={14} />
                Active Honeypots
              </span>
              <span className="at-plan-meter-val">
                <strong>{honeypotUsed}</strong> / {maxHoneypots >= 9999 ? '∞' : maxHoneypots}
              </span>
            </div>
            <div className="at-plan-progress-track">
              <div
                className={`at-plan-progress-fill ${
                  honeypotRatio >= 90 ? 'is-danger' : honeypotRatio >= 70 ? 'is-warning' : 'is-normal'
                }`}
                style={{ width: `${maxHoneypots >= 9999 ? 25 : honeypotRatio}%` }}
              />
            </div>
            <div className="at-plan-meter-sub">
              {maxHoneypots >= 9999 ? (
                <span>Unlimited deployments enabled</span>
              ) : honeypotUsed >= maxHoneypots ? (
                <span className="at-text-danger">
                  <AlertTriangle size={11} /> Quota reached — upgrade to add more
                </span>
              ) : (
                <span>{maxHoneypots - honeypotUsed} slot{maxHoneypots - honeypotUsed === 1 ? '' : 's'} available</span>
              )}
            </div>
          </div>

          {/* Meter 2: Monthly Events */}
          <div className="at-plan-meter-card">
            <div className="at-plan-meter-top">
              <span className="at-plan-meter-label">
                <Zap size={14} />
                Monthly Ingestion
              </span>
              <span className="at-plan-meter-val">
                <strong>{eventCount.toLocaleString()}</strong> /{' '}
                {maxEvents >= 1000000 ? '∞' : maxEvents.toLocaleString()}
              </span>
            </div>
            <div className="at-plan-progress-track">
              <div
                className={`at-plan-progress-fill ${
                  eventRatio >= 90 ? 'is-danger' : eventRatio >= 70 ? 'is-warning' : 'is-normal'
                }`}
                style={{ width: `${maxEvents >= 1000000 ? 15 : Math.max(8, eventRatio)}%` }}
              />
            </div>
            <div className="at-plan-meter-sub">
              <span>{plan.retentionDays}-day forensic retention</span>
            </div>
          </div>

          {/* Meter 3: Export Formats Entitlement */}
          <div className="at-plan-meter-card">
            <div className="at-plan-meter-top">
              <span className="at-plan-meter-label">
                <Download size={14} />
                Export Entitlements
              </span>
              <span className="at-plan-meter-val">
                <small>{plan.exportFormats.length} format{plan.exportFormats.length === 1 ? '' : 's'}</small>
              </span>
            </div>
            <div className="at-plan-formats-pills">
              <span className="at-format-tag is-enabled" title="CSV Export included">
                <Check size={10} /> CSV
              </span>
              <span
                className={`at-format-tag ${plan.exportFormats.includes('JSON') ? 'is-enabled' : 'is-locked'}`}
                title={plan.exportFormats.includes('JSON') ? 'JSON Export included (Pro)' : 'Requires Pro Plan'}
              >
                {plan.exportFormats.includes('JSON') ? <Check size={10} /> : <Lock size={10} />} JSON (Pro)
              </span>
              <span
                className={`at-format-tag ${plan.exportFormats.includes('STIX') ? 'is-enabled' : 'is-locked'}`}
                title={plan.exportFormats.includes('STIX') ? 'STIX/TAXII included (Enterprise)' : 'Requires Enterprise'}
              >
                {plan.exportFormats.includes('STIX') ? <Check size={10} /> : <Lock size={10} />} STIX / PDF
              </span>
            </div>
            <div className="at-plan-meter-sub">
              {isBasic && (
                <span className="at-plan-upgrade-link" onClick={openUpgradeModal}>
                  Upgrade for JSON exports →
                </span>
              )}
              {isPro && <span>JSON exports unlocked</span>}
              {!isBasic && !isPro && <span>Full TAXII &amp; PDF suite active</span>}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
