import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Check,
  History,
  KeyRound,
  Loader2,
  Pencil,
  Plus,
  RefreshCw,
  Shield,
  Users,
  X,
} from 'lucide-react';
import { useAuth } from '../../contexts/AuthContext';
import { isPublicDemo } from '../../src/utils/demoMode';
import {
  rbacService,
  type RbacAuditLog,
  type RbacGroup,
  type RbacPermission,
  type RbacUser,
} from '../../api/services/rbacService';
import { handleApiError } from '../../api/client';

type Tab = 'users' | 'groups' | 'permissions' | 'audit';

const MODULE_LABELS: Record<string, string> = {
  osm: 'Recon',
  ioc: 'IOC Manager',
  threat_intel: 'Threat Intelligence',
  infrastructure: 'Infrastructure',
  threat_map: 'Threat Map',
  rbac: 'Access Control',
};

const moduleLabel = (m: string) => MODULE_LABELS[m] || m;

// Module scope on purpose: declared inside AccessControlView it was re-created on every keystroke,
// remounting the inputs and re-firing autoFocus on the Email field.
const ModalShell: React.FC<{
  title: string;
  onClose: () => void;
  children: React.ReactNode;
  footer: React.ReactNode;
  error?: string | null;
}> = ({
  title,
  onClose,
  children,
  footer,
  error,
}) => (
  <div className="fixed inset-0 z-[80] flex items-center justify-center bg-black/70 p-4" role="presentation" onClick={onClose}>
    <div
      role="dialog"
      className="w-full max-w-lg max-h-[85vh] flex flex-col rounded-xl border border-gray-700 bg-[#0b0d12] shadow-2xl"
      onClick={(e) => e.stopPropagation()}
    >
      <div className="flex items-center justify-between px-5 py-4 border-b border-gray-800">
        <h3 className="text-sm font-bold text-white tracking-wide">{title}</h3>
        <button type="button" onClick={onClose} className="p-1.5 rounded hover:bg-gray-800 text-gray-400 hover:text-white">
          <X size={16} />
        </button>
      </div>
      {error && (
        <div className="mx-5 mt-4 p-3 bg-red-950/60 border border-red-500/50 rounded-lg text-xs font-mono text-red-200 animate-shake">
          {error}
        </div>
      )}
      <div className="flex-1 overflow-y-auto px-5 py-4 space-y-4 custom-scrollbar">{children}</div>
      <div className="flex justify-end gap-2 px-5 py-4 border-t border-gray-800">{footer}</div>
    </div>
  </div>
);

export const AccessControlView: React.FC = () => {
  const { can, refreshPermissions, admin } = useAuth();
  const isPlatform = !admin?.CustomerID;
  const canUsers = can('rbac.users.manage');
  const canGroups = can('rbac.groups.manage');

  const [tab, setTab] = useState<Tab>(canUsers ? 'users' : canGroups ? 'groups' : 'permissions');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [permissions, setPermissions] = useState<RbacPermission[]>([]);
  const [groups, setGroups] = useState<RbacGroup[]>([]);
  const [users, setUsers] = useState<RbacUser[]>([]);
  const [auditLogs, setAuditLogs] = useState<RbacAuditLog[]>([]);
  const [auditTotal, setAuditTotal] = useState(0);
  const [expandedAuditId, setExpandedAuditId] = useState<string | null>(null);

  // Modals
  const [showAddUser, setShowAddUser] = useState(false);
  const [showAddGroup, setShowAddGroup] = useState(false);
  const [editUser, setEditUser] = useState<RbacUser | null>(null);
  const [editGroup, setEditGroup] = useState<RbacGroup | null>(null);

  // Forms
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [selectedGroups, setSelectedGroups] = useState<string[]>([]);
  const [groupName, setGroupName] = useState('');
  const [groupDesc, setGroupDesc] = useState('');
  const [groupPerms, setGroupPerms] = useState<string[]>([]);
  const [saving, setSaving] = useState(false);

  const flash = (msg: string) => {
    setSuccess(msg);
    setTimeout(() => setSuccess(null), 3000);
  };

  const load = useCallback(async () => {
    if (isPublicDemo()) {
      setLoading(false);
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const tasks: Promise<unknown>[] = [
        rbacService.listPermissions(),
        rbacService.listGroups(),
        // The audit trail is platform-only on the backend; customer admins skip it
        isPlatform ? rbacService.listAuditLogs({ limit: 100 }) : Promise.resolve({ total: 0, logs: [] as RbacAuditLog[] }),
      ];
      if (canUsers) tasks.push(rbacService.listUsers());
      const [perms, grps, audit, usrs] = (await Promise.all(tasks)) as [
        RbacPermission[],
        RbacGroup[],
        { total: number; logs: RbacAuditLog[] },
        RbacUser[] | undefined,
      ];
      setPermissions(perms);
      setGroups(grps);
      setAuditLogs(audit.logs);
      setAuditTotal(audit.total);
      setUsers(usrs || []);
    } catch (e) {
      setError(handleApiError(e));
    } finally {
      setLoading(false);
    }
  }, [canUsers, isPlatform]);

  useEffect(() => {
    void load();
  }, [load]);

  const permsByModule = useMemo(() => {
    const map = new Map<string, RbacPermission[]>();
    for (const p of permissions) {
      const list = map.get(p.Module) || [];
      list.push(p);
      map.set(p.Module, list);
    }
    return [...map.entries()].sort((a, b) => moduleLabel(a[0]).localeCompare(moduleLabel(b[0])));
  }, [permissions]);

  const resetUserForm = () => {
    setEmail('');
    setPassword('');
    setSelectedGroups([]);
  };

  const openAddUser = () => {
    resetUserForm();
    setShowAddUser(true);
    setError(null);
  };

  const openEditUser = (u: RbacUser) => {
    setEditUser(u);
    setSelectedGroups(u.groups.map((g) => g.GroupId));
    setPassword('');
    setError(null);
  };

  const openAddGroup = () => {
    setGroupName('');
    setGroupDesc('');
    setGroupPerms([]);
    setShowAddGroup(true);
    setError(null);
  };

  const openEditGroup = (g: RbacGroup) => {
    setEditGroup(g);
    setGroupName(g.Name);
    setGroupDesc(g.Description || '');
    setGroupPerms([...g.permissionIds]);
    setError(null);
  };

  const isWeakPassword = (pw: string) => {
    if (pw.length < 12) return true;
    if (!/[A-Z]/.test(pw)) return true;
    if (!/[a-z]/.test(pw)) return true;
    if (!/[0-9]/.test(pw)) return true;
    if (!/[^A-Za-z0-9]/.test(pw)) return true;
    return false;
  };

  const submitCreateUser = async () => {
    if (!email.trim() || !password) {
      setError('Email and password are required.');
      return;
    }
    if (isWeakPassword(password)) {
      setError('Password does not meet requirements: at least 12 characters with upper case, lower case, number and symbol.');
      return;
    }
    setSaving(true);
    setError(null);
    try {
      await rbacService.createUser({
        AdminEmail: email.trim(),
        AdminPassword: password,
        groupIds: selectedGroups,
      });
      setShowAddUser(false);
      resetUserForm();
      flash('User created');
      await load();
    } catch (e) {
      setError(handleApiError(e));
    } finally {
      setSaving(false);
    }
  };

  const submitEditUser = async () => {
    if (!editUser) return;
    if (password && isWeakPassword(password)) {
      setError('Password does not meet requirements: at least 12 characters with upper case, lower case, number and symbol.');
      return;
    }
    setSaving(true);
    setError(null);
    try {
      await rbacService.updateUser(editUser.AdminID, {
        groupIds: selectedGroups,
        ...(password ? { AdminPassword: password } : {}),
      });
      setEditUser(null);
      flash('User updated');
      await load();
      await refreshPermissions();
    } catch (e) {
      setError(handleApiError(e));
    } finally {
      setSaving(false);
    }
  };

  const toggleActive = async (u: RbacUser) => {
    try {
      await rbacService.updateUser(u.AdminID, { IsActive: !u.IsActive });
      flash(u.IsActive ? 'User deactivated' : 'User activated');
      await load();
    } catch (e) {
      setError(handleApiError(e));
    }
  };

  const submitCreateGroup = async () => {
    if (!groupName.trim()) {
      setError('Group name is required.');
      return;
    }
    setSaving(true);
    setError(null);
    try {
      await rbacService.createGroup({
        Name: groupName.trim(),
        Description: groupDesc.trim(),
        permissionIds: groupPerms,
      });
      setShowAddGroup(false);
      flash('Group created');
      await load();
    } catch (e) {
      setError(handleApiError(e));
    } finally {
      setSaving(false);
    }
  };

  const submitEditGroup = async () => {
    if (!editGroup) return;
    if (!groupName.trim()) {
      setError('Group name is required.');
      return;
    }
    setSaving(true);
    setError(null);
    try {
      await rbacService.updateGroup(editGroup.GroupId, {
        Name: groupName.trim(),
        Description: groupDesc.trim(),
        permissionIds: groupPerms,
      });
      setEditGroup(null);
      flash('Group updated');
      await load();
      await refreshPermissions();
    } catch (e) {
      setError(handleApiError(e));
    } finally {
      setSaving(false);
    }
  };

  const toggleGroupSel = (id: string) => {
    setSelectedGroups((prev) => (prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id]));
  };

  const togglePerm = (id: string) => {
    setGroupPerms((prev) => (prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id]));
  };

  if (!canUsers && !canGroups) {
    return (
      <div className="h-[calc(100vh-70px)] flex items-center justify-center text-gray-500 text-sm">
        You don’t have permission to manage access.
      </div>
    );
  }

  const permPicker = (
    <div className="space-y-4 max-h-64 overflow-y-auto border border-gray-800 rounded-lg p-3 bg-black/40 custom-scrollbar">
      {permsByModule.map(([mod, list]) => (
        <div key={mod}>
          <div className="text-[11px] font-semibold text-cyber-cyan/90 mb-2 tracking-wide">{moduleLabel(mod)}</div>
          <div className="space-y-1.5">
            {list.map((p) => (
              <label key={p.PermissionId} className="flex items-start gap-2 text-xs text-gray-300 cursor-pointer hover:text-white">
                <input
                  type="checkbox"
                  className="mt-0.5 accent-cyan-500"
                  checked={groupPerms.includes(p.PermissionId)}
                  onChange={() => togglePerm(p.PermissionId)}
                />
                <span>{p.Description}</span>
              </label>
            ))}
          </div>
        </div>
      ))}
    </div>
  );

  return (
    <div className="h-[calc(100vh-70px)] bg-cyber-grid flex flex-col overflow-hidden">
      {/* Header — matches IOC / System Guide style */}
      <div className="p-6 border-b border-gray-800 bg-black/40 backdrop-blur-sm shrink-0 flex items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-lg border border-cyber-cyan/30 bg-cyber-cyan/10 text-cyber-cyan">
            <KeyRound size={22} />
          </div>
          <div>
            <h2 className="text-xl font-bold text-white font-cyber">
              ACCESS <span className="text-cyber-cyan">CONTROL</span>
            </h2>
            <p className="text-xs text-gray-500 mt-0.5">Manage who can sign in, what they can do, and review every access change</p>
          </div>
        </div>
        <button
          type="button"
          onClick={() => void load()}
          className="px-3 py-1.5 bg-gray-800 hover:bg-gray-700 rounded text-gray-400 hover:text-white text-xs font-bold flex items-center gap-2"
        >
          <RefreshCw size={14} className={loading ? 'animate-spin' : ''} /> Refresh
        </button>
      </div>

      {/* Tabs + primary actions */}
      <div className="px-6 border-b border-gray-800 bg-gray-900/30 flex items-center justify-between gap-4 shrink-0">
        <div className="flex gap-1">
          {canUsers && (
            <button
              type="button"
              onClick={() => setTab('users')}
              className={`px-4 py-3 text-xs font-bold border-b-2 flex items-center gap-1.5 ${
                tab === 'users' ? 'border-cyber-cyan text-white' : 'border-transparent text-gray-500 hover:text-gray-300'
              }`}
            >
              <Users size={13} /> Users
            </button>
          )}
          {canGroups && (
            <button
              type="button"
              onClick={() => setTab('groups')}
              className={`px-4 py-3 text-xs font-bold border-b-2 flex items-center gap-1.5 ${
                tab === 'groups' ? 'border-cyber-cyan text-white' : 'border-transparent text-gray-500 hover:text-gray-300'
              }`}
            >
              <Shield size={13} /> Groups
            </button>
          )}
          <button
            type="button"
            onClick={() => setTab('permissions')}
            className={`px-4 py-3 text-xs font-bold border-b-2 ${
              tab === 'permissions' ? 'border-cyber-cyan text-white' : 'border-transparent text-gray-500 hover:text-gray-300'
            }`}
          >
            Permissions
          </button>
          {isPlatform && (
          <button
            type="button"
            onClick={() => setTab('audit')}
            className={`px-4 py-3 text-xs font-bold border-b-2 flex items-center gap-1.5 ${
              tab === 'audit' ? 'border-cyber-cyan text-white' : 'border-transparent text-gray-500 hover:text-gray-300'
            }`}
          >
            <History size={13} /> Audit trail
          </button>
          )}
        </div>

        <div className="flex gap-2 py-2">
          {tab === 'users' && canUsers && (
            <button
              type="button"
              onClick={openAddUser}
              className="px-3 py-1.5 rounded-lg bg-cyber-cyan/15 border border-cyber-cyan/40 text-cyber-cyan text-xs font-bold flex items-center gap-1.5 hover:bg-cyber-cyan/25"
            >
              <Plus size={14} /> Add user
            </button>
          )}
          {tab === 'groups' && canGroups && (
            <button
              type="button"
              onClick={openAddGroup}
              className="px-3 py-1.5 rounded-lg bg-cyber-cyan/15 border border-cyber-cyan/40 text-cyber-cyan text-xs font-bold flex items-center gap-1.5 hover:bg-cyber-cyan/25"
            >
              <Plus size={14} /> Add group
            </button>
          )}
        </div>
      </div>

      {(error || success) && (
        <div
          className={`mx-6 mt-3 px-3 py-2 rounded-lg text-xs border ${
            error
              ? 'bg-red-900/20 border-red-500/40 text-red-300'
              : 'bg-green-900/20 border-green-500/40 text-green-300'
          }`}
        >
          {error || success}
        </div>
      )}

      <div className="flex-1 overflow-auto p-6 custom-scrollbar">
        {loading ? (
          <div className="flex items-center justify-center py-24 text-gray-500 gap-2 text-sm">
            <Loader2 className="animate-spin" size={18} /> Loading…
          </div>
        ) : tab === 'users' && canUsers ? (
          <div className="border border-gray-800 rounded-lg overflow-hidden bg-black/30">
            <table className="w-full text-left text-sm">
              <thead className="bg-gray-900/80 text-[10px] uppercase tracking-wider text-gray-500 border-b border-gray-800">
                <tr>
                  <th className="px-4 py-3 font-semibold">Email</th>
                  <th className="px-4 py-3 font-semibold">Groups</th>
                  <th className="px-4 py-3 font-semibold w-24">Status</th>
                  <th className="px-4 py-3 font-semibold w-36 text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {users.length === 0 && (
                  <tr>
                    <td colSpan={4} className="px-4 py-10 text-center text-gray-500 text-xs">
                      No users yet. Click <strong className="text-gray-300">Add user</strong> to create one.
                    </td>
                  </tr>
                )}
                {users.map((u) => (
                  <tr key={u.AdminID} className="border-b border-gray-800/80 hover:bg-white/[0.02]">
                    <td className="px-4 py-3 text-white">{u.AdminEmail}</td>
                    <td className="px-4 py-3 text-gray-400 text-xs">
                      {u.groups.length ? u.groups.map((g) => g.Name).join(', ') : '—'}
                    </td>
                    <td className="px-4 py-3">
                      <span
                        className={`text-[10px] font-bold px-2 py-0.5 rounded border ${
                          u.IsActive
                            ? 'text-green-400 border-green-500/30 bg-green-900/20'
                            : 'text-gray-500 border-gray-600 bg-gray-800/50'
                        }`}
                      >
                        {u.IsActive ? 'Active' : 'Inactive'}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-right space-x-2">
                      <button
                        type="button"
                        onClick={() => openEditUser(u)}
                        className="inline-flex items-center gap-1 text-xs text-gray-400 hover:text-cyber-cyan"
                      >
                        <Pencil size={12} /> Edit
                      </button>
                      <button
                        type="button"
                        onClick={() => void toggleActive(u)}
                        className="text-xs text-gray-500 hover:text-white"
                      >
                        {u.IsActive ? 'Disable' : 'Enable'}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : tab === 'groups' && canGroups ? (
          <div className="border border-gray-800 rounded-lg overflow-hidden bg-black/30">
            <table className="w-full text-left text-sm">
              <thead className="bg-gray-900/80 text-[10px] uppercase tracking-wider text-gray-500 border-b border-gray-800">
                <tr>
                  <th className="px-4 py-3 font-semibold">Group</th>
                  <th className="px-4 py-3 font-semibold">Description</th>
                  <th className="px-4 py-3 font-semibold w-28">Access rights</th>
                  <th className="px-4 py-3 font-semibold w-24 text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {groups.map((g) => (
                  <tr key={g.GroupId} className="border-b border-gray-800/80 hover:bg-white/[0.02]">
                    <td className="px-4 py-3 text-white font-medium">{g.Name}</td>
                    <td className="px-4 py-3 text-gray-400 text-xs">{g.Description || '—'}</td>
                    <td className="px-4 py-3 text-gray-500 text-xs">{g.permissionIds.length}</td>
                    <td className="px-4 py-3 text-right">
                      <button
                        type="button"
                        onClick={() => openEditGroup(g)}
                        className="inline-flex items-center gap-1 text-xs text-gray-400 hover:text-cyber-cyan"
                      >
                        <Pencil size={12} /> Edit
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : tab === 'permissions' ? (
          <div className="space-y-6 max-w-3xl">
            <p className="text-xs text-gray-500">
              These are the built-in access rights used by the platform. You assign them through{' '}
              <button type="button" className="text-cyber-cyan hover:underline" onClick={() => canGroups && setTab('groups')}>
                Groups
              </button>
              — they aren’t created one-by-one.
            </p>
            {permsByModule.map(([mod, list]) => (
              <div key={mod}>
                <h3 className="text-sm font-bold text-white mb-2 pl-2 border-l-2 border-cyber-cyan">{moduleLabel(mod)}</h3>
                <ul className="space-y-1.5 ml-3">
                  {list.map((p) => (
                    <li key={p.PermissionId} className="text-sm text-gray-400 flex items-start gap-2">
                      <Check size={14} className="text-gray-600 mt-0.5 shrink-0" />
                      {p.Description}
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
        ) : (
          <div className="border border-gray-800 rounded-lg overflow-hidden bg-black/30">
            <div className="px-4 py-3 border-b border-gray-800 bg-gray-900/50 flex items-center justify-between">
              <p className="text-xs text-gray-500">
                Every create/update on users and groups is recorded here. Passwords are never stored.
              </p>
              <span className="text-[10px] uppercase tracking-wider text-gray-600">{auditTotal} events</span>
            </div>
            <table className="w-full text-left text-sm">
              <thead className="bg-gray-900/80 text-[10px] uppercase tracking-wider text-gray-500 border-b border-gray-800">
                <tr>
                  <th className="px-4 py-3 font-semibold w-44">When</th>
                  <th className="px-4 py-3 font-semibold w-28">Action</th>
                  <th className="px-4 py-3 font-semibold">Actor</th>
                  <th className="px-4 py-3 font-semibold">Target</th>
                  <th className="px-4 py-3 font-semibold">Summary</th>
                </tr>
              </thead>
              <tbody>
                {auditLogs.length === 0 && (
                  <tr>
                    <td colSpan={5} className="px-4 py-10 text-center text-gray-500 text-xs">
                      No RBAC changes yet. Create or update a user/group to start the trail.
                    </td>
                  </tr>
                )}
                {auditLogs.map((log) => {
                  const open = expandedAuditId === log.AuditId;
                  return (
                    <React.Fragment key={log.AuditId}>
                      <tr
                        className="border-b border-gray-800/80 hover:bg-white/[0.02] cursor-pointer"
                        onClick={() => setExpandedAuditId(open ? null : log.AuditId)}
                      >
                        <td className="px-4 py-3 text-gray-400 text-xs whitespace-nowrap">
                          {log.createdAt ? new Date(log.createdAt).toLocaleString() : '—'}
                        </td>
                        <td className="px-4 py-3">
                          <span className="text-[10px] font-bold px-2 py-0.5 rounded border border-gray-700 text-cyber-cyan bg-cyber-cyan/10">
                            {log.Action}
                          </span>
                        </td>
                        <td className="px-4 py-3 text-gray-300 text-xs">{log.ActorEmail}</td>
                        <td className="px-4 py-3 text-white text-xs">
                          <span className="text-gray-500 mr-1">{log.TargetType}</span>
                          {log.TargetLabel || log.TargetId}
                        </td>
                        <td className="px-4 py-3 text-gray-400 text-xs">{log.Summary}</td>
                      </tr>
                      {open && (
                        <tr className="border-b border-gray-800/80 bg-black/40">
                          <td colSpan={5} className="px-4 py-3">
                            <div className="grid md:grid-cols-2 gap-3 text-[11px]">
                              <div>
                                <div className="text-gray-500 mb-1 font-semibold uppercase tracking-wider">Before</div>
                                <pre className="whitespace-pre-wrap break-all text-gray-400 bg-black/50 border border-gray-800 rounded p-2 max-h-48 overflow-auto custom-scrollbar">
                                  {log.Before ? JSON.stringify(log.Before, null, 2) : '—'}
                                </pre>
                              </div>
                              <div>
                                <div className="text-gray-500 mb-1 font-semibold uppercase tracking-wider">After</div>
                                <pre className="whitespace-pre-wrap break-all text-gray-400 bg-black/50 border border-gray-800 rounded p-2 max-h-48 overflow-auto custom-scrollbar">
                                  {log.After ? JSON.stringify(log.After, null, 2) : '—'}
                                </pre>
                              </div>
                            </div>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Add user */}
      {showAddUser && (
        <ModalShell
          error={error}
          title="Add user"
          onClose={() => setShowAddUser(false)}
          footer={
            <>
              <button type="button" onClick={() => setShowAddUser(false)} className="px-3 py-1.5 rounded-lg bg-gray-800 text-gray-300 text-xs">
                Cancel
              </button>
              <button
                type="button"
                disabled={saving}
                onClick={() => void submitCreateUser()}
                className="px-3 py-1.5 rounded-lg bg-cyber-cyan/20 border border-cyber-cyan/40 text-cyber-cyan text-xs font-bold disabled:opacity-50 flex items-center gap-1.5"
              >
                {saving && <Loader2 size={12} className="animate-spin" />} Create user
              </button>
            </>
          }
        >
          <label className="block space-y-1">
            <span className="text-[10px] uppercase tracking-wider text-gray-500">Email</span>
            <input
              autoFocus
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="name@company.com"
              className="w-full bg-black/60 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white placeholder:text-gray-600 focus:border-cyber-cyan/50 focus:outline-none"
            />
          </label>
          <label className="block space-y-1">
            <span className="text-[10px] uppercase tracking-wider text-gray-500">Password</span>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••••••"
              className="w-full bg-black/60 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white placeholder:text-gray-600 focus:border-cyber-cyan/50 focus:outline-none font-mono"
            />
            <p className="text-[11px] text-gray-400 font-mono pt-1">
              Password rule: at least 12 characters with upper case, lower case, number and symbol.
            </p>
          </label>
          <div className="space-y-2">
            <span className="text-[10px] uppercase tracking-wider text-gray-500">Groups</span>
            <div className="flex flex-wrap gap-2">
              {groups.map((g) => (
                <label
                  key={g.GroupId}
                  className={`text-xs px-2.5 py-1.5 rounded-lg border cursor-pointer ${
                    selectedGroups.includes(g.GroupId)
                      ? 'border-cyber-cyan/50 bg-cyber-cyan/10 text-cyber-cyan'
                      : 'border-gray-700 text-gray-400 hover:border-gray-500'
                  }`}
                >
                  <input
                    type="checkbox"
                    className="sr-only"
                    checked={selectedGroups.includes(g.GroupId)}
                    onChange={() => toggleGroupSel(g.GroupId)}
                  />
                  {g.Name}
                </label>
              ))}
            </div>
          </div>
        </ModalShell>
      )}

      {/* Edit user */}
      {editUser && (
        <ModalShell
          error={error}
          title={`Edit ${editUser.AdminEmail}`}
          onClose={() => setEditUser(null)}
          footer={
            <>
              <button type="button" onClick={() => setEditUser(null)} className="px-3 py-1.5 rounded-lg bg-gray-800 text-gray-300 text-xs">
                Cancel
              </button>
              <button
                type="button"
                disabled={saving}
                onClick={() => void submitEditUser()}
                className="px-3 py-1.5 rounded-lg bg-cyber-cyan/20 border border-cyber-cyan/40 text-cyber-cyan text-xs font-bold disabled:opacity-50 flex items-center gap-1.5"
              >
                {saving && <Loader2 size={12} className="animate-spin" />} Save
              </button>
            </>
          }
        >
          <label className="block space-y-1">
            <span className="text-[10px] uppercase tracking-wider text-gray-500">New password (optional)</span>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Leave blank to keep current"
              className="w-full bg-black/60 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white placeholder:text-gray-600 focus:border-cyber-cyan/50 focus:outline-none font-mono"
            />
            <p className="text-[11px] text-gray-400 font-mono pt-1">
              Password rule: at least 12 characters with upper case, lower case, number and symbol.
            </p>
          </label>
          <div className="space-y-2">
            <span className="text-[10px] uppercase tracking-wider text-gray-500">Groups</span>
            <div className="flex flex-wrap gap-2">
              {groups.map((g) => (
                <label
                  key={g.GroupId}
                  className={`text-xs px-2.5 py-1.5 rounded-lg border cursor-pointer ${
                    selectedGroups.includes(g.GroupId)
                      ? 'border-cyber-cyan/50 bg-cyber-cyan/10 text-cyber-cyan'
                      : 'border-gray-700 text-gray-400 hover:border-gray-500'
                  }`}
                >
                  <input
                    type="checkbox"
                    className="sr-only"
                    checked={selectedGroups.includes(g.GroupId)}
                    onChange={() => toggleGroupSel(g.GroupId)}
                  />
                  {g.Name}
                </label>
              ))}
            </div>
          </div>
        </ModalShell>
      )}

      {/* Add group */}
      {showAddGroup && (
        <ModalShell
          error={error}
          title="Add group"
          onClose={() => setShowAddGroup(false)}
          footer={
            <>
              <button type="button" onClick={() => setShowAddGroup(false)} className="px-3 py-1.5 rounded-lg bg-gray-800 text-gray-300 text-xs">
                Cancel
              </button>
              <button
                type="button"
                disabled={saving}
                onClick={() => void submitCreateGroup()}
                className="px-3 py-1.5 rounded-lg bg-cyber-cyan/20 border border-cyber-cyan/40 text-cyber-cyan text-xs font-bold disabled:opacity-50 flex items-center gap-1.5"
              >
                {saving && <Loader2 size={12} className="animate-spin" />} Create group
              </button>
            </>
          }
        >
          <label className="block space-y-1">
            <span className="text-[10px] uppercase tracking-wider text-gray-500">Name</span>
            <input
              autoFocus
              value={groupName}
              onChange={(e) => setGroupName(e.target.value)}
              placeholder="e.g. SOC Analysts"
              className="w-full bg-black/60 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white placeholder:text-gray-600 focus:border-cyber-cyan/50 focus:outline-none"
            />
          </label>
          <label className="block space-y-1">
            <span className="text-[10px] uppercase tracking-wider text-gray-500">Description</span>
            <input
              value={groupDesc}
              onChange={(e) => setGroupDesc(e.target.value)}
              placeholder="Short summary"
              className="w-full bg-black/60 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white placeholder:text-gray-600 focus:border-cyber-cyan/50 focus:outline-none"
            />
          </label>
          <div className="space-y-2">
            <span className="text-[10px] uppercase tracking-wider text-gray-500">Access rights</span>
            {permPicker}
          </div>
        </ModalShell>
      )}

      {/* Edit group */}
      {editGroup && (
        <ModalShell
          error={error}
          title={`Edit group · ${editGroup.Name}`}
          onClose={() => setEditGroup(null)}
          footer={
            <>
              <button type="button" onClick={() => setEditGroup(null)} className="px-3 py-1.5 rounded-lg bg-gray-800 text-gray-300 text-xs">
                Cancel
              </button>
              <button
                type="button"
                disabled={saving}
                onClick={() => void submitEditGroup()}
                className="px-3 py-1.5 rounded-lg bg-cyber-cyan/20 border border-cyber-cyan/40 text-cyber-cyan text-xs font-bold disabled:opacity-50 flex items-center gap-1.5"
              >
                {saving && <Loader2 size={12} className="animate-spin" />} Save
              </button>
            </>
          }
        >
          <label className="block space-y-1">
            <span className="text-[10px] uppercase tracking-wider text-gray-500">Name</span>
            <input
              value={groupName}
              onChange={(e) => setGroupName(e.target.value)}
              className="w-full bg-black/60 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:border-cyber-cyan/50 focus:outline-none"
            />
          </label>
          <label className="block space-y-1">
            <span className="text-[10px] uppercase tracking-wider text-gray-500">Description</span>
            <input
              value={groupDesc}
              onChange={(e) => setGroupDesc(e.target.value)}
              className="w-full bg-black/60 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:border-cyber-cyan/50 focus:outline-none"
            />
          </label>
          <div className="space-y-2">
            <span className="text-[10px] uppercase tracking-wider text-gray-500">Access rights</span>
            {permPicker}
          </div>
        </ModalShell>
      )}
    </div>
  );
};
