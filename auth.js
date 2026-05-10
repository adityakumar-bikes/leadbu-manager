/* ═════════════════════════════════════════════════════════════════
   USER AUTHENTICATION & ACCESS CONTROL
   Bikes — AOP Target Tracker
   ─────────────────────────────────────────────────────────────────
   Feature flag: AUTH_ENABLED (below). When false, app behaves as
   before. The live link is unaffected until you push this file
   alongside index.html with the flag flipped on.
   ═════════════════════════════════════════════════════════════════ */

const AUTH_ENABLED       = true;                          // ← FLIP TO false TO DISABLE AUTH
const ALLOWED_DOMAIN     = '@girnarsoft.com';             // primary domain
const ALLOWED_EMAILS     = ['karun.seth@girnarcare.com']; // individual exceptions (any domain)
const SUPER_ADMIN_EMAIL  = 'aditya.kumar@girnarsoft.com'; // bootstraps as admin on first login
const ROLE_RANK = {admin:3, editor:2, viewer:1, pending:0};

// Firebase keys can't contain dots — sanitize email for use as a key
function _emailKey(email){ return email.toLowerCase().replace(/\./g,','); }

let AUTH_USER     = null;   // firebase.User
let AUTH_PROFILE  = null;   // {uid, role, email, displayName, photoURL, disabled, ...}
let _authReady    = false;
let _userListRef  = null;
let _roleAuditRef = null;
let _sessionStart = Date.now();

function _authIsAdmin() { return !!(AUTH_PROFILE && AUTH_PROFILE.role==='admin'  && !AUTH_PROFILE.disabled); }
function _authIsEditor(){ return !!(AUTH_PROFILE && (AUTH_PROFILE.role==='admin'||AUTH_PROFILE.role==='editor') && !AUTH_PROFILE.disabled); }
function _authIsViewer(){ return !!(AUTH_PROFILE && AUTH_PROFILE.role==='viewer' && !AUTH_PROFILE.disabled); }

/* Override existing getCurrentUser() / isAdmin() — when authed, use Google email.
   The originals are kept as fallbacks for the AUTH_ENABLED=false path. */
if (typeof getCurrentUser === 'function') {
  const _origGetCurrentUser = getCurrentUser;
  window.getCurrentUser = function(){
    if (AUTH_ENABLED && AUTH_USER && AUTH_USER.email) return AUTH_USER.email;
    return _origGetCurrentUser();
  };
  // Re-assign top-level name so existing call sites bind to the new fn
  // (function declarations are reassignable at script top level)
  // eslint-disable-next-line no-global-assign
  getCurrentUser = window.getCurrentUser;
}
if (typeof isAdmin === 'function') {
  const _origIsAdmin = isAdmin;
  window.isAdmin = function(){
    if (AUTH_ENABLED && AUTH_PROFILE) return _authIsAdmin();
    return _origIsAdmin();
  };
  // eslint-disable-next-line no-global-assign
  isAdmin = window.isAdmin;
}

/* ─── Login overlay ─────────────────────────────────────────────── */
function _buildAuthGate(){
  if (document.getElementById('auth-gate')) return;
  const gate = document.createElement('div');
  gate.id = 'auth-gate';
  gate.style.cssText = 'position:fixed;inset:0;z-index:99998;background:radial-gradient(circle at 30% 20%,#1c2128 0%,#0d1117 60%);display:flex;align-items:center;justify-content:center;padding:24px;font-family:-apple-system,Segoe UI,Roboto,sans-serif;color:#e6edf3';
  gate.innerHTML = `
    <div style="max-width:420px;width:100%;background:#161b22;border:1px solid #30363d;border-radius:14px;padding:34px;box-shadow:0 24px 70px rgba(0,0,0,.55)">
      <div style="display:flex;align-items:center;gap:11px;margin-bottom:6px">
        <div style="width:38px;height:38px;border-radius:9px;background:linear-gradient(135deg,#58a6ff,#388bfd);display:flex;align-items:center;justify-content:center;font-size:18px">📊</div>
        <div>
          <div style="font-size:14px;font-weight:700;letter-spacing:.2px">Bikes — AOP Target Tracker</div>
          <div style="font-size:11px;color:#7d8590">Lead BU · FY27</div>
        </div>
      </div>
      <h1 style="margin:26px 0 6px;font-size:21px;font-weight:600;letter-spacing:-.3px">Sign in to continue</h1>
      <p style="margin:0 0 22px;font-size:13px;color:#7d8590;line-height:1.55">Access is restricted to <b style="color:#e6edf3">${ALLOWED_DOMAIN}</b> Google accounts. Your role determines what you can see and edit.</p>
      <button id="auth-google-btn" onclick="_authSignIn()" style="width:100%;display:flex;align-items:center;justify-content:center;gap:10px;padding:11px 14px;background:#fff;color:#202124;border:none;border-radius:8px;font-size:14px;font-weight:500;cursor:pointer;font-family:inherit;transition:transform .1s">
        <svg width="18" height="18" viewBox="0 0 24 24"><path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/><path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/><path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/><path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/></svg>
        Continue with Google
      </button>
      <div id="auth-gate-msg" style="margin-top:14px;font-size:12px;color:#7d8590;text-align:center;min-height:16px;line-height:1.5"></div>
      <div style="margin-top:24px;padding-top:18px;border-top:1px solid #21262d;font-size:11px;color:#6e7681;line-height:1.6">
        First time signing in? Your account will start with <b>Viewer</b> access (read-only). Ask <b>Aditya</b> to promote you.
      </div>
    </div>`;
  document.body.appendChild(gate);
}
function _authShowGate(msg){
  _buildAuthGate();
  const g=document.getElementById('auth-gate');
  g.style.display='flex';
  document.body.style.overflow='hidden';
  if (msg!=null) document.getElementById('auth-gate-msg').innerHTML=msg;
}
function _authHideGate(){
  const g=document.getElementById('auth-gate');
  if (g) g.style.display='none';
  document.body.style.overflow='';
}
function _authShowSpecial(title, body){
  _buildAuthGate();
  const g=document.getElementById('auth-gate');
  g.style.display='flex'; document.body.style.overflow='hidden';
  g.querySelector('h1').innerHTML=title;
  g.querySelector('p').innerHTML=body;
  const btn=document.getElementById('auth-google-btn');
  if (btn) btn.outerHTML='<button onclick="_authSignOut()" style="width:100%;padding:11px 14px;background:#21262d;color:#e6edf3;border:1px solid #30363d;border-radius:8px;font-size:13px;font-weight:500;cursor:pointer;font-family:inherit">Sign out</button>';
}

function _authSignIn(){
  if (typeof firebase==='undefined' || !firebase.auth){
    document.getElementById('auth-gate-msg').innerHTML='<span style="color:#f85149">⚠ Firebase Auth SDK not loaded</span>';
    return;
  }
  const provider=new firebase.auth.GoogleAuthProvider();
  provider.setCustomParameters({hd:'girnarsoft.com', prompt:'select_account'});
  const btn=document.getElementById('auth-google-btn'); if(btn) btn.disabled=true;
  firebase.auth().signInWithPopup(provider).catch(err=>{
    if(btn) btn.disabled=false;
    const msg=document.getElementById('auth-gate-msg');
    let txt = err.message || err.code || 'Sign-in failed';
    if (err.code==='auth/popup-blocked') txt='Popup was blocked. Allow popups for this site and try again.';
    if (err.code==='auth/popup-closed-by-user') txt='Sign-in cancelled.';
    if (err.code==='auth/operation-not-allowed') txt='Google sign-in is not yet enabled in Firebase Console (Authentication → Sign-in method).';
    if (err.code==='auth/unauthorized-domain') txt='This domain is not authorised. Add it under Firebase → Authentication → Settings → Authorized domains.';
    if (msg) msg.innerHTML='<span style="color:#f85149">⚠ '+txt+'</span>';
  });
}
function _authSignOut(){
  try{ firebase.auth().signOut(); }catch(e){}
  setTimeout(()=>location.reload(), 250);
}

/* ─── Apply role-based UI ───────────────────────────────────────── */
function _authApplyRoleUI(){
  const role = AUTH_PROFILE ? AUTH_PROFILE.role : '';
  document.body.dataset.role = role;

  // Show/hide admin-only nav entries
  document.querySelectorAll('.auth-admin-only').forEach(el=>{
    el.style.display = _authIsAdmin() ? '' : 'none';
  });

  // Update the user pill in the header
  const lbl = document.getElementById('user-label');
  if (lbl && AUTH_USER){
    const name = AUTH_USER.displayName || AUTH_USER.email.split('@')[0];
    const ico  = AUTH_USER.photoURL
      ? `<img src="${AUTH_USER.photoURL}" style="width:14px;height:14px;border-radius:50%;margin-right:5px;vertical-align:-3px" referrerpolicy="no-referrer">`
      : '';
    const roleColor = {admin:'#ee6a3a',editor:'#3fb950',viewer:'#7d8590',pending:'#f0a500'}[role]||'#7d8590';
    lbl.innerHTML = ico + name +
      ` <span style="font-size:9px;padding:1px 5px;border-radius:3px;background:${roleColor}33;color:${roleColor};font-weight:600;letter-spacing:.5px;text-transform:uppercase;margin-left:3px">${role}</span>`;
  }
  // Re-target user button click → menu (don't break the existing prompt for AUTH_ENABLED=false)
  const ubtn = document.getElementById('user-btn');
  if (ubtn) ubtn.setAttribute('onclick','_authUserMenu(event)');
}

function _authUserMenu(ev){
  if (ev) ev.stopPropagation();
  const existing=document.getElementById('auth-user-menu');
  if (existing){ existing.remove(); return; }
  const role = AUTH_PROFILE ? AUTH_PROFILE.role : '—';
  const menu=document.createElement('div');
  menu.id='auth-user-menu';
  menu.style.cssText='position:fixed;top:50px;right:14px;z-index:99997;background:#161b22;border:1px solid #30363d;border-radius:8px;padding:6px;box-shadow:0 12px 30px rgba(0,0,0,.5);min-width:220px;font-family:-apple-system,Segoe UI,Roboto,sans-serif;font-size:12px';
  menu.innerHTML = `
    <div style="padding:10px 12px;border-bottom:1px solid #21262d;margin-bottom:4px">
      <div style="font-weight:600;color:#e6edf3">${AUTH_USER ? (AUTH_USER.displayName||'') : ''}</div>
      <div style="font-size:11px;color:#7d8590;font-family:'JetBrains Mono',monospace">${AUTH_USER ? AUTH_USER.email : ''}</div>
      <div style="margin-top:5px;font-size:10px;color:#7d8590;text-transform:uppercase;letter-spacing:.5px">Role: <b style="color:#e6edf3">${role}</b></div>
    </div>
    ${_authIsAdmin()?`<div onclick="setPage('users');document.getElementById('auth-user-menu').remove()" style="padding:8px 12px;cursor:pointer;border-radius:5px;color:#e6edf3" onmouseover="this.style.background='#21262d'" onmouseout="this.style.background=''">👥 User Management</div>`:''}
    <div onclick="_authSignOut()" style="padding:8px 12px;cursor:pointer;border-radius:5px;color:#e6edf3" onmouseover="this.style.background='#21262d'" onmouseout="this.style.background=''">↩️ Sign out</div>`;
  document.body.appendChild(menu);
  setTimeout(()=>{
    document.addEventListener('click', function close(e){
      if(!menu.contains(e.target)){ menu.remove(); document.removeEventListener('click', close); }
    });
  },0);
}

/* ─── Auth state listener / bootstrap ───────────────────────────── */
async function _authInit(){
  if (!AUTH_ENABLED){ console.log('[auth] disabled by flag'); return; }
  if (typeof firebase==='undefined' || !firebase.auth){
    console.warn('[auth] firebase.auth SDK not present — include firebase-auth-compat.js');
    return;
  }
  // Wait for _fbDb to exist
  let waits=0;
  while (typeof _fbDb==='undefined' && waits<50){ await new Promise(r=>setTimeout(r,50)); waits++; }
  if (typeof _fbDb==='undefined'){ console.warn('[auth] _fbDb never initialized'); return; }

  _userListRef  = _fbDb.ref('authUsers');
  _roleAuditRef = _fbDb.ref('roleAudit');

  _authShowGate('<span style="opacity:.6">Checking sign-in…</span>');

  firebase.auth().onAuthStateChanged(async user=>{
    try {
    AUTH_USER = user;
    if (!user){
      AUTH_PROFILE = null;
      _authReady = false;
      _authShowGate('');
      return;
    }
    // Domain check — allow primary domain OR individual whitelisted emails
    const emailLower = (user.email||'').toLowerCase();
    const allowed = emailLower.endsWith(ALLOWED_DOMAIN) || ALLOWED_EMAILS.map(e=>e.toLowerCase()).includes(emailLower);
    if (!user.email || !allowed){
      _authShowGate('<span style="color:#f85149">Only '+ALLOWED_DOMAIN+' accounts are permitted.</span>');
      try{ await firebase.auth().signOut(); }catch(e){}
      return;
    }
    // Force the auth token to be attached to the RTDB connection before any reads
    await user.getIdToken(true);
    await new Promise(r => setTimeout(r, 300));
    const uid = user.uid;
    const ref = _userListRef.child(uid);
    const snap = await ref.once('value');
    let prof = snap.val();

    if (!prof){
      // First sign-in: check for a pre-invite, then bootstrap
      let preInvite = null;
      try {
        const preSnap = await _fbDb.ref('preInvited/'+_emailKey(user.email)).once('value');
        preInvite = preSnap.val();
      } catch(e) {
        console.warn('[auth] Could not read preInvited:', e.code || e.message);
      }
      const isSuper = (user.email.toLowerCase() === SUPER_ADMIN_EMAIL.toLowerCase());
      const initialRole = isSuper ? 'admin' : (preInvite && preInvite.role ? preInvite.role : 'viewer');
      prof = {
        email: user.email.toLowerCase(),
        displayName: user.displayName || '',
        photoURL: user.photoURL || '',
        role: initialRole,
        disabled: false,
        firstSeen: firebase.database.ServerValue.TIMESTAMP,
        lastLogin: firebase.database.ServerValue.TIMESTAMP
      };
      await ref.set(prof);
      // Consume the pre-invite so it doesn't linger
      if (preInvite) await _fbDb.ref('preInvited/'+_emailKey(user.email)).remove();
      _roleAuditRef.push({ts:firebase.database.ServerValue.TIMESTAMP, actor: preInvite ? preInvite.addedBy : 'SYSTEM', target:user.email, action:'create', oldRole:null, newRole:initialRole});
    } else {
      await ref.update({
        lastLogin: firebase.database.ServerValue.TIMESTAMP,
        photoURL:  user.photoURL || prof.photoURL || '',
        displayName: user.displayName || prof.displayName || ''
      });
    }
    AUTH_PROFILE = Object.assign({uid}, prof);

    if (prof.disabled){
      _authShowSpecial(
        '<span style="color:#f85149">Access revoked</span>',
        `Your account <b style="color:#e6edf3">${user.email}</b> has been disabled by an admin. Contact <b>${SUPER_ADMIN_EMAIL}</b> if this is an error.`);
      return;
    }

    _authHideGate();
    _authApplyRoleUI();
    _authReady = true;
    if (typeof _fbStartSync==='function') _fbStartSync(); // start Firebase data sync now that user is authed
    if (typeof _updateAdminUI==='function') _updateAdminUI();

    // Live profile listener — react to role change / disable / force-signout
    ref.on('value', s=>{
      const np = s.val();
      if (!np){ _authShowGate('Account removed.'); firebase.auth().signOut(); return; }
      const prevRole = AUTH_PROFILE && AUTH_PROFILE.role;
      AUTH_PROFILE = Object.assign({uid}, np);
      if (np.disabled){
        _authShowSpecial(
          '<span style="color:#f85149">Access revoked</span>',
          `Your account has been disabled. Contact <b>${SUPER_ADMIN_EMAIL}</b>.`);
        return;
      }
      if (np.forceSignoutAt && np.forceSignoutAt > _sessionStart){
        _authShowSpecial('Session ended', 'An admin has signed you out. Please sign in again.');
        firebase.auth().signOut();
        return;
      }
      _authApplyRoleUI();
      if (prevRole !== np.role && typeof _updateAdminUI==='function') _updateAdminUI();
      // If we were on /users page but lost admin, kick out
      if (typeof PAGE !== 'undefined' && PAGE==='users' && !_authIsAdmin()) setPage('overview');
      if (typeof PAGE !== 'undefined' && PAGE==='users') renderUsers();
    });
    } catch(err) {
      // Surface any unexpected error in the sign-in gate instead of silently dying
      console.error('[auth] onAuthStateChanged error:', err);
      const msg = document.getElementById('auth-gate-msg');
      if (msg) msg.innerHTML = '<span style="color:#f85149">⚠ Sign-in error: ' + (err.message||err.code||String(err)) + '</span>';
      const btn = document.getElementById('auth-google-btn');
      if (btn) btn.disabled = false;
    }
  });
}

/* ─── User Management page ──────────────────────────────────────── */
let _allUsers = {};
let _allUsersListening = false;
let _onlineUsers = {};

function _watchAllUsers(){
  if (_allUsersListening || !_userListRef) return;
  _allUsersListening = true;
  _userListRef.on('value', snap=>{
    _allUsers = snap.val() || {};
    if (typeof PAGE!=='undefined' && PAGE==='users') renderUsers();
    const pending = Object.values(_allUsers).filter(u=>u && u.role==='pending' && !u.disabled).length;
    const badge = document.getElementById('pn-pending-count');
    if (badge){
      if (pending>0){ badge.textContent=pending; badge.style.display=''; }
      else badge.style.display='none';
    }
  });
  _fbDb.ref('presence').on('value', s=>{
    _onlineUsers = s.val() || {};
    if (typeof PAGE!=='undefined' && PAGE==='users') renderUsers();
  });
}

function renderUsers(){
  const el = document.getElementById('page-users');
  if (!el) return;
  if (!AUTH_ENABLED){
    el.innerHTML = '<div style="padding:60px;text-align:center;color:var(--text3)">Auth is currently disabled. Set <code>AUTH_ENABLED=true</code> in <code>auth.js</code> to use User Management.</div>';
    return;
  }
  if (!AUTH_PROFILE){
    el.innerHTML = '<div style="padding:60px;text-align:center;color:var(--text3)">Sign in required.</div>';
    return;
  }
  if (!_authIsAdmin()){
    el.innerHTML = '<div style="padding:60px;text-align:center;color:var(--text3)">⛔ Admin only. Your role is <b>'+AUTH_PROFILE.role+'</b>.</div>';
    return;
  }
  _watchAllUsers();

  const users = Object.entries(_allUsers).map(([uid,u])=>Object.assign({uid},u));
  users.sort((a,b)=>{
    if ((a.disabled?1:0)!==(b.disabled?1:0)) return (a.disabled?1:0)-(b.disabled?1:0);
    const ra = a.role==='pending' ? 9 : (ROLE_RANK[a.role]||0);
    const rb = b.role==='pending' ? 9 : (ROLE_RANK[b.role]||0);
    if (ra!==rb) return rb-ra;
    return (a.email||'').localeCompare(b.email||'');
  });

  // Online detection: presence stores {name, email?}; match either email or displayName
  const onlineEmails = new Set();
  const onlineNames  = new Set();
  Object.values(_onlineUsers).forEach(roomBucket=>{
    if (!roomBucket || typeof roomBucket!=='object') return;
    Object.values(roomBucket).forEach(p=>{
      if (!p) return;
      if (p.email) onlineEmails.add(String(p.email).toLowerCase());
      if (p.name)  onlineNames.add(String(p.name).toLowerCase());
    });
  });

  const fmtDate = ts => {
    if (!ts) return '—';
    const d = new Date(ts);
    return d.toLocaleDateString('en-IN',{day:'2-digit',month:'short'}) + ' ' +
           d.toLocaleTimeString('en-IN',{hour:'2-digit',minute:'2-digit'});
  };
  const roleBadge = (role,disabled)=>{
    const c = {admin:'#ee6a3a',editor:'#3fb950',viewer:'#7d8590',pending:'#f0a500'}[role]||'#7d8590';
    return `<span style="display:inline-block;padding:2px 8px;border-radius:4px;font-size:10px;font-weight:600;letter-spacing:.5px;text-transform:uppercase;background:${c}1a;color:${c};${disabled?'opacity:.4;text-decoration:line-through':''}">${role}</span>`;
  };
  const isUserOnline = u => onlineEmails.has((u.email||'').toLowerCase()) || onlineNames.has((u.displayName||'').toLowerCase());

  // ── Header
  const onlineCount = users.filter(isUserOnline).length;
  let html = `<div style="padding:18px 22px 12px"><div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px"><div><div style="font-size:18px;font-weight:600;color:var(--text1);letter-spacing:-.2px">User Management</div><div style="font-size:12px;color:var(--text3);margin-top:2px">${users.length} user${users.length!==1?'s':''} · <span style="color:#3fb950">●</span> ${onlineCount} online</div></div><div style="display:flex;gap:8px"><button onclick="_authViewRoleAudit()" class="btn btn-dim" style="padding:5px 11px">📜 Role audit log</button></div></div></div>`;

  // ── Stats strip
  const counts = {admin:0,editor:0,viewer:0,pending:0,disabled:0};
  users.forEach(u=>{ if(u.disabled) counts.disabled++; else counts[u.role]=(counts[u.role]||0)+1; });
  html += `<div style="display:grid;grid-template-columns:repeat(5,1fr);gap:8px;padding:0 22px 14px">`;
  [['admin','Admins','#ee6a3a'],['editor','Editors','#3fb950'],['viewer','Viewers','#7d8590'],['pending','Pending','#f0a500'],['disabled','Disabled','#f85149']].forEach(([k,lbl,c])=>{
    html += `<div style="background:var(--bg2);border:1px solid var(--border);border-radius:6px;padding:11px 14px"><div style="font-size:10px;color:var(--text3);text-transform:uppercase;letter-spacing:.5px;margin-bottom:4px">${lbl}</div><div style="font-size:22px;font-weight:600;color:${c};font-family:var(--mono)">${counts[k]||0}</div></div>`;
  });
  html += `</div>`;

  // ── Pre-add user form
  html += `<div style="margin:0 22px 14px;background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:14px">
    <div style="font-size:12px;font-weight:600;color:var(--text1);margin-bottom:4px">➕ Pre-add User</div>
    <div style="font-size:11px;color:var(--text3);margin-bottom:10px;line-height:1.55">Add a teammate before they sign in — their role is applied automatically on first login.</div>
    <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:flex-end">
      <div style="flex:1;min-width:180px">
        <div style="font-size:10px;color:var(--text3);margin-bottom:4px;text-transform:uppercase;letter-spacing:.5px">Email</div>
        <input id="pre-add-email" type="email" placeholder="name@girnarsoft.com"
          style="width:100%;box-sizing:border-box;background:var(--bg);border:1px solid var(--border2);border-radius:6px;padding:7px 10px;color:var(--text1);font-size:12px;font-family:inherit;outline:none">
      </div>
      <div>
        <div style="font-size:10px;color:var(--text3);margin-bottom:4px;text-transform:uppercase;letter-spacing:.5px">Role</div>
        <select id="pre-add-role" style="background:var(--bg);border:1px solid var(--border2);border-radius:6px;padding:7px 10px;color:var(--text1);font-size:12px;font-family:inherit;outline:none">
          <option value="viewer">Viewer</option>
          <option value="editor">Editor</option>
          <option value="admin">Admin</option>
        </select>
      </div>
      <button class="btn btn-pri" onclick="_authPreAddUser()" style="padding:7px 14px;font-size:12px">Add</button>
    </div>
    <div id="pre-invite-list"></div>
  </div>`;

  // ── Pending queue
  const pendings = users.filter(u=>u.role==='pending' && !u.disabled);
  if (pendings.length){
    html += `<div style="margin:0 22px 14px;background:#f0a50012;border:1px solid #f0a50044;border-radius:8px;padding:14px"><div style="font-size:12px;font-weight:600;color:#f0a500;margin-bottom:8px;text-transform:uppercase;letter-spacing:.5px">⚠ Pending approval (${pendings.length})</div>`;
    pendings.forEach(u=>{
      const av = u.photoURL ? `<img src="${u.photoURL}" style="width:30px;height:30px;border-radius:50%" referrerpolicy="no-referrer">` : `<div style="width:30px;height:30px;border-radius:50%;background:var(--bg3);display:flex;align-items:center;justify-content:center;font-size:11px;color:var(--text2)">${(u.email||'?').slice(0,1).toUpperCase()}</div>`;
      html += `<div style="display:flex;align-items:center;gap:11px;padding:8px 0;border-top:1px solid #f0a50022">${av}<div style="flex:1;min-width:0"><div style="font-size:12px;color:var(--text1);font-weight:500">${u.displayName||u.email}</div><div style="font-size:11px;color:var(--text3);font-family:var(--mono)">${u.email}</div></div><button class="btn btn-pri" onclick="_authSetRole('${u.uid}','editor')" style="padding:4px 10px;font-size:11px">✓ Approve as Editor</button><button class="btn btn-dim" onclick="_authSetRole('${u.uid}','viewer')" style="padding:4px 10px;font-size:11px">View only</button><button class="btn btn-dim" onclick="_authToggleDisabled('${u.uid}',true)" style="padding:4px 10px;font-size:11px;color:#f85149">Reject</button></div>`;
    });
    html += `</div>`;
  }

  // ── User table
  html += `<div style="margin:0 22px 22px;background:var(--bg2);border:1px solid var(--border);border-radius:8px;overflow:hidden"><table style="width:100%;border-collapse:collapse;font-size:12px"><thead><tr style="background:var(--bg3);color:var(--text3);font-size:10px;text-transform:uppercase;letter-spacing:.5px"><th style="text-align:left;padding:10px 14px">User</th><th style="text-align:left;padding:10px 8px">Email</th><th style="text-align:center;padding:10px 8px">Role</th><th style="text-align:center;padding:10px 8px">Status</th><th style="text-align:left;padding:10px 8px">First seen</th><th style="text-align:left;padding:10px 8px">Last login</th><th style="text-align:right;padding:10px 14px">Actions</th></tr></thead><tbody>`;
  users.forEach((u,i)=>{
    const me = AUTH_USER && u.email === AUTH_USER.email.toLowerCase();
    const online = isUserOnline(u);
    const bg = i%2 ? 'var(--bg2)' : 'var(--bg)';
    const av = u.photoURL ? `<img src="${u.photoURL}" style="width:30px;height:30px;border-radius:50%" referrerpolicy="no-referrer">` : `<div style="width:30px;height:30px;border-radius:50%;background:var(--bg3);display:flex;align-items:center;justify-content:center;font-size:12px;color:var(--text2);font-weight:600">${(u.displayName||u.email||'?').slice(0,1).toUpperCase()}</div>`;
    html += `<tr style="background:${bg};border-top:1px solid var(--border)${u.disabled?';opacity:.55':''}">
      <td style="padding:9px 14px"><div style="display:flex;align-items:center;gap:9px;position:relative">${av}${online?'<span style="position:absolute;left:22px;top:-1px;width:10px;height:10px;background:#3fb950;border:2px solid var(--bg);border-radius:50%" title="Online"></span>':''}<div><div style="color:var(--text1);font-weight:500">${u.displayName||(u.email||'').split('@')[0]}${me?' <span style="font-size:9px;color:var(--accent);font-weight:600">YOU</span>':''}</div><div style="font-size:10px;color:var(--text3)">${online?'<span style="color:#3fb950">●</span> Online now':'Offline'}</div></div></div></td>
      <td style="padding:9px 8px;color:var(--text2);font-family:var(--mono);font-size:11px">${u.email||'—'}</td>
      <td style="padding:9px 8px;text-align:center">${roleBadge(u.role,u.disabled)}</td>
      <td style="padding:9px 8px;text-align:center"><span style="font-size:11px;color:${u.disabled?'#f85149':'var(--text2)'}">${u.disabled?'Disabled':'Active'}</span></td>
      <td style="padding:9px 8px;color:var(--text3);font-size:11px;white-space:nowrap">${fmtDate(u.firstSeen)}</td>
      <td style="padding:9px 8px;color:var(--text3);font-size:11px;white-space:nowrap">${fmtDate(u.lastLogin)}</td>
      <td style="padding:9px 14px;text-align:right">${_authActionMenu(u,me)}</td>
    </tr>`;
  });
  html += `</tbody></table></div>`;

  html += `<div style="padding:0 22px 22px;font-size:11px;color:var(--text3);line-height:1.7;max-width:780px"><b style="color:var(--text2)">Quick rules:</b> Admins manage users + edit data. Editors edit data only. Viewers see everything but cannot change anything. Disabling a user revokes access immediately on their next page load. Force sign-out ends a user's current session next time the page reloads.</div>`;

  el.innerHTML = html;
  _watchPreInvites();   // start/keep live listener
  _renderPreInvites();  // paint from cached data immediately
}

/* ─── Pre-invite management ──────────────────────────────────────── */
let _allPreInvites = {};
let _preInvitesListening = false;

function _watchPreInvites(){
  if (_preInvitesListening || !_fbDb) return;
  _preInvitesListening = true;
  _fbDb.ref('preInvited').on('value', snap=>{
    _allPreInvites = snap.val() || {};
    _renderPreInvites();
  });
}

function _renderPreInvites(){
  const el = document.getElementById('pre-invite-list');
  if (!el) return;
  const invites = Object.entries(_allPreInvites);
  if (!invites.length){ el.innerHTML = ''; return; }
  const roleColor = {admin:'#ee6a3a', editor:'#3fb950', viewer:'#7d8590'};
  const fmtDate = ts => ts ? new Date(ts).toLocaleDateString('en-IN',{day:'2-digit',month:'short',year:'2-digit'}) : '—';
  let h = `<div style="margin-top:10px;border-top:1px solid var(--border);padding-top:8px">
    <div style="font-size:10px;color:var(--text3);text-transform:uppercase;letter-spacing:.5px;margin-bottom:6px">Pending invites — role applied on first login</div>`;
  invites.forEach(([key, inv])=>{
    const c = roleColor[inv.role] || '#7d8590';
    h += `<div style="display:flex;align-items:center;gap:10px;padding:5px 0;border-bottom:1px solid var(--border)">
      <div style="flex:1;font-size:11px;color:var(--text1);font-family:var(--mono)">${inv.email||key}</div>
      <span style="padding:2px 7px;border-radius:4px;font-size:10px;font-weight:600;background:${c}1a;color:${c};text-transform:uppercase;letter-spacing:.5px">${inv.role}</span>
      <span style="font-size:10px;color:var(--text3);white-space:nowrap">Added ${fmtDate(inv.addedAt)}</span>
      <button class="btn btn-dim" onclick="_authRevokeInvite('${key}')" style="padding:2px 8px;font-size:10px;color:#f85149">Revoke</button>
    </div>`;
  });
  h += `</div>`;
  el.innerHTML = h;
}

async function _authPreAddUser(){
  if (!_authIsAdmin()) return;
  const emailEl = document.getElementById('pre-add-email');
  const roleEl  = document.getElementById('pre-add-role');
  const email   = (emailEl ? emailEl.value : '').trim().toLowerCase();
  const role    = roleEl ? roleEl.value : 'viewer';
  if (!email){ alert('Enter an email address.'); return; }
  if (!email.endsWith(ALLOWED_DOMAIN)){ alert('Only '+ALLOWED_DOMAIN+' addresses are permitted.'); return; }
  // Don't pre-add someone who's already registered
  if (Object.values(_allUsers).some(u=>u && (u.email||'').toLowerCase()===email)){
    alert(email+' is already a registered user.\nChange their role directly from the table.'); return;
  }
  if (_allPreInvites[_emailKey(email)]){
    if (!confirm(email+' already has a pending invite. Overwrite with '+role+'?')) return;
  }
  await _fbDb.ref('preInvited/'+_emailKey(email)).set({
    email, role,
    addedBy: AUTH_USER ? AUTH_USER.email : 'admin',
    addedAt: firebase.database.ServerValue.TIMESTAMP
  });
  if (emailEl) emailEl.value = '';
}

async function _authRevokeInvite(key){
  if (!_authIsAdmin()) return;
  const inv = _allPreInvites[key];
  if (!confirm('Revoke pre-invite for '+(inv?inv.email:key)+'?')) return;
  await _fbDb.ref('preInvited/'+key).remove();
}

function _authActionMenu(u, me){
  if (me){
    return '<span style="font-size:10px;color:var(--text3)">— you —</span>';
  }
  let h = '<div style="display:flex;gap:5px;justify-content:flex-end;flex-wrap:wrap">';
  if (u.disabled){
    h += `<button class="btn btn-pri" onclick="_authToggleDisabled('${u.uid}',false)" style="padding:3px 9px;font-size:10px">Re-enable</button>`;
  } else {
    if (u.role === 'pending'){
      h += `<button class="btn btn-pri" onclick="_authSetRole('${u.uid}','editor')" style="padding:3px 9px;font-size:10px">Approve→Editor</button>`;
      h += `<button class="btn btn-dim" onclick="_authSetRole('${u.uid}','viewer')" style="padding:3px 9px;font-size:10px">→Viewer</button>`;
    } else {
      const opts = [];
      if (u.role !== 'admin')  opts.push(`<button class="btn btn-dim" onclick="_authSetRole('${u.uid}','admin')"  style="padding:3px 9px;font-size:10px;color:#ee6a3a">↑ Admin</button>`);
      if (u.role !== 'editor') opts.push(`<button class="btn btn-dim" onclick="_authSetRole('${u.uid}','editor')" style="padding:3px 9px;font-size:10px;color:#3fb950">${u.role==='admin'?'↓':'→'} Editor</button>`);
      if (u.role !== 'viewer') opts.push(`<button class="btn btn-dim" onclick="_authSetRole('${u.uid}','viewer')" style="padding:3px 9px;font-size:10px;color:#7d8590">↓ Viewer</button>`);
      h += opts.join('');
    }
    h += `<button class="btn btn-dim" onclick="_authForceSignout('${u.uid}')" style="padding:3px 9px;font-size:10px" title="Force a fresh sign-in next page load">Sign out</button>`;
    h += `<button class="btn btn-dim" onclick="_authToggleDisabled('${u.uid}',true)" style="padding:3px 9px;font-size:10px;color:#f85149">Disable</button>`;
  }
  h += '</div>';
  return h;
}

async function _authSetRole(uid, newRole){
  if (!_authIsAdmin()) return;
  const u = _allUsers[uid]; if (!u) return;
  if (AUTH_USER && u.email === AUTH_USER.email.toLowerCase()){ alert('Cannot change your own role.'); return; }
  if (!confirm(`Change ${u.email} role from ${u.role} → ${newRole}?`)) return;
  await _userListRef.child(uid).update({role:newRole});
  _roleAuditRef.push({ts:firebase.database.ServerValue.TIMESTAMP, actor:AUTH_USER.email, target:u.email, action:'role_change', oldRole:u.role, newRole});
}
async function _authToggleDisabled(uid, disabled){
  if (!_authIsAdmin()) return;
  const u = _allUsers[uid]; if (!u) return;
  if (AUTH_USER && u.email === AUTH_USER.email.toLowerCase()){ alert('Cannot disable yourself.'); return; }
  if (disabled && !confirm(`Disable access for ${u.email}? They'll be locked out on next page load.`)) return;
  await _userListRef.child(uid).update({disabled});
  _roleAuditRef.push({ts:firebase.database.ServerValue.TIMESTAMP, actor:AUTH_USER.email, target:u.email, action: disabled?'disable':'enable', oldRole:u.role, newRole:u.role});
}
async function _authForceSignout(uid){
  if (!_authIsAdmin()) return;
  const u = _allUsers[uid]; if (!u) return;
  await _userListRef.child(uid).update({forceSignoutAt: firebase.database.ServerValue.TIMESTAMP});
  _roleAuditRef.push({ts:firebase.database.ServerValue.TIMESTAMP, actor:AUTH_USER.email, target:u.email, action:'force_signout', oldRole:u.role, newRole:u.role});
  alert(`${u.email} will be signed out on their next page load.`);
}

async function _authViewRoleAudit(){
  if (!_roleAuditRef) return;
  const snap = await _roleAuditRef.orderByChild('ts').limitToLast(200).once('value');
  const entries = [];
  snap.forEach(s=>entries.push(s.val()));
  entries.reverse();
  const fmtDate = ts => {
    if (!ts) return '—';
    const d = new Date(ts);
    return d.toLocaleString('en-IN',{day:'2-digit',month:'short',hour:'2-digit',minute:'2-digit'});
  };
  let html = `<div style="background:var(--bg);border-radius:10px;border:1px solid var(--border);max-width:820px;width:92%;max-height:80vh;overflow:auto">
    <div style="padding:14px 20px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center;position:sticky;top:0;background:var(--bg);z-index:1"><div style="font-size:14px;font-weight:600;color:var(--text1)">Role change audit log</div><button onclick="document.getElementById('auth-audit-overlay').remove()" style="background:none;border:none;color:var(--text2);font-size:22px;cursor:pointer;line-height:1">×</button></div>`;
  if (!entries.length){
    html += '<div style="padding:30px;text-align:center;color:var(--text3)">No role changes recorded yet.</div>';
  } else {
    html += '<table style="width:100%;border-collapse:collapse;font-size:12px"><thead><tr style="background:var(--bg2);color:var(--text3);font-size:10px;text-transform:uppercase;letter-spacing:.5px"><th style="text-align:left;padding:9px 14px">When</th><th style="text-align:left;padding:9px 8px">Actor</th><th style="text-align:left;padding:9px 8px">Target</th><th style="text-align:left;padding:9px 8px">Action</th><th style="text-align:left;padding:9px 14px">Change</th></tr></thead><tbody>';
    entries.forEach((e,i)=>{
      const bg = i%2 ? 'var(--bg2)' : 'var(--bg)';
      const actC = {role_change:'#58a6ff',create:'#3fb950',disable:'#f85149',enable:'#3fb950',force_signout:'#f0a500'}[e.action]||'var(--text2)';
      html += `<tr style="background:${bg};border-top:1px solid var(--border)"><td style="padding:8px 14px;color:var(--text2);font-size:11px;white-space:nowrap">${fmtDate(e.ts)}</td><td style="padding:8px 8px;color:var(--text2);font-family:var(--mono);font-size:11px">${e.actor||'—'}</td><td style="padding:8px 8px;color:var(--text2);font-family:var(--mono);font-size:11px">${e.target||'—'}</td><td style="padding:8px 8px;color:${actC};font-weight:500">${e.action||'—'}</td><td style="padding:8px 14px;color:var(--text3)">${e.oldRole||''}${e.oldRole&&e.newRole?' → ':''}<b style="color:var(--text2)">${e.newRole||''}</b></td></tr>`;
    });
    html += '</tbody></table>';
  }
  html += '</div>';
  const ov = document.createElement('div');
  ov.id='auth-audit-overlay';
  ov.style.cssText='position:fixed;inset:0;background:rgba(0,0,0,.55);z-index:99996;display:flex;align-items:center;justify-content:center';
  ov.innerHTML = html;
  ov.onclick = e => { if (e.target === ov) ov.remove(); };
  document.body.appendChild(ov);
}

/* ─── Viewer-mode read-only CSS ─────────────────────────────────── */
(function(){
  const css = `
    body[data-role="viewer"] input:not([type=checkbox]):not([type=radio]):not([type=button]):not([type=submit]),
    body[data-role="viewer"] textarea,
    body[data-role="viewer"] select{ pointer-events:none !important; opacity:.85 !important; }
    body[data-role="viewer"] [contenteditable="true"]{ pointer-events:none !important; }
    body[data-role="viewer"] .viewer-hide,
    body[data-role="viewer"] [data-role-hide="viewer"]{ display:none !important; }
    body[data-role="viewer"] .add-row,
    body[data-role="viewer"] #btn-clear-actuals,
    body[data-role="viewer"] [onclick*="openClientUpsert"],
    body[data-role="viewer"] [onclick*="openModal"]:not(.viewer-allow){ /* stays clickable for read-only modals */ }
    body[data-role="viewer"] .row-actions{ display:none !important; }
    body[data-role="viewer"] [data-role="editor-only"]{ display:none !important; }
    body[data-role="viewer"]::after{
      content:"👁  Viewer mode — read only";
      position:fixed; bottom:14px; left:50%; transform:translateX(-50%);
      background:#7d8590; color:#fff; padding:6px 14px; border-radius:18px;
      font-size:11px; font-weight:600; letter-spacing:.4px; z-index:99990;
      box-shadow:0 6px 18px rgba(0,0,0,.4); pointer-events:none;
      font-family:-apple-system,Segoe UI,Roboto,sans-serif;
    }
  `;
  const s = document.createElement('style');
  s.textContent = css;
  document.head.appendChild(s);
})();

/* ─── Boot ──────────────────────────────────────────────────────── */
// Show the login gate IMMEDIATELY at script parse time so Firebase DB
// never fires an unauthenticated read (which would trigger offline-fallback).
if (AUTH_ENABLED) {
  const _earlyGate = () => { _buildAuthGate(); _authShowGate('<span style="opacity:.6">Checking sign-in…</span>'); };
  if (document.body) _earlyGate();
  else document.addEventListener('DOMContentLoaded', _earlyGate);
}
window.addEventListener('load', _authInit);
