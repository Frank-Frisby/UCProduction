/**
 * UC Production app: sign-in and team tab API.
 *
 * Bind this script to the "Production State of The Union" Google Sheet
 * (Extensions > Apps Script from inside that sheet), then deploy it as a web app:
 *   Execute as: Me    Who has access: Anyone
 * Paste the web app URL into TEAM_API_URL in index.html.
 *
 * Everything the app shows comes from this sheet:
 *   Production Roster      -> who can sign in, their role and team(s)
 *   2026 New Production... -> onboarding steps (directors check these off)
 *   Director View          -> team health (refreshed every morning by Claude)
 *   Potential Volunteers   -> outreach list (status + notes are editable)
 * Passwords live in a hidden "App Logins" tab as salted hashes, never in plain text.
 */

var CFG = {
  ROSTER: 'Production Roster',
  STEPS: '2026 New Production Volunteers',
  DIRECTOR_VIEW: 'Director View',
  POTENTIAL: 'Potential Volunteers',
  LEADERSHIP: 'Leadership',
  LOGINS: 'App Logins',
  APP_URL: 'https://frank-frisby.github.io/UCProduction/',
  TOKEN_DAYS: 30,
  HASH_ROUNDS: 2500,
  MAX_FAILS: 5,
  LOCK_MINUTES: 15,
  MIN_PASSWORD: 8,
  DEFAULT_STAFF: ['franklin.frisby@elevationchurch.org']
};

var STEPS = [
  {key: 'director', label: 'Director reached out', header: 'contacted by director'},
  {key: 'initial',  label: 'First conversation',   header: 'initial contact made'},
  {key: 'ap',       label: 'Connected to AP',      header: 'connected to ap'},
  {key: 'pco',      label: 'Added to PCO',         header: 'added to pco'},
  {key: 'w1',       label: 'Shadow week 1',        header: 'week 1 show'},
  {key: 'w2',       label: 'Shadow week 2',        header: 'week 2 show'},
  {key: 'w3',       label: 'Shadow week 3',        header: 'week 3 show'}
];
var REMOVE_REASONS = ['Not interested in production', 'Serving on another team', "Schedule doesn't work", 'Moved away', 'No response after several tries', 'Other'];
var OUTREACH = ['To reach out', 'Reached out', 'Interested', 'Not now', 'Added to 2026'];
var TEAM_ACCESS = ['staff', 'director', 'coordinator'];
var ALL_TEAMS = ['A Week', 'B Week', 'eYA'];

/* ------------------------------------------------------------------ entry points */

function doGet() {
  return json_({ok: true, service: 'uc production team api'});
}

function doPost(e) {
  var req;
  try { req = JSON.parse(e.postData.contents); } catch (err) { return json_({ok: false, error: 'bad_request'}); }
  try {
    switch (req.action) {
      case 'requestPassword': return json_(requestPassword_(req));
      case 'login':           return json_(login_(req));
      case 'changePassword':  return json_(changePassword_(req));
      case 'me':              return json_(withUser_(req, function (u) { return {ok: true, user: publicUser_(u)}; }));
      case 'teamData':        return json_(withUser_(req, teamData_));
      case 'updateStep':      return json_(withUser_(req, function (u) { return updateStep_(u, req); }));
      case 'updateOutreach':  return json_(withUser_(req, function (u) { return updateOutreach_(u, req); }));
      case 'setPipelineStatus': return json_(withUser_(req, function (u) { return setPipelineStatus_(u, req); }));
      default:                return json_({ok: false, error: 'unknown_action'});
    }
  } catch (err) {
    console.error(err && err.stack || err);
    return json_({ok: false, error: 'server_error'});
  }
}

/* ------------------------------------------------------------------ sign-in */

function requestPassword_(req) {
  var email = normEmail_(req.email);
  var generic = {ok: true, message: 'If that email is on the production roster, a starter password is on its way.'};
  if (!email) return generic;
  var cache = CacheService.getScriptCache();
  if (cache.get('req:' + email)) return generic;           // one email per 10 minutes per address
  cache.put('req:' + email, '1', 600);
  var user = findUser_(email);
  if (!user) return generic;
  sendStarterPassword_(user);
  return generic;
}

function sendStarterPassword_(user) {
  var temp = randomPassword_();
  var rec = getLogin_(user.email) || {email: user.email, version: 0};
  rec.salt = Utilities.getUuid();
  rec.hash = hash_(temp, rec.salt);
  rec.mustChange = true;
  rec.version = (Number(rec.version) || 0) + 1;            // signs out any old sessions
  rec.tempSent = new Date();
  saveLogin_(rec);
  MailApp.sendEmail({
    to: user.email,
    subject: 'Your UC Production app sign-in',
    body:
      'Hi ' + (user.name.split(' ')[0] || 'there') + ',\n\n' +
      'Here is your starter password for the UC Production app:\n\n' +
      '    ' + temp + '\n\n' +
      'Sign in at ' + CFG.APP_URL + ' with this email address. You will choose your own password right after.\n\n' +
      'If you did not ask for this, you can ignore this email.\n\nUC Production'
  });
}

function login_(req) {
  var email = normEmail_(req.email);
  var cache = CacheService.getScriptCache();
  var fails = Number(cache.get('fail:' + email) || 0);
  if (fails >= CFG.MAX_FAILS) return {ok: false, error: 'locked'};
  var user = email && findUser_(email);
  var rec = user && getLogin_(email);
  if (!user || !rec || !rec.hash || rec.disabled || hash_(String(req.password || ''), rec.salt) !== rec.hash) {
    cache.put('fail:' + email, String(fails + 1), CFG.LOCK_MINUTES * 60);
    return {ok: false, error: 'bad_credentials'};
  }
  cache.remove('fail:' + email);
  rec.lastLogin = new Date();
  saveLogin_(rec);
  return {ok: true, token: makeToken_(email, rec.version), mustChange: !!rec.mustChange, user: publicUser_(user)};
}

function changePassword_(req) {
  return withUser_(req, function (user, rec) {
    var next = String(req.newPassword || '');
    if (next.length < CFG.MIN_PASSWORD) return {ok: false, error: 'too_short'};
    if (!rec.mustChange && hash_(String(req.currentPassword || ''), rec.salt) !== rec.hash) return {ok: false, error: 'bad_current'};
    rec.salt = Utilities.getUuid();
    rec.hash = hash_(next, rec.salt);
    rec.mustChange = false;
    rec.version = (Number(rec.version) || 0) + 1;
    saveLogin_(rec);
    return {ok: true, token: makeToken_(user.email, rec.version), user: publicUser_(user)};
  }, true);
}

/** Runs fn(user, loginRecord) for a valid session token. A forced password change blocks everything else. */
function withUser_(req, fn, allowMustChange) {
  var parsed = readToken_(req.token);
  if (!parsed) return {ok: false, error: 'signed_out'};
  var rec = getLogin_(parsed.email);
  var user = findUser_(parsed.email);
  if (!user || !rec || rec.disabled || Number(rec.version) !== parsed.version) return {ok: false, error: 'signed_out'};
  if (rec.mustChange && !allowMustChange) return {ok: false, error: 'must_change'};
  return fn(user, rec);
}

/* ------------------------------------------------------------------ team data */

function teamData_(user) {
  if (TEAM_ACCESS.indexOf(user.role) < 0) return {ok: true, access: false, user: publicUser_(user)};
  var teams = visibleTeams_(user);
  var leaders = leadership_();
  return {
    ok: true,
    access: true,
    user: publicUser_(user),
    teams: teams,
    leaders: leaders,
    steps: readSteps_(leaders).filter(function (s) { return teams.indexOf(s.team) >= 0; }),
    notJoining: readSteps_(leaders, true).filter(function (s) { return teams.indexOf(s.team) >= 0; }),
    removeReasons: REMOVE_REASONS,
    health: readHealth_().filter(function (h) { return teams.indexOf(h.team) >= 0; }),
    prospects: readProspects_().filter(function (p) { return prospectVisible_(p, teams, leaders); }),
    refreshed: cell_(CFG.DIRECTOR_VIEW, 'A3')
  };
}

function updateStep_(user, req) {
  if (TEAM_ACCESS.indexOf(user.role) < 0) return {ok: false, error: 'forbidden'};
  var idx = indexOfStep_(req.step);
  var row = Number(req.row);
  if (idx < 0 || !(row >= 2)) return {ok: false, error: 'bad_request'};
  var lock = LockService.getScriptLock(); lock.waitLock(10000);
  try {
    var sh = sheet_(CFG.STEPS);
    var head = headerMap_(sh);
    var vals = sh.getRange(row, 1, 1, sh.getLastColumn()).getValues()[0];
    var name = String(vals[head['name']] || '').trim();
    if (!name || normName_(name) !== normName_(req.name)) return {ok: false, error: 'row_moved'};
    var team = teamOf_(vals[head['a/b week']]);
    if (visibleTeams_(user).indexOf(team) < 0) return {ok: false, error: 'forbidden'};
    var flags = STEPS.map(function (s) { return isTrue_(vals[head[s.header]]); });
    var value = req.value === true;
    if (value && idx > 0 && !flags[idx - 1]) return {ok: false, error: 'out_of_order', need: STEPS[idx - 1].label};
    if (!value && flags.slice(idx + 1).some(Boolean)) return {ok: false, error: 'later_steps_done'};
    sh.getRange(row, head[STEPS[idx].header] + 1).setValue(value);
    flags[idx] = value;
    var nextIdx = flags.indexOf(false);
    return {ok: true, next: nextIdx < 0 ? null : STEPS[nextIdx].label};
  } finally { lock.releaseLock(); }
}

/** Takes someone out of the new-volunteer pipeline (or puts them back). Their row stays in the sheet. */
function setPipelineStatus_(user, req) {
  if (TEAM_ACCESS.indexOf(user.role) < 0) return {ok: false, error: 'forbidden'};
  var row = Number(req.row);
  if (!(row >= 2)) return {ok: false, error: 'bad_request'};
  var lock = LockService.getScriptLock(); lock.waitLock(10000);
  try {
    var sh = sheet_(CFG.STEPS);
    var head = headerMap_(sh);
    if (head['pipeline status'] == null) return {ok: false, error: 'not_set_up'};
    var vals = sh.getRange(row, 1, 1, sh.getLastColumn()).getValues()[0];
    if (!vals[head['name']] || normName_(vals[head['name']]) !== normName_(req.name)) return {ok: false, error: 'row_moved'};
    if (visibleTeams_(user).indexOf(teamOf_(vals[head['a/b week']])) < 0) return {ok: false, error: 'forbidden'};
    var removing = req.removed === true;
    sh.getRange(row, head['pipeline status'] + 1).setValue(removing ? 'Not joining' : 'Active');
    if (head['not joining reason'] != null) {
      sh.getRange(row, head['not joining reason'] + 1).setValue(removing ? String(req.reason || '').slice(0, 300) : '');
    }
    return {ok: true};
  } finally { lock.releaseLock(); }
}

function updateOutreach_(user, req) {
  if (TEAM_ACCESS.indexOf(user.role) < 0) return {ok: false, error: 'forbidden'};
  var row = Number(req.row);
  if (!(row >= 2)) return {ok: false, error: 'bad_request'};
  if (req.status != null && OUTREACH.indexOf(req.status) < 0) return {ok: false, error: 'bad_status'};
  var sh = sheet_(CFG.POTENTIAL);
  var vals = sh.getRange(row, 1, 1, 12).getDisplayValues()[0];
  if (!vals[0] || normName_(vals[0]) !== normName_(req.name)) return {ok: false, error: 'row_moved'};
  var p = {director: vals[1], team: vals[2]};
  if (!prospectVisible_(p, visibleTeams_(user), leadership_())) return {ok: false, error: 'forbidden'};
  if (req.status != null) sh.getRange(row, 11).setValue(req.status);
  if (req.note != null) sh.getRange(row, 12).setValue(String(req.note).slice(0, 1000));
  return {ok: true};
}

function isRemoved_(row, head) {
  return head['pipeline status'] != null && /not joining/i.test(String(row[head['pipeline status']] || ''));
}

function readSteps_(leaders, wantRemoved) {
  var sh = sheet_(CFG.STEPS);
  var head = headerMap_(sh);
  var values = sh.getDataRange().getValues();
  var shown = sh.getDataRange().getDisplayValues();
  var out = [];
  for (var r = 1; r < values.length; r++) {
    var name = String(values[r][head['name']] || '').trim();
    if (!name) continue;
    if (isRemoved_(values[r], head) !== !!wantRemoved) continue;
    var flags = STEPS.map(function (s) { return isTrue_(values[r][head[s.header]]); });
    var nextIdx = flags.indexOf(false);
    if (nextIdx < 0 && !wantRemoved) continue;              // finished onboarding
    var team = teamOf_(values[r][head['a/b week']]);
    out.push({
      row: r + 1, name: name, team: team,
      eday: shown[r][head['eday date']] || '',
      phone: shown[r][head['telephone']] || '',
      email: shown[r][head['email address']] || '',
      role: shown[r][head['suggested role']] || '',
      notes: shown[r][head['notes']] || '',
      stepIndex: nextIdx, next: nextIdx < 0 ? null : STEPS[nextIdx].key, nextLabel: nextIdx < 0 ? 'Complete' : STEPS[nextIdx].label,
      reason: head['not joining reason'] != null ? shown[r][head['not joining reason']] : '',
      owner: (leaders[team] || {}).director || ''
    });
  }
  return out;
}

function readHealth_() {
  var sh = sheet_(CFG.DIRECTOR_VIEW);
  var rows = sh.getDataRange().getDisplayValues();
  var start = -1;
  for (var i = 0; i < rows.length; i++) if (String(rows[i][0]).trim() === 'Team health') { start = i + 2; break; }
  if (start < 0) return [];
  var out = [];
  for (var r = start; r < rows.length && rows[r][0]; r++) {
    var x = rows[r];
    out.push({director: x[0], name: x[1], team: x[2], position: x[3], health: x[4], lastCheckIn: x[5], daysSince: x[6], lastServed: x[7], scheduled: x[8], declined: x[9]});
  }
  return out;
}

function readProspects_() {
  var sh = sheet_(CFG.POTENTIAL);
  var rows = sh.getDataRange().getDisplayValues();
  var out = [];
  for (var r = 1; r < rows.length; r++) {
    var x = rows[r];
    if (!x[0]) continue;
    out.push({row: r + 1, name: x[0], director: x[1], team: x[2], priority: x[3], why: x[4], interest: x[5], phone: x[6], email: x[7], eday: x[8], onRoster: x[9] === 'Yes', status: x[10] || 'To reach out', note: x[11]});
  }
  return out;
}

function prospectVisible_(p, teams, leaders) {
  if (teams.indexOf(p.team) >= 0) return true;
  // People with no team stay with the director who first talked to them.
  return teams.some(function (t) { return leaders[t] && normName_(leaders[t].director) === normName_(p.director); });
}

/* ------------------------------------------------------------------ people */

/** Everyone who may sign in: the Production Roster plus staff emails (Script Property STAFF_EMAILS, comma separated). */
function findUser_(email) {
  email = normEmail_(email);
  if (!email) return null;
  if (staffEmails_().indexOf(email) >= 0) {
    var r0 = rosterRow_(email);
    return {email: email, name: r0 ? r0.name : nameFromEmail_(email), role: 'staff', teams: ALL_TEAMS.slice()};
  }
  var r = rosterRow_(email);
  if (!r) return null;
  return {email: email, name: r.name, role: r.role, teams: r.teams};
}

function rosterRow_(email) {
  var sh = sheet_(CFG.ROSTER);
  var head = headerMap_(sh);
  var rows = sh.getDataRange().getDisplayValues();
  for (var i = 1; i < rows.length; i++) {
    if (normEmail_(rows[i][head['contact: email']]) !== email) continue;
    var roleRaw = String(rows[i][head['volunteer role']] || '').replace(/\*/g, '').trim().toLowerCase();
    var role = /director/.test(roleRaw) ? 'director' : /coordinator/.test(roleRaw) ? 'coordinator' : /leader/.test(roleRaw) ? 'leader' : 'volunteer';
    var teams = String(rows[i][head['volunteer team']] || '').split(',').map(teamOf_).filter(Boolean);
    return {name: String(rows[i][head['contact: full name']] || '').trim(), role: role, teams: teams};
  }
  return null;
}

function staffEmails_() {
  var prop = PropertiesService.getScriptProperties().getProperty('STAFF_EMAILS');
  var list = prop ? prop.split(',') : CFG.DEFAULT_STAFF;
  return list.map(normEmail_).filter(Boolean);
}

function visibleTeams_(user) {
  return user.role === 'staff' ? ALL_TEAMS.slice() : user.teams.slice();
}

function publicUser_(u) {
  return {name: u.name, email: u.email, role: u.role, teams: visibleTeams_(u), teamAccess: TEAM_ACCESS.indexOf(u.role) >= 0};
}

function leadership_() {
  var rows = sheet_(CFG.LEADERSHIP).getDataRange().getDisplayValues();
  var out = {};
  (rows[0] || []).forEach(function (headCell, c) {
    var team = teamOf_(headCell);
    if (!team) return;
    var t = {director: '', pm: ''};
    for (var r = 1; r < rows.length; r++) {
      var cellText = String(rows[r][c] || '');
      var cut = cellText.indexOf('-');
      if (cut < 0) continue;
      var role = cellText.slice(0, cut).toLowerCase().replace(/diretor/, 'director');
      var name = cellText.slice(cut + 1).trim();
      if (/project manager/.test(role)) t.pm = name;
      else if (/director/.test(role)) t.director = name;
    }
    out[team] = t;
  });
  return out;
}

/* ------------------------------------------------------------------ login storage */

var LOGIN_HEAD = ['Email', 'Salt', 'Hash', 'Must change', 'Version', 'Starter sent', 'Last login', 'Disabled'];

function loginSheet_() {
  var ss = SpreadsheetApp.getActive();
  var sh = ss.getSheetByName(CFG.LOGINS);
  if (!sh) {
    sh = ss.insertSheet(CFG.LOGINS);
    sh.getRange(1, 1, 1, LOGIN_HEAD.length).setValues([LOGIN_HEAD]).setFontWeight('bold');
    sh.setFrozenRows(1);
    sh.hideSheet();
    var p = sh.protect().setDescription('App logins: only the script owner edits this');
    p.removeEditors(p.getEditors());
  }
  return sh;
}

function getLogin_(email) {
  var rows = loginSheet_().getDataRange().getValues();
  for (var i = 1; i < rows.length; i++) {
    if (normEmail_(rows[i][0]) === email) {
      return {row: i + 1, email: email, salt: rows[i][1], hash: rows[i][2], mustChange: rows[i][3] === true,
              version: Number(rows[i][4]) || 0, tempSent: rows[i][5], lastLogin: rows[i][6], disabled: rows[i][7] === true};
    }
  }
  return null;
}

function saveLogin_(rec) {
  var sh = loginSheet_();
  var values = [[rec.email, rec.salt || '', rec.hash || '', !!rec.mustChange, rec.version || 0, rec.tempSent || '', rec.lastLogin || '', !!rec.disabled]];
  if (rec.row) sh.getRange(rec.row, 1, 1, values[0].length).setValues(values);
  else { sh.appendRow(values[0]); rec.row = sh.getLastRow(); }
}

/* ------------------------------------------------------------------ crypto helpers */

function hash_(password, salt) {
  var h = salt + '|' + password;
  for (var i = 0; i < CFG.HASH_ROUNDS; i++) {
    h = Utilities.base64Encode(Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, h + '|' + salt, Utilities.Charset.UTF_8));
  }
  return h;
}

function secret_() {
  var props = PropertiesService.getScriptProperties();
  var s = props.getProperty('TOKEN_SECRET');
  if (!s) { s = Utilities.getUuid() + Utilities.getUuid(); props.setProperty('TOKEN_SECRET', s); }
  return s;
}

function makeToken_(email, version) {
  var exp = Date.now() + CFG.TOKEN_DAYS * 86400000;
  var payload = Utilities.base64EncodeWebSafe(JSON.stringify({e: email, v: version, x: exp}));
  var sig = Utilities.base64EncodeWebSafe(Utilities.computeHmacSha256Signature(payload, secret_()));
  return payload + '.' + sig;
}

function readToken_(token) {
  if (!token || String(token).indexOf('.') < 0) return null;
  var parts = String(token).split('.');
  var expected = Utilities.base64EncodeWebSafe(Utilities.computeHmacSha256Signature(parts[0], secret_()));
  if (expected !== parts[1]) return null;
  try {
    var data = JSON.parse(Utilities.newBlob(Utilities.base64DecodeWebSafe(parts[0])).getDataAsString());
    if (!data.x || data.x < Date.now()) return null;
    return {email: normEmail_(data.e), version: Number(data.v)};
  } catch (err) { return null; }
}

function randomPassword_() {
  var chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789';
  var bytes = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, Utilities.getUuid() + Date.now());
  var out = '';
  for (var i = 0; i < 10; i++) out += chars.charAt(((bytes[i] % 256) + 256) % 256 % chars.length);
  return out;
}

/* ------------------------------------------------------------------ small helpers */

function json_(obj) { return ContentService.createTextOutput(JSON.stringify(obj)).setMimeType(ContentService.MimeType.JSON); }
function sheet_(name) { var sh = SpreadsheetApp.getActive().getSheetByName(name); if (!sh) throw new Error('Missing tab: ' + name); return sh; }
function cell_(name, a1) { var sh = SpreadsheetApp.getActive().getSheetByName(name); return sh ? sh.getRange(a1).getDisplayValue() : ''; }
function headerMap_(sh) { var m = {}; sh.getRange(1, 1, 1, sh.getLastColumn()).getDisplayValues()[0].forEach(function (h, i) { m[String(h).trim().toLowerCase()] = i; }); return m; }
function normEmail_(e) { return String(e || '').trim().toLowerCase(); }
function normName_(n) { return String(n || '').normalize('NFD').replace(/[̀-ͯ]/g, '').toLowerCase().replace(/[^a-z]/g, ''); }
function isTrue_(v) { return v === true || String(v).trim().toUpperCase() === 'TRUE'; }
function indexOfStep_(key) { for (var i = 0; i < STEPS.length; i++) if (STEPS[i].key === key) return i; return -1; }
function nameFromEmail_(e) { return e.split('@')[0].replace(/[._]/g, ' ').replace(/\b\w/g, function (c) { return c.toUpperCase(); }); }
function teamOf_(v) {
  var s = String(v || '').toLowerCase();
  if (/a week/.test(s)) return 'A Week';
  if (/b week/.test(s)) return 'B Week';
  if (/thurs|eya/.test(s)) return 'eYA';
  return '';
}

/* ------------------------------------------------------------------ admin menu (in the sheet) */

function onOpen() {
  SpreadsheetApp.getUi().createMenu('Production app')
    .addItem('Send starter passwords to directors and coordinators', 'sendLeaderInvites')
    .addItem('Send a starter password to one person…', 'sendOneInvite')
    .addItem('Turn off a login…', 'disableLogin')
    .addToUi();
}

/** Emails a starter password to every Director, Coordinator and staff member who doesn't have a login yet. */
function sendLeaderInvites() {
  var sh = sheet_(CFG.ROSTER);
  var head = headerMap_(sh);
  var rows = sh.getDataRange().getDisplayValues();
  var emails = staffEmails_();
  for (var i = 1; i < rows.length; i++) {
    var role = String(rows[i][head['volunteer role']] || '').toLowerCase();
    if (/director|coordinator/.test(role)) emails.push(normEmail_(rows[i][head['contact: email']]));
  }
  var sent = [];
  emails.filter(function (e, i) { return e && emails.indexOf(e) === i; }).forEach(function (e) {
    var rec = getLogin_(e);
    if (rec && rec.hash) return;                             // already has a login
    var user = findUser_(e);
    if (user) { sendStarterPassword_(user); sent.push(user.name); }
  });
  SpreadsheetApp.getUi().alert(sent.length ? 'Starter passwords sent to: ' + sent.join(', ') : 'Everyone already has a login.');
}

function sendOneInvite() {
  var ui = SpreadsheetApp.getUi();
  var res = ui.prompt('Send a starter password', 'Email address from the Production Roster:', ui.ButtonSet.OK_CANCEL);
  if (res.getSelectedButton() !== ui.Button.OK) return;
  var user = findUser_(res.getResponseText());
  if (!user) { ui.alert('That email is not on the Production Roster or the staff list.'); return; }
  sendStarterPassword_(user);
  ui.alert('Starter password sent to ' + user.name + '.');
}

function disableLogin() {
  var ui = SpreadsheetApp.getUi();
  var res = ui.prompt('Turn off a login', 'Email address:', ui.ButtonSet.OK_CANCEL);
  if (res.getSelectedButton() !== ui.Button.OK) return;
  var rec = getLogin_(normEmail_(res.getResponseText()));
  if (!rec) { ui.alert('No login found for that email.'); return; }
  rec.disabled = true;
  rec.version = (Number(rec.version) || 0) + 1;
  saveLogin_(rec);
  ui.alert('Login turned off. They are signed out everywhere.');
}
