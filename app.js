// --- 模組導入 ---
const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '.env') });

const express = require('express');
const cookieParser = require('cookie-parser');
const fetch = (...args) => import('node-fetch').then(({ default: fetch }) => fetch(...args));
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const sendResetEmail = require('./sendResetEmail.js');

// --- 應用程式初始化 ---
const app = express();
app.use(express.json({ type: ['application/json', 'application/fhir+json'] }));
app.use(cookieParser());

// --- 常數設定 ---
const JWT_SECRET = process.env.JWT_SECRET;
const FHIR_BASE = process.env.FHIR_SERVER_BASE || 'http://203.64.84.204:8080/fhir';
const APP_BASE_URL = process.env.APP_BASE_URL || 'http://203.64.84.204:3000';                                                         
const PORT = process.env.PORT || 3000;
const EMAIL_SYSTEM = 'http://example.org/fhir/email';
const PASSWORD_SYSTEM = 'http://example.org/fhir/password';
const FHIR_BEARER = process.env.FHIR_BEARER_TOKEN;

// --- 統一 FHIR 請求函數（使用 204 伺服器） ---
async function fetchFHIR(url, options = {}) {
  // 確保 URL 是完整的 FHIR 端點
  const fullUrl = url.startsWith('http') ? url : `${FHIR_BASE}/${url.replace(/^\//, '')}`;
  return fetch(fullUrl, {
    ...options,
    headers: {
      "Content-Type": "application/fhir+json",
      ...(FHIR_BEARER ? { "Authorization": `Bearer ${FHIR_BEARER}` } : {}),
      ...(options.headers || {})
    }
  });
}

if (!JWT_SECRET) {
  console.error('錯誤：JWT_SECRET 未設定！');
  process.exit(1);
}

// --- Debug Middleware ---
app.use((req, res, next) => {
  console.log(`\n[${new Date().toISOString()}] ${req.method} ${req.url}`);
  if (req.body && Object.keys(req.body).length > 0) {
    console.log('  body:', JSON.stringify(req.body, null, 2));
  }
  console.log('  cookies:', req.cookies);
  next();
});

// --- 靜態資源 ---
app.use(express.static(path.join(__dirname, 'public')));
app.use('/locales', express.static(path.join(__dirname, 'locales')));
app.get('/', (req, res) => res.redirect('/login.html'));

// --- Person 註冊 ---
app.post('/api/register', async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password)
    return res.status(400).json({ error: "姓名、Email 和密碼皆為必填" });

  try {
    // A. 查重
    const searchIdentifier = encodeURIComponent(`${EMAIL_SYSTEM}|${email}`);
    const checkUrl = `Person?identifier=${searchIdentifier}`;

    const checkData = await (await fetchFHIR(checkUrl)).json();
    if (checkData.total > 0)
      return res.status(409).json({ error: "此 Email 已被註冊" });

    // B. Hash 密碼
    const hashedPassword = await bcrypt.hash(password, 10);

    // C. 建 Person（密碼放在 identifier）
    const person = {
      resourceType: "Person",
      name: [{ text: name }],
      telecom: [{ system: "email", value: email, use: "home" }],
      identifier: [
        { system: EMAIL_SYSTEM, value: email },
        { system: PASSWORD_SYSTEM, value: hashedPassword }
      ]
    };

    // D. 送到 FHIR 建立 Person
    const createRes = await fetchFHIR('Person', {
      method: "POST",
      body: JSON.stringify(person)
    });

    const newPerson = await createRes.json();
    const personId = newPerson.id;

    // E. postRegistrationToken 加上 email
    const postRegistrationToken = jwt.sign(
      {
        id: personId,
        email: email,
        purpose: "post-registration"
      },
      JWT_SECRET,
      { expiresIn: "5m" }
    );

    res.status(201).json({
      message: "註冊成功",
      personId,
      postRegistrationToken
    });

  } catch (err) {
    console.error("register error:", err);
    res.status(500).json({ error: "註冊失敗", detail: err.message });
  }
});

// --- 登入 ---
app.post('/api/login', async (req, res) => {
  const { email, password, postRegistrationToken } = req.body;

  try {

    // ============================================================
    // 🟦 A. Portal 管理員登入（讀取 .env）
    // ============================================================
    const PORTAL_ADMIN_EMAIL = process.env.PORTAL_ADMIN_EMAIL;
    const PORTAL_ADMIN_PASSWORD = process.env.PORTAL_ADMIN_PASSWORD;

    if (email === PORTAL_ADMIN_EMAIL && password === PORTAL_ADMIN_PASSWORD) {
      const loginToken = jwt.sign(
        {
          id: "portal-admin",
          email: PORTAL_ADMIN_EMAIL,
          role: "PortalAdmin"
        },
        JWT_SECRET,
        { expiresIn: "5m" }
      );

      res.cookie("token", loginToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        maxAge: 3600000
      });

      return res.json({
        message: "Portal 管理員登入成功",
        isPortalAdmin: true
      });
    }

    // ============================================================
    // 🟦 B. 註冊後 auto-login
    // ============================================================
    if (postRegistrationToken) {
      const payload = jwt.verify(postRegistrationToken, JWT_SECRET);
      if (payload.purpose !== 'post-registration')
        return res.status(401).json({ error: '權杖用途不符' });

      const loginToken = jwt.sign(
        { id: payload.id, email: payload.email },
        JWT_SECRET,
        { expiresIn: '7d' }
      );

      res.cookie('token', loginToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        maxAge: 3600000
      });

      return res.json({ message: '註冊後自動登入成功' });
    }

    // ============================================================
    // 🟦 C. 一般登入（走 FHIR）
    // ============================================================
    if (!email || !password)
      return res.status(400).json({ error: '請提供 Email 和密碼' });

    const searchUrl = `Person?identifier=${encodeURIComponent(EMAIL_SYSTEM)}|${encodeURIComponent(email)}`;
    const searchRes = await fetchFHIR(searchUrl);
    const searchData = await searchRes.json();

    if (searchData.total === 0)
      return res.status(401).json({ error: 'Email 或密碼錯誤' });

    const person = searchData.entry[0].resource;

    const hashEntry = person.identifier.find(i => i.system === PASSWORD_SYSTEM);

    if (!hashEntry)
      return res.status(500).json({ error: '使用者帳號設定不完整：找不到密碼欄位' });

    const isPasswordCorrect = await bcrypt.compare(password, hashEntry.value);
    if (!isPasswordCorrect)
      return res.status(401).json({ error: 'Email 或密碼錯誤' });

    const emailEntry = person.identifier.find(i => i.system === EMAIL_SYSTEM);
    const userEmail = emailEntry?.value;

    if (!userEmail)
      return res.status(500).json({ error: "Person 缺少 email 欄位（identifier）" });

    const loginToken = jwt.sign(
      {
        id: person.id,
        email: userEmail,
        role: "User"
      },
      JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.cookie('token', loginToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 3600000
    });

    res.json({
      message: '登入成功',
      isPortalAdmin: false
    });

  } catch (err) {
    console.error("login error:", err);
    res.status(500).json({ error: '登入失敗', detail: err.message });
  }
});

// --- 取得 Person 資料（正確讀取姓名）---

app.get('/api/person', async (req, res) => {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ error: '未登入' });

  try {
    const personId = jwt.verify(token, JWT_SECRET).id;

    // 取得 FHIR Person 資源
    const fhirRes = await fetchFHIR(`Person/${personId}`);
    if (!fhirRes.ok) {
      throw new Error('無法取得 Person 資料');
    }
    const person = await fhirRes.json();
    console.log('Person 資源:', JSON.stringify(person, null, 2)); // 除錯用

    // 讀 email
    const emailId = person.identifier?.find(i => i.system === EMAIL_SYSTEM)?.value;

    // 讀姓名
    let name = '';
    if (person.name && person.name.length > 0) {
      const nameObj = person.name[0];
      if (nameObj.text) {
        name = nameObj.text;
      } else {
        const given = (nameObj.given || []).join(' ');
        const family = nameObj.family || '';
        name = `${family}${given ? ' ' + given : ''}`.trim();
      }
    }

    // 讀 Patient ID（link 指向 Patient）
    const patientLink = person.link?.find(l => l.target?.reference?.startsWith('Patient/'));
    const patientRef = patientLink?.target?.reference;
    const patientId = patientRef ? patientRef.split('/')[1] : null;

    res.json({
      personId,
      email: emailId,
      name: name || '未設定姓名',
      patientId
    });

  } catch (err) {
    console.error('取得 Person 資料錯誤:', err);
    res.status(401).json({ error: 'Token 驗證失敗或無法取得資料' });
  }
});
app.post('/api/logout', (req, res) => {
  res.clearCookie('token');  // 清掉登入 token
  res.json({ message: "已登出" });
});


// --- 檢查統編 ---
app.get('/api/check-taxid', async (req, res) => {
  const { taxId } = req.query;
  if (!taxId) return res.status(400).json({ error: '缺少 taxId' });

  try {
    // 查 FHIR Organization 是否有該統編
    const fhirRes = await fetchFHIR(`Organization?identifier=http://example.org/fhir/tax-id|${taxId}`);
    const fhirData = await fhirRes.json();

    if (fhirData.total > 0) {
      const org = fhirData.entry[0].resource;
      res.json({ exists: true, active: org.active });
    } else {
      res.json({ exists: false });
    }
  } catch (err) {
    res.status(500).json({ error: '查詢失敗', detail: err.message });
  }
});

// --- 請求重設密碼 ---
app.post('/api/request-reset', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: '請輸入 Email' });

  try {
    const searchUrl = `Person?identifier=${encodeURIComponent(EMAIL_SYSTEM)}|${encodeURIComponent(email)}`;
    const searchRes = await fetchFHIR(searchUrl);
    const searchData = await searchRes.json();

    if (searchData.total === 0) return res.json({ message: '若此 Email 已註冊，您將會收到重設密碼郵件' });

    const personId = searchData.entry[0].resource.id;
    const resetToken = jwt.sign({ id: personId, purpose: 'password-reset' }, JWT_SECRET, { expiresIn: '15m' });
    const resetLink = `${APP_BASE_URL}/reset.html?token=${resetToken}`;

    await sendResetEmail(email, resetLink);
    res.json({ message: '若此 Email 已註冊，您將會收到重設密碼郵件' });
  } catch (err) {
    res.status(500).json({ error: '請求重設密碼失敗', detail: err.message });
  }
});

// --- 執行密碼重設 ---
app.post('/api/reset-password', async (req, res) => {
  const { token, password } = req.body;
  if (!token || !password) return res.status(400).json({ error: '缺少權杖或新密碼' });

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    if (payload.purpose !== 'password-reset') return res.status(401).json({ error: '權杖用途不符' });

    const personId = payload.id;
    const getRes = await fetchFHIR(`Person/${personId}`);
    if (!getRes.ok) return res.status(404).json({ error: '找不到使用者' });

    const person = await getRes.json();
    person.identifier = (person.identifier || []).filter(i => i.system !== PASSWORD_SYSTEM);
    person.identifier.push({ system: PASSWORD_SYSTEM, value: await bcrypt.hash(password, 10) });

    const updateRes = await fetchFHIR(`Person/${personId}`, {
      method: 'PUT',
      body: JSON.stringify(person)
    });

    if (!updateRes.ok) throw new Error(await updateRes.text());
    res.json({ message: '密碼已成功更新' });
  } catch (err) {
    if (err instanceof jwt.JsonWebTokenError || err instanceof jwt.TokenExpiredError) {
      return res.status(401).json({ error: '重設連結無效或已過期', detail: err.message });
    }
    res.status(500).json({ error: '重設密碼失敗', detail: err.message });
  }
});

// =============================================
// ➤ 取得 active = true 的組織列表
// =============================================
app.get("/api/active-orgs", async (req, res) => {
  try {
    const userEmail = req.session.email; // 或其他認證方式取得使用者 email
    // 先取得使用者已加入的 orgId
    const userOrgsRes = await fetch(`${FHIR_BASE}/PractitionerRole?email=${userEmail}`);
    const userOrgsData = await userOrgsRes.json();
    const joinedOrgIds = (userOrgsData.entry || []).map(e => e.resource.organization?.reference?.split("/")[1]);

    // 取得所有 active 組織
    const url = `${FHIR_BASE}/Organization?active=true`;
    const fhirRes = await fetch(url);
    const data = await fhirRes.json();
    const orgs = (data.entry || []).map(e => e.resource);

    // 過濾掉已加入的
    const filteredOrgs = orgs.filter(org => !joinedOrgIds.includes(org.id));

    res.json({ organizations: filteredOrgs });
  } catch (err) {
    console.error("❌ 取得啟用組織列表失敗:", err);
    res.status(500).json({ error: "伺服器錯誤" });
  }
});
app.post('/api/organizations/select', (req, res) => {
  const { orgId } = req.body;

  if (!orgId) {
    return res.status(400).json({ error: "缺少 orgId" });
  }

  // 將組織 ID 存入 cookie
  res.cookie("selectedOrgId", orgId, {
    httpOnly: true,
    sameSite: "lax"
  });

  res.json({ ok: true });
});

// --- 取得使用者通過審核的登入資訊 ---
app.get('/api/organizations', async (req, res) => {
  console.log("=== 開始載入使用者組織列表 ===");

  try {
    const token = req.cookies.token;
    if (!token) {
      console.log("❌ 未找到 token");
      return res.json([]);
    }

    // 1️⃣ 解析 JWT（取得 personId + email）
    let personId, email;
    try {
      const payload = jwt.verify(token, JWT_SECRET);
      personId = payload.id;
      email = payload.email;

      console.log("🔑 JWT personId:", personId);
      console.log("🔑 JWT email:", email);
      
      if (!email) {
        return res.status(400).json({ error: "JWT 缺少 email，無法綁定 Practitioner" });
      }
    } catch (error) {
      console.error("❌ JWT 驗證失敗:", error);
      return res.status(401).json({ error: "Token 驗證失敗" });
    }

    // 2️⃣ 抓 Person
    const personRes = await fetchFHIR(`Person/${personId}`);
    if (!personRes.ok) {
      console.error("❌ 無法取得 Person 資料");
      return res.json([]);
    }
    const person = await personRes.json();
    console.log("👤 Person 資料:", JSON.stringify(person, null, 2));

    // 3️⃣ 查 Practitioner（用 email）
    console.log("🔍 依 email 查 Practitioner:", email);
    const pracQueryUrl = `Practitioner?identifier=${encodeURIComponent(EMAIL_SYSTEM + '|' + email)}`;
    const pracQueryRes = await fetchFHIR(pracQueryUrl);
    const pracQueryData = await pracQueryRes.json();

    if (pracQueryData.total === 0) {
      console.log("⚠ 無 Practitioner 與此 email 綁定。");
      return res.json([]);
    }

    const practitioner = pracQueryData.entry[0].resource;
    const practitionerId = practitioner.id;
    const practitionerFullUrl = `Practitioner/${practitionerId}`;

    console.log("🔗 找到 Practitioner:", practitionerFullUrl);

    // 4️⃣ 如果 Person.link 沒綁這個 Practitioner → 自動建立
    const alreadyLinked = person.link?.some(
      l => l.target?.reference === practitionerFullUrl
    );

    if (!alreadyLinked) {
      console.log("🛠 Person.link 未找到 Practitioner → 正在新增");

      person.link = person.link || [];
// 把 Practitioner 放到最前面
person.link.unshift({ target: { reference: practitionerFullUrl } });


      const updateRes = await fetchFHIR(`Person/${personId}`, {
        method: "PUT",
        body: JSON.stringify(person)
      });

      if (!updateRes.ok) {
        console.log("❌ Person 更新失敗");
      } else {
        console.log("✨ Person.link 已成功綁定 Practitioner");
      }
    }

    const results = [];

    // 5️⃣ 查 PractitionerRole（用 identifier 法）
    console.log("🔎 查 PractitionerRole（用 email identifier）");
    const pracIdentifier = encodeURIComponent(`${EMAIL_SYSTEM}|${email}`);
    const rolesRes = await fetchFHIR(`PractitionerRole?practitioner.identifier=${pracIdentifier}`);
    const rolesData = await rolesRes.json();

    if (!rolesData.entry || rolesData.entry.length === 0) {
      console.log("❌ 無 PractitionerRole");
      return res.json([]);
    }

    // 遍歷角色
    for (let entry of rolesData.entry) {
      const role = entry.resource;

      if (!role.active) {
        console.log("⏸ 跳過未啟用的角色:", role.id);
        continue;
      }

      if (!role.organization?.reference) continue;

      const orgId = role.organization.reference.split("/")[1];

      // 取得組織
      const orgRes = await fetchFHIR(`Organization/${orgId}`);
      const orgData = await orgRes.json();

      if (!orgData.active) {
        console.log("⏸ 組織未啟用:", orgId);
        continue;
      }

      results.push({
        orgId,
        orgName: orgData.name,
        roleDisplay: role.code?.[0]?.coding?.[0]?.display || "未設定職位",
        roleId: role.id,
        practitionerId
      });
    }
      const selectedOrgId = req.cookies.selectedOrgId;

if (selectedOrgId) {
  results.sort((a, b) => {
    if (a.orgId === selectedOrgId) return -1; // a 排第一
    if (b.orgId === selectedOrgId) return 1;  // b 排後面
    return 0;
  });
}
    console.log("📦 最終結果:", results);
    res.json(results);

  } catch (error) {
    console.error("❌ 後端錯誤：", error);
    res.status(500).json({ error: "伺服器錯誤", detail: error.message });
  }
});

// ------- helper：從 FHIR 回應解析 id -------
function extractIdFromResponse(body) {
  if (!body) return null;
  if (typeof body === 'string') return null;
  if (body.id) return body.id;
  if (body.resource && body.resource.id) return body.resource.id;
  if (body.entry && body.entry[0] && body.entry[0].resource && body.entry[0].resource.id) {
    return body.entry[0].resource.id;
  }
  return null;
}

// ------- helper：找 Person -------
async function findPerson(email) {
  const url = `Person?identifier=${encodeURIComponent(EMAIL_SYSTEM)}|${encodeURIComponent(email)}`;
  console.log("查 Person email=", JSON.stringify(email));
  console.log("findPerson URL:", url);

  const data = await (await fetchFHIR(url)).json();
  if (!data || data.total === 0) throw new Error('找不到 Person（請先註冊）');
  return data.entry[0].resource;
}

// ------- helper：確保 Practitioner 存在 -------
async function ensurePractitionerExists(email) {
  const check = await (await fetchFHIR(`Practitioner?identifier=${encodeURIComponent(EMAIL_SYSTEM + '|' + email)}`)).json();
  if (check && check.total > 0) return check.entry[0].resource.id;

  const resource = {
    resourceType: "Practitioner",
    active: true,
    identifier: [{ system: EMAIL_SYSTEM, value: email }]
  };

  const created = await fetchFHIR('Practitioner', {
    method: 'POST',
    body: JSON.stringify(resource)
  });

  const body = await created.json();
  const id = extractIdFromResponse(body);
  if (!id) throw new Error('建立 Practitioner 後無法取得 id: ' + JSON.stringify(body));
  return id;
}

// ------- helper：建立 Organization -------
async function createOrganization(orgName, orgType, taxId, addressParam) {
  let addressField = undefined;
  if (addressParam) {
    if (Array.isArray(addressParam)) {
      addressField = addressParam;
    } else if (typeof addressParam === 'string') {
      const text = addressParam.trim();
      if (text.length > 0) {
        addressField = [{
          type: "physical",
          text: text,
          line: [text]
        }];
      }
    } else if (typeof addressParam === 'object') {
      addressField = [addressParam];
    }
  }

  const orgResource = {
    resourceType: "Organization",
    active: false,
    identifier: [
      { system: "http://example.org/fhir/tax-id", value: taxId }
    ],
    type: [
      {
        coding: [
          { system: "http://example.org/fhir/org-type", code: orgType, display: orgType }
        ]
      }
    ],
    name: orgName
  };

  if (addressField) orgResource.address = addressField;

  const res = await fetchFHIR('Organization', {
    method: 'POST',
    body: JSON.stringify(orgResource)
  });

  const body = await res.json();
  if (!res.ok) throw new Error(`FHIR 建立 Organization 失敗: ${JSON.stringify(body)}`);

  const id = extractIdFromResponse(body);
  if (!id) throw new Error('建立 Organization 後無法取得 id，回傳內容: ' + JSON.stringify(body));
  return id;
}

// ------- helper：建立 PractitionerRole -------
async function createPractitionerRole(practitionerId, orgId, roleCode, roleDisplay) {
  const roleResource = {
    resourceType: "PractitionerRole",
    active: false,
    practitioner: {
      reference: `Practitioner/${practitionerId}`
    },
    organization: {
      reference: `Organization/${orgId}`
    },
    code: [
      {
        coding: [
          {
            system: "http://example.org/fhir/role",
            code: roleCode,       // ← 用傳進來的 FHIR code
            display: roleDisplay  // ← 顯示用名稱：物流管理員/社區志工
          }
        ]
      }
    ]
  };

  const created = await fetchFHIR('PractitionerRole', {
    method: "POST",
    body: JSON.stringify(roleResource)
  });

  const body = await created.json();
  const id = extractIdFromResponse(body);
  if (!id) throw new Error("建立 PractitionerRole 後無法取得 id: " + JSON.stringify(body));
  return id;
}

// ------- helper：更新 Person link -------
async function updatePersonLink(personId, practitionerId) {
  // 先取得 Person
  const res = await fetchFHIR(`Person/${personId}`);
  const person = await res.json();

  // 確保 link 是陣列
  if (!Array.isArray(person.link)) person.link = [];

  // 檢查是否已經有相同 Practitioner reference
  const exists = person.link.some(l => l.target?.reference === `Practitioner/${practitionerId}`);
  if (!exists) {
    person.link.push({
      target: { reference: `Practitioner/${practitionerId}` },
      type: "seealso" // type 通常需要填
    });
  }

  // PUT 更新整個 Person
  const updateRes = await fetchFHIR(`Person/${personId}`, {
    method: "PUT",
    headers: { "Content-Type": "application/fhir+json" },
    body: JSON.stringify(person)
  });

  const body = await updateRes.json();
  if (!updateRes.ok) throw new Error('更新 Person.link 失敗: ' + JSON.stringify(body));

  return body;
}

// ------- 申請機構組織 -------
app.post('/api/apply-logistics', async (req, res) => {
  const { email, orgName, orgType, position, taxId, address } = req.body;

  if (!email || !orgName || !orgType || !position || !taxId || !address) {
    return res.status(400).json({ error: '缺少參數（email/orgName/orgType/position/taxId/address 均為必填）' });
  }

  try {
    const person = await findPerson(email);
    const practitionerId = await ensurePractitionerExists(email);

    // ⭐ 組織類型映射
    const orgTypeDisplayMap = {
      logistics: "Logistics Company",
      retail: "Community Store"
    };
    const mappedType = orgTypeDisplayMap[orgType] || "Other";
    const orgId = await createOrganization(orgName, mappedType, taxId, address);

    const roleDisplayMap = {
      LogisticsRootAdmin: "物流負責人",
      CommunityAdmin: "社區管理員"
    };

    // 找對應顯示名稱
    const roleDisplay = roleDisplayMap[position] || "未知職位";

    // 建立 PractitionerRole
    const practitionerRoleId = await createPractitionerRole(
      practitionerId,
      orgId,
      position,        // FHIR code
      roleDisplay      // 顯示名稱
    );

    await updatePersonLink(person.id, practitionerId);

    res.json({
      message: "申請已送出，等待審核",
      practitionerId,
      orgId,
      practitionerRoleId,
      pending: true
    });
  } catch (err) {
    console.error('❌ apply-logistics error:', err);
    return res.status(err.status || 500).json({
      error: '申請失敗',
      message: err.message,
      body: err.body || null
    });
  }
});

async function searchPractitionerRole(practitionerId, orgId) {
  const url = `${FHIR_BASE}/PractitionerRole?practitioner=${practitionerId}&organization=${orgId}`;

  const res = await fetch(url);
  const bundle = await res.json();

  if (!bundle.entry || bundle.entry.length === 0) return null;

  return bundle.entry[0].resource;  // 只要有任何一筆就算重複
}

// ------- 建立職位 -------
app.post("/api/apply-existing-org", async (req, res) => {
  const { email, orgId, roleCode, roleName } = req.body;

  if (!email || !orgId || !roleCode || !roleName) {
    return res.status(400).json({ error: "缺少參數（email/orgId/roleCode/roleName 必填）" });
  }

  try {
    // 找 Person
    const person = await findPerson(email);

    // 確保 Practitioner 存在
    const practitionerId = await ensurePractitionerExists(email);

    const existingRole = await searchPractitionerRole(practitionerId, orgId);
    if (existingRole) {
      return res.status(400).json({
        error: "你已在此組織擁有職位，不能再次申請其他職位"
      });
    }
    // 建立角色
    const practitionerRoleId = await createPractitionerRole(
      practitionerId,
      orgId,
      roleCode,
      roleName
    );

    // Person.link 指到 Practitioner
    await updatePersonLink(person.id, practitionerId);

    res.json({
      message: "組織職位申請已送出",
      practitionerId,
      orgId,
      practitionerRoleId
    });

  } catch (err) {
    console.error("apply-existing-org error:", err);
    res.status(500).json({ error: err.message });
  }
});

// --- 檢查組織角色 ---
app.get('/api/organization/check-role', async (req, res) => {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ error: '未登入' });

  const { orgId } = req.query;
  if (!orgId) return res.status(400).json({ error: '缺少 orgId' });

  let personId;
  try {
    personId = jwt.verify(token, JWT_SECRET).id;
  } catch {
    return res.status(401).json({ error: 'Token 驗證失敗' });
  }

  try {
    // 1️⃣ 取得 Person
    const personRes = await fetchFHIR(`Person/${personId}`);
    const person = await personRes.json();

    if (!person.link || person.link.length === 0) {
      return res.json({ hasRole: false });
    }

    // 2️⃣ 從 Person 拿 PractitionerId
// 2️⃣ 從 Person 找 Practitioner link
const practitionerLink = (person.link || []).find(l =>
  l.target?.reference?.startsWith("Practitioner/")
);

if (!practitionerLink) {
  return res.json({ hasRole: false });
}

const practitionerId = practitionerLink.target.reference.split('/')[1];

    // 3️⃣ 查 PractitionerRole
    const roleUrl = `PractitionerRole?practitioner=Practitioner/${practitionerId}&organization=Organization/${orgId}`;
    const roleRes = await fetchFHIR(roleUrl);
    const roleData = await roleRes.json();

    if (roleData.total > 0) {
      const role = roleData.entry[0].resource;

      // 4️⃣ 取得 Organization
      const orgRes = await fetchFHIR(`Organization/${orgId}`);
      const org = await orgRes.json();

      return res.json({
        hasRole: true,
        active: role.active,
        position: role.code?.[0]?.coding?.[0]?.display || '未設定職位',
        organizationName: org.name || '未命名組織'
      });
    } else {
      return res.json({ hasRole: false });
    }

  } catch (err) {
    return res.status(500).json({
      error: '查詢 PractitionerRole 失敗',
      detail: err.message
    });
  }
});

// --- 取得 Person 角色和 Patient 資料 ---
app.get('/api/person-role', async (req, res) => {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ error: "未登入" });

  let personId;
  try {
    personId = jwt.verify(token, JWT_SECRET).id;
  } catch {
    return res.status(401).json({ error: "Token 驗證失敗" });
  }

  try {
    // 1️⃣ 取得 Person
    const personRes = await fetchFHIR(`Person/${personId}`);
    const person = await personRes.json();

    if (!person.link || person.link.length === 0) {
      return res.json({ isPatient: false });
    }

    // 2️⃣ 找 Patient/xxxx
    const patientLink = person.link.find(l => l.target.reference.startsWith("Patient/"));
    if (!patientLink) {
      return res.json({ isPatient: false });
    }

    const patientRef = patientLink.target.reference; // "Patient/2192"
    const patientId = patientRef.split("/")[1];

    // 3️⃣ 抓 Patient 資料
    const patientRes = await fetchFHIR(patientRef);
    const patient = await patientRes.json();

    res.json({
      isPatient: true,
      patientId,
      patient
    });

  } catch (err) {
    res.status(500).json({
      error: "查詢 Person Role 失敗",
      detail: err.message
    });
  }
});

// --- 取得 Patient 資料 ---
app.get('/api/patient', async (req, res) => {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ error: '未登入' });

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const personId = payload.id;

    // 1. 先取得 Person 資源
    const personRes = await fetchFHIR(`Person/${personId}`);
    if (!personRes.ok) {
      return res.status(404).json({ error: '找不到 Person 資料' });
    }
    const person = await personRes.json();

    // 2. 從 Person.link 找到對應的 Patient
    const patientLink = person.link?.find(l => l.target?.reference?.startsWith('Patient/'));
    if (!patientLink) {
      return res.status(404).json({ error: '未找到相關的 Patient 資料' });
    }

    const patientId = patientLink.target.reference.split('/')[1];
    const patientRes = await fetchFHIR(`Patient/${patientId}`);
    
    if (!patientRes.ok) {
      return res.status(404).json({ error: '找不到 Patient 資料' });
    }

    const patient = await patientRes.json();
    res.json(patient);

  } catch (err) {
    console.error('取得 Patient 資料錯誤:', err);
    res.status(500).json({ error: '取得 Patient 資料失敗', detail: err.message });
  }
});

// --- 創建或更新 Patient 資料 ---
app.post('/api/patient', async (req, res) => {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ error: '未登入' });

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const personId = payload.id;
    const userEmail = payload.email;

    const {
      name, // Person 姓名
      birthDate,
      gender,
      phone,
      address
    } = req.body;

    // 1. 更新 Person 的姓名（如果需要）
    if (name) {
      const personRes = await fetchFHIR(`Person/${personId}`);
      if (personRes.ok) {
        const person = await personRes.json();
        
        // 更新姓名
        if (person.name && person.name.length > 0) {
          person.name[0].text = name;
        } else {
          person.name = [{ text: name }];
        }

        // 更新 Person
        await fetchFHIR(`Person/${personId}`, {
          method: 'PUT',
          body: JSON.stringify(person)
        });
      }
    }

    // 2. 檢查是否已有 Patient 連結
    const personRes = await fetchFHIR(`Person/${personId}`);
    const person = await personRes.json();
    
    let patientId;
    let existingPatient = null;

    // 檢查現有的 Patient 連結
    const patientLink = person.link?.find(l => l.target?.reference?.startsWith('Patient/'));
    if (patientLink) {
      patientId = patientLink.target.reference.split('/')[1];
      const patientRes = await fetchFHIR(`Patient/${patientId}`);
      if (patientRes.ok) {
        existingPatient = await patientRes.json();
      }
    }

    // 3. 準備 Patient 資源（簡化版本，移除不需要的欄位）
    let patientResource = {
      resourceType: "Patient",
      active: true,
      name: [
        {
          use: "official",
          text: name,
          family: name, // 簡單處理，實際應拆分姓氏
          given: [name] // 簡單處理，實際應拆分名字
        }
      ],
      telecom: [],
      gender: gender,
      birthDate: birthDate,
      address: [
        {
          use: "home",
          type: "both",
          text: address,
          line: [address]
        }
      ]
    };

    // 添加電話
    if (phone) {
      patientResource.telecom.push({
        system: "phone",
        value: phone,
        use: "mobile"
      });
    }

    // 4. 創建或更新 Patient
    let finalPatient;
    if (existingPatient) {
      // 更新現有 Patient
      patientResource.id = patientId;
      patientResource.meta = existingPatient.meta;
      
      const updateRes = await fetchFHIR(`Patient/${patientId}`, {
        method: 'PUT',
        body: JSON.stringify(patientResource)
      });
      
      if (!updateRes.ok) {
        throw new Error(`更新 Patient 失敗: ${await updateRes.text()}`);
      }
      
      finalPatient = await updateRes.json();
    } else {
      // 創建新 Patient
      const createRes = await fetchFHIR('Patient', {
        method: 'POST',
        body: JSON.stringify(patientResource)
      });
      
      if (!createRes.ok) {
        throw new Error(`創建 Patient 失敗: ${await createRes.text()}`);
      }
      
      finalPatient = await createRes.json();
      patientId = finalPatient.id;

      // 5. 更新 Person 的 link 到新創建的 Patient
      const updatedPerson = await fetchFHIR(`Person/${personId}`);
      const personData = await updatedPerson.json();
      
      personData.link = personData.link || [];
      
      // 移除現有的 Patient link（如果有的話）
      personData.link = personData.link.filter(link => 
        !link.target?.reference?.startsWith('Patient/')
      );
      
      // 添加新的 Patient link
      personData.link.push({
        target: {
          reference: `Patient/${patientId}`
        }
      });

      await fetchFHIR(`Person/${personId}`, {
        method: 'PUT',
        body: JSON.stringify(personData)
      });
    }

    res.json({
      message: existingPatient ? 'Patient 資料更新成功' : 'Patient 資料創建成功',
      patientId: patientId,
      personUpdated: !!name
    });

  } catch (err) {
    console.error('創建/更新 Patient 錯誤:', err);
    res.status(500).json({ 
      error: '創建/更新 Patient 資料失敗', 
      detail: err.message 
    });
  }
});

// --- 取得待審核的申請 ---
app.get('/api/admin/pending-logistics', async (req, res) => {
  try {
    // 抓所有 Organization 類型為物流且 active=false
    const orgRes = await fetchFHIR('Organization?active=false');
    const orgData = await orgRes.json();

    if (!orgData.entry) return res.json([]);

    const requests = await Promise.all(
      orgData.entry.map(async (orgEntry) => {
        const org = orgEntry.resource;
  
        // ⭐ 先把 Organization.address 整理出來
        let addressText = "未填寫地址";
        if (org.address && org.address.length > 0) {
          const addr = org.address[0];
          const line = addr.line?.join(" ") || "";
          const city = addr.city || "";
          const district = addr.district || "";
          const state = addr.state || "";
          const postal = addr.postalCode || "";
          const country = addr.country || "";

          addressText = [line, city, district, state, postal, country]
            .filter(x => x && x.trim() !== "")
            .join(" ");
        }

        // 找該公司的 PractitionerRole
        const roleRes = await fetchFHIR(`PractitionerRole?organization=Organization/${org.id}`);
        const roleData = await roleRes.json();
        if (!roleData.entry || roleData.total === 0) return null;

        const role = roleData.entry[0].resource;

        // 取得 Practitioner
        const pracId = role.practitioner.reference.split('/')[1];
        const pracRes = await fetchFHIR(`Practitioner/${pracId}`);
        const prac = await pracRes.json();

        const emailEntry = prac.identifier.find(i => i.system === EMAIL_SYSTEM);
        const email = emailEntry ? emailEntry.value : '未設定 Email';

        return {
          organizationId: org.id,
          practitionerId: pracId,
          roleId: role.id,

          orgName: org.name || '未命名公司',
          orgType: (org.type?.[0]?.coding?.[0]?.display) || '物流公司',

          email,
          position: (role.code?.[0]?.coding?.[0]?.display) || '未設定職位',

          // ⭐ 加入地址（前端就能正常顯示了）
          address: addressText
        };
      })
    );

    res.json(requests.filter(r => r !== null));
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: '取得待審核物流公司失敗', detail: err.message });
  }
});

// --- 管理員審核申請（通過） --- 
app.post('/api/admin/approve-logistics', async (req, res) => {
  const { organizationId, practitionerId, roleId } = req.body;

  if (!organizationId || !practitionerId || !roleId) {
    return res.status(400).json({
      error: '缺少必要參數（organizationId / practitionerId / roleId）'
    });
  }

  try {
    // 1️⃣ Organization
    const org = await (await fetchFHIR(`Organization/${organizationId}`)).json();
    delete org.meta;
    org.active = true;

    await fetchFHIR(`Organization/${organizationId}`, {
      method: 'PUT',
      body: JSON.stringify(org)
    });

    // 2️⃣ Practitioner
    const prac = await (await fetchFHIR(`Practitioner/${practitionerId}`)).json();
    delete prac.meta;
    prac.active = true;

    await fetchFHIR(`Practitioner/${practitionerId}`, {
      method: 'PUT',
      body: JSON.stringify(prac)
    });

    // 3️⃣ PractitionerRole
    const role = await (await fetchFHIR(`PractitionerRole/${roleId}`)).json();
    delete role.meta;
    role.active = true;

    await fetchFHIR(`PractitionerRole/${roleId}`, {
      method: 'PUT',
      body: JSON.stringify(role)
    });

    res.json({
      message: '審核已通過',
      organizationId,
      practitionerId,
      roleId
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: '審核通過失敗', detail: err.message });
  }
});

// --- 管理員審核申請（拒絕） ---
// 支援 LogisticsRootAdmin + CommunityAdmin
app.post('/api/admin/reject-admin', async (req, res) => {
  const { organizationId, reason } = req.body;
  if (!organizationId || !reason)
    return res.status(400).json({ error: '缺少參數' });

  try {
    // ---👉 查找 PractitionerRole（兩種管理員職位）
    const logisticsRoleRes = await fetchFHIR(
      `PractitionerRole?organization=Organization/${organizationId}&code=LogisticsRootAdmin`
    );
    const communityRoleRes = await fetchFHIR(
      `PractitionerRole?organization=Organization/${organizationId}&code=CommunityAdmin`
    );

    const logisticsRoles = (await logisticsRoleRes.json()).entry || [];
    const communityRoles = (await communityRoleRes.json()).entry || [];

    // 合併兩種職位
    const allRoles = [...logisticsRoles, ...communityRoles];

    if (allRoles.length > 0) {
      const role = allRoles[0].resource;
      const practitionerId = role.practitioner.reference.split('/')[1];

      // ---👉 找 Person（有 link 連 practitioner）
      const personRes = await fetchFHIR(
        `Person?link.target=Practitioner/${practitionerId}`
      );
      const personData = await personRes.json();

      if (personData.total > 0) {
        const person = personData.entry[0].resource;

        // ---👉 移除 Person.link
        await fetchFHIR(`Person/${person.id}`, {
          method: 'PATCH',
          body: JSON.stringify([
            { op: 'remove', path: '/link/0' }
          ])
        });
      }

      // ---👉 刪 PractitionerRole
      await fetchFHIR(`PractitionerRole/${role.id}`, { method: 'DELETE' });

      // ---👉 刪 Practitioner
      await fetchFHIR(`Practitioner/${practitionerId}`, { method: 'DELETE' });
    }

    // ---👉 最後刪 Organization
    await fetchFHIR(`Organization/${organizationId}`, { method: 'DELETE' });

    res.json({ message: '已拒絕並刪除資源' });

  } catch (err) {
    res.status(500).json({
      error: '審核拒絕失敗',
      detail: err.message
    });
  }
});

// --- 選擇組織 ---
app.post("/api/select-organization", async (req, res) => {
  const { organizationId, practitionerRoleId } = req.body;

  if (!organizationId || !practitionerRoleId) {
    return res.status(400).json({ error: "缺少參數" });
  }

  try {
    // 1. 取得 PractitionerRole
    const roleRes = await fetchFHIR(`PractitionerRole/${practitionerRoleId}`);
    const role = await roleRes.json();

    if (!roleRes.ok || !role) {
      return res.status(404).json({ error: "找不到 PractitionerRole" });
    }

    // 2. 抽出角色代碼
    const code = role.code?.[0]?.coding?.[0]?.code;
    const display = role.code?.[0]?.coding?.[0]?.display || "";

    // 檢查是否有 code
    if (!code) {
      return res.status(400).json({ error: "角色代碼不存在" });
    }

    // 3. 檢查 active
    if (role.active !== true) {
      return res.status(403).json({ error: "此角色尚未啟用" });
    }

    // 4. 回傳角色讓前端決定跳轉頁面
    return res.json({
      message: "角色確認成功",
      role: code,
      display
    });

  } catch (err) {
    return res.status(500).json({
      error: "後端錯誤",
      detail: err.message
    });
  }
});

// --- 啟動伺服器 ---
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));