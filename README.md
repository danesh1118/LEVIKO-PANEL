# Leviko Panel

**پنل لویکو** — VLESS روی Cloudflare Workers با مدیریت کاربر و داشبورد اختصاصی.

سورس کاملاً مستقل و از صفر نوشته شده. وابسته به هیچ پنل دیگری (Nahan / Zeus / TrexBridge و …) نیست.

---

## امکانات

- پروکسی **VLESS + WebSocket** روی لبه کلودفلر
- دیتابیس **D1** برای کاربران و تنظیمات
- داشبورد ادمین با ظاهر شیشه‌ای سه‌بعدی
- ساخت کاربر با سقف حجم و روز انقضا
- لینک سابسکریپشن و صفحه وضعیت کاربر
- فعال / غیرفعال، ریست ترافیک، حذف
- رمز پنل با هش SHA-256

---

## نصب سریع

### ۱) دیتابیس D1
1. Cloudflare Dashboard → **Storage & databases** → **D1**
2. Create database — مثلاً `leviko-db`

### ۲) Worker
1. **Workers & Pages** → Create Worker
2. نام مثلاً `leviko`
3. Edit code → کل محتوای `worker.js` را جایگزین کن
4. Save and Deploy

### ۳) Binding
1. Worker → **Settings** → **Bindings**
2. Add → **D1 Database**
3. Variable name را دقیقاً بگذار: **`DB`**
4. دیتابیس را انتخاب کن → Save → دوباره Deploy

### ۴) ورود
باز کن:

```
https://YOUR-WORKER.YOUR-SUBDOMAIN.workers.dev/leviko
```

اولین بار رمز پنل را خودت می‌سازی.

---

## مسیرها

| مسیر | کاربرد |
|------|--------|
| `/leviko` | پنل ادمین |
| `/sub/{username}` | سابسکریپشن |
| `/status/{username}` | صفحه وضعیت کاربر |
| `/lv` | مسیر WebSocket برای VLESS |
| `/api/*` | API داخلی |

---

## ساخت کانفیگ دستی

```
vless://UUID@HOST:443?encryption=none&security=tls&sni=HOST&fp=chrome&type=ws&host=HOST&path=%2Flv#Leviko
```

`UUID` را از پنل کپی کن. `HOST` همان دامنه Worker است.

---

## ساختار

```
leviko-panel/
├── worker.js    # کل سورس Worker (یک فایل)
└── README.md
```

---

## نکات

- Variable name بایندینگ **حتماً `DB`** باشد.
- برای پایداری بیشتر، دامنه اختصاصی به Worker وصل کن.
- حجم ترافیک تقریبی است (بر اساس بایت‌های رد و بدل‌شده در Worker).

---

## نسخه

`1.0.0` — Leviko original
