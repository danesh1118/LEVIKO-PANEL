<div align="center">

# ⚡ Leviko Panel

### Serverless VLESS Panel on Cloudflare Workers

پنل مدیریت VLESS روی لبهٔ کلودفلر — سبک، سریع، بدون سرور

<br>

[![Cloudflare](https://img.shields.io/badge/Cloudflare-Workers-F38020?style=for-the-badge&logo=cloudflare&logoColor=white)](https://workers.cloudflare.com)
[![D1](https://img.shields.io/badge/Storage-D1%20SQLite-FF6B00?style=for-the-badge)](https://developers.cloudflare.com/d1/)
[![JS](https://img.shields.io/badge/JavaScript-100%25-F7DF1E?style=for-the-badge&logo=javascript&logoColor=black)](./worker.js)
[![License](https://img.shields.io/badge/License-MIT-22c55e?style=for-the-badge)](#-license)

<br>

## 🚀 Web Installer

### 👉 [https://danesh1118.github.io/LEVIKO-PANEL/](https://danesh1118.github.io/LEVIKO-PANEL/)

یک توکن بساز · نصب کن · وارد پنل شو

</div>

---

## 📖 فهرست

- [نصب سریع](#-نصب-سریع)
- [امکانات](#-امکانات)
- [پیش‌نیازها](#-پیش‌نیازها)
- [نصب دستی](#-نصب-دستی)
- [ورود به پنل](#-ورود-به-پنل)
- [مسیرها](#-مسیرها)
- [مدیریت کاربران](#-مدیریت-کاربران)
- [کانفیگ و سابسکریپشن](#-کانفیگ-و-سابسکریپشن)
- [ساختار پروژه](#-ساختار-پروژه)
- [رفع مشکل](#-رفع-مشکل)
- [License](#-license)

---

## 🚀 نصب سریع

بهترین و ساده‌ترین روش، **اینستالر تحت وب** است:

1. باز کن: **[Leviko Installer](https://danesh1118.github.io/LEVIKO-PANEL/)**
2. دکمهٔ **ساخت توکن آماده‌شده** را بزن و توکن را کپی کن
3. توکن را در اینستالر پیست کن
4. نام Worker را انتخاب کن و **شروع** را بزن

اینستالر به‌صورت خودکار انجام می‌دهد:

| مرحله | کار |
|:-----:|-----|
| ۱ | اتصال به حساب Cloudflare |
| ۲ | دریافت آخرین سورس از همین مخزن |
| ۳ | ساخت دیتابیس D1 |
| ۴ | استقرار Worker + Binding |
| ۵ | فعال‌سازی آدرس workers.dev |

> **بروزرسانی:** داخل اینستالر حالت Update هم هست — فقط کد Worker را عوض می‌کند و دیتابیس دست نخورده می‌ماند.

---

## ✨ امکانات

| | قابلیت | توضیح |
|---|--------|--------|
| ⚡ | **VLESS + WebSocket** | پروکسی روی شبکهٔ لبهٔ Cloudflare |
| 🗄️ | **D1 Database** | ذخیرهٔ پایدار کاربران و تنظیمات |
| 🎛️ | **داشبورد ادمین** | مدیریت کامل از مسیر `/leviko` |
| 👥 | **چندکاربره** | ساخت نامحدود کاربر با UUID جدا |
| 📦 | **سقف حجم** | محدودیت GB برای هر کاربر · ۰ = نامحدود |
| ⏳ | **انقضا** | محدودیت روز از زمان ساخت · ۰ = بدون انقضا |
| 📊 | **آمار مصرف** | نمایش مصرف، باقیمانده و درصد |
| 🔗 | **سابسکریپشن** | لینک یک‌خطی برای کلاینت‌ها |
| 📄 | **صفحه وضعیت** | صفحهٔ کاربرپسند با دکمهٔ کپی کانفیگ |
| 🔐 | **رمز پنل** | هش SHA-256 · تنظیم در اولین ورود |
| 🔄 | **کنترل سریع** | فعال / قطع / ریست ترافیک / حذف |
| 🌐 | **اینستالر وب** | نصب و آپدیت بدون ترمینال |

---

## 🔧 پیش‌نیازها

- حساب [Cloudflare](https://dash.cloudflare.com/sign-up) (پلن رایگان کافی است)
- دسترسی به **Workers** و **D1**
- مرورگر مدرن

برای اینستالر خودکار، توکن با این دسترسی‌ها:

- Account → Read  
- Account Analytics → Read  
- D1 → Edit  
- Workers Scripts → Edit  

---

## 📖 نصب دستی

اگر می‌خواهی بدون اینستالر نصب کنی:

### ۱. ساخت D1

Dashboard → **Storage & databases** → **D1** → Create  
نام پیشنهادی: `leviko-db`

### ۲. ساخت Worker

**Workers & Pages** → Create Worker → نام مثلاً `leviko` → Deploy  
Edit code → محتوای [`worker.js`](./worker.js) را جایگزین کن → Save and Deploy

### ۳. اتصال دیتابیس

Worker → **Settings** → **Bindings** → Add  

| فیلد | مقدار |
|------|--------|
| Type | D1 Database |
| Variable name | `DB` ← دقیقاً همین |
| Database | دیتابیسی که ساختی |

Save → دوباره Deploy

---

## 🖥 ورود به پنل

```text
https://<worker-name>.<subdomain>.workers.dev/leviko
```

- **اولین ورود:** رمز پنل را خودت انتخاب می‌کنی  
- بعد از آن با همان رمز وارد می‌شوی  

---

## 🔗 مسیرها

| مسیر | کاربرد |
|------|--------|
| `/leviko` | پنل مدیریت |
| `/sub/{username}` | سابسکریپشن کاربر |
| `/status/{username}` | صفحه وضعیت و کانفیگ |
| `/lv` | مسیر WebSocket |
| `/api/*` | API داخلی |

---

## 👥 مدیریت کاربران

از داخل داشبورد می‌توانی:

- کاربر جدید با نام، سقف حجم و روز انقضا بسازی  
- لینک ساب و صفحه وضعیت را کپی کنی  
- کاربر را فعال / غیرفعال کنی  
- ترافیک را ریست کنی  
- کاربر را حذف کنی  

آمار کلی (تعداد کاربران، فعال‌ها، مصرف کل) بالای پنل نمایش داده می‌شود.

---

## 📡 کانفیگ و سابسکریپشن

### لینک سابسکریپشن

```text
https://<host>/sub/<username>
```

### کانفیگ دستی

```text
vless://UUID@HOST:443?encryption=none&security=tls&sni=HOST&fp=chrome&type=ws&host=HOST&path=%2Flv#Leviko
```

`UUID` را از پنل بردار. `HOST` همان دامنهٔ Worker است.

---

## 📁 ساختار پروژه

```text
LEVIKO-PANEL/
├── worker.js              # هسته پنل و پروکسی
├── index.html             # اینستالر تحت وب
├── installer-proxy.js     # پروکسی CORS اختیاری
└── README.md
```

| فایل | نقش |
|------|-----|
| `worker.js` | پنل ادمین · API · VLESS · صفحه کاربر |
| `index.html` | نصب و بروزرسانی خودکار |
| `installer-proxy.js` | در صورت خطای CORS مرورگر |

---

## ❓ رفع مشکل

**پیام `D1 binding 'DB' is missing`**  
→ Variable name در Bindings باید دقیقاً `DB` باشد. بعد از اصلاح دوباره Deploy کن.

**اینستالر به API وصل نمی‌شود**  
→ احتمالاً CORS. فایل `installer-proxy.js` را به‌عنوان Worker جدا Deploy کن و آدرسش را در تنظیمات پیشرفته اینستالر بگذار.

**صفحهٔ اصلی خالی یا ساده است**  
→ طبیعی است. پنل فقط روی `/leviko` باز می‌شود.

**فراموشی رمز پنل**  
→ در D1 Console جدول `settings` را ببین یا Worker را با دیتابیس جدید وصل کن و از اول رمز بگذار.

**محدودیت پلن رایگان**  
→ حدود ۱۰۰٬۰۰۰ درخواست در روز برای هر Worker. برای چند کاربر سبک معمولاً کافی است.

---

## 📄 License

MIT — آزاد برای استفاده، تغییر و انتشار.

---

<div align="center">

**Leviko** `v1.0.0`

[Installer](https://danesh1118.github.io/LEVIKO-PANEL/) · [Issues](https://github.com/danesh1118/LEVIKO-PANEL/issues) · [Source](https://github.com/danesh1118/LEVIKO-PANEL)

</div>
