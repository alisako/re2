# RVG Gateway v2 · Render Edition

## قابلیت‌ها
- VLESS WebSocket TLS
- پنل مدیریت فارسی کامل
- ربات تلگرام با مدیریت کامل
- نوتیف اتصال جدید + IP + کشور + ISP
- Anti-sleep خودکار هر ۱۰ دقیقه
- ذخیره لینک‌ها در JSON
- تاریخ انقضای لینک
- محدودیت دستگاه همزمان
- Subscription Link
- بلاک/آنبلاک IP
- گزارش روزانه خودکار

---

## مراحل Deploy

### ۱. GitHub
فایل‌ها رو توی GitHub بذار

### ۲. Render
- render.com → New → Web Service
- ریپو رو وصل کن
- Build: `pip install -r requirements.txt`
- Start: `uvicorn main:app --host 0.0.0.0 --port $PORT --workers 1`

### ۳. متغیرهای محیطی

| نام | مقدار |
|-----|-------|
| `ADMIN_PASSWORD` | رمز پنل |
| `BOT_TOKEN` | توکن ربات تلگرام |
| `BOT_PASSWORD` | رمز ربات |
| `ADMIN_CHAT_IDS` | Chat ID ادمین (با کاما جدا) |
| `RENDER_EXTERNAL_URL` | آدرس کامل سایت مثلاً https://yourapp.onrender.com |

---

## دستورات ربات تلگرام

```
/create عنوان | سهمیه | روزهای انقضا | حداکثر دستگاه
/create برای علی | 10 GB | 30 | 2

/links     — لیست لینک‌ها
/stats     — آمار سرور
/block IP  — بلاک IP
/unblock IP — آنبلاک
/blocked   — لیست بلاک
/report    — گزارش امروز
```