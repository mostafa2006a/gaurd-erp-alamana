# رفع تطبيق الأمانة على استضافة (v7 — SQLite)

قاعدة البيانات ملف واحد `amanah.db` (SQL). لا تحتاج MySQL ولا مكتبات إضافية — Python 3.8+ فقط.

## أي استضافة تناسب؟
| النوع | يناسب؟ |
|---|---|
| **VPS** (Hostinger/Contabo/DigitalOcean) | ✅ الأفضل — الطريقة (أ) |
| **cPanel فيه "Setup Python App"** | ✅ الطريقة (ب) |
| استضافة PHP عادية بدون Python | ❌ لا تعمل |

> استخدم **دومين فرعي** (مثل `app.example.com`) وليس مسارًا فرعيًا (`example.com/app`).

---
## (أ) VPS — Ubuntu
```bash
# 1) الملفات
sudo apt update && sudo apt install -y python3 unzip caddy
sudo useradd -r -m amanah
sudo mkdir -p /opt/amanah /var/lib/amanah
sudo unzip amanah_guard_web_v7.zip -d /opt/amanah
sudo chown -R amanah:amanah /opt/amanah /var/lib/amanah

# 2) الخدمة
sudo cp /opt/amanah/deploy/amanah.service /etc/systemd/system/
sudo systemctl enable --now amanah

# 3) HTTPS: عدّل الدومين في الملف ثم
sudo cp /opt/amanah/deploy/Caddyfile /etc/caddy/Caddyfile
sudo systemctl restart caddy
```
وجّه سجل **A** للدومين الفرعي إلى IP السيرفر قبل الخطوة 3. افتح `https://app.example.com` وأنشئ المدير.

## (ب) cPanel — Setup Python App
1. **Setup Python App → Create Application**: إصدار Python 3.8+، **Application root** = `amanah` (خارج `public_html`)، **Application URL** = الدومين الفرعي.
2. **Application startup file**: `passenger_wsgi.py` — **Application entry point**: `application`
3. ارفع محتويات الـ ZIP إلى مجلد `amanah` (File Manager → Upload → Extract).
4. في قسم **Environment variables** أضف:
   - `AMANAH_DATA` = `/home/اسم_الحساب/amanah_data` (خارج مجلد التطبيق)
   - `AMANAH_TRUST_PROXY` = `1` (فقط إذا كان الدومين خلف Cloudflare)
5. اضغط **Restart** ثم افتح الرابط وأنشئ المدير.
6. فعّل **SSL** (AutoSSL / Let's Encrypt) للدومين الفرعي.

---
## نقل بياناتك من v5
ضع `state.json` و`users.json` في مجلد البيانات (`AMANAH_DATA`) **قبل أول تشغيل**.
عند أول تشغيل تُنقل تلقائيًا ويُتحقق أنها مطابقة 100% قبل اعتمادها، وتبقى كلمات المرور كما هي.
أو يدويًا: `python3 db_tools.py import-json /مسار/المجلد`

## الصيانة
```bash
python3 db_tools.py stats          # أعداد الصفوف
python3 db_tools.py backup         # نسخة الآن
python3 db_tools.py export-json    # تصدير JSON
python3 db_tools.py reset-admin    # نسيت كلمة مرور المدير الوحيد (البيانات تبقى)
```
- نسخ تلقائية في `AMANAH_DATA/backups/` (كل 10 دقائق عند وجود تعديل، آخر 150). **حمّل نسخة دورية إلى جهازك.**
- ترقية التطبيق مستقبلًا: استبدل ملفات الكود فقط، **لا تلمس مجلد البيانات**.

## أمان — تأكد قبل الاستخدام
- HTTPS مفعّل (الكوكي يصبح Secure تلقائيًا).
- مجلد البيانات **خارج** مجلد الموقع العام.
- كلمات مرور المدير قوية، والمحاسبون بدور "محاسب"، وغيرهم "مشاهدة".
- قفل تلقائي: 5 محاولات خاطئة لكل حساب، و20 لكل IP.
