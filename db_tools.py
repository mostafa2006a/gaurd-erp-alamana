#!/usr/bin/env python3
"""أدوات قاعدة بيانات الأمانة.
  python db_tools.py stats                    ← أعداد الصفوف وآخر تعديل
  python db_tools.py import-json [مجلد]       ← نقل state.json + users.json (من v5) مع التحقق
  python db_tools.py export-json [مجلد]       ← تصدير نسخة JSON (للفحص أو الخروج من النظام)
  python db_tools.py backup                   ← نسخة احتياطية الآن
  python db_tools.py reset-admin              ← حذف كل الحسابات لإنشاء مدير جديد من شاشة البداية (البيانات لا تُمس)
المجلد الافتراضي للقاعدة: data/ أو المتغير AMANAH_DATA.
"""
import json, sys
from pathlib import Path
import server as S


def main(argv):
    cmd = argv[1] if len(argv) > 1 else 'stats'
    S.ensure_ready()
    c = S.connect()
    try:
        if cmd == 'stats':
            st = S.load_state(c)
            print('قاعدة البيانات:', S.DB_PATH)
            print('الإصدار rev:', st['rev'], '| آخر تعديل:', st['updatedAt'], 'بواسطة', st['updatedBy'])
            print('المستخدمون:', c.execute('SELECT COUNT(*) FROM users').fetchone()[0])
            for r in c.execute('SELECT c.name, c.kind, COUNT(r.k) n FROM collections c LEFT JOIN records r ON r.coll=c.name GROUP BY c.name ORDER BY c.pos'):
                print(f'  {r["name"]:<20} {r["kind"]:<7} {r["n"]}')
        elif cmd == 'import-json':
            d = Path(argv[2] if len(argv) > 2 else S.DATA)
            res = S.import_legacy(c, d / 'state.json', d / 'users.json')
            print('القاعدة تحتوي بيانات سابقة — لم يُكتب فوقها.' if res is None else f'تم النقل والتحقق ✓  {json.dumps(res, ensure_ascii=False)}')
        elif cmd == 'export-json':
            d = Path(argv[2] if len(argv) > 2 else S.DATA / 'export')
            d.mkdir(parents=True, exist_ok=True)
            st = S.load_state(c)
            (d / 'state.json').write_text(json.dumps(st, ensure_ascii=False), encoding='utf-8')
            users = [{'id': u['id'], 'name': u['name'], 'username': u['username'], 'role': u['role'], 'active': bool(u['active']),
                      'cred': {'salt': u['salt'], 'hash': u['hash'], 'iter': u['iter']}, 'createdAt': u['created_at'], 'lastLogin': u['last_login']}
                     for u in c.execute('SELECT * FROM users')]
            (d / 'users.json').write_text(json.dumps({'users': users}, ensure_ascii=False), encoding='utf-8')
            print('تم التصدير إلى', d)
        elif cmd == 'backup':
            S.make_backup(force=True)
            print('تمت النسخة في', S.BACKUPS)
        elif cmd == 'reset-admin':
            if input('سيُحذف كل المستخدمين (البيانات تبقى). اكتب نعم للمتابعة: ').strip() != 'نعم':
                return print('أُلغي.')
            S.make_backup(force=True)
            c.execute('DELETE FROM sessions'); c.execute('DELETE FROM users')
            print('تم. افتح التطبيق لإنشاء مدير جديد.')
        else:
            print(__doc__)
    finally:
        c.close()


if __name__ == '__main__':
    main(sys.argv)
