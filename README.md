كيفية الاستخدام:
تثبيت المتطلبات:

bash
pip install requests beautifulsoup4 colorama
فحص عنوان URL واحد:

bash
python scanner.py -u http://example.com
فحص قائمة من العناوين من ملف:

bash
python scanner.py -f urls.txt
زحف الموقع لاكتشاف الصفحات:

bash
python scanner.py -u http://example.com -c
حفظ التقرير بصيغة JSON:

bash
python scanner.py -u http://example.com -o json
نصائح أمنية:
احصل على إذن كتابي قبل فحص أي موقع لا تملكه.

استخدم الأداة لأغراض اختبار الاختراق الأخلاقي فقط.

بعض الفحوصات قد تكون ضارة بالموقع - كن حذراً.

الأداة لا تغطي جميع أنواع الثغرات الأمنية.

قد يتم حظر عنوان IP الخاص بك إذا أجرينا طلبات كثيرة في وقت قصير.

