# Data Anonymizer

A local, policy-driven Python tool for transforming sensitive fields in CSV and JSON datasets before they are shared, tested, or analyzed.

> **Privacy note:** this tool provides practical redaction, masking, generalization, and keyed pseudonymization. It does not by itself prove that a dataset is anonymous under any law or eliminate re-identification risk.

## English

### Why this project exists
Development and analytics workflows often need realistic data shapes without exposing original identifiers. Data Anonymizer makes transformations explicit in a reviewable JSON policy, runs entirely on the local machine, and requires no service account or network connection.

### Features
- CSV and JSON input/output with UTF-8 support.
- `redact`: replace a value with a fixed marker or configured replacement.
- `mask`: preserve only the last N characters.
- `hmac`: deterministic HMAC-SHA256 pseudonyms for stable joins across files when the same secret key is used.
- `generalize_number`: convert numbers into configurable ranges such as `20-30`.
- `keep`: explicitly leave a field unchanged.
- Strict mode for schema-sensitive pipelines.
- JSON processing report for automation.
- Refuses to overwrite the source file.
- Python API and CLI; runtime uses only the Python standard library.

### Preview
```text
$ data-anonymizer check examples/policy.json
Policy OK: 6 field rule(s)

$ data-anonymizer run examples/sample.csv output/anonymized.csv --policy examples/policy.json
Anonymized 2 record(s); changed 10 field value(s).
```
The sample is synthetic. HMAC rules additionally require a key as shown below.

### Requirements & installation
- Python 3.10+

```bash
git clone https://github.com/rad03i2/data-anonymizer.git
cd data-anonymizer
python -m pip install -e .
```

For development/testing:
```bash
python -m pip install -e . pytest
```

### Usage
Set a strong secret key when the policy contains `hmac` rules. Do not put the key in the policy or repository.

Linux/macOS:
```bash
export DATA_ANONYMIZER_KEY='replace-with-a-long-random-secret'
data-anonymizer run examples/sample.csv output/anonymized.csv --policy examples/policy.json --json-report
```

PowerShell:
```powershell
$env:DATA_ANONYMIZER_KEY = 'replace-with-a-long-random-secret'
data-anonymizer run examples/sample.csv output/anonymized.csv --policy examples/policy.json --json-report
```

You can choose a different environment-variable name with `--key-env`. Use `--strict` when every configured field must exist in every record. `python -m data_anonymizer ...` is equivalent to the installed command.

### Policy format
```json
{
  "fields": {
    "email": {"action": "hmac", "length": 20},
    "phone": {"action": "mask", "visible": 3},
    "age": {"action": "generalize_number", "bucket": 10},
    "notes": {"action": "redact"},
    "city": {"action": "keep"}
  }
}
```
HMAC output is prefixed with `anon_`; digest length can be 8–64 hexadecimal characters. Null JSON values remain null. Fields not mentioned in the policy remain unchanged.

### Python API
```python
from data_anonymizer import anonymize_records

rows, report = anonymize_records(
    [{"user_id": "A-123", "age": 27}],
    {"user_id": {"action": "hmac"}, "age": {"action": "generalize_number", "bucket": 10}},
    key=b"use-a-strong-secret-key",
)
```

### Project structure
```text
src/data_anonymizer/   engine, CLI, public API
tests/                 core and CLI tests
examples/              synthetic CSV and policy
.github/workflows/     cross-platform CI
SECURITY.md             security/privacy guidance
CONTRIBUTING.md         contribution guide
```

### Testing
```bash
python -m pytest
python -m compileall -q src
data-anonymizer check examples/policy.json
```
CI runs the suite on Python 3.10, 3.12, and 3.13 across Ubuntu, Windows, and macOS.

### Security & privacy
Processing is local and the program has no telemetry or network code. HMAC is keyed so repeated source values can map to stable pseudonyms without storing the originals in the output. Protect the key separately from anonymized data. Review `SECURITY.md` before handling sensitive datasets.

### Limitations
- CSV headers are required; JSON input must be a top-level array of objects.
- The tool processes datasets in memory and is not intended for very large streaming workloads.
- HMAC pseudonymization is not encryption and does not make all datasets anonymous.
- Masked/generalized values can still carry identifying information in combination with other fields.
- The tool does not automatically discover PII or assess k-anonymity/differential privacy.

### Optional roadmap
Streaming processing, nested JSON field paths, and additional statistically grounded privacy transforms are reasonable future extensions; none are claimed as current features.

### Contributing & license
See `CONTRIBUTING.md`. Licensed under the MIT License; see `LICENSE`.

### Author
**Radwan Abdulhadi Ahmed**  
**رضوان عبدالهادي أحمد**  
GitHub: **@rad03i2**

---

## العربية

### نظرة عامة
**Data Anonymizer** أداة بايثون محلية تعتمد سياسة JSON واضحة لتحويل الحقول الحساسة في ملفات CSV وJSON قبل مشاركة البيانات أو استخدامها في الاختبارات والتحليل. لا ترسل الأداة البيانات إلى أي خدمة خارجية.

### لماذا أُنشئ المشروع؟
تحتاج فرق التطوير والتحليل أحيانًا إلى الاحتفاظ ببنية البيانات مع تقليل كشف المعرّفات الأصلية. يضع هذا المشروع قواعد التحويل في ملف سياسة قابل للمراجعة، ويعمل محليًا دون حسابات خدمة أو اتصال شبكي.

### الميزات
- قراءة وكتابة CSV وJSON بترميز UTF-8.
- `redact` لاستبدال القيمة بعلامة ثابتة.
- `mask` لإخفاء القيمة مع إبقاء آخر عدد محدد من المحارف.
- `hmac` لإنشاء أسماء مستعارة ثابتة باستخدام HMAC-SHA256 ومفتاح سري.
- `generalize_number` لتحويل الرقم إلى نطاق مثل `20-30`.
- `keep` لإبقاء الحقل كما هو بصورة صريحة.
- وضع `--strict` للتحقق من وجود جميع الحقول المحددة.
- تقرير JSON مناسب للأتمتة.
- منع الكتابة فوق ملف المصدر.
- واجهة أوامر وPython API، ولا توجد اعتمادات تشغيل خارج المكتبة القياسية.

### المعاينة والتثبيت
المتطلب Python 3.10 أو أحدث:
```bash
git clone https://github.com/rad03i2/data-anonymizer.git
cd data-anonymizer
python -m pip install -e .
data-anonymizer check examples/policy.json
```

### الاستخدام والإعداد
إذا احتوت السياسة على قاعدة `hmac`، ضع مفتاحًا عشوائيًا قويًا في متغير البيئة `DATA_ANONYMIZER_KEY` ولا تحفظه داخل المستودع. ثم شغّل:
```bash
data-anonymizer run examples/sample.csv output/anonymized.csv --policy examples/policy.json --json-report
```
يمكن تغيير اسم متغير المفتاح بواسطة `--key-env`. الحقول غير المذكورة في السياسة تبقى دون تغيير، وقيم JSON الفارغة `null` تبقى فارغة.

### Python API
يمكن استدعاء `anonymize_records` أو `anonymize_file` مباشرة من الحزمة. المثال الإنجليزي أعلاه يستخدم مفتاح HMAC صريحًا ويعيد البيانات المحولة مع تقرير بعدد السجلات والقيم المتغيرة.

### بنية المشروع
المحرك والـCLI داخل `src/data_anonymizer/`، والاختبارات داخل `tests/`، والأمثلة الاصطناعية داخل `examples/`، وCI داخل `.github/workflows/`، مع إرشادات الأمان والمساهمة في `SECURITY.md` و`CONTRIBUTING.md`.

### الاختبارات
```bash
python -m pytest
python -m compileall -q src
```
ويختبر CI المشروع على Python 3.10 و3.12 و3.13 في Ubuntu وWindows وmacOS.

### الأمان والخصوصية
المعالجة محلية ولا يحتوي البرنامج على telemetry أو كود شبكي. يجب حماية مفتاح HMAC بصورة منفصلة عن البيانات الناتجة. الأسماء المستعارة ليست تشفيرًا، ولا تعني وحدها أن البيانات أصبحت مجهولة قانونيًا أو إحصائيًا. راجع `SECURITY.md` قبل التعامل مع بيانات حساسة.

### القيود
يحتاج CSV إلى صف عناوين، ويجب أن يكون JSON مصفوفة عليا من الكائنات. تُحمّل البيانات في الذاكرة، لذلك المشروع ليس لمعالجة الملفات العملاقة المتدفقة. كما لا يكتشف PII تلقائيًا ولا يحسب k-anonymity أو differential privacy، وقد تبقى إمكانية إعادة التعرف قائمة عند جمع عدة حقول معًا.

### خارطة طريق اختيارية
يمكن مستقبلًا إضافة المعالجة المتدفقة، ومسارات JSON المتداخلة، وتحويلات خصوصية إحصائية إضافية. هذه أفكار مستقبلية وليست ميزات حالية.

### المساهمة والترخيص
راجع `CONTRIBUTING.md`. المشروع مرخص برخصة MIT الموجودة في `LICENSE`.

### المؤلف
**Radwan Abdulhadi Ahmed**  
**رضوان عبدالهادي أحمد**  
GitHub: **@rad03i2**
