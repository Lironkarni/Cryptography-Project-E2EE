# פרוטוקול העברת הודעות מוצפנות מקצה לקצה (EE2E)
**מאת לירון קרני ואיתן קוט**

---

## הקדמה
הפרוטוקול המוצע נועד להבטיח תקשורת מאובטחת ואמינה בין לקוחות בסביבה שבה האיומים על פרטיות וסודיות המידע הולכים וגוברים. הוא תוכנן במיוחד כדי להגן על נתונים אישיים, להבטיח את הזהות של המשתתפים בתקשורת, ולאפשר החלפה בטוחה של מפתחות הצפנה בין לקוחות.

---

## מטרת הפרוטוקול
המטרה העיקרית של הפרוטוקול היא להקים ערוץ תקשורת מאובטח בין לקוחות באמצעות טכניקות קריפטוגרפיות מתקדמות. הפרוטוקול מוודא שפרטי ההתקשרות מוגנים מפני גורמים עוינים (MITM), תוך שמירה על שלמות המידע ויכולת אימות הדדית של זהות המשתתפים.

---

## חשיבות הפרוטוקול
- **שמירה על פרטיות וסודיות:** הפרוטוקול משתמש במנגנוני הצפנה חזקים (AES-256, RSA) כדי למנוע מגורמים לא מורשים לגשת לתוכן ההודעות.
- **אימות זהות המשתתפים:** השימוש בחתימות דיגיטליות וב-HMAC מאפשר לוודא שכל משתתף בתקשורת הוא אכן זה שהוא טוען להיות.
- **עמידה בפני התקפות:** הפרוטוקול עמיד בפני התקפות נפוצות כמו התקפת אדם במרכז (MITM) או זיוף הודעות.
- **עבודה בתנאי אי-חיבור:** במידה ואחד המשתתפים אינו מחובר, השרת שומר את ההודעות עד שהמשתתף יתחבר.

---

## פעולות מרכזיות בפרוטוקול
- **רישום ואימות:** הלקוח מבצע רישום מאובטח לשרת, כולל יצירת מפתחות קריפטוגרפיים ואימות זהות באמצעות OTP.
- **החלפת מפתחות:** תהליך מובנה לאבטחת העברת מפתחות ההצפנה בין הלקוחות, תוך אימות זהותם.
- **שליחת הודעות:** הצפנה ושמירה על שלמות ההודעה באמצעות HMAC והעברת ההודעות דרך שרת מאובטח.
- **שליחת אישורים:** מנגנון מובנה לשליחת אישור על קבלת ההודעה, כולל אימות הדדי.

באמצעות הפרוטוקול, ניתן להבטיח שהתקשורת תתבצע בסביבה מאובטחת ומוגנת מפני איומים אפשריים, תוך שמירה על שקיפות ותאימות למשתמשים.

---

## שלב 1: רישום לקוחות ואימות ראשוני

### 1.1 בקשת הרשמה
- הלקוח שולח בקשת הרשמה לשרת יחד עם מספר הטלפון שלו.

### 1.2 שליחת OTP
- השרת שולח ללקוח קוד חד-פעמי (OTP) בן 6 ספרות דרך ערוץ בטוח (SMS).
- ה-OTP תקף ל-5 דקות בלבד.

### 1.3 יצירת מפתחות בצד הלקוח
- כל לקוח יוצר זוג מפתחות RSA:
  - מפתח פרטי וציבורי נשמרים מקומית.
  - מפתח ציבורי, שישלח לשרת, מפתח פרטי, בעזרתו יפענח ויחתום.

### 1.4 יצירת Salt משותף
- השרת והלקוח יוצרים Salt זהה באמצעות HMAC:
  - `HMAC-SHA256(PhoneNumber, OTP) = Salt`

### 1.5 יצירת מפתח קריפטוגרפי חד פעמי (K_temp)
- הלקוח והשרת יוצרים את אותו (K_temp) באמצעות KDF:
  - `PBKDF2(OTP, Salt, Iterations, KeyLength) = K_temp`

### 1.6 שליחת מפתח ציבורי ואימות
- הלקוח:
  1. מחשב חתימה דיגיטלית על המפתח הציבורי שלו עם K_temp באמצעות HMAC:
     - `HMAC-SHA256(PublicKey, K_temp) = Signature`
  2. שולח לשרת את:
     - Public Key
     - Signature

- השרת:
  1. מחשב את החתימה Public Key של הלקוח באופן עצמאי.
  2. משווה את החתימה עם זו שהתקבלה מהלקוח.
  3. אם יש התאמה, ולא עברו 5 דקות משליחת ה-OTP, המפתח הציבורי של הלקוח נשמר בטבלה עם המזהה של הלקוח (מספר הטלפון).

---

## שלב 2: החלפת מפתחות בין לקוחות A ו-B

### 2.1 בקשת תחילת שיחה חדשה
- לקוח A מודיע לשרת שהוא רוצה להתחיל תקשורת עם לקוח B.

### 2.2 אישור זמינות של לקוח B
- השרת מוודא שלקוח B קיים.

### 2.3 השרת מעביר ללקוח A את המפתח הציבורי של לקוח B
- השרת:
  1. מפעיל SHA-256 על המפתח הציבורי של לקוח B ואז מצפין עם ה-Private Key שלו (של השרת) על מנת ליצור חתימה.
  2. שולח ללקוח A:
     - Public Key של לקוח B.
     - Signature – החתימה שיצר.

### 2.4 אימות המפתח הציבורי שנשלח ללקוח המעוניין בתקשורת
- לקוח A:
  1. מפענח את החתימה באמצעות המפתח הציבורי של השרת.
  2. מפעיל SHA-256 על המפתח הציבורי שהשרת שלח ומשווה עם החתימה.
  3. אם יש התאמה, המפתח מאומת ולקוח A שומר אותו.

### 2.5 יצירת מפתח סימטרי ושילוב חתימה
- לקוח A:
  1. יוצר מפתח סימטרי אקראי K.
  2. מצפין את K בשני שלבים:
     - פעם ראשונה עם Public Key של B.
     - פעם שנייה מפעיל על K פונקציית ריבוב SHA-256 ומצפין עם ה-Private Key שלו (של A) – על מנת ליצור חתימה דיגיטלית (Signature).
  3. שולח לשרת:
     - K המפתח הסימטרי מוצפן במפתח הציבורי של B.
     - Signature.

### 2.6 השרת
- מפעיל SHA-256 על המפתח הציבורי של לקוח A ואז מצפין עם ה-Private Key שלו (של השרת).

### 2.7 העברת המפתח הסימטרי והמפתח הציבורי של לקוח A ללקוח B
- השרת מעביר את המפתח הסימטרי המוצפן ואת החתימה שקיבל מלקוח A ללקוח B, ומצרף את המפתח הציבורי של לקוח A ואת החתימה שיצר.

### 2.8 אימות המפתח הציבורי שנשלח ללקוח B
- לקוח B:
  1. מפענח את החתימה באמצעות המפתח הציבורי של השרת.
  2. מפעיל SHA-256 על המפתח הציבורי שהשרת שלח ומשווה עם החתימה.
  3. אם יש התאמה, המפתח הציבורי מאומת והלקוח שומר אותו.

### 2.9 פענוח ואימות המפתח הסימטרי
- לקוח B:
  1. מפענח את המפתח הסימטרי המוצפן באמצעות המפתח הפרטי שלו (של B).
  2. מפעיל על K פונקציית ריבוב SHA-256, מפענח את החתימה באמצעות המפתח הציבורי של A ומשווה ביניהם לאימות.
  3. אם האימות מצליח, המפתח הסימטרי נשמר בקובץ חיצוני.

---

## שלב 3: שליחת הודעות

### 3.1 הצפנת ההודעה
- לקוח A:
  1. כותב הודעה M.
  2. מצפין את M עם המפתח הסימטרי באמצעות AES-256.
  3. מחשב HMAC-SHA256 מהמפתח הסימטרי ומ-M.
  4. יוצר IV חדש.

### 3.2 שליחת ההודעה
- הלקוח:
  שולח לשרת:
  - `M_encrypted`: ההודעה המוצפנת.
  - `HMAC`: החתימה על ההודעה.
  - `IV`.

- השרת:
  - מקבל את ההודעה ללא יכולת לפענחה.
  - בודק שלקוח B מחובר ומעביר את ההודעה ללקוח B ללא שינוי.
  - אם לקוח B לא מחובר, השרת שומר את ההודעה בטבלה עד שהלקוח יתחבר.

### 3.3 פענוח ואימות בצד לקוח B
- לקוח B:
  1. מפענח את `M_encrypted` עם המפתח הסימטרי וה-IV.
  2. מחשב HMAC ומשווה לערך שהתקבל.
  3. אם יש התאמה, ההודעה מאומתת ונקראת.

---

## שלב 4: שליחת אישור (ACK)

### 4.1 יצירת ACK
- לקוח B:
  1. יוצר הודעת אישור.
  2. יוצר חתימה עם HMAC-SHA256 על ה-ACK עם המפתח הסימטרי.

### 4.2 שליחת ה-ACK לשרת
- הלקוח שולח לשרת את ה-ACK והחתימה.

### 4.3 העברת ה-ACK ללקוח A
- השרת מעביר את ה-ACK והחתימה ללקוח A.

### 4.4 אימות ה-ACK
- לקוח A:
  1. יוצר חתימה עם HMAC-SHA256 על ה-ACK שקיבל עם המפתח הסימטרי.
  2. משווה את החתימה שהוא יצר עם החתימה שנשלחה אליו.
  3. אם יש התאמה, האישור מתקבל.
  
     ---


     
