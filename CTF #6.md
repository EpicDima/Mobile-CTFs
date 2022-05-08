# CTF \#6

- [Задача](#Задача)
- [Решение](#Решение)

## [Задача](https://github.com/dh0ck/Mystiko-CTF-challenges/tree/main/kryptonite)

В приложении имеется флаг, который нужно каким-то образом найти. Больше ничего неизвестно.

## Решение

Установим приложение и откроем его.
<details>
  <summary>Скриншот</summary>
  
  ![](/CTF6/1.png)
</details>

Приложение содержит два поля ввода. Первое имеет текст: enter message. Второе - enter key. Также есть две кнопки для шифрования и дешифрования. А также текстовое поле для вывода результата.

Введём в оба поля 123 и нажмём кнопку шифрования. Получаем сообщение, что длина ключа неверная. Тоже самое происходит и при нажатии второй кнопки.
<details>
  <summary>Скриншот</summary>
  
  ![](/CTF6/2.png)
</details>

Откроем приложение в jadx-gui. В манифесте нас встречают две Активити: MainActivity, которая запускается при нажатии на значок приложения, и H1dD3N, которая исходя из названия как-то скрыта.

```xml
<application android:theme="@style/Theme.AppCompat.NoActionBar" android:label="@string/app_name" android:icon="@mipmap/ic_launcher" android:allowBackup="true" android:supportsRtl="true" android:roundIcon="@mipmap/ic_launcher_round" android:appComponentFactory="androidx.core.app.CoreComponentFactory">
    <activity android:name="com.example.kryptonite.H1dD3N"/>
    <activity android:name="com.example.kryptonite.MainActivity">
        <intent-filter>
            <action android:name="android.intent.action.MAIN"/>
            <category android:name="android.intent.category.LAUNCHER"/>
        </intent-filter>
    </activity>
</application>
```

Посмотрим MainActivity. В методе onCreate можно увидеть как двум кнопкам присваиваются обработчики нажатия.

```java
public void onCreate(Bundle bundle) {
    super.onCreate(bundle);
    setContentView(R.layout.activity_main);
    ((Button) findViewById(R.id.encrypt)).setOnClickListener(new a());
    ((Button) findViewById(R.id.decrypt)).setOnClickListener(new b());
}
```

Посмотрим первый обработчик, который называется 'a'. Так как это реализация интерфейса View.OnClickListener, следовательно нас интересует метод onClick.

В коде метода можно сразу увидеть знакомое сообщение, а именно "Wr0Ng k3Y L3n6tH" и понять, при каком условии оно появляется. Видим, что длина строки obj2, которая является введённым ключом, должна быть равна 16, 24 или 32 символа. Если ключ верной длины, то далее идёт создание криптографического ключа AES, потом вызываются методы с нечитаемыми названиями, после чего вызывается метод 't' класса MainActivity, который просто шифрует строку (введённое пользователем сообщение) и кодирует результат в base64, далее передаётся в метод c.b.a.a.a. Потом можно увидеть, как закрывается база данных.

```java
@Override // android.view.View.OnClickListener
public void onClick(View view) {
    TextView textView = (TextView) MainActivity.this.findViewById(R.id.result);
    String obj = ((EditText) MainActivity.this.findViewById(R.id.message)).getText().toString();
    String obj2 = ((EditText) MainActivity.this.findViewById(R.id.key)).getText().toString();
    if (!(obj2.length() == 16 || obj2.length() == 24 || obj2.length() == 32)) {
        Toast.makeText(MainActivity.this.getApplicationContext(), "Wr0Ng k3Y L3n6tH", 0).show();
    }
    Log.e("message: ", obj);
    Log.e("key: ", obj2);
    try {
        int i = MainActivity.o;
        SecretKeySpec secretKeySpec = new SecretKeySpec(obj2.getBytes(), "AES");
        textView.setText(MainActivity.this.t(obj, secretKeySpec));
        Context applicationContext = MainActivity.this.getApplicationContext();
        if (c.b.a.a.f729c == null) {
            c.b.a.a.f729c = new c.b.a.a(applicationContext);
        }
        c.b.a.a.f728b = c.b.a.a.f729c.a.getWritableDatabase();
        c.b.a.a.a("New User", MainActivity.this.t(obj, secretKeySpec));
        SQLiteDatabase sQLiteDatabase = c.b.a.a.f728b;
        if (sQLiteDatabase != null) {
            sQLiteDatabase.close();
        }
    } catch (Exception e) {
        e.printStackTrace();
    }
}
```

Метод 't' класса MainActivity.

```java
public String t(String str, SecretKey secretKey) {
    Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
    cipher.init(1, secretKey);
    return Base64.encodeToString(cipher.doFinal(str.getBytes("UTF-8")), 2);
}
```

Посмотрим на класс, который содержит базу данных и который содержит метод, в который передаётся зашифрованная строка. Легко можно увидеть SQL запрос в таблицу с названием "test". В конструкторе класса можно наблюдать создание экземпляра SQLiteOpenHelper, а точнее класса 'b', который от него наследуется.

```java
public class a {

    /* renamed from: b  reason: collision with root package name */
    public static SQLiteDatabase f728b;

    /* renamed from: c  reason: collision with root package name */
    public static a f729c;
    public SQLiteOpenHelper a;

    public a(Context context) {
        this.a = new b(context);
    }

    public static void a(String str, String str2) {
        String str3 = "INSERT INTO test VALUES ('" + str + "', '" + str2 + "');";
        Log.e("xxxxxxxxxxxxxx", str3);
        f728b.execSQL(str3);
        Log.e("yyyyyyyyyyyyyy", str3);
    }
}
```

Класс 'b' является до нельзя простым и просто содержит название файла с БД. Следовательно мы можем найти базу данных в приватном каталоге приложения, плюс зная название таблицы получить все записи.

```java
public class b extends a {
    public b(Context context) {
        super(context, "default.db", null, 1);
    }
}
```

Для просмотра БД воспользуемся adb shell, который даст доступ к консоли устройства, где мы сможем воспользоваться консольной утилитой sqlite3.

Перейдём в приватную директорию приложения, для этого нужно знать название пакета. Его можно узнать из манифеста и оно равно "com.example.kryptonite". По пути "/data/data/com.example.kryptonite" можно обнаружить две директории "cache" и "code_cache". Ни одна из директорий не называется databases, которая по умолчанию содержит базы данных. Поэтому давайте введём ключ верной длины и нажмём первую кнопку для того, чтобы база данных была создана.
<details>
  <summary>Скриншот</summary>
  
  ![](/CTF6/3.png)
</details>

После успешного результата, который можно видеть на экране, снова посмотрим на директории внутри папки приложения и в этот раз действительно появляется новым - databases. Внутри себя она содержит знакомое название - default.db. Воспользуемся встроенным в Android - sqlite3.

```txt
generic_x86:/data/data/com.example.kryptonite/databases # sqlite3
SQLite version 3.22.0 2018-12-19 01:30:22
Enter ".help" for usage hints.
Connected to a transient in-memory database.
Use ".open FILENAME" to reopen on a persistent database.
sqlite> .open default.db
sqlite> SELECT * FROM test;
J0hn|XAc860TQ62HaVTjOGV5egywXXWS0hUc6yOR/0eu5aQM=
P4u7|bq3G0iIKEKfb4bJcqvpsziaHZLEsEZfzxRY21d9yV3g=
M4r14|vEpr9q0DVMSbe7pDyqz7TtjWEhxZZ03uDcksStPArvo=
New User|DGYYLscQhABl66pHxebOkA==
```

В таблице, кроме созданного нами юзера с именем "New User" (можно понять по вызову метода 'c.b.a.a.a' в обработчик нажатия 'a') находятся ещё три записи. Каждая запись содержит ключ, который зашифрован, а после закодирован в формате base64, что тоже выяснили из кода программы.

На самом деле, исходная база данных находится в apk файле в папке assets. Это можно выяснить просто полазав по ресурсам, которые лежат в файле приложения, или посмотрев, от какого именно класса наследуется класс 'b', в котором обнаружилась строка с название файла БД. В нём можно найти строки, которые логируются и говорят о каком-то копировании. Есть строка "copying database from assets..." явно говорящая о том, что происходит. Не стоит забывать, что это происходит только один раз при первом обращении к БД.

<details>
  <summary>Код класса 'a'</summary>

```java
public class a extends SQLiteOpenHelper {
    public static final String k = a.class.getSimpleName();

    /* renamed from: b  reason: collision with root package name */
    public final Context f871b;

    /* renamed from: c  reason: collision with root package name */
    public final String f872c;
    public final SQLiteDatabase.CursorFactory d;
    public final int e;
    public SQLiteDatabase f = null;
    public boolean g = false;
    public String h;
    public String i;
    public String j;

    /* renamed from: c.d.a.a$a  reason: collision with other inner class name */
    /* loaded from: classes.dex */
    public static class C0041a extends SQLiteException {
        public C0041a(String str) {
            super(str);
        }
    }

    public a(Context context, String str, SQLiteDatabase.CursorFactory cursorFactory, int i) {
        super(context, str, (SQLiteDatabase.CursorFactory) null, i);
        if (i >= 1) {
            this.f871b = context;
            this.f872c = str;
            this.d = null;
            this.e = i;
            this.i = c.a.a.a.a.b("databases/", str);
            this.h = context.getApplicationInfo().dataDir + "/databases";
            this.j = c.a.a.a.a.c("databases/", str, "_upgrade_%s-%s.sql");
            return;
        }
        throw new IllegalArgumentException("Version must be >= 1, was " + i);
    }

    public final void a() {
        InputStream inputStream;
        FileOutputStream fileOutputStream;
        Log.w(k, "copying database from assets...");
        String str = this.i;
        String str2 = this.h + "/" + this.f872c;
        boolean z = false;
        try {
            try {
                try {
                    inputStream = this.f871b.getAssets().open(str);
                } catch (IOException unused) {
                    inputStream = this.f871b.getAssets().open(str + ".gz");
                }
            } catch (IOException e) {
                StringBuilder e2 = c.a.a.a.a.e("Missing ");
                e2.append(this.i);
                e2.append(" file (or .zip, .gz archive) in assets, or target folder not writable");
                C0041a aVar = new C0041a(e2.toString());
                aVar.setStackTrace(e.getStackTrace());
                throw aVar;
            }
        } catch (IOException unused2) {
            inputStream = this.f871b.getAssets().open(str + ".zip");
            z = true;
        }
        try {
            File file = new File(this.h + "/");
            if (!file.exists()) {
                file.mkdir();
            }
            if (z) {
                inputStream = b.a(inputStream);
                if (inputStream != null) {
                    fileOutputStream = new FileOutputStream(str2);
                } else {
                    throw new C0041a("Archive is missing a SQLite database file");
                }
            } else {
                fileOutputStream = new FileOutputStream(str2);
            }
            b.c(inputStream, fileOutputStream);
            Log.w(k, "database copy complete");
        } catch (IOException e3) {
            C0041a aVar2 = new C0041a(c.a.a.a.a.c("Unable to write ", str2, " to data directory"));
            aVar2.setStackTrace(e3.getStackTrace());
            throw aVar2;
        }
    }

    public final SQLiteDatabase b(boolean z) {
        StringBuilder sb = new StringBuilder();
        sb.append(this.h);
        sb.append("/");
        sb.append(this.f872c);
        SQLiteDatabase d = new File(sb.toString()).exists() ? d() : null;
        if (d == null) {
            a();
            return d();
        } else if (!z) {
            return d;
        } else {
            Log.w(k, "forcing database upgrade!");
            a();
            return d();
        }
    }

    public final void c(int i, int i2, int i3, ArrayList<String> arrayList) {
        InputStream inputStream;
        int i4;
        String format = String.format(this.j, Integer.valueOf(i2), Integer.valueOf(i3));
        try {
            inputStream = this.f871b.getAssets().open(format);
        } catch (IOException unused) {
            Log.w(k, "missing database upgrade script: " + format);
            inputStream = null;
        }
        if (inputStream != null) {
            arrayList.add(String.format(this.j, Integer.valueOf(i2), Integer.valueOf(i3)));
            i4 = i2 - 1;
        } else {
            i4 = i2 - 1;
            i2 = i3;
        }
        if (i4 >= i) {
            c(i, i4, i2, arrayList);
        }
    }

    @Override // android.database.sqlite.SQLiteOpenHelper, java.lang.AutoCloseable
    public synchronized void close() {
        if (!this.g) {
            SQLiteDatabase sQLiteDatabase = this.f;
            if (sQLiteDatabase != null && sQLiteDatabase.isOpen()) {
                this.f.close();
                this.f = null;
            }
        } else {
            throw new IllegalStateException("Closed during initialization");
        }
    }

    public final SQLiteDatabase d() {
        try {
            SQLiteDatabase openDatabase = SQLiteDatabase.openDatabase(this.h + "/" + this.f872c, this.d, 0);
            String str = k;
            Log.i(str, "successfully opened database " + this.f872c);
            return openDatabase;
        } catch (SQLiteException e) {
            String str2 = k;
            StringBuilder e2 = c.a.a.a.a.e("could not open database ");
            e2.append(this.f872c);
            e2.append(" - ");
            e2.append(e.getMessage());
            Log.w(str2, e2.toString());
            return null;
        }
    }

    @Override // android.database.sqlite.SQLiteOpenHelper
    public synchronized SQLiteDatabase getReadableDatabase() {
        SQLiteDatabase sQLiteDatabase = this.f;
        if (sQLiteDatabase != null && sQLiteDatabase.isOpen()) {
            return this.f;
        } else if (!this.g) {
            try {
                return getWritableDatabase();
            } catch (SQLiteException e) {
                if (this.f872c != null) {
                    String str = k;
                    Log.e(str, "Couldn't open " + this.f872c + " for writing (will try read-only):", e);
                    this.g = true;
                    String path = this.f871b.getDatabasePath(this.f872c).getPath();
                    SQLiteDatabase openDatabase = SQLiteDatabase.openDatabase(path, this.d, 1);
                    if (openDatabase.getVersion() == this.e) {
                        onOpen(openDatabase);
                        Log.w(str, "Opened " + this.f872c + " in read-only mode");
                        this.f = openDatabase;
                        this.g = false;
                        if (openDatabase != openDatabase) {
                            openDatabase.close();
                        }
                        return openDatabase;
                    }
                    throw new SQLiteException("Can't upgrade read-only database from version " + openDatabase.getVersion() + " to " + this.e + ": " + path);
                }
                throw e;
            }
        } else {
            throw new IllegalStateException("getReadableDatabase called recursively");
        }
    }

    @Override // android.database.sqlite.SQLiteOpenHelper
    public synchronized SQLiteDatabase getWritableDatabase() {
        SQLiteDatabase sQLiteDatabase = this.f;
        if (sQLiteDatabase != null && sQLiteDatabase.isOpen() && !this.f.isReadOnly()) {
            return this.f;
        } else if (!this.g) {
            this.g = true;
            SQLiteDatabase b2 = b(false);
            int version = b2.getVersion();
            if (version != 0 && version < 0) {
                b2 = b(true);
                b2.setVersion(this.e);
                version = b2.getVersion();
            }
            if (version != this.e) {
                b2.beginTransaction();
                if (version != 0) {
                    if (version > this.e) {
                        String str = k;
                        Log.w(str, "Can't downgrade read-only database from version " + version + " to " + this.e + ": " + b2.getPath());
                    }
                    onUpgrade(b2, version, this.e);
                }
                b2.setVersion(this.e);
                b2.setTransactionSuccessful();
                b2.endTransaction();
            }
            onOpen(b2);
            this.g = false;
            SQLiteDatabase sQLiteDatabase2 = this.f;
            if (sQLiteDatabase2 != null) {
                try {
                    sQLiteDatabase2.close();
                } catch (Exception unused) {
                }
            }
            this.f = b2;
            return b2;
        } else {
            throw new IllegalStateException("getWritableDatabase called recursively");
        }
    }

    @Override // android.database.sqlite.SQLiteOpenHelper
    public final void onConfigure(SQLiteDatabase sQLiteDatabase) {
    }

    @Override // android.database.sqlite.SQLiteOpenHelper
    public final void onCreate(SQLiteDatabase sQLiteDatabase) {
    }

    @Override // android.database.sqlite.SQLiteOpenHelper
    public final void onDowngrade(SQLiteDatabase sQLiteDatabase, int i, int i2) {
    }

    @Override // android.database.sqlite.SQLiteOpenHelper
    public void onUpgrade(SQLiteDatabase sQLiteDatabase, int i, int i2) {
        String str = k;
        StringBuilder e = c.a.a.a.a.e("Upgrading database ");
        e.append(this.f872c);
        e.append(" from version ");
        e.append(i);
        e.append(" to ");
        e.append(i2);
        e.append("...");
        Log.w(str, e.toString());
        ArrayList<String> arrayList = new ArrayList<>();
        c(i, i2 - 1, i2, arrayList);
        if (!arrayList.isEmpty()) {
            Collections.sort(arrayList, new c());
            Iterator<String> it = arrayList.iterator();
            while (it.hasNext()) {
                String next = it.next();
                try {
                    String str2 = k;
                    Log.w(str2, "processing upgrade: " + next);
                    InputStream open = this.f871b.getAssets().open(next);
                    String str3 = b.a;
                    String next2 = new Scanner(open).useDelimiter("\\A").next();
                    if (next2 != null) {
                        Iterator it2 = ((ArrayList) b.b(next2, ';')).iterator();
                        while (it2.hasNext()) {
                            String str4 = (String) it2.next();
                            if (str4.trim().length() > 0) {
                                sQLiteDatabase.execSQL(str4);
                            }
                        }
                    }
                } catch (IOException e2) {
                    e2.printStackTrace();
                }
            }
            String str5 = k;
            StringBuilder e3 = c.a.a.a.a.e("Successfully upgraded database ");
            e3.append(this.f872c);
            e3.append(" from version ");
            e3.append(i);
            e3.append(" to ");
            e3.append(i2);
            Log.w(str5, e3.toString());
            return;
        }
        Log.e(str, "no upgrade script path from " + i + " to " + i2);
        throw new C0041a("no upgrade script path from " + i + " to " + i2);
    }
}
```

</details>

Декодирование трёх строк из БД не даёт результата, при декодировании получаются кракозябры.

Пришло дело взглянуть на скрытую Активити. Судя по всему просто открыть через интерфейс MainActivity её нельзя, так что откроем её с помощью adb, потому что на устройстве с root правами можно открыть не только exported=true Activity. Для этого воспользуемся командой "adb shell am start -n com.example.kryptonite/.H1dD3N".

После успешного старта можно увидеть какой-то код, изображённый на этом экране.
<details>
  <summary>Скриншот</summary>
  
  ![](/CTF6/4.png)
</details>

Перепишем в текстовый вид и запомним его: OUSRuRRHNCtyyvHMQq3G+9QCE0z+tuHB/bWq8EZG3YGg/4H1uflzq1NzT2faKtMy

Также при нажатии на значок вверху появляется текстовое сообщение о том, что произошла ошибка и нужно посмотреть логи.
<details>
  <summary>Скриншот</summary>
  
  ![](/CTF6/5.png)
</details>

Так и сделаем. Откроем logcat командой "adb logcat" и снова нажмём на иконку. В итоге в логах видим следующее (убрал лишние справочные данные, такие как id процесса, дату и время).

```txt
test1   : Hydrogen
test2   : Helium
test3   : Deuterium
test4   : Tritium
test5   : Neonkryptonite
test6   : Nitrogenkryptonite
test7   : Carbon monoxide
test8   : Fluorine
test9   : Argon
test10  : Oxygen
test11  : Methane
test12  : Kyrpt... Error found when processing current gas element...
test12 (re-testing...): KrYp70N1t3_k1LLz_$uPerM4N&H4ck3R
test13  : Nitric Oxyde
test14  : Fluorine monoxide
test15  : Silane
test16  : Ozone
test17  : Xenon
test18  : Ethylene
test19  : Phosphorus
test20  : Diborane
test21  : Acetylene
test22  : Ethane
```

В логах можно увидеть в строке с повторением test12 интересный текст, который нам вероятно пригодится "KrYp70N1t3_k1LLz_$uPerM4N&H4ck3R".

На самом деле данную строку также можно было обнаружить внутри apk файла, так как текст справа от двоеточия находится в строковых ресурсах приложения, так как код логгирования лежит в Активити H1dD3N в методе onClick класса 'a', вызывающийся при нажатии на картинку.
<details>
  <summary>Код класса H1dD3N</summary>

```java
public class H1dD3N extends h {

    /* loaded from: classes.dex */
    public class a implements View.OnClickListener {
        public a() {
        }

        @Override // android.view.View.OnClickListener
        public void onClick(View view) {
            c.a.a.a.a.f(H1dD3N.this, R.string.a1, "test1");
            c.a.a.a.a.f(H1dD3N.this, R.string.a2, "test2");
            c.a.a.a.a.f(H1dD3N.this, R.string.a3, "test3");
            c.a.a.a.a.f(H1dD3N.this, R.string.a4, "test4");
            c.a.a.a.a.f(H1dD3N.this, R.string.b1, "test5");
            c.a.a.a.a.f(H1dD3N.this, R.string.b2, "test6");
            c.a.a.a.a.f(H1dD3N.this, R.string.b3, "test7");
            c.a.a.a.a.f(H1dD3N.this, R.string.c1, "test8");
            c.a.a.a.a.f(H1dD3N.this, R.string.c2, "test9");
            c.a.a.a.a.f(H1dD3N.this, R.string.c3, "test10");
            c.a.a.a.a.f(H1dD3N.this, R.string.c4, "test11");
            c.a.a.a.a.f(H1dD3N.this, R.string.c5, "test12");
            c.a.a.a.a.f(H1dD3N.this, R.string.c6, "test12 (re-testing...)");
            c.a.a.a.a.f(H1dD3N.this, R.string.d1, "test13");
            c.a.a.a.a.f(H1dD3N.this, R.string.d2, "test14");
            c.a.a.a.a.f(H1dD3N.this, R.string.d3, "test15");
            c.a.a.a.a.f(H1dD3N.this, R.string.d4, "test16");
            c.a.a.a.a.f(H1dD3N.this, R.string.d5, "test17");
            c.a.a.a.a.f(H1dD3N.this, R.string.e1, "test18");
            c.a.a.a.a.f(H1dD3N.this, R.string.e2, "test19");
            c.a.a.a.a.f(H1dD3N.this, R.string.e3, "test20");
            c.a.a.a.a.f(H1dD3N.this, R.string.e4, "test21");
            c.a.a.a.a.f(H1dD3N.this, R.string.e5, "test22");
            Toast.makeText(H1dD3N.this.getApplicationContext(), "An error occurred. Check the logs for more information.", 0).show();
        }
    }

    @Override // b.b.c.h, b.k.a.e, androidx.activity.ComponentActivity, b.h.b.g, android.app.Activity
    public void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        setContentView(R.layout.activity_h1d_d3_n);
        ((ImageButton) findViewById(R.id.Krypton)).setOnClickListener(new a());
    }
}
```

</details>

Последняя найденная строка содержит 32 символа, что подходит для использования её в качестве ключа. Можно попробовать взять данные из БД, этот ключ и дешифровать их.

Первая строка "XAc860TQ62HaVTjOGV5egywXXWS0hUc6yOR/0eu5aQM=" превращается в "Pl4N37_kRYp70N_X-P70d3d", что похоже на осмысленный текст, значит идём в верном направлении.
<details>
  <summary>Скриншот</summary>
  
  ![](/CTF6/6.png)
</details>

Вторая строка "bq3G0iIKEKfb4bJcqvpsziaHZLEsEZfzxRY21d9yV3g=" превращается в "(%)KrYpT0NyT3_4_L1F3~".
<details>
  <summary>Скриншот</summary>
  
  ![](/CTF6/7.png)
</details>

Третья строка "vEpr9q0DVMSbe7pDyqz7TtjWEhxZZ03uDcksStPArvo=" превращается в "#36kRyPtoN_GaZ_4_LuNCH?@".
<details>
  <summary>Скриншот</summary>
  
  ![](/CTF6/8.png)
</details>

Первая строка длиной 23 символа, вторая - 21, третья - 24. Третья из-за длины похожа на ключ. У нас есть ещё одна найденная строка, которую нашли в скрытой Активити и её можно попробовать дешифровать.

Введём длинную строку с картинки в качестве сообщени в первое поле ввода, во второе поле ввода введём третью дешифрованную строку длиной 24 символа, нажмём вторую кнопку для дешифрования и получаем флаг в поле результата.
<details>
  <summary>Скриншот</summary>
  
  ![](/CTF6/9.png)
</details>

Флаг получен: Mystiko{AES_Krypt0nite_f0r_pr1v8_L1f3}

Задача решена.
