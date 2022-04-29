# CTF \#1

- [Задача](#Задача)
- [Решение](#Решение)

## [Задача](https://github.com/rednaga/training/tree/master/DEFCON23/challenges/defensive/crackmes/garage4hackers)

Имеется два приложения: GETSECRET.apk и SENDSECRET.apk.
Первоначально нужно открыть первое приложение и далее после некоторых манипуляций откроется второе приложение, которое передаёт секрет обратно первому приложению. Благодаря этому секрету следует получить флаг.

## Решение

Для начала установим и откроем приложение GETSECRET в эмуляторе.
На экране можно увидеть поле для ввода и кнопку, после ввода "123" и нажатия кнопки видим сообщение, которое говорит о том, что введённый код неверный.

<details>
  <summary>Скриншот</summary>
  
  ![](/CTF1/1.png)
</details>

Установим и откроем второе приложение SENDSECRET. После запуска видим экран без каких-либо элементов, только надпись, желающая удачи. Также можно заметить появляющееся сообщение "Received Token: 0", по которому можно сделать вывод, что данное приложение должно действительно запускаться с Интентом, содержащим числовой токен, как и написано в задаче.
<details>
  <summary>Скриншот</summary>

  ![](/CTF1/2.png)
</details>

В обоих приложениях есть меню (кнопка из трёх точек в правом верхнем углу экрана), однако оно несёт какой-либо информации для решения задачи, позже в этом убедимся.

Следующим этапом является декомпиляция apk файлов. Для этого откроем оба apk файла с помощью jadx-gui.

Для начала рассмотрим GETSECRET.
В манифесте можно обнаружить 3 Активити.

```xml
<application android:theme="@style/AppTheme" android:label="@string/app_name" android:icon="@drawable/ic_launcher" android:allowBackup="false">
    <activity android:label="@string/app_name" android:name="opensecurity.getsecret.LoginActivity">
        <intent-filter>
            <action android:name="android.intent.action.MAIN"/>
            <category android:name="android.intent.category.LAUNCHER"/>
        </intent-filter>
    </activity>
    <activity android:label="@string/title_activity_ask_secret" android:name="opensecurity.getsecret.AskSecret">
        <intent-filter>
            <action android:name="opensecurity.getsecret.AskSecret"/>
            <category android:name="android.intent.category.DEFAULT"/>
        </intent-filter>
    </activity>
    <activity android:label="@string/title_activity_get_flag" android:name="opensecurity.getsecret.GetFlag">
        <intent-filter>
            <action android:name="opensecurity.getsecret.GetFlag"/>
            <category android:name="android.intent.category.DEFAULT"/>
        </intent-filter>
    </activity>
</application>
```

Также можно увидеть эти 3 класса в дереве файлов.
<details>
  <summary>Скриншот</summary>
  
  ![](/CTF1/3.png)
</details>

Стартовая Активити - LoginActivity, в которую нужно ввести правильный код, для дальнейшей работы, поэтому рассмотрим её детальнее.

В методе onCreate обнаруживаем следующие две строки.

```java
this.f1439 = (Button) findViewById(R.id.button);
this.f1439.setOnClickListener(new View$OnClickListenerC0406(this));
```

Это просто нахождение кнопки по id и подключение к ней обработчика нажатия, который нам интересен. Поэтому переходим в класс обработчика.

Класс обработчика это простая реализация интерфейса View.OnClickListener, чего и следовало ожидать. Сразу находим метод onClick, который обязательно должен быть реализован.

```java
@Override // android.view.View.OnClickListener
public void onClick(View view) {
    String obj = this.f1387.f1438.getText().toString(); // 1
    byte b = f1385[4];
    if (obj.equals(m1893(b, b, b).intern())) { // 2
        Toast.makeText(this.f1387.getApplicationContext(), "Oh Boy! That escalated quickly.", 0).show();
        this.f1387.startActivity(new Intent(this.f1387, AskSecret.class)); // 3
        return;
    }
    Toast.makeText(this.f1387.getApplicationContext(), "Oh Boy! You missed it by an inch.", 0).show(); // 4
}
```

Вот здесь действительно интересные вещи происходят. Обозначил их цифрами.
1 - Как можно догадаться, это взятие текста из поля ввода.
2 - Сравнение этого текста с результатом метода m1893
3 - При успешном сравнении открывается Активити AskSecret, находящаяся в этом приложении.
4 - При неудачном сравнении показывает сообщение с представленным текстом, который мы уже видели.

Для того, чтобы попасть на следующий экран, нужно получить код, следовательно нужно его достать из метода m1893. Можно использовать Frida, однако у меня возникли трудности с нахождением методов, так как они называются очень странными символами. Благо, можно пойти другим способом.

Как можно увидеть, для запуска метода используется некое число из массива f1385.

```java
byte b = f1385[4];
if (obj.equals(m1893(b, b, b).intern())) {
```

Массив выглядит следующим образом:

```java
private static final byte[] f1385 = {106, 115, 110, 51, 0, 2, -2};
```

<details>
  <summary>Метод m1893</summary>
  
```java
private static String m1893(int i, int i2, int i3) {
    int i4 = 4 - (i * 3);
    int i5 = 4 - (i2 * 3);
    int i6 = 0;
    int i7 = (i3 * 4) + 49;
    byte[] bArr = f1385;
    byte[] bArr2 = new byte[i5];
    int i8 = i5 - 1;
    if (bArr == null) {
        i4++;
        i7 = i7 + (-i8) + 2;
    }
    while (true) {
        bArr2[i6] = (byte) i7;
        if (i6 == i8) {
            return new String(bArr2, 0);
        }
        int i9 = i7;
        byte b = bArr[i4];
        i6++;
        i4++;
        i7 = i9 + (-b) + 2;
    }
}
```

</details>

Так как поле с массивом приватное, значит к нему не должны иметь доступ извне. Это можно подтвердить командой Find Usage. Проверяем это, чтобы определить, мог ли кто-либо поменять элементы массива, чтобы реверсить было сложнее.
<details>
  <summary>Скриншоты</summary>

  ![](/CTF1/4.png)
  ![](/CTF1/5.png)
</details>

Тоже самое верно и для метода m1893.
<details>
  <summary>Скриншот</summary>
  
  ![](/CTF1/6.png)
</details>

Массив используется также и внутри метода m1893. Но не изменяется, что важно, так как в ином случае может потребоваться повторный вызов метода для получения необходимого значения.

Для получения нужной строки воспользуемся Android Studio, создадим проект, создадим **обычный** класс LoginActivity и скопируем туда массив f1385 и метод m1893 из jadx-gui. Также создадим публичный статический метод call, который будет повторять оригинальный вызов метода m1893 и возвращать полученную строку. Этот метод вызовем в MainActivity (запускаемая Activity) и записывать результат в лог.

<details>
  <summary>Код класса LoginActivity</summary>
  
```java
public class LoginActivity {

    public static String call() {
        byte b = f1385[4];
        return m1893(b, b, b);
    }

    private static final byte[] f1385 = {106, 115, 110, 51, 0, 2, -2};

    /* renamed from: ˊ  reason: contains not printable characters */
    private static String m1893(int i, int i2, int i3) {
        int i4 = 4 - (i * 3);
        int i5 = 4 - (i2 * 3);
        int i6 = 0;
        int i7 = (i3 * 4) + 49;
        byte[] bArr = f1385;
        byte[] bArr2 = new byte[i5];
        int i8 = i5 - 1;
        if (bArr == null) {
            i4++;
            i7 = i7 + (-i8) + 2;
        }
        while (true) {
            bArr2[i6] = (byte) i7;
            if (i6 == i8) {
                return new String(bArr2, 0);
            }
            int i9 = i7;
            byte b = bArr[i4];
            i6++;
            i4++;
            i7 = i9 + (-b) + 2;
        }
    }
}
```

</details>

Вызов метода call в MainActivity будет находится в onCreate и выглядеть так:

```java
Log.d("MainActivity", "LoginActivity secret: " + LoginActivity.call());
```

Запускаем приложение и получаем в logcat сообщение такого вида:<br> D/MainActivity: LoginActivity secret: 1337

Секрет: 1337. Попробуем ввести его и посмотреть, что будет дальше.

Ожидаемо открывается новая Активити и мы получаем сообщение об успешном сравнении, которое видели ранее в коде.
<details>
  <summary>Скриншот</summary>
  
  ![1](/CTF1/7.png)
</details>

На этом экране две кнопки. Нижняя кнопка HINT ведёт на сайт, который сейчас отдаёт статус 404. Верхняя кнопка "GET SECRET" открывает приложение SENDSECRET и передаёт туда код, который меняется при каждом нажатии.
<details>
  <summary>Скриншот</summary>
  
  ![](/CTF1/8.png)
</details>

Открытая Активити после ввода кода называется AskSecret. Нужно найти, почему именно код отправляемый в другое приложение разный.
Таким же образом, как и раньше, находим в onCreate findViewById, далее обработчик. Здесь две кнопки, поэтому нужно посмотреть обработчик каждой кнопки.

```java
public void onCreate(Bundle bundle) {
    super.onCreate(bundle);
    setContentView(R.layout.activity_ask_secret);
    this.f1433 = (Button) findViewById(R.id.button2);
    this.f1434 = (Button) findViewById(R.id.button3);
    this.f1433.setOnClickListener(new View$OnClickListenerC0371(this));
    this.f1434.setOnClickListener(new View$OnClickListenerC0372(this));
}
```

Обработчик кнопки с id button2:

```java
@Override // android.view.View.OnClickListener
public void onClick(View view) {
    int nextInt = new Random().nextInt(19) + 80;
    Intent intent = new Intent();
    intent.setComponent(new ComponentName("opensecurity.sendsecret", "opensecurity.sendsecret.ValidateAccess"));
    intent.putExtra("token", nextInt);
    this.f1352.startActivity(intent);
}
```

Обработчик кнопки с id button3:

```java
@Override // android.view.View.OnClickListener
public void onClick(View view) {
    this.f1353.startActivity(new Intent("android.intent.action.VIEW", Uri.parse("http://opensecurity.in/labz/g4hctf_hints.txt")));
}
```

Обработчик кнопки button3 просто открывает ссылку.
А вот обработчик кнопки button2 более интересный.
В первой строке генерируется случайное значение, всего вариантов 19.
Во сторой создаётся Intent. Далее указывается компонент - открываемая Активити ValidateAccess приложения SENDSECRET, добавляется случайное число по ключу token, после чего отправляется данный Интент для запуска Активити.

Можно сделать вывод, что необходимо много раз нажать на кнопку, чтобы угадать случайное число. Сделаем это чуть позже, а пока посмотрим второе приложение в jadx-gui.

Сразу посмотрим Android Manifest. Можно увидеть, что там всего 2 Активити.

```xml
<application android:theme="@style/AppTheme" android:label="@string/app_name" android:icon="@drawable/ic_launcher" android:allowBackup="false">
    <activity android:label="@string/app_name" android:name="opensecurity.sendsecret.ValidateAccess" android:exported="true">
        <intent-filter>
            <action android:name="android.intent.action.MAIN"/>
            <category android:name="android.intent.category.LAUNCHER"/>
        </intent-filter>
    </activity>
    <activity android:label="@string/title_activity_send_secret" android:name="o.ActivityC0371"/>
</application>
```

Видим Активити с именем ValidateAccess, которая как раз и открывается из первого приложения, а также имеет intent-filter, показывающий, что эта же Активити открывается по нажатию на значок в списке приложений.

Посмотрим код класса ValidateAccess. Сразу видим в методе onCreate случайную генерацию числа, получение токена по соответствующем ключу и сравнение обоих, при удачно сравнении создаётся Intent для запуска ActivityC0371, в который кладётся результат вызова метода m1948 по ключу VIEW_TOKEN.

```java
int i3 = f1429[12] + 1;
m1948(i3, i3, i3).intern();
int nextInt = new Random().nextInt(19) + 80;
int intExtra = getIntent().getIntExtra("token", 0);
Toast.makeText(getApplicationContext(), "Received Token: " + intExtra, 0).show();
if (intExtra == nextInt) {
    Intent intent = new Intent(this, ActivityC0371.class);
    int i4 = f1429[12] + 1;
    intent.putExtra("VIEW_TOKEN", m1948(i4, i4, i4).intern());
    startActivity(intent);
}
```

В общем код похож на то, что мы уже видели, за исключением угадывания числа. Есть массив f1429, есть метод m1948, результат которого используется для запуска Активити.

Массив:

```java
private static final byte[] f1429 = {28, -117, 87, 105, 9, -3, 17, 13, -6, 6, 26, 5, -1, 19, 13, -67, 67, 13, -53, 9, 9, 9, 9, 9, 9, -14, 39, -21, 9, 9, 65};
```

<details>
  <summary>Метод m1948</summary>
  
```java
private static String m1948(int i, int i2, int i3) {
    int i4 = 111 - (i2 * 2);
    int i5 = (i * 2) + 28;
    int i6 = (i3 * 2) + 4;
    int i7 = -1;
    byte[] bArr = f1429;
    byte[] bArr2 = new byte[i5];
    int i8 = i5 - 1;
    if (bArr == null) {
        i4 = (i4 + i6) - 8;
        i6++;
    }
    while (true) {
        i7++;
        bArr2[i7] = (byte) i4;
        if (i7 == i8) {
            return new String(bArr2, 0);
        }
        i4 = (i4 + bArr[i6]) - 8;
        i6++;
    }
}
```

</details>

В этом случае не требуется подбирать значение, которое выдаёт метод, так как нужно просто угадать число. Поэтому посмотрим открываемую Активити - ActivityC0371.

Сразу обращаем внимание на метод onCreate. В нём видим получение значения по ключу VIEW_TOKEN из Интента, которое кладётся туда при вызове этой Активити. Оно сравнивается с результатом вызова другого метода и в случае успеха показывается сообщение, далее создаётся Интент, указывается компонент - Активити GetFlag приложения GETSECRET, после чего кладётся по ключу TOPSECRET результат метода m1797. После чего вызывается метод startActivity для запуска.

```java
public void onCreate(Bundle bundle) {
    super.onCreate(bundle);
    setContentView(R.layout.activity_send_secret);
    String stringExtra = getIntent().getStringExtra("VIEW_TOKEN");
    byte b = f1352[4];
    if (stringExtra.equals(m1797(b, b - 1, f1352[4]).intern())) {
        Toast.makeText(getApplicationContext(), "Sending Secret Token....", 0).show();
        Intent intent = new Intent();
        intent.setFlags(268435456);
        intent.setComponent(new ComponentName("opensecurity.getsecret", "opensecurity.getsecret.GetFlag"));
        byte b2 = f1352[4];
        intent.putExtra("TOPSECRET", m1797(f1352[4] - 1, b2, b2 - 1).intern());
        startActivity(intent);
    }
}
```

Перейдём в Активити GetFlag в jadx-gui и посмотрим, что происходит со значением TOPSECRET. Можно увидеть, что со значением ничего не происходит, но говорящее название заставляет думать, что значение пригодится.

```java
public void onCreate(Bundle bundle) {
    super.onCreate(bundle);
    setContentView(R.layout.activity_get_flag2);
    getIntent().getStringExtra("TOPSECRET");
    this.f1435 = (Button) findViewById(R.id.button4);
    this.f1436 = (EditText) findViewById(R.id.editText2);
    this.f1437 = (TextView) findViewById(R.id.textView2);
    this.f1435.setOnClickListener(new View$OnClickListenerC0403(this));
}
```

Поэтому по такой же технологии, как было с LoginActivity, сделаем новый класс, скопируем массив f1352 и метод m1797 из ActivityC0371.
Создадим класс ActivityC0371, скопируем массив и метод, создадим метод call для повторения вызова этого метода.

<details>
  <summary>Код класса ActivityC0371</summary>
  
```java
public class ActivityC0371 {

    public static String call() {
        byte b = f1352[4];
        m1797(b, b - 1, f1352[4]);
        byte b2 = f1352[4];
        return m1797(f1352[4] - 1, b2, b2 - 1);
    }

    private static final byte[] f1352 = {103, -21, 11, -27, 1, -11, 9, 5, -14, -2, 18, -3, -9, 11, 5, -75, 59, 5, -61, 1, 1, 1, 1, 1, 1, -22, 31, -29, 1, 1, 57, -51, 52, -59, 74, -18, -3, 1, -2, 18, 1, -71, 75, -22, -50, 74};

    private static String m1797(int i, int i2, int i3) {
        byte[] bArr = f1352;
        int i4 = (i3 * 8) + 103;
        int i5 = 30 - (i * 27);
        int i6 = 28 - (i2 * 12);
        int i7 = 0;
        byte[] bArr2 = new byte[i6];
        int i8 = i6 - 1;
        if (bArr == null) {
            i4 = i8 + i5;
        }
        while (true) {
            i5++;
            bArr2[i7] = (byte) i4;
            int i9 = i7;
            i7++;
            if (i9 == i8) {
                return new String(bArr2, 0);
            }
            i4 += bArr[i5];
        }
    }
}
```

</details>

Вызов метода call в MainActivity будет находится в onCreate и выглядеть так:

```java
Log.d("MainActivity", "ActivityC0371 secret: " + ActivityC0371.call());
```

Запускаем тестовое приложение и получаем в logcat сообщение такого вида:<br> D/D/MainActivity: ActivityC0371 secret: g4h-webcast-xb0z

Рассмотрим Активити GetFlag подробнее.
В onCreate можно заметить один обработчик нажатия, перейдём к нему.
Это тоже стандартный обработчик, реализующий View.OnClickListener и метод onClick. Сам класс принимает в конструкторе объект класса GetFlag.

<details>
  <summary>Код метода onClick</summary>
  
```java
@Override // android.view.View.OnClickListener
public void onClick(View view) {
    try {
        String str = this.f1375.m1948("q7jwHCFy7ADGQ+ol3V9k225uOOi21J6n8Q974DNoPi6uy+ushhg/L/MVVCdr8393RhbTYs/jP7eDvTEUJUucpg==", this.f1375.f1436.getText().toString());
        this.f1375.f1437.setText(str);
        Log.v("FLAG", str);
    } catch (Exception e) {
        Toast.makeText(this.f1375.getApplicationContext(), "Wrong Secret", 0).show();
    }
}
```

</details>

Здесь можно увидеть вызов метода m1948, который находится в GetFlag, а также поле f1436, которое является объектом EditText, из которого достаётся введённый текст и отправляется в m1948 вторым аргументом.
Рассмотрим m1948 получше.
Код метода:

```java
/* renamed from: ˊ  reason: contains not printable characters */
public String m1948(String str, String str2) {
    try {
        SecretKeySpec secretKeySpec = new SecretKeySpec(str2.getBytes(), "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(2, secretKeySpec);
        return new String(cipher.doFinal(Base64.decode(str, 0)), "UTF-8");
    } catch (Exception e) {
        return null;
    }
}
```

Первый параметр str, который записан в коде вызова этого метода, используется как текст, который расшифровывается.
Второй параметр str2, является ключом алгоритма AES. Подобрать ключ каким-либо алгоритмом аля брутфорс нам не подходит, если это вообще возможно. Поэтому попробуем скопировать метод m1948 и его вызов в тестовое приложение.

Для этого создадим класс GetFlag, добавим метод m1948, сделаем его статическим, импортируем необходимые зависимости, создадим метод call, который будет принимать один аргумент - строку для создания ключа.

<details>
  <summary>Код класса GetFlag</summary>
  
```java
import android.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class GetFlag {
    public static String call(String str2) {
        return m1948("q7jwHCFy7ADGQ+ol3V9k225uOOi21J6n8Q974DNoPi6uy+ushhg/L/MVVCdr8393RhbTYs/jP7eDvTEUJUucpg==", str2);
    }

    private static String m1948(String str, String str2) {
        try {
            SecretKeySpec secretKeySpec = new SecretKeySpec(str2.getBytes(), "AES");
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(2, secretKeySpec);
            return new String(cipher.doFinal(Base64.decode(str, 0)), "UTF-8");
        } catch (Exception e) {
            return null;
        }
    }
}
```

</details>

Для вызова метода GetFlag.call используем полученный ранее секрет из ActivityC0371.

```java
Log.d("MainActivity", "GetFlag secret: " + GetFlag.call("g4h-webcast-xb0z"));
```

Запустим приложение и посмотрим, что выведется в логах.
В логах получаем следующее:<br>
D/MainActivity: GetFlag secret: Flag is {Do not go gentle into that good night -xboz}

Ура, флаг получен.

Полученный флаг: {Do not go gentle into that good night -xboz}

В итоге, практически не запуская приложения, нашли флаг благодаря декомпилированному коду и его запуску в тестовом приложении.
