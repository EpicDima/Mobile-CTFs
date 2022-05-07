# CTF \#5

- [Задача](#Задача)
- [Решение](#Решение)

## [Задача](https://github.com/tlamb96/kgb_messenger)

В приложении имеется три флага, которые нужно найти, взаимодействуя с ним.

## Решение

Установим приложение и откроем его.
<details>
  <summary>Скриншот</summary>
  
  ![](/CTF5/1.png)
</details>

Появляется диалог с информацией о том, что устройство не русское. Обойти диалог без каких-либо средств нельзя, поэтому откроем файл приложения в jadx-gui.

Сразу взглянем на Android Manifest, который содержит три Активити, которые вероятно будут содержать в том или ином виде один из трёх флагов.

```xml
<application android:theme="@style/AppTheme" android:label="@string/app_name" android:icon="@mipmap/ic_kgb_launcher_icon" android:allowBackup="true" android:supportsRtl="true" android:roundIcon="@mipmap/ic_kgb_launcher_icon">
    <activity android:name="com.tlamb96.kgbmessenger.MainActivity">
        <intent-filter>
            <action android:name="android.intent.action.MAIN"/>
            <category android:name="android.intent.category.LAUNCHER"/>
        </intent-filter>
    </activity>
    <activity android:name="com.tlamb96.kgbmessenger.MessengerActivity"/>
    <activity android:name="com.tlamb96.kgbmessenger.LoginActivity"/>
    <meta-data android:name="android.support.VERSION" android:value="25.4.0"/>
</application>
```

Откроем запускаемую Активити - MainActivity. Обратим внимание на основной метод onCreate и увидим, что там происходит проверка системных свойств и в случае не совпадения с ожидаемыми вызывается метод 'a', который открывает диалог, а при нажатии на кнопку закрывает Активити методом finish.

Метод onCreate.

```java
@Override // android.support.v7.app.c, android.support.v4.b.l, android.support.v4.b.h, android.app.Activity
public void onCreate(Bundle bundle) {
    super.onCreate(bundle);
    setContentView(R.layout.activity_main);
    String property = System.getProperty("user.home");
    String str = System.getenv("USER");
    if (property == null || property.isEmpty() || !property.equals("Russia")) {
        a("Integrity Error", "This app can only run on Russian devices.");
    } else if (str == null || str.isEmpty() || !str.equals(getResources().getString(R.string.User))) {
        a("Integrity Error", "Must be on the user whitelist.");
    } else {
        a.a(this);
        startActivity(new Intent(this, LoginActivity.class));
    }
}
```

Метод 'a'.

```java
private void a(String str, String str2) {
    b b = new b.a(this).b();
    b.setTitle(str);
    b.a(str2);
    b.setCancelable(false);
    b.a(-3, "EXIT", new DialogInterface.OnClickListener() { // from class: com.tlamb96.kgbmessenger.MainActivity.1
        @Override // android.content.DialogInterface.OnClickListener
        public void onClick(DialogInterface dialogInterface, int i) {
            dialogInterface.dismiss();
            MainActivity.this.finish();
        }
    });
    b.show();
    LinearLayout linearLayout = (LinearLayout) b.a(-3).getParent();
    linearLayout.setGravity(1);
    linearLayout.getChildAt(1).setVisibility(8);
}
```

Можно изменить значения, которые приложение получает из системных свойств. Для этого воспользуемся frida.

Первое значение, которое сравнивается со строкой "Russia" получается по ключу "user.home", значит заменим возвращаемое значения при вызове с этим ключом на необходимое.

Второе значение, получается из системного окружения по ключу "USER", который сравнивается со строкой из ресурсов. Поэтому найдём строку по id "R.string.User". Значение равно "RkxBR3s1N0VSTDFOR180UkNIM1J9Cg==".

Сделаем скрипт, который будет подменять вызовы системных методов.

```javascript
Java.perform(function () {
    const System = Java.use("java.lang.System");

    System.getProperty.overload("java.lang.String").implementation = function (key) {
        if (key == "user.home") {
            console.log("Substitution by the \"user.home\" key");
            return "Russia";
        } else {
            return System.getProperty(key);
        }
    };

    System.getenv.overload("java.lang.String").implementation = function (key) {
        if (key == "USER") {
            console.log("Substitution by the \"USER\" key");
            return "RkxBR3s1N0VSTDFOR180UkNIM1J9Cg==";
        } else {
            return System.getenv(key);
        }
    };
});
```

После запуска со скриптом диалоговое окно не появляется и открывается другая Activity - LoginActivity (это можно увидеть в коде в ветке else в onCreate).
В консоли получим вывод в консоль.

```txt
[*] Running Script
Substitution by the "user.home" key
Substitution by the "USER" key
```

<details>
  <summary>Скриншот</summary>
  
  ![](/CTF5/2.png)
</details>

Значение для ключа "USER" похоже на строку, которая закодирована в base64, поэтому воспользуемся онлайн декодером и узнаем настоящее значение.
Получаем первый флаг: FLAG{57ERL1NG_4RCH3R}

При вводе логина "123" и пароля "123" появляется сообщение о том, что юзер не распознан.
<details>
  <summary>Скриншот</summary>
  
  ![](/CTF5/3.png)
</details>

Данная строка есть в методе onLogin.

```java
public void onLogin(View view) {
    EditText editText = (EditText) findViewById(R.id.login_username);
    EditText editText2 = (EditText) findViewById(R.id.login_password);
    this.n = editText.getText().toString();
    this.o = editText2.getText().toString();
    if (this.n != null && this.o != null && !this.n.isEmpty() && !this.o.isEmpty()) {
        if (!this.n.equals(getResources().getString(R.string.username))) {
            Toast.makeText(this, "User not recognized.", 0).show();
            editText.setText("");
            editText2.setText("");
        } else if (!j()) {
            Toast.makeText(this, "Incorrect password.", 0).show();
            editText.setText("");
            editText2.setText("");
        } else {
            i();
            startActivity(new Intent(this, MessengerActivity.class));
        }
    }
}
```

Посмотрим на метод чуть лучше. Можно увидеть, что сообщение появляется при неудачном сравнении введённого логина и строки, которая лежит в ресурсах по идентификатору "R.string.username". Этой строкой является "codenameduchess".

Введём данный логин в приложение. Пароль, как и раньше, используем 123. При нажатии кнопки появляется сообщение о неверном пароле, чего и следовало ожидать.
<details>
  <summary>Скриншот</summary>
  
  ![](/CTF5/4.png)
</details>

Для определения корретности пароля используется метод 'j', который из строки 'o', являющейся введённым паролем, высчитывает MD5 хэш и далее сравнивает со строкой по id "R.string.password". Строка равна этому значению "84e343a0486ff05530df6c705c8bb4".

```java
private boolean j() {
    byte[] digest;
    String str = "";
    for (int i = 0; i < this.m.digest(this.o.getBytes()).length; i++) {
        str = str + String.format("%x", Byte.valueOf(digest[i]));
    }
    return str.equals(getResources().getString(R.string.password));
}
```

После нескольких попыток подобрать строку с таким же хэшем на онлайн ресурсах ничего не нашлось. Поэтому снова обратил внимание на логин, который выглядит как какие-то слова и просто загуглил. Оказывается это какой-то персонаж с описанием, что он лучший шпион в мире. Попробуем загуглить такую строку "codenameduchess password". Первой ссылкой (может быть и не первой, естественно) находится pdf файл с записью диалога, поиск по тексту по слову "password" перекидывает к моменту, где говорят пароль. Паролем является строка "Guest." Но благодаря подсказке из описания задачи, понятно, что пароль содержит только символы в нижнем регистре.
<details>
  <summary>Скриншот</summary>
  
  ![](/CTF5/5.png)
</details>

Введём "guest." в качестве пароля, логин уже известен. Но пароль снова не подходит...

Введём "guest", точку отбросим и вуаля, открывается новый экран с мессенджером, а внизу экрана появляется сообщение с флагом, который мы ищем.
<details>
  <summary>Скриншот</summary>
  
  ![](/CTF5/6.png)
</details>

Флаг номер 2: FLAG{G00G13_PR0}

В мессенджере есть поле ввода, поэтому введём 123 и отправим. К сожалению никакой реакции не произошло. Поэтому нужно лезть в код и понять, что приложение ожидает.

Откроем третью Activity - MessengerActivity. После краткого осмотра класса в глаза бросается метод с говорящим названием - onSendMessage. Судя по всему он вызывается при нажатии на кнопку отправки и в нём есть два условия, в которых вызываются методы 'a' и 'b' и сравниваются с переменными 'p' и 'r'.

```java
public void onSendMessage(View view) {
    EditText editText = (EditText) findViewById(R.id.edittext_chatbox);
    String obj = editText.getText().toString();
    if (!TextUtils.isEmpty(obj)) {
        this.o.add(new com.tlamb96.kgbmessenger.b.a(R.string.user, obj, j(), false));
        this.n.c();
        if (a(obj.toString()).equals(this.p)) {
            Log.d("MessengerActivity", "Successfully asked Boris for the password.");
            this.q = obj.toString();
            this.o.add(new com.tlamb96.kgbmessenger.b.a(R.string.boris, "Only if you ask nicely", j(), true));
            this.n.c();
        }
        if (b(obj.toString()).equals(this.r)) {
            Log.d("MessengerActivity", "Successfully asked Boris nicely for the password.");
            this.s = obj.toString();
            this.o.add(new com.tlamb96.kgbmessenger.b.a(R.string.boris, "Wow, no one has ever been so nice to me! Here you go friend: FLAG{" + i() + "}", j(), true));
            this.n.c();
        }
        this.m.b(this.m.getAdapter().a() - 1);
        editText.setText("");
    }
}
```

Пойдём по порядку и посмотрим на метод 'a' и поле 'p'. В методе происходит реверс строки, что можно легко увидеть по тому, что цикл идёт лишь до половины от всего размера, а также, что происходит обмен значениями массива по индексу 'i' и по индексу 'длина массива - i - 1'. Также есть две операции XOR. Так как XOR и переворот строки операции, которые работают одинаково в обе стороны.

```java
private String p = "V@]EAASB\u0012WZF\u0012e,a$7(&am2(3.\u0003";

private String a(String str) {
    char[] charArray = str.toCharArray();
    for (int i = 0; i < charArray.length / 2; i++) {
        char c = charArray[i];
        charArray[i] = (char) (charArray[(charArray.length - i) - 1] ^ '2');
        charArray[(charArray.length - i) - 1] = (char) (c ^ 'A');
    }
    return new String(charArray);
}
```

Сделаем в тестовом приложении класс KgbMessengerFirst, в который скопируем этот метод и вызовем его со строкой из поля 'p', которую также скопируем. Сделаем метод и поле статическими для удобства. Добавим также метод call, который будет содержать сам процесс вызова метода с нужными параметрами.

<details>
  <summary>Класс KgbMessengerFirst</summary>
  
```java
public class KgbMessengerFirst {

    private static final String p = "V@]EAASB\u0012WZF\u0012e,a$7(&am2(3.\u0003";

    public static String call() {
        return a(p);
    }

    private static String a(String str) {
        char[] charArray = str.toCharArray();
        for (int i = 0; i < charArray.length / 2; i++) {
            char c = charArray[i];
            charArray[i] = (char) (charArray[(charArray.length - i) - 1] ^ 'A');
            charArray[(charArray.length - i) - 1] = (char) (c ^ '2');
        }
        return new String(charArray);
    }
}
```

</details>

Вызов метода call в MainActivity выглядит так.

```java
Log.d("KGB", "First string: " + KgbMessengerFirst.call());
```

После запуска в логах приложения можно обнаружить строку с расшифровкой.

```txt
D/KGB: First string: Boris, give me the password
```

Полученая строка "Boris, give me the password", попробуем её ввести в приложении. После отправки получаем ответ, что говорит о правильности сообщения.
<details>
  <summary>Скриншот</summary>
  
  ![](/CTF5/7.png)
</details>

Осталось второе условие, которое использует для валидации метод 'b' и строку из поля 'r'. Логика метода в этот раз сложнее. Здесь есть два цикла, первый цикл делает битовый сдвиг на 0-7 битов у символа, после чего проводит операцию XOR с оригинальным символом и записывает результат в массив. Второй цикл проще, он всего лишь делает реверс строки без какой-либо дополнительной логики.

```java
private String r = "\u0000dslp}oQ\u0000 dks$|M\u0000h +AYQg\u0000P*!M$gQ\u0000";

private String b(String str) {
    char[] charArray = str.toCharArray();
    for (int i = 0; i < charArray.length; i++) {
        charArray[i] = (char) ((charArray[i] >> (i % 8)) ^ charArray[i]);
    }
    for (int i2 = 0; i2 < charArray.length / 2; i2++) {
        char c = charArray[i2];
        charArray[i2] = charArray[(charArray.length - i2) - 1];
        charArray[(charArray.length - i2) - 1] = c;
    }
    return new String(charArray);
}
```

В этот раз способ, который сработал с первой строкой, не работает и получаем такой ответ в логах:

```txt
D/KGB: Second string: ��Qf%I% x��gP[E.(\��M}%tf}0��Qn~waoV��
```

Надо сделать метод, который будет подбирать символы, так как при сдвиге биты пропадают. Поэтому возьмём символы, которые могут, вероятно, находиться в строке - это будут английские буквы (нижнего и верхнего регистра), цифры, символы пунктуации, пробел, ещё немного частоиспользуемых символов. В итоге получаем поле с, так называемым, алфавитом.

```java
private static final String ABC = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~ ";
```

Для подбора будет использовать строку 'r'. Для начала развернём её, дальше будем проходить по каждому её элементу и подбирать символ из алфавита (то есть выполнять операцию сдвига и XOR), и в случае совпадения записывать в массив, который позже отобразим в логах в виде строки.

```java
public static String searchB() {
    // получаем массив символов из XOR-нутой строки
    char[] xoredCharArray = r.toCharArray();

    // разворачиваем её
    for (int i2 = 0; i2 < xoredCharArray.length / 2; i2++) {
        char c = xoredCharArray[i2];
        xoredCharArray[i2] = xoredCharArray[(xoredCharArray.length - i2) - 1];
        xoredCharArray[(xoredCharArray.length - i2) - 1] = c;
    }

    // создаём пустую строку размером со строкой, с которой сверяемся
    char[] result = new char[xoredCharArray.length];

    // идём по XOR-нутой строке
    for (int i = 0; i < xoredCharArray.length; i++) {
        // проходим по нашему списку символов из алфавита, цифр, знаков препинания и пробела
        for (char ch : ABC.toCharArray()) {
            // в случае совпадения записываем в результирующий массив исходный символ
            // индексы, кратные числу 8, игнорируем, так как на этих местах находится
            // двухбайтовый символ из нулевых битов, отображаемый как два непоказывающихся символв
            if (i % 8 != 0 && ((ch >> (i % 8)) ^ ch) == xoredCharArray[i]) {
                result[i] = ch;

                // выходим после нахождения первого символа
                // (в ходе тестирования метода, выявлено, что только
                // для кратных 8 индексов находится больше одного символа)
                break;
            }
        }
    }

    // возвращаем результат в виде строки
    return new String(result);
}
```

<details>
  <summary>Код класса KgbMessengerSecond</summary>
  
```java
public class KgbMessengerSecond {

    private static final String r = "\u0000dslp}oQ\u0000 dks$|M\u0000h +AYQg\u0000P*!M$gQ\u0000";

    private static final String ABC = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~ ";

    public static String[] call() {
        return new String[]{b(r), searchB(r)};
    }

    private static String b(String str) {
        char[] charArray = str.toCharArray();
        for (int i = 0; i < charArray.length; i++) {
            charArray[i] = (char) ((charArray[i] >> (i % 8)) ^ charArray[i]);
        }
        for (int i2 = 0; i2 < charArray.length / 2; i2++) {
            char c = charArray[i2];
            charArray[i2] = charArray[(charArray.length - i2) - 1];
            charArray[(charArray.length - i2) - 1] = c;
        }
        return new String(charArray);
    }

    public static String searchB(String str) {
        // получаем массив символов из XOR-нутой строки
        char[] xoredCharArray = str.toCharArray();

        // разворачиваем её
        for (int i2 = 0; i2 < xoredCharArray.length / 2; i2++) {
            char c = xoredCharArray[i2];
            xoredCharArray[i2] = xoredCharArray[(xoredCharArray.length - i2) - 1];
            xoredCharArray[(xoredCharArray.length - i2) - 1] = c;
        }

        // создаём пустую строку размером со строкой, с которой сверяемся
        char[] result = new char[xoredCharArray.length];

        // идём по XOR-нутой строке
        for (int i = 0; i < xoredCharArray.length; i++) {
            // проходим по нашему списку символов из алфавита, цифр, знаков препинания и пробела
            for (char ch : ABC.toCharArray()) {
                // в случае совпадения записываем в результирующий массив исходный символ
                // индексы, кратные числу 8, игнорируем, так как на этих местах находится
                // двухбайтовый символ из нулевых битов, отображаемый как два непоказывающихся символв
                if (i % 8 != 0 && ((ch >> (i % 8)) ^ ch) == xoredCharArray[i]) {
                    result[i] = ch;

                    // выходим после нахождения первого символа
                    // (в ходе тестирования метода, выявлено, что только
                    // для кратных 8 индексов находится больше одного символа)
                    break;
                }
            }
        }

        // возвращаем результат в виде строки
        return new String(result);
    }
}
```

</details>

Код вызова метода для нахождения второй строки в MainActivity и записи её в логи.

```java
Log.d("KGB", "Second string: " + KgbMessengerSecond.call()[0]);
Log.d("KGB", "Second string after search: " + KgbMessengerSecond.call()[1]);
```

Запустим приложение и в логах увидим следующее.

```txt
D/KGB: Second string after search: ��ay I *P��EASE* h��ve the ��assword��
```

Здесь каждые два таких символа '�' - это двухбайтный символ из нулевых битов, который можно увидеть в строке 'r' на позициях кратных 8 (после реверса позиции не изменяются). Поэтому надо заменить каждый такой кусочек "��" на один символ. Можно попробовать удалить просто один символ '�', а можно заменить на, например, 'a'. Оба варианта работают, так как при сдвиге на 7 бит, символ будет содержать только нулевые биты, без разницы, каким он был до этого и следовательно всё будет успешно сравниваться.
<details>
  <summary>Скриншот</summary>
  
  ![](/CTF5/8.png)
</details>

Однако, если посмотреть на эту строку, то можно легко увидеть английские слова, поэтому можно подставить по-настоящему правильные символы. В результате получится такая строка "May I *PLEASE* have the password?", которая также подходит.
<details>
  <summary>Скриншот</summary>
  
  ![](/CTF5/9.png)
</details>

После каждой успешной отправки второй строки, получаем сообщение, которое содержит флаг: FLAG{p455w0rd_P134SE}

Данный флаг нельзя было достать ранее, так как в коде приложения для его расчёта используются введённые нами строки, что легко можно увидеть из метода 'i' класса MessengerActivity, которые рассчитывает внутреннюю строку, которая содержится между фигурных скобок флага. Здесь 'q' - это правильно введённая первая строка, а 's' - правильно введённая вторая строка.

```java
private String i() {
    if (this.q == null || this.s == null) {
        return "Nice try but you're not that slick!";
    }
    char[] charArray = this.q.substring(19).toCharArray();
    charArray[1] = (char) (charArray[1] ^ 'U');
    charArray[2] = (char) (charArray[2] ^ 'F');
    charArray[3] = (char) (charArray[3] ^ 'F');
    charArray[5] = (char) (charArray[5] ^ '_');
    Log.i("MessengerActivity", "flag: " + new String(charArray));
    char[] charArray2 = this.s.substring(7, 13).toCharArray();
    charArray2[1] = (char) (charArray2[1] ^ '}');
    charArray2[2] = (char) (charArray2[2] ^ 'v');
    charArray2[3] = (char) (charArray2[3] ^ 'u');
    return new String(charArray) + "_" + new String(charArray2);
}
```

В итоге задание решено, найдены 3 флага.
