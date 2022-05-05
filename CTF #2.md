# CTF \#2

- [Задача](#Задача)
- [Решение](#Решение)

## [Задача](https://github.com/num1r0/android_crackmes)

Здесь 3 задачи:

- [crackme_0x01](#crackme0x01)
- [crackme_0x02](#crackme0x02)
- [crackme_0x03](#crackme0x03)

Во всех трёх нужно найти скрытый пароль, ввести его в приложении и получить флаг.

## Решение

### crackme_0x01

Как всегда первым делом устанавливаем приложение и открываем. Из основных элементов видим поле ввода пароля и кнопку подтверждения.
<details>
  <summary>Скриншот</summary>
  
  ![](/CTF2/1.png)
</details>

После ввода 123 и нажатия кнопки получаем следующее.
<details>
  <summary>Скриншот</summary>
  
  ![](/CTF2/2.png)
</details>

Далее, тоже как всегда, открываем приложение в jadx-gui. И сразу смотрим манифест.

```xml
<application android:theme="@style/AppTheme" android:label="@string/app_name" android:icon="@mipmap/launcher_ic" android:allowBackup="true" android:supportsRtl="true" android:roundIcon="@mipmap/launcher_ic">
    <activity android:name="com.entebra.crackme0x01.MainActivity">
        <intent-filter>
            <action android:name="android.intent.action.MAIN"/>
            <category android:name="android.intent.category.LAUNCHER"/>
        </intent-filter>
    </activity>
</application>
```

В манифесте обнаруживаем только одну Активити - MainActivity. Далее заходим внутрь класса и в методе onCreate видим такие строки:

```java
final EditText editText = (EditText) findViewById(R.id.password);
((Button) findViewById(R.id.submit)).setOnClickListener(new View.OnClickListener() {
```

Первая строка - это нахождение поля ввода.
Вторая строка - это привязывание обработчика нажатия к кнопке. Нам это и нужно.

Обработчик нажатия выглядит примерно таким образом:

```java
String flag = new FlagGuard().getFlag(editText.getText().toString());
if (flag != null) {
    // сообщение об успехе и отображение флага
    return;
}
// сообщение о неудаче
```

Как можно заметить, метод getFlag возвращает строку с флагом, но магия происходит внутри него, так как в этот метод передаётся введённый в поле ввода текст. Посмотрим на метод:

```java
public String getFlag(String str) {
    if (str.equals(new Data().getData())) {
        return unscramble();
    }
    return null;
}
```

Видим просто сравнение введённой строки с результатом метода getData объекта класса Data. Флаг возвращается методом unscramle, который можно скопировать в тестовое приложение, после чего вызвать метод и получить флаг. Но пойдём другим путём.

Зайдём в метод getData.

```java
public String getData() {
    getClass();
    return "s3cr37_p4ssw0rd_1337";
}
```

Как оказалось этот путь проще, здесь просто константой лежит пароль, который нам нужен. Введём его в приложении.
<details>
  <summary>Скриншот</summary>
  
  ![](/CTF2/3.png)
</details>

Первое задание решено.
Полученный флаг: fl4g_f0r_cr4ckm3_0x01_hgf82f8bm

### crackme_0x02

Устанавливаем приложение, запускаем и видим точной такой же экран с полем ввода и кнопкой подтверждения.
<details>
  <summary>Скриншот</summary>
  
  ![](/CTF2/4.png)
</details>

При вводе 123 и нажатии кнопки снова получаем диалоговое окно с текстом о неверном пароле.
<details>
  <summary>Скриншот</summary>
  
  ![](/CTF2/5.png)
</details>

Откроем apk файл в jadx-gui.
В манифесте как и предыдущем приложении есть одна MainActivity.

В методе onCreate также ничего не изменилось, поменялись лишь аргументы метода getFlag, теперь туда передаётся Context и введённая строка. Внутри метода тоже почти ничего не поменялось, за исключением вызова метода getData с параметром Контекста.

```java
public String getFlag(Context context, String str) {
    if (str.equals(new Data().getData(context))) {
        return unscramble();
    }
    return null;
}
```

Посмотрим на метод getData:

```java
public String getData(Context context) {
    this.secret = context.getString(R.string.secret);
    return this.secret;
}
```

Видим получение строки secret из ресурсов по id R.string.secret. Значит наш пароль находится в строковых ресурсах приложения.

Чтобы найти значение строкового ресурса воспользуемся глобальным поиском (Ctrl+Shift+F), введём название secret, далее оставим только галочку на типе Resource.
<details>
  <summary>Скриншот</summary>
  
  ![](/CTF2/6.png)
</details>

Перейдём в ресурсы и найдём тем самым пароль.

```xml
<string name="secret">s0m3_0th3r_s3cr3t_passw0rd</string>
```

Пароль: s0m3_0th3r_s3cr3t_passw0rd

Введём пароль в приложении и получим флаг.
<details>
  <summary>Скриншот</summary>
  
  ![](/CTF2/7.png)
</details>

Второе задание решено.
Полученный флаг: th1s_1s_fl4g_f0r_cr4ckm3_0x02_jh4bo

### crackme_0x03

Устанавливаем приложение, запускаем и видим точной такой же экран с полем ввода и кнопкой подтверждения.
<details>
  <summary>Скриншот</summary>
  
  ![](/CTF2/8.png)
</details>

При вводе 123 и нажатии кнопки получаем диалоговое окно с текстом о том, что пароль слишком короткий.
<details>
  <summary>Скриншот</summary>
  
  ![](/CTF2/9.png)
</details>

При переборе более длинных комбинаций получаем другое сообщение при вводе текста 123456.
<details>
  <summary>Скриншот</summary>
  
  ![](/CTF2/10.png)
</details>

При вводе 1234567 получаем третье сообщение, что пароль слишком длинный.
<details>
  <summary>Скриншот</summary>
  
  ![](/CTF2/11.png)
</details>

Откроем apk файл в jadx-gui.
В манифесте находится только одна MainActivity.

В методе onCreate ничего не изменилось по сравнению с первым заданием.
Немного изменилась реализация метода getFlag.

```java
public String getFlag(String str) {
    if (new Data().isPasswordOk(str)) {
        return generate();
    }
    return null;
}
```

Но по сути ничего не поменялось, просто названия методов отличаются.
Посмотрим как реализован isPasswordOk.

```java
public boolean isPasswordOk(String str) {
    if (str.length() < this.password_length) {
        lastError = "Password too SHORT";
        return false;
    } else if (str.length() > this.password_length) {
        lastError = "Password too LONG";
        return false;
    } else if (str.length() != this.password_length) {
        return false;
    } else {
        getClass();
        if (!MD5Compare(str, "ac43bb53262e4edd82c0e82a93c84755")) {
            lastError = "WRONG password entered";
            return false;
        }
        getClass();
        return MD5Compare(str, "ac43bb53262e4edd82c0e82a93c84755");
    }
}
```

Можно увидеть знакомый текст из диалогового окна при вводе различных паролей. А также говорящий название метода: MD5Compare, в который передаётся строка str (вводится на экране приложения) и хэш, с которым будет проводиться сравнение.

<details>
  <summary>Метод MD5Comapre</summary>

```java
private boolean MD5Compare(String str, String str2) {
    try {
        MessageDigest messageDigest = MessageDigest.getInstance("MD5");
        messageDigest.update(str.getBytes());
        byte[] digest = messageDigest.digest();
        messageDigest.reset();
        StringBuilder sb = new StringBuilder();
        for (byte b : digest) {
            String hexString = Integer.toHexString(b & 255);
            while (hexString.length() < 2) {
                hexString = "0" + hexString;
            }
            sb.append(hexString);
        }
        return sb.toString().contentEquals(str2);
    } catch (Exception e) {
        Log.e("Exception MD5 compare", e.getMessage());
        return false;
    }
}
```

</details>

Алгоритм хэширования MD5 уже давно имеет славу не самого лучшего алгоритма и существует большое число сервисов по подбору строки с таким же хэшем.

После попыток на нескольких сайтах нашёлся [один](https://hashes.com/en/decrypt/hash), где выдало результат, им оказалась строка: 3#8H1J

Строка длиной 6 символов, что нам и требуется. Возможен случай, когда строка подберётся, но будет иметь другую длину, нам этот вариант не подобшёл бы. Пробуем ввести её и получаем флаг.
<details>
  <summary>Скриншот</summary>
  
  ![](/CTF2/12.png)
</details>

Третье задание решено.
Полученный флаг: hERe_yOu_gO_tAkE_IT_
