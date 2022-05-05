# CTF \#3

- [Задача](#Задача)
- [Решение](#Решение)

## [Задача](https://github.com/OWASP/owasp-mstg/tree/master/Crackmes)

Здесь 3 задачи:

- [Level_01](#Level_01)
- [Level_02](#Level_02)
- [Level_03](#Level_03)

Во всех трёх нужно найти секретную строку, которая находится где-то в приложении.

## Решение

### Level_01

Устанавливаем приложение на эмулятор и запускаем. Нас встречаем экран, что на устройстве присутствует root, что правда, так как даже не скрывается никаким способом. При нажатии на кнопку ОК диалогового окна приложение сразу закрывается.
<details>
  <summary>Скриншот</summary>
  
  ![](/CTF3/1.png)
</details>

Попробуем открыть приложение в jadx-gui и посмотреть, что это за диалог, как закрывается программа и как проверяется наличие root прав.

После того, как jadx-gui загрузил и обработал файл приложения, зайдём в манифест. Можем увидеть всего-лишь одну Activity под названием MainActivity, которая содержит intent-filter свойственный для Активити, которая запускается по нажатию на иконку в меню приложений.
```xml
<application android:theme="@style/AppTheme" android:label="@string/app_name" android:icon="@mipmap/ic_launcher" android:allowBackup="true">
    <activity android:label="@string/app_name" android:name="sg.vantagepoint.uncrackable1.MainActivity">
        <intent-filter>
            <action android:name="android.intent.action.MAIN"/>
            <category android:name="android.intent.category.LAUNCHER"/>
        </intent-filter>
    </activity>
</application>
```

Рассмотрим класс MainActivity.

Сразу нас встречаем метод, в котором создаётся и отображается диалог. Код на удивление прост. Также видим обработчик нажатия по кнопке диалога, который просто вызывает ```System.exit(0)```. Метод принимает заголовок диалога, поэтому нужно посмотреть, где он вызывается.

```java
private void a(String str) {
    AlertDialog create = new AlertDialog.Builder(this).create();
    create.setTitle(str);
    create.setMessage("This is unacceptable. The app is now going to exit.");
    create.setButton(-3, "OK", new DialogInterface.OnClickListener() {
        @Override
        public void onClick(DialogInterface dialogInterface, int i) {
            System.exit(0);
        }
    });
    create.setCancelable(false);
    create.show();
}
```

Место вызова найти просто, в методе onCreate происходит проверка на root с помощью обычного условия и вызова нескольких вспомогательных методов. В случае нахождения root прав, вызывается метод отображения диалогового окна с текстом "Root detected!". Также есть условие для проверки приложения на флаг debuggable, который может указываться в манифесте и давать возможность пройтись по коду отладчиком. В нашем случае приложение не debuggable, но установлено на устройстве с root правами.

Проверка на root права содержится в одном классе.

<details>
  <summary>Класс для нахождения root на устройстве</summary>

```java
public class c {
    public static boolean a() {
        for (String str : System.getenv("PATH").split(":")) {
            if (new File(str, "su").exists()) {
                return true;
            }
        }
        return false;
    }

    public static boolean b() {
        String str = Build.TAGS;
        return str != null && str.contains("test-keys");
    }

    public static boolean c() {
        for (String str : new String[]{"/system/app/Superuser.apk", "/system/xbin/daemonsu", "/system/etc/init.d/99SuperSUDaemon", "/system/bin/.ext/.su", "/system/etc/.has_su_daemon", "/system/etc/.installed_su_daemon", "/dev/com.koushikdutta.superuser.daemon/"}) {
            if (new File(str).exists()) {
                return true;
            }
        }
        return false;
    }
}
```
</details>

Для того, чтобы иметь возможность ввода в соответствующее поле в приложении, нужно либо не показывать диалоговое окно, либо не закрывать приложение при нажатии на ОК. Это можно сделать разными способами, например просто изменить код приложения и запаковать его, также сделать возможным его отладку для поиска секретной строки. Я пойду другим путём и воспользуюсь замечательным инструментом frida, который позволит мне изменить поведение некоторых методов во время рантайма.

Как установить и запустить frida рассказывать не буду, это делается достаточно просто и легко можно найти в интернете. Так как эмулятор имеет root права, то изменять файл приложения, перепаковывать его не нужно, так как frida будет установлена на устройстве отдельно.

Сделаем метод отображения диалога пустышкой. Для этого напишем маленький скрипт.
```js
Java.perform(function () {
    const MainActivity = Java.use("sg.vantagepoint.uncrackable1.MainActivity");

    MainActivity.a.implementation = function (title) {
        console.log("Dialog with title '" + title + "' is ignored :D");
    };
});
```

Сначала находим класс MainActivity по полному названию, которое включаем название пакета. Далее заменяем реализацию метода 'a' на нашу собственную, которая просто выводит текст в консоль, просто чтобы видеть, как отработал вызов метода-заглушки.

Запустим приложение и frida с этим скриптом.

Сразу после запуска видим экран приложения и не видим диалогового окна.
<details>
  <summary>Скриншот</summary>
  
  ![](/CTF3/2.png)
</details>

В консоли наблюдаем следующий вывод.
<details>
  <summary>Скриншот</summary>
  
  ![](/CTF3/3.png)
</details>

Прекрасно, первая преграда сломлена.

В поле ввода введём 123 и посмотрим на вывод. После нажатия на кнопку появилось диалоговое окно с текстом о том, что введённый текст не тот, который ожидался.
<details>
  <summary>Скриншот</summary>
  
  ![](/CTF3/4.png)
</details>

Посмотрим ещё раз код MainActivity. Там можно заметить метод verify, который содержит константу, а именно строку, которую мы видели при некорректном вводе. По сути вся логика сводится к некоему методу 'a' некоего класса 'a'.
```java
if (a.a(obj)) {
    create.setTitle("Success!");
    str = "This is the correct secret.";
} else {
    create.setTitle("Nope...");
    str = "That's not it. Try again.";
}
```

Здесь переменная obj - это строка, которую мы ввели.

Метод 'a' класс 'a' также передаёт управление другому методу, который принимает две строки в виде байтовых массивов и возвращает тоже массив байт, с помощью которого создаётся новая строка и сравнивается с введённой строкой.
```java
public static boolean a(String str) {
    byte[] bArr = new byte[0];
    try {
        bArr = sg.vantagepoint.a.a.a(b("8d127684cbc37c17616d806cf50473cc"), Base64.decode("5UJiFctbmgbDoLXmpL12mkno8HT4Lv8dlat8FxR2GOc=", 0));
    } catch (Exception e) {
        Log.d("CodeCheck", "AES error:" + e.getMessage());
    }
    return str.equals(new String(bArr));
}
```

Метод, в который передаётся управление является методом шифрования алгоритма AES.

```java
public static byte[] a(byte[] bArr, byte[] bArr2) {
    SecretKeySpec secretKeySpec = new SecretKeySpec(bArr, "AES/ECB/PKCS7Padding");
    Cipher cipher = Cipher.getInstance("AES");
    cipher.init(2, secretKeySpec);
    return cipher.doFinal(bArr2);
}
```

Так как весь код, включая код и данные для AES у нас есть, можно скопировать их в тестовый проект, выполнить данный метод и показать результат в логах. Однако можно сделать это и с помощью frida. Если немного уточнить, то эти методы действительно можно реализовать в JavaScript, либо просто запустить эти методы без необходимости пользовательского ввода, а можно просто подсмотреть результат работы метода при нажатии кнопки в приложении, так и поступим.

Для этого дополним скрипт следующим кодом.
```javascript
Java.perform(function () {
    const a = Java.use("sg.vantagepoint.a.a");
    const String = Java.use("java.lang.String");

    a.a.overload("[B", "[B").implementation = function (bytes1, bytes2) {
        const result = a.a(bytes1, bytes2);

        console.log("Secret string: " + String.$new(result));

        return result;
    };
});
```

Сначала находим наш класс, который содержит метод для шифрования. Также нам понадобится класс String для превращения байтового массива в строку, как это и сделано в оригинальном коде. Заменяем реализацию метода 'a' на собственную. Указываем overload и принимаемый тип параметров, так как имеются другие методы 'a' с другими параметрами. Далее вызываем оригинальный метод (```a.a()```) с переданными двумя аргументами (```bytes1``` и ```bytes2```), получаем результат (```result```) и на его основе создаём экземпляр строки, которую сразу логируем. Сам результат возвращаем, чтобы не менять поведение приложения.

Попробуем запустить таким образом приложение. Вводим 123 и нажимаем кнопку. Получаем такую же ошибку, зато в логах можем увидеть следующее.
<details>
  <summary>Скриншот</summary>
  
  ![](/CTF3/5.png)
</details>

У нас есть строка "I want to believe". Введём её и нажмём кнопку.
Это правильная строка, о чём и говорит диалоговое окно.
<details>
  <summary>Скриншот</summary>
  
  ![](/CTF3/6.png)
</details>

Первое задание решено.


### Level_02
Установим и откроем приложение. Снова появляется диалоговое окно, которое оповещает, что на устройстве есть root права. При нажатии на ОК также закрывается приложение.
<details>
  <summary>Скриншот</summary>
  
  ![](/CTF3/7.png)
</details>

Откроем файл приложения в jadx-gui. Манифест не отличается от предыдущего, содержит только одну MainActivity.

Посмотрим сам класс MainActivity. Он содержит метод отображения диалогового окна, который тоже не отличается от такого же метода из предыдущего задания. Следовательно можно воспользоваться скриптом из предыдущего задания для отключения диалога, только изменить полное название класса.

```javascript
Java.perform(function () {
    const MainActivity = Java.use("sg.vantagepoint.uncrackable2.MainActivity");

    MainActivity.a.implementation = function (title) {
        console.log("Dialog with title '" + title + "' is ignored :D");
    };
});
```

Попробуем запустить и получаем ошибку в консоли.
<details>
  <summary>Скриншот</summary>
  
  ![](/CTF3/8.png)
</details>

Это произошло, как можно понять из текста, что существует несколько методов с таким названием в классе MainActivity, однако таких методов нельзя обнаружить в самом классе, это происходит потому что они находятся в родительских классах. Чтобы исправить, следует указать сигнатуру метода, который мы хотим захукать. Код будет выглядеть так.
```javascript
Java.perform(function () {
    const MainActivity = Java.use("sg.vantagepoint.uncrackable2.MainActivity");

    MainActivity.a.overload("java.lang.String").implementation = function (title) {
        console.log("Dialog with title '" + title + "' is ignored :D");
    };
});
```

При запуске диалог не появляется, а в консоли видим соответствующее сообщение.
<details>
  <summary>Скриншот</summary>
  
  ![](/CTF3/9.png)
</details>

Введём 123 и нажмём кнопку VERIFY, после чего получим сообщение о неверном вводе.
<details>
  <summary>Скриншот</summary>
  
  ![](/CTF3/10.png)
</details>

Условие проверки валидности также находится в методе verify в MainActivity. Проверка происходит в методе другого класса. Посмотрим, что там происходит. Класс содержит два метода: публичный 'a', который верифицирует ввод пользователя и нативный метод bar, который возвращает булевское значение.

```java
public class CodeCheck {
    private native boolean bar(byte[] bArr);

    public boolean a(String str) {
        return bar(str.getBytes());
    }
}
```

Если есть нативный метод, значит файл приложения содержит нативную библиотеку. Посмотрим папку lib, в которой находятся библиотеки. Действительно внутри лежит libfoo.so для каждой архитектуры. Нам нужна x86, так как эмулятор такой, хотя в данном случае разницы быть не должно, но всё же зависит от того, что нам придётся делать дальше.
<details>
  <summary>Скриншот</summary>
  
  ![](/CTF3/11.png)
</details>

Откроем apk файл через архиватор и выгрузим библиотеку. Это нужно для её анализа в специальном инструменте ghidra.

Для этого откроем ghidra, создадим проект, перетащим файл библиотеки в окно программы (тоже самое, что выбрать в меню импорт файла), далее после загрузки, отображения некоторой информации по нему, два раза нажмём на файл, который отображается в дереве проекта, потом откроется окно в котором предложат провести анализ, соглашаемся и через несколько секунд загружается окно с полноценной информацией по нативной библиотеке.
<details>
  <summary>Скриншот</summary>
  
  ![](/CTF3/12.png)
</details>

Нативные методы, которые доступны в Java коде, с помощью JNI, используют для наименования определённые правила, поэтому такие функции в нативной библиотеке легко найти. Эти функции можно найти во вкладке Exports, так как они должны быть видны всем, кто использует эту библиотеку в качестве зависимости.
<details>
  <summary>Скриншот</summary>
  
  ![](/CTF3/13.png)
</details>

Видим две функции, по названию которых можно понять, где в коде они находятся: 
1) метод bar в классе CodeCheck
2) метод init в классе MainActivity
Метод init нам, как минимум сейчас, не интересен, поэтому нажмём на первый.

После этого справа появляется декомпилированный из бинарника код на C, который в разы понятнее и читаемее ассемблерных инструкций.

Также для функции можно изменить типы, так как контракт JNI функций известен. Как добавить JNI типы в ghidra можно найти в интернете. Благодаря этому некоторые непонятные методы будут иметь читаемые названия, как в реальном коде.

Код декомпилированного метода bar.
<details>
  <summary>До установки JNI типов</summary>

```c
undefined4 Java_sg_vantagepoint_uncrackable2_CodeCheck_bar(int *param_1,undefined4 param_2,undefined4 param_ 3)
{
  char *__s1;
  int iVar1;
  undefined4 uVar2;
  int in_GS_OFFSET;
  undefined4 local_30;
  undefined4 local_2c;
  undefined4 local_28;
  undefined4 local_24;
  undefined2 local_20;
  undefined4 local_1e;
  undefined2 local_1a;
  int local_18;
  
  local_18 = *(int *)(in_GS_OFFSET + 0x14);
  if (DAT_00014008 == '\x01') {
    local_30 = 0x6e616854;
    local_2c = 0x6620736b;
    local_28 = 0x6120726f;
    local_24 = 0x74206c6c;
    local_20 = 0x6568;
    local_1e = 0x73696620;
    local_1a = 0x68;
    __s1 = (char *)(**(code **)(*param_1 + 0x2e0))(param_1,param_3,0);
    iVar1 = (**(code **)(*param_1 + 0x2ac))(param_1,param_3);
    if (iVar1 == 0x17) {
      iVar1 = strncmp(__s1,(char *)&local_30,0x17);
      if (iVar1 == 0) {
        uVar2 = 1;
        goto LAB_00011009;
      }
    }
  }
  uVar2 = 0;
LAB_00011009:
  if (*(int *)(in_GS_OFFSET + 0x14) == local_18) {
    return uVar2;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```
</details>

<details>
  <summary>После установки JNI типов</summary>

```c
undefined4 Java_sg_vantagepoint_uncrackable2_CodeCheck_bar(JNIEnv *param_1,undefined4 param_2,jbyteArray param_3)
{
  jbyte *__s1;
  jsize jVar1;
  int iVar2;
  undefined4 uVar3;
  int in_GS_OFFSET;
  undefined4 local_30;
  undefined4 local_2c;
  undefined4 local_28;
  undefined4 local_24;
  undefined2 local_20;
  undefined4 local_1e;
  undefined2 local_1a;
  int local_18;
  
  local_18 = *(int *)(in_GS_OFFSET + 0x14);
  if (DAT_00014008 == '\x01') {
    local_30 = 0x6e616854;
    local_2c = 0x6620736b;
    local_28 = 0x6120726f;
    local_24 = 0x74206c6c;
    local_20 = 0x6568;
    local_1e = 0x73696620;
    local_1a = 0x68;
    __s1 = (*(*param_1)->GetByteArrayElements)(param_1,param_3,(jboolean *)0x0);
    jVar1 = (*(*param_1)->GetArrayLength)(param_1,param_3);
    if (jVar1 == 0x17) {
      iVar2 = strncmp(__s1,(char *)&local_30,0x17);
      if (iVar2 == 0) {
        uVar3 = 1;
        goto LAB_00011009;
      }
    }
  }
  uVar3 = 0;
LAB_00011009:
  if (*(int *)(in_GS_OFFSET + 0x14) == local_18) {
    return uVar3;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```
</details>


После подстановки JNI типов можно увидеть вызов метода GetArrayLength и сохранение результата в переменную jVar1. Далее происходит сравнение переменной с константой 0x17, которая в десятичной системе равна 23. Можно сделать вывод, что необходима строка длиной 23. Нужно понять, откуда эта строка взялась.

Пойдём немного вверх и видим метод GetByteArrayElements, который принимает аргументы param1 и param3. param3 - это массив байт, который передаётся третьим аргументом в метод Java_sg_vantagepoint_uncrackable2_CodeCheck_bar. А это параметр, который мы передаём сюда из Java кода, то есть наша введённая строка в виде массива байт.

При успешном сравнении в условии, строка передаётся в функцию strncmp первым параметром, вторым параметром передаётся ссылка на другую строку, так как [strncmp](https://www.cplusplus.com/reference/cstring/strncmp/) в качестве аргументов две строки и количество символов для сравнения, а выдаёт:
- 0, если строки равны
- меньше 0, если первая строка меньше (вторая строка больше)
- больше 0, если первая строка больше (вторая строка меньше)

Результат сравнения используется в условии и если будет равен 0, то возвращается 1, то есть true для Java кода, а иначе переменная uVar3 будет равна 0 - false для Java.
<details>
  <summary>Скриншот</summary>
  
  ![](/CTF3/14.png)
</details>

Попробуем найти строку длиной 23 с помощью встроенного поиска по строкам в ghidra. Однако, кроме названий JNI методов, других таких же длинных строк не нашлось. Поэтому достать строку попробуем другим способом.
<details>
  <summary>Скриншоты</summary>
  
  ![](/CTF3/15.png)
  ![](/CTF3/16.png)
</details>

Так как frida может хукать не только Java методы, но и нативные, попробуем сделать хук функции strncmp.

Добавим в файл следующий код. Здесь мы находим функцию strncmp в библиотеке libc.so, так как функция стандартная и находится в стандартной библиотеке. Также благодаря этому не требуется ожидать дополнительное время для загрузки локальной библиотеки, в случае хука функции именно в ней.
```javascript
Interceptor.attach(Module.findExportByName("libc.so", "strncmp"), {
    onEnter: function (args) {
        console.log("Secret string: " + Memory.readUtf8String(args[1]));
    }
});
```

При запуске в консоли появляется огромное число строк, которые сравниваются этой функцией, что нам не подходит. Поэтому нужно сделать условия для получения нашей строки. Мы знаем, что до вызова функции сравнения строк происходит проверка введённой строки на длину, которая должна быть 23. Поэтому добавим условие.
```javascript
Interceptor.attach(Module.findExportByName("libc.so", "strncmp"), {
    onEnter: function (args) {
        if (args[2].toInt32() == 23) {
            console.log("\nInput string : " + Memory.readCString(args[0]));
            console.log("Secret string: " + Memory.readCString(args[1]));
        }
    }
});
```

Теперь попробуем запустить. Вывод строк значительно сократился, но не до нуля. Введём строку длиной 23 в поле ввода, например пусть это будет "12345678901234567890123". Цифры удобно использовать, так как не будет проблем с кодировкой, с латинскими символами в принципе тоже.

После ввода и нажатия кнопки получаем в консоли результат.
<details>
  <summary>Скриншот</summary>
  
  ![](/CTF3/17.png)
</details>

Как можно увидеть, введённая строка значительно длинее, чем 23 символа, что странно, но объсняется тем, что наша функция readCString по умолчанию считывает данные из памяти до NUL символа, который не включён в строку после конвертации из байтового массива.

Для получения только нашей строки абсолютно без вывода других аргументов, сделаем условие более чётким. Добавим чтение первого аргумента, возьмём из него только первые 23 символа и сравним со строкой, которую вводим.

```javascript
Interceptor.attach(Module.findExportByName("libc.so", "strncmp"), {
    onEnter: function (args) {
        if (args[2].toInt32() == 23 && Memory.readCString(args[0]).substring(0, 23) === "12345678901234567890123") {
            console.log("Secret string: " + Memory.readCString(args[1]));
        }
    }
});
```

В итоге весь вывод используемого скрипта сводится к двум строкам.
<details>
  <summary>Скриншот</summary>
  
  ![](/CTF3/18.png)
</details>

Секретная строка: Thanks for all the fish

Теперь убедимся в этом, просто введём её в приложении и получаем диалог с текстом об успехе.
<details>
  <summary>Скриншот</summary>
  
  ![](/CTF3/19.png)
</details>

Второе задание решено.


### Level_03
Установим и откроем третье приложение. Снова появляется диалоговое окно, которое оповещает, что на устройстве есть root права или приложение подделано.
<details>
  <summary>Скриншот</summary>
  
  ![](/CTF3/20.png)
</details>

Посмотрим приложение в jadx-gui. В манифесте только MainActivity. Сразу перейдём к ней.

Сразу встречается метод showDialog, который делает точно тоже самое, что и аналогичный метод в других приложениях. Подменим его имеющимся скриптом, только изменим пакет класс и название метода.
<details>
  <summary>Метод отображения диалога</summary>

```java
public void showDialog(String str) {
    AlertDialog create = new AlertDialog.Builder(this).create();
    create.setTitle(str);
    create.setMessage("This is unacceptable. The app is now going to exit.");
    create.setButton(-3, "OK", new DialogInterface.OnClickListener() {
        @Override
        public void onClick(DialogInterface dialogInterface, int i) {
            System.exit(0);
        }
    });
    create.setCancelable(false);
    create.show();
}
```
</details>

Скрипт для этого приложения, который будет игнорировать создание диалога, выглядит так. В этот раз не пришлось указывать принимаемые параметры, так перегруженных методов с таким же названием в классе и его родителях нет.
```javascript
Java.perform(function () {
    const MainActivity = Java.use("sg.vantagepoint.uncrackable3.MainActivity");

    MainActivity.showDialog.implementation = function (title) {
        console.log("Dialog with title '" + title + "' is ignored :D");
    };
});
```

При запуске приложения с frida приложение открывается, диалоговое окно не появляется, но через мгновение приложение закрывается.

Если посмотреть класс MainActivity подробнее, то можно увидеть, что System.exit(0) есть ещё в одном месте, в методе verifyLibs, который проверяет контрольные суммы нативных библиотек и файла dex. Однако не стоит беспокоиться об этом методе, потому что перепаковку и изменение оригинального приоложения не проводили, следовательно и проблема будет не здесь.
<details>
  <summary>Метод verifyLibs</summary>

```java
private void verifyLibs() {
    this.crc = new HashMap();
    this.crc.put("armeabi-v7a", Long.valueOf(Long.parseLong(getResources().getString(R.string.armeabi_v7a))));
    this.crc.put("arm64-v8a", Long.valueOf(Long.parseLong(getResources().getString(R.string.arm64_v8a))));
    this.crc.put("x86", Long.valueOf(Long.parseLong(getResources().getString(R.string.x86))));
    this.crc.put("x86_64", Long.valueOf(Long.parseLong(getResources().getString(R.string.x86_64))));
    try {
        ZipFile zipFile = new ZipFile(getPackageCodePath());
        for (Map.Entry<String, Long> entry : this.crc.entrySet()) {
            String str = "lib/" + entry.getKey() + "/libfoo.so";
            ZipEntry entry2 = zipFile.getEntry(str);
            Log.v(TAG, "CRC[" + str + "] = " + entry2.getCrc());
            if (entry2.getCrc() != entry.getValue().longValue()) {
                tampered = 31337;
                Log.v(TAG, str + ": Invalid checksum = " + entry2.getCrc() + ", supposed to be " + entry.getValue());
            }
        }
        ZipEntry entry3 = zipFile.getEntry("classes.dex");
        Log.v(TAG, "CRC[classes.dex] = " + entry3.getCrc());
        if (entry3.getCrc() != baz()) {
            tampered = 31337;
            Log.v(TAG, "classes.dex: crc = " + entry3.getCrc() + ", supposed to be " + baz());
        }
    } catch (IOException unused) {
        Log.v(TAG, "Exception");
        System.exit(0);
    }
}
```
</details>

Как уже поняли, приложение содержит нативные библиотеки, которые могут также иметь код, который закроет приложение.

Для начала посмотрим логи устройства и найдём логи краша приложения.

Для этого воспользуемся командой "adb logcat" и запустим приложение с frida. После закрытия приложения, отключим logcat и поищем что-нибудь интересное. И действительно в логах есть бэктрейс краша.

<details>
  <summary>Логи краша</summary>

```log
05-05 07:41:02.812 11983 11983 I crash_dump32: performing dump of process 11946 (target tid = 11977)
05-05 07:41:02.818 11983 11983 F DEBUG   : *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** ***
05-05 07:41:02.819 11983 11983 F DEBUG   : Build fingerprint: 'google/sdk_gphone_x86/generic_x86:10/QSR1.210802.001/7603624:userdebug/dev-keys'
05-05 07:41:02.819 11983 11983 F DEBUG   : Revision: '0'
05-05 07:41:02.819 11983 11983 F DEBUG   : ABI: 'x86'
05-05 07:41:02.819 11983 11983 F DEBUG   : Timestamp: 2022-05-05 07:41:02+0000
05-05 07:41:02.819 11983 11983 F DEBUG   : pid: 11946, tid: 11977, name: tg.uncrackable3  >>> owasp.mstg.uncrackable3 <<<
05-05 07:41:02.819 11983 11983 F DEBUG   : uid: 10155
05-05 07:41:02.819 11983 11983 F DEBUG   : signal 6 (SIGABRT), code -6 (SI_TKILL), fault addr --------
05-05 07:41:02.819 11983 11983 F DEBUG   :     eax 00000000  ebx 00002eaa  ecx 00002ec9  edx 00000006
05-05 07:41:02.819 11983 11983 F DEBUG   :     edi 00000006  esi 00002eaa
05-05 07:41:02.819 11983 11983 F DEBUG   :     ebp bc5ebf68  esp bc5ebf1c  eip e8f87ef9
05-05 07:41:02.820 11983 11983 F DEBUG   :
05-05 07:41:02.820 11983 11983 F DEBUG   : backtrace:
05-05 07:41:02.820 11983 11983 F DEBUG   :       #00 pc 00000ef9  [vdso] (__kernel_vsyscall+9)
05-05 07:41:02.820 11983 11983 F DEBUG   :       #01 pc 0010385c  /apex/com.android.runtime/lib/bionic/libc.so!libc.so (offset 0x102000) (tgkill+28) (BuildId: 471745f0fbbcedb3db1553d5bd6fcd8b)
05-05 07:41:02.820 11983 11983 F DEBUG   :       #02 pc 000b9c44  /apex/com.android.runtime/lib/bionic/libc.so!libc.so (offset 0xb2000) (raise+68) (BuildId: 471745f0fbbcedb3db1553d5bd6fcd8b)
05-05 07:41:02.820 11983 11983 F DEBUG   :       #03 pc 00003021  /data/app/owasp.mstg.uncrackable3-4IiPGRXgi8owN2j7s5-pmA==/lib/x86/libfoo.so (goodbye()+33) (BuildId: 59b27d3ad212b5435a2b89003d9bf36b3bcf3aa5)
05-05 07:41:02.820 11983 11983 F DEBUG   :       #04 pc 00003179  /data/app/owasp.mstg.uncrackable3-4IiPGRXgi8owN2j7s5-pmA==/lib/x86/libfoo.so (BuildId: 59b27d3ad212b5435a2b89003d9bf36b3bcf3aa5)
05-05 07:41:02.820 11983 11983 F DEBUG   :       #05 pc 0011a8e5  /apex/com.android.runtime/lib/bionic/libc.so!libc.so (offset 0x117000) (__pthread_start(void*)+53) (BuildId: 471745f0fbbcedb3db1553d5bd6fcd8b)
05-05 07:41:02.820 11983 11983 F DEBUG   :       #06 pc 000af6a7  /apex/com.android.runtime/lib/bionic/libc.so!libc.so (offset 0xaf000) (__start_thread+71) (BuildId: 471745f0fbbcedb3db1553d5bd6fcd8b)
```
</details>

Среди логов можно увидеть libc.so - стандартную библиотеку, а также libfoo.so, которая неизвестна, но если посмотреть полный путь, то можно по названию пакета определить, что это нативная библиотека приложения. И действительно в jadx-gui можно найти её.

Достанем файл x86 нативной библиотеки libfoo.so из apk архиватором и откроем в ghidra.

В логах также можно видеть название функции (или адрес) возле названия файла библиотеки. Возле libfoo.so есть функция goodbye, которую можно рассмотреть для начала.

В программе ghidra в exports находится функция goodbye, которая выглядит очень просто - [raise](https://www.cplusplus.com/reference/csignal/raise/) выбрасывает SIGABRT, после чего приложение экстренно завершается.
```c
void goodbye(void)
{
  raise(6);
                    /* WARNING: Subroutine does not return */
  _exit(0);
}
```

Найдём ссылки на эту функцию, по названию ссылки есть, но нет места, где она вызывается, если искать по адресу, то находится одно место с вызовом функции goodbye. Вызывается в неэкспортируемой функции.
<details>
  <summary></summary>

```c
void FUN_00013080(void)
{
  FILE *__stream;
  char *pcVar1;
  char local_214 [516];
  
  __stream = fopen("/proc/self/maps","r");
  if (__stream == (FILE *)0x0) {
LAB_0001314f:
    pcVar1 = "Error opening /proc/self/maps! Terminating...";
  }
  else {
    do {
      while (pcVar1 = fgets(local_214,0x200,__stream), pcVar1 == (char *)0x0) {
        fclose(__stream);
        usleep(500);
        __stream = fopen("/proc/self/maps","r");
        if (__stream == (FILE *)0x0) goto LAB_0001314f;
      }
      pcVar1 = strstr(local_214,"frida");
    } while ((pcVar1 == (char *)0x0) && (pcVar1 = strstr(local_214,"xposed"), pcVar1 == (char *)0x 0)
            );
    pcVar1 = "Tampering detected! Terminating...";
  }
  __android_log_print(2,"UnCrackable3",pcVar1);
                    /* WARNING: Subroutine does not return */
  goodbye();
}
```
</details>

Функция в бесконечном цикле каждые 500 микросекунд читает виртуальный файл /proc/self/maps (содержит маппинг виртуальной памяти с указанием процессов и потоков, так при подключении frida она там указывается в том числе) и ищет в каждой считанной строке подстроку "frida" или "xposed", в случае нахождения цикл завершается и вызывается функция goodbye.

Для нахождения подстроки используется функция [strstr](https://www.cplusplus.com/reference/cstring/strstr/), которая возвращает нулевой указатель, если строка не найдена, и указатель на подстроку, если найдена.

Попробуем через frida заменить возвращаемое значение на нулевой указатель, а понимать, что это тот самый вызов по второму аргументу равнов строке "frida".

Скрипт для подмены получится таким, добавим этот кусочек к предыдущему. Логирование закомментировано, так как будет слишком много ненужного вывода, а эффект от скрипта и так будет заметен.

```javascript
Interceptor.attach(Module.findExportByName("libc.so", "strstr"), {
    onEnter: function (args) {
        this.isFrida = Memory.readCString(args[0]).includes("frida");
    },
    onLeave: function (retval) {
        if (this.isFrida) {
            // console.log("strstr(\"frida\") is patched!");
            retval.replace(0);
        }
    }
});
```

После запуска программы диалоговое окно не появляется, а сама программа не завершается. Попробуем ввести 123 и посмотреть на поведение программы.
Ожидаемо получаем диалог о неверном вводе.
<details>
  <summary>Скриншот</summary>
  
  ![](/CTF3/21.png)
</details>

Вернёмся к MainActivity. Там находится метод verify, который не отличается от такого же метода в предыдущем приложении. Посмотрим класс CodeCheck, метод которого выполняет проверку ввода и отдаёт либо true, либо false.
```java
public class CodeCheck {
    private static final String TAG = "CodeCheck";

    private native boolean bar(byte[] bArr);

    public boolean check_code(String str) {
        return bar(str.getBytes());
    }
}
```

Можно увидеть нативный метод bar, принимаемый на вход байтовый массив. Следовательно нужно найти этот метод в нативной библиотеке. Это сделать просто, вспоминая про контракт наименования JNI функций.

<details>
  <summary>Нативный метод bar с приведением к JNI типам</summary>

```c
jboolean Java_sg_vantagepoint_uncrackable3_CodeCheck_bar
                   (JNIEnv *param_1,jobject param_2,jbyteArray param_3)
{
  jboolean jVar1;
  jbyte *pjVar2;
  jsize jVar3;
  uint uVar4;
  undefined4 *puVar5;
  int in_GS_OFFSET;
  undefined local_40 [16];
  undefined4 local_30;
  undefined4 local_2c;
  undefined local_28;
  int local_18;
  
  local_18 = *(int *)(in_GS_OFFSET + 0x14);
  local_40 = ZEXT816(0);
  local_2c = 0;
  local_30 = 0;
  local_28 = 0;
  if (DAT_00016038 == 2) {
    FUN_00010fa0((undefined4 *)local_40);
    pjVar2 = (*(*param_1)->GetByteArrayElements)(param_1,param_3,(jboolean *)0x0);
    jVar3 = (*(*param_1)->GetArrayLength)(param_1,param_3);
    if (jVar3 == 0x18) {
      uVar4 = 0;
      puVar5 = &DAT_0001601c;
      do {
        if (pjVar2[uVar4] != (*(byte *)puVar5 ^ local_40[uVar4])) goto LAB_00013456;
        uVar4 = uVar4 + 1;
        puVar5 = (undefined4 *)((int)puVar5 + 1);
      } while (uVar4 < 0x18);
      jVar1 = '\x01';
      if (uVar4 == 0x18) goto LAB_00013458;
    }
  }
LAB_00013456:
  jVar1 = '\0';
LAB_00013458:
  if (*(int *)(in_GS_OFFSET + 0x14) == local_18) {
    return jVar1;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```
</details>

Благодаря приведению к JNI типам можно увидеть вызов метода GetByteArrayElements, который просто возвращает байтовый массив введённой строки. А также метод GetArrayLength, который возвращает длину массива, после чего результат проверяется в условии с константой 0x18 (24 в десятичной системе счисления). Значит строка должна быть длиной 24 символа.

Дальше есть цикл, в котором можно заметить операцию XOR, которая сравнивает значение нашего массива pjVar2 с результатом Исключающего ИЛИ между puVar5 и массивом local_40.
```c
if (pjVar2[uVar4] != (*(byte *)puVar5 ^ local_40[uVar4])) goto LAB_00013456;
```

Так как эта строка вызывается внутри функции и очевидно не является функцией, то кажется, что мы не сможем захукать через frida. НО! Сможем!
Для этого нам нужно найти адрес этой операции, но не в декомпилированном коде, а в ассемблерном представлении в ghidra. Для этого нажмём на операцию XOR, а точнее на значок '^' и подсветится нужная строка.
```txt
00013443 32  14  04       XOR        DL,byte ptr [ESP  + EAX *0x1 ]=>local_40
```

Немного отвлечёмся и посмотрим на MainActivity. Ранее можно было обратить внимание, что в ней есть два нативных метода: baz и init. Первый возвращает число, которое используется для сравнения контрольных сумм. А второй принимает на вход массив байт, а вызывается в onCreate, где получает массив байт из переменной xorkey, которая является обычной строкой "pizzapizzapizzapizzapizz". По названию можно понять, что это может быть одним из значений, которые используются для шифрования строки в бинарном коде. Очевидно, что так сделано для упрощения решения этого задания, было бы немного сложнее, не будь у переменной осмысленного названия. Сама строка нам не пригодится, так как способ решения используется другие вещи, но эта задача решается не единственным вариантом, поэтому сама строка из MainActivity может пригодиться.

Для получения данных массивов надо подключиться frida во время исполнения кода туда, где выполняется XOR операция. Для этого нужно получить адрес, который написан в строке выше из ghidra слева и равен 00013443. Если промотаем список в ghidra в самый верх, то увидим, что начинаются адреса с 00010000. Значит нам нужно к базовому адресу библиотеки в памяти добавить сдвиг на 00013443 - 00010000 = 00003443 (числа приводятся в шестнадцатеричной системе счисления).

Чтобы лучше понять дальнейшее объяснение немного поясню на кусочке ассемблерного кода, который является циклом.

```asm
LAB_00013440 ; начало цикла. EAX равен 0
00013440   MOVZX  EDX ,byte ptr [ECX]=>DAT_0001601c ; записываем в регистр EDX байт из массива по указателю ECX
00013443   XOR    DL,byte ptr [ESP  + EAX *0x1]=>local_40 ; операция XOR между байтом из EDX (DL) и байтом из массива по указателю ESP + EAX
00013446   CMP    byte ptr [ESI  + EAX *0x1],DL ; сравнение байта из массива по указателю ESI + EAX с результатом XOR в EDX (DL)
00013449   JNZ    LAB_00013456 ; неудачное завершение цикла при несовпадении значений введённой строки и XOR результата
0001344b   INC    EAX ; увеличение счётчика цикла (также используется для взятия элемента массива)
0001344c   INC    ECX ; увеличение счётчика для взятия элемента массива
0001344d   CMP    EAX ,0x18 ; сравнение EAX с числом 24 (длина массива)
00013450   JC     LAB_00013440 ; возврат в начало цикла
00013452   MOV    AL,0x1
00013454   JZ     LAB_00013458 ; нормальное завершение цикла
```

По сути у нас есть указатель на начало каждого из массивов, которые находятся в регистрах. А также известна длина массива и размер элемента массива (так как массив байтов, то и элемент равен байту). Поэтому с помощью frida нужно получить начало массивов, а дальше в JavaScript'е выполнить XOR для 24 элементов и вывести результат в консоль.

Код скрипта будет таким. setTimeout нужен для того, чтобы дать время для загрузки локальной библиотеки libfoo.so, она загружается в статическом блоке класса MainActivity. Данный способ работает с x86 библиотекой, поэтому регистры могут отличаться в библиотеках скомпилированных для других архитектур.
```javascript
setTimeout(function() {
    var xorLineAddress = Module.findBaseAddress("libfoo.so").add(0x3443);

    Interceptor.attach(xorLineAddress, {
        onEnter: function() {
            let secret = "";
            
            for (let i = 0; i < 24; i++) {
                let x = Memory.readS8(ptr((parseInt(this.context.ecx) + i).toString()));
                let y = Memory.readS8(ptr((parseInt(this.context.esp) + i).toString()));
    
                secret += String.fromCharCode(x ^ y);
            }

            console.log("Secret string: " + secret);
        }
    });
}, 100);
```

После запуска приложения с дополненным скриптом и ввода строки из 24 символов, например "123456789012345678901234", получаем в логах следующее.
<details>
  <summary>Скриншот</summary>
  
  ![](/CTF3/22.png)
</details>

Секретная строка: making owasp great again

Проблема с данным способом, что при вводе верной строки будет засчитываться, что она неверная, поэтому скрипт для нахождения секретной строки надо закомментировать, перезапустить приложение и ввести её для верификации. При запуске и вводе секретной строки получаем сообщение, что всё успешно.
<details>
  <summary>Скриншот</summary>
  
  ![](/CTF3/23.png)
</details>

Третья задача решена.
