# CTF \#4

- [Задача](#Задача)
- [Решение](#Решение)

## [Задача](https://github.com/nowsecure/cybertruckchallenge19)

В одном приложении нужно найти 6 спрятанных ключей.
Описание для каждого можно посмотреть на странице задачи по ссылке выше.

## Решение

Установим приложение и откроем его.
<details>
  <summary>Скриншот</summary>
  
  ![](/CTF4/1.png)
</details>

Как ни странно, никаких диалоговых окон о том, что на устройстве есть root не появляется. Но можно увидеть свитч с названием TamperProof. Попробуем переключить его. После этого появляется Toats с текстом "Tampering detected!" и приложение закрывается.

Откроем apk файл в jadx-gui. Сразу перейдём в манифест.

Он не содержит ничего интересного, кроме нескольких разрешений, которые непонятно, зачем нужны в этом приложении.

```xml
<uses-permission android:name="android.permission.BLUETOOTH"/>
<uses-permission android:name="android.permission.BLUETOOTH_ADMIN"/>
<uses-permission android:name="android.permission.INTERNET"/>
<uses-permission android:name="android.permission.ACCESS_NETWORK_STATE"/>
<uses-permission android:name="android.permission.ACCESS_WIFI_STATE"/>
```

Но важно узнать какие Активити присутствуют. Объявлена лишь одна - MainActivity.

```xml
<application android:theme="@style/AppTheme" android:label="@string/app_name" android:icon="@mipmap/ic_launcher" android:debuggable="true" android:allowBackup="true" android:supportsRtl="true" android:roundIcon="@mipmap/ic_launcher_round" android:appComponentFactory="android.support.v4.app.CoreComponentFactory">
    <activity android:name="org.nowsecure.cybertruck.MainActivity">
        <intent-filter>
            <action android:name="android.intent.action.MAIN"/>
            <category android:name="android.intent.category.LAUNCHER"/>
        </intent-filter>
    </activity>
</application>
```

В методе onCreate класса MainActivity можно быстро обнаружить строку, которая была в тосте при включении свитча.
Она находится внутри обработчика свитча и показывается при совпадении двух условий: свитч активирован и метод isFridaServerInDevice класса HookDetector вернул true. В случае обнаружения frida на устройстве отображается сообщение и через 2 секунды (2000 миллисекунд) приложение закрывается с помощью System.exit(0). Поэтому нужно данное поведение изменить.

```java
@Override // android.widget.CompoundButton.OnCheckedChangeListener
public void onCheckedChanged(CompoundButton compoundButton, boolean z) {
    if (z && new HookDetector().isFridaServerInDevice()) {
        Toast.makeText(MainActivity.j, "Tampering detected!", 0).show();
        new CountDownTimer(2000L, 1000L) {
            @Override // android.os.CountDownTimer
            public void onFinish() {
                System.exit(0);
            }

            @Override // android.os.CountDownTimer
            public void onTick(long j2) {
            }
        }.start();
    }
}
```

Для отключения проверки можно наиболее простым способом подменить метод exit. Можно и подменить метод, которые находит frida на устройстве и будем возвращать false. Сделаем вторым способом, хотя особой разницы нет.

```javascript
Java.perform(function () {
    const HookDetector = Java.use("org.nowsecure.cybertruck.detections.HookDetector");

    HookDetector.isFridaServerInDevice.implementation = function () {
        console.log("Frida server ignored!")
        return false;
    };
});
```

После запуска и переключения свитча с приложением ничего не происходит, а в консоли появляется сообщение из скрипта.
<details>
  <summary>Скриншот</summary>
  
  ![](/CTF4/2.png)
</details>

Второй свитч при переключении показывает просто сообщение.
<details>
  <summary>Скриншот</summary>
  
  ![](/CTF4/4.png)
</details>

В коде обработка нажатия выглядит так. Кроме сообщения никакой логики нет.

```java
@Override // android.widget.CompoundButton.OnCheckedChangeListener
public void onCheckedChanged(CompoundButton compoundButton, boolean z) {
    if (z) {
        Toast.makeText(MainActivity.j, "Wiping keys...!", 0).show();
    }
}
```

При нажатии на кнопку UNLOCK появляется сообщение на экране и всё.
<details>
  <summary>Скриншот</summary>
  
  ![](/CTF4/3.png)
</details>

Поэтому посмотрим код обработки нажатия.

```java
@Override // android.view.View.OnClickListener
public void onClick(View view) {
    if (button != null) {
        Toast.makeText(MainActivity.this.getApplicationContext(), "Unlocking cars...", 0).show();
        MainActivity.this.k();
    }
}
```

Вызывается какой-то метод k. Посмотрим на него.

```java
protected void k() {
    new Challenge1();
    new a(j);
    init();
}
```

Метод состоит из трёх строк, каждая похожа на отдельный этап задания. Поэтому пойдём по порядку. Рассмотрим класс Challenge1.

```java
public class Challenge1 {
    private static final String TAG = "CyberTruckChallenge";

    public Challenge1() {
        generateKey();
    }

    protected byte[] generateDynamicKey(byte[] bArr) {
        SecretKey generateSecret = SecretKeyFactory.getInstance("DES").generateSecret(new DESKeySpec("s3cr3t$_n3veR_mUst_bE_h4rdc0d3d_m4t3!".getBytes()));
        Cipher cipher = Cipher.getInstance("DES");
        cipher.init(1, generateSecret);
        return cipher.doFinal(bArr);
    }

    protected void generateKey() {
        Log.d(TAG, "KEYLESS CRYPTO [1] - Unlocking carID = 1");
        try {
            generateDynamicKey("CyB3r_tRucK_Ch4113ng3".getBytes());
        } catch (InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException | BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException e) {
            e.printStackTrace();
        }
    }
}
```

Здесь сразу бросается в глаза строчка "s3cr3t$_n3veR_mUst_bE_h4rdc0d3d_m4t3!", которая и является первой секретной строкой, что можно понять по описанию задания, где указано, что первый секрет используется для создания ключа DES.

Второй секрет генерируется в рантайме для разблокировки carid=1. Строку с похожим текстом можно увидеть в методе generateKey, однако метод ничего не возвращает, а только лишь вызывает метод generateDynamicKey и передаёт туда данные. Получить второй токен можно просто скопировав этот класс в тестовое приложение, дальше надо его запустить и получить результат. Это можно сделать, так как все данные используемые для создания ключа и генерации находятся прямо в классе.

Пойдём снова другим путём и просто воспользуемся frida, это будет быстрее, чем создание тестового приложения.

Для этого нужно найти класс Challenge1, заменить реализацию метода generateDynamicKey, просто добавив логирование результата выполнения оригинального методам и по заданию нужно привести токен в шестнадцатеричную форму, для этого воспользуемся отдельной функцией взятой с просторов интернета.

```javascript
Java.perform(function () {
    const Challenge1 = Java.use("org.nowsecure.cybertruck.keygenerators.Challenge1");

    Challenge1.generateDynamicKey.implementation = function (bytes) {
        const dynamicKey = this.generateDynamicKey(bytes);
        console.log("Challenge1 token: " + toHexString(dynamicKey));
        return dynamicKey;
    };
});

function toHexString(byteArray) {
    return Array.from(byteArray, function(byte) {
        return ("0" + (byte & 0xFF).toString(16)).slice(-2);
    }).join("")
}
```

После запуска приложения с frida, нажатия кнопки (перед этим нажмём на свитч TamperProof, не зря же скрипт для обхода написали :D), получаем следующий вывод в консоль.
<details>
  <summary>Скриншот</summary>
  
  ![](/CTF4/5.png)
</details>

Наш токен: 046e04ff67535d25dfea022033fcaaf23606b95a5c07a8c6

Далее разберём класс 'a', который относится к Challenge2.

В отличие от класса Challenge1, этот класс имеет нечитаемые названия и все методы называются 'a'. Понимать где какой можно по передаваемым аргументам. Так в конструкторе принимается Context, который передаётся в метод 'a' с одним параметром типа Context и возвращаемым значением в виде байтового массива.
Если посмотреть метод, то можно легко увидеть стандартное считывание из файла в папке assets, о чём говорит метод getAssets. Поэтому посмотрим этот файл.

```java
public class a {
    public a(Context context) {
        try {
            a("uncr4ck4ble_k3yle$$".getBytes(), a(context));
        } catch (InvalidKeyException | NoSuchAlgorithmException | BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException e) {
            e.printStackTrace();
        }
    }

    protected byte[] a(Context context) {
        InputStream inputStream;
        String readLine;
        Log.d("CyberTruckChallenge", "KEYLESS CRYPTO [2] - Unlocking carID = 2");
        StringBuilder sb = new StringBuilder();
        String str = null;
        try {
            inputStream = context.getAssets().open("ch2.key");
        } catch (IOException e) {
            e.printStackTrace();
            inputStream = null;
        }
        BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStream));
        while (true) {
            try {
                readLine = bufferedReader.readLine();
            } catch (IOException e2) {
                e2.printStackTrace();
            }
            if (readLine == null) {
                return sb.toString().getBytes();
            }
            str = readLine;
            sb.append(str);
        }
    }

    protected byte[] a(byte[] bArr, byte[] bArr2) {
        SecretKeySpec secretKeySpec = new SecretKeySpec(bArr2, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS7Padding");
        cipher.init(1, secretKeySpec);
        return cipher.doFinal(bArr);
    }
}
```

В jadx-gui открыть файл в папке assets можно в дереве проекта.
<details>
  <summary>Скриншот</summary>
  
  ![](/CTF4/6.png)
</details>

Файл обычный текстовый и содержит строку "d474_47_r357_mu57_pR073C73D700!!", которая и есть секрет.

Ключ, который считывается из файла, далее передаётся в метод 'a', который принимает два байтовых массива и возвращает тоже байтовый массив. Этот метод использует первый аргумент для создания ключа AES, а второй для генерации динамического токена, по аналогии с Challenge1. Поэтому сделаем хук для этого метода.

Находим класс 'a' по полному наименованию, дальше находим метод 'a' с аргументами из двух байтовых массивов ("[B" - типы можно подсмотреть во вкладке Smali внизу в jadx-gui, где типы пишутся в том виде, в котором frida их понимает, обычно сложность вызывают массивы, так как классы называются по полному имени, то есть с пакетом, и можно увидеть это в импортах, а примитивные типы, не массивы, пишутся как и называются). При вызове метода 'a' мы вызовем оригинальный метод и запишем результат в консоль. Функция toHexString точно такая же, как была при решении Challenge1 выше.
<details>
  <summary>Скриншот</summary>
  
  ![](/CTF4/7.png)
</details>

Код скрипта.

```javascript
Java.perform(function () {
    const a = Java.use("org.nowsecure.cybertruck.keygenerators.a");

    a.a.overload("[B", "[B").implementation = function (bytes1, bytes2) {
        const dynamicKey = this.a(bytes1, bytes2);
        console.log("Challenge2 token: " + toHexString(dynamicKey));
        return dynamicKey;
    };
});
```

Запустим приложение и нажмём кнопку. В результате получаем в консоли вывод второго токена.
<details>
  <summary>Скриншот</summary>
  
  ![](/CTF4/8.png)
</details>

Второй токен: 512100f7cc50c76906d23181aff63f0d642b3d947f75d360b6b15447540e4f16

Переходим к Challenge3.
В методе 'k' третьей строкой вызывается нативный метод init, который, как можно понять из статического блока вверху MainActivity, находится в библиотеке native-lib, значит нужно искать её. Для этого посмотрим папку lib и там дейсвительно есть библиотека. Выгрузим её с помощью архиватора из apk файла и откроем, проанализируем в ghidra.

В задании написано, что первая строка этого этапа просто находится в нативном коде, попробуем найти её. Для этого воспользуемся поиском по строкам в ghidra, установим минимальную длину например 10. Получаем список строк и одну интересную строку, а именно "Native_c0d3_1s_h4rd3r_To_r3vers3," - здесь есть в конце запятая, но наверное она лишняя, просто её уберём и получим "Native_c0d3_1s_h4rd3r_To_r3vers3".
<details>
  <summary>Скриншот</summary>
  
  ![](/CTF4/9.png)
</details>

Теперь найдём метод init в нативной библиотеке в ghidra.
<details>
  <summary>Декомпилированный метод init</summary>

```c
void Java_org_nowsecure_cybertruck_MainActivity_init(JNIEnv *param_1,jobject param_2)
{
  int in_GS_OFFSET;
  byte abStack124 [4];
  byte *local_78;
  undefined4 local_74;
  JNIEnv *local_70;
  jobject local_6c;
  undefined **local_68;
  size_t local_64;
  byte *local_60;
  int local_5c;
  size_t local_58;
  undefined4 local_54;
  undefined4 local_50;
  undefined4 local_4c;
  undefined4 local_48;
  undefined4 local_44;
  undefined4 local_40;
  undefined4 local_3c;
  undefined4 local_38;
  undefined4 local_34;
  undefined4 local_30;
  undefined4 local_2c;
  undefined4 local_28;
  undefined4 local_24;
  undefined4 local_20;
  undefined4 local_1c;
  undefined4 local_18;
  int local_14;
  
  local_60 = abStack124;
  local_68 = &__DT_PLTGOT;
  local_14 = *(int *)(in_GS_OFFSET + 0x14);
  local_6c = param_2;
  local_70 = param_1;
  local_74 = __android_log_print(2,"CyberTruckChallenge","KEYLESS CRYPTO [3] - Unlocking carID = 3 ")
  ;
  local_18 = 0x33737265;
  local_1c = 0x7633725f;
  local_20 = 0x6f545f72;
  local_24 = 0x33647234;
  local_28 = 0x685f7331;
  local_2c = 0x5f336430;
  local_30 = 0x635f6576;
  local_34 = 0x6974614e;
  local_38 = 0x17571c56;
  local_3c = 0x1257433d;
  local_40 = 0x1d641917;
  local_44 = 0x71170b00;
  local_48 = 0x1f333245;
  local_4c = 0x7b462914;
  local_50 = 0x116f5512;
  local_54 = 0x217002c;
  local_64 = strlen((char *)&local_34);
  local_78 = abStack124 + -(local_64 + 0xf & 0xfffffff0);
  for (local_5c = 0; local_5c < (int)local_64; local_5c = local_5c + 1) {
    local_78[local_5c] = *(byte *)((int)&local_34 + local_5c) ^ *(byte *)((int)&local_54 + local_5 c)
    ;
  }
  if (*(int *)(in_GS_OFFSET + 0x14) == local_14) {
    return;
  }
  local_58 = local_64;
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```

</details>

В коде внизу метода можно увидеть цикл и также можно увидеть в нём операцию XOR и присвоение её результата, следовательно можно догадаться, что это как раз и создание токена. Как и в других методах ранее результат получения токена никуда не попадает, поэтому дополнительных сведений кроме цикла и операции XOR нет и аналогичных функций или чего-то подозрительного кроме этой функции тоже нет. Поэтому попробуем достать результат операции. А сделаем это с помощью frida.

Так как с помощью frida можно приаттачиться к любому адресу в нативной библиотеке, то сделаем это в момент присвоения результата XOR в элемент массива. Для этого найдём в ghidra адрес этого участка и будем забирать из регистра значение.
<details>
  <summary>Скриншот</summary>
  
  ![](/CTF4/10.png)
</details>

Адрес участка равен 0x6d9, так как отбрасывается часть, при которой начинается отсчёт во всей библиотеке, который равен 0x00010000 (0x000106d9 - 0x00010000 = 0x000006d9 = 0x6d9).

Регистр DL - это нижняя часть регистра EDX размером один байт, поэтому для получения значения нужно делать операцию И для четырёхбайтового регистра EDX и числа 0xFF. Это можно не делать, если остальные байты регистра очищены, то есть равны 0.

Скрипт получится таким. Сначала находим базовый адрес библиотеки в памяти, добавляем сдвиг к нужному адресу. Далее при входе на этот адрес считываем значение регистра EDX, делаем операцию И для получения значения регистра DL, после чего из этого числа получаем символ и добавляем к строке, затем выводим всю строку. Вывод строки будет происходить до момента окончания цикла, постепенно строка будет становиться больше. Также перед запуском данной логики ожидаем 500 миллисекунд для загрузки библиотеки.

```javascript
setTimeout(function() {
    const lineAddress = Module.findBaseAddress("libnative-lib.so").add(0x6d9);

    let secret = "";

    Interceptor.attach(lineAddress, {
        onEnter: function() {
            secret += String.fromCharCode(this.context.edx & 0xFF);
            console.log(secret);
        }
    });
}, 500);
```

В итоге получаем такой вывод в консоль.

```txt
[*] Running Script
Challenge1 token: 046e04ff67535d25dfea022033fcaaf23606b95a5c07a8c6
Challenge2 token: 512100f7cc50c76906d23181aff63f0d642b3d947f75d360b6b15447540e4f16
b
ba
bac
back
backd
backd0
backd00
backd00r
backd00r$
backd00r$M
backd00r$Mu
backd00r$Mu$
backd00r$Mu$t
backd00r$Mu$tA
backd00r$Mu$tAl
backd00r$Mu$tAlw
backd00r$Mu$tAlw4
backd00r$Mu$tAlw4y
backd00r$Mu$tAlw4ys
backd00r$Mu$tAlw4ysB
backd00r$Mu$tAlw4ysBe
backd00r$Mu$tAlw4ysBeF
backd00r$Mu$tAlw4ysBeF0
backd00r$Mu$tAlw4ysBeF0r
backd00r$Mu$tAlw4ysBeF0rb
backd00r$Mu$tAlw4ysBeF0rb1
backd00r$Mu$tAlw4ysBeF0rb1d
backd00r$Mu$tAlw4ysBeF0rb1dd
backd00r$Mu$tAlw4ysBeF0rb1dd3
backd00r$Mu$tAlw4ysBeF0rb1dd3n
backd00r$Mu$tAlw4ysBeF0rb1dd3n$
backd00r$Mu$tAlw4ysBeF0rb1dd3n$$
backd00r$Mu$tAlw4ysBeF0rb1dd3n$$m
backd00r$Mu$tAlw4ysBeF0rb1dd3n$$m/
backd00r$Mu$tAlw4ysBeF0rb1dd3n$$m/´
backd00r$Mu$tAlw4ysBeF0rb1dd3n$$m/´
âackd00r$Mu$tAlw4ysBeF0rb1dd3n$$m/´§
backd00r$Mu$tAlw4ysBeF0rb1dd3n$$m/´§
backd00r$Mu$tAlw4ysBeF0rb1dd3n$$m/´§o
backd00r$Mu$tAlw4ysBeF0rb1dd3n$$m/´§o®
backd00r$Mu$tAlw4ysBeF0rb1dd3n$$m/´§o®L
backd00r$Mu$tAlw4ysBeF0rb1dd3n$$m/´§o®Lt
backd00r$Mu$tAlw4ysBeF0rb1dd3n$$m/´§o®Ltæ
backd00r$Mu$tAlw4ysBeF0rb1dd3n$$m/´§o®Ltæ 
backd00r$Mu$tAlw4ysBeF0rb1dd3n$$m/´§o®Ltæ =
```

В задании указано, что при отправке нужно понять размер токена, он равен 32 символа, следовательно найдём такую строку в консоли, она и будет искомым секретом.

Секретный токен: backd00r$Mu$tAlw4ysBeF0rb1dd3n$$

Задание решено, все 6 секретных строк найдены.
