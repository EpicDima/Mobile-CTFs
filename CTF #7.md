# CTF \#7

- [Задача](#Задача)
- [Решение](#Решение)

## [Задача](https://ctf.hacker101.com/ctf)

Здесь несколько задача для Android:

- [H1 Thermostat](#H1%20Thermostat) ([ссылка](https://ctf.hacker101.com/ctf/start/13))
- [Intentional Exercise](#Intentional%20Exercise) ([ссылка](https://ctf.hacker101.com/ctf/start/15))
- [Oauthbreaker](#Oauthbreaker) ([ссылка](https://ctf.hacker101.com/ctf/start/21))
- [Mobile Webdev](#Mobile%20Webdev) ([ссылка](https://ctf.hacker101.com/ctf/start/22))

Во всех нужно найти флаги формата "^FLAG^...HEX...\$FLAG\$". Флаги уникальны и отличаются для каждого пользователя.

В первом, третьем и четвёртом - два флага, во втором - один флаг.


## Решение

### H1 Thermostat
Установим и откроем приложение. После нажатия на всех элементах интерфейса и сдвига слайдера вправо и влево, ничего ощутимого не происходит.
<details>
  <summary>Скриншот</summary>
  
  ![](/CTF7/1.png)
</details>

Откроем приложение через jadx-gui. Сразу посмотрим манифест приложения на наличие скрытых Активити, но в манифесте их нет, только одна главная - ThermostatActivity.
```xml
<application android:theme="@style/AppTheme" android:label="@string/app_name" android:icon="@drawable/ic_product_icon_outlined" android:allowBackup="true" android:supportsRtl="true" android:usesCleartextTraffic="true" android:roundIcon="@drawable/ic_product_icon_outlined" android:appComponentFactory="androidx.core.app.CoreComponentFactory">
    <activity android:name="com.hacker101.level11.ThermostatActivity" android:screenOrientation="portrait">
        <intent-filter>
            <action android:name="android.intent.action.MAIN"/>
            <category android:name="android.intent.category.LAUNCHER"/>
        </intent-filter>
    </activity>
    <provider android:name="androidx.lifecycle.ProcessLifecycleOwnerInitializer" android:exported="false" android:multiprocess="true" android:authorities="com.hacker101.level11.lifecycle-process"/>
</application>
```

В классе ThermostatActivity на первый взгляд нет ничего существенного, поэтому вглянем на классы в пакете com.hacker101.level11.
<details>
  <summary>Скриншот</summary>
  
  ![](/CTF7/2.png)
</details>

ThermostatModel - это ViewModel для работы интерфейса приложения, который содержит некоторые интерактивные элементы.

ColorArcProgressBar - это почти круговая шкала температуры в центре экрана.

BuildConfig - это стандартный автосгенерированный класс с параметрами сборки.

PayloadRequest - это класс, который реализует абстрактный класс Request\<T> из пакета com.android.volley, для использования его в сетевых запросов.

R - это стандартный класс со списком идентификаторов ресурсов.

ThermostatActivity - это единственная Активити, которая отображает интерфейс, обрабатывает пользовательский ввод и всё.

Из интересного это PayloadRequest, который как-то связан с сетевыми запросами, хотя приложение такого не подразумевает. При рассмотрении практически моментально можно увидеть два флага в конструкторе.

```java
public PayloadRequest(JSONObject jSONObject, final Response.Listener<String> listener) throws Exception {
    super(1, "https://f2cdbc6c3a7ed502ac901b3c4345a0a9.ctf.hacker101.com/", new Response.ErrorListener() { // from class: com.hacker101.level11.PayloadRequest.1
        @Override // com.android.volley.Response.ErrorListener
        public void onErrorResponse(VolleyError volleyError) {
            Response.Listener.this.onResponse("Connection failed");
        }
    });
    this.mListener = listener;
    String buildPayload = buildPayload(jSONObject);
    this.mParams.put("d", buildPayload);
    MessageDigest messageDigest = MessageDigest.getInstance("MD5");
    messageDigest.update("^FLAG^726095868b93bbafb88267261081028ca506d2f903f7c27745fb1186478b6632$FLAG$".getBytes());
    messageDigest.update(buildPayload.getBytes());
    this.mHeaders.put("X-MAC", Base64.encodeToString(messageDigest.digest(), 0));
    this.mHeaders.put("X-Flag", "^FLAG^9bb5a0d91d81886effea9c35fc251b75c445976f250d617ee0ba44ce49d06a5f$FLAG$");
}
```

Первый флаг лежит в методе messageDigest.update, второй флаг кладётся в качестве значения заголовка X-Flag.

Два флага найдены, задача решена.

### Intentional Exercise
Устанавливаем и запускаем приложение. После некоторого ожидания загружается страница, на которой есть ссылка Flag.
<details>
  <summary>Скриншот</summary>
  
  ![](/CTF7/3.png)
</details>

После нажатия на ссылку загружается другая страница с текстом о неверном флаге.
<details>
  <summary>Скриншот</summary>
  
  ![](/CTF7/4.png)
</details>

Судя по логике работы, всё сделано в WebView. Поэтому посмотреть какие ссылки открываются можно через код программы. Откроем apk файл в jadx-gui.

В манифесте находится только MainActivity из основных компонентов, но указаны несколько интент-фильтров, что может пригодиться.
```xml
<application android:theme="@style/AppTheme" android:label="@string/app_name" android:icon="@mipmap/ic_launcher" android:allowBackup="true" android:supportsRtl="true" android:usesCleartextTraffic="true" android:roundIcon="@mipmap/ic_launcher_round" android:appComponentFactory="android.support.v4.app.CoreComponentFactory">
    <activity android:name="com.hacker101.level13.MainActivity">
        <intent-filter>
            <action android:name="android.intent.action.MAIN"/>
            <category android:name="android.intent.category.LAUNCHER"/>
        </intent-filter>
        <intent-filter>
            <action android:name="android.intent.action.VIEW"/>
            <category android:name="android.intent.category.DEFAULT"/>
            <category android:name="android.intent.category.BROWSABLE"/>
            <data android:scheme="http" android:host="level13.hacker101.com"/>
        </intent-filter>
        <intent-filter>
            <action android:name="android.intent.action.VIEW"/>
            <category android:name="android.intent.category.DEFAULT"/>
            <category android:name="android.intent.category.BROWSABLE"/>
            <data android:scheme="https" android:host="level13.hacker101.com"/>
        </intent-filter>
    </activity>
</application>
```

Класс MainActivity достаточно компактный. Сразу видим в методе OnCreate получение экземпляра WebView, также видим получение данных из интента, ну и url для загрузки страницы.
```java
public class MainActivity extends AppCompatActivity {
    /* JADX INFO: Access modifiers changed from: protected */
    @Override // android.support.v7.app.AppCompatActivity, android.support.v4.app.FragmentActivity, android.support.v4.app.SupportActivity, android.app.Activity
    public void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        setContentView(R.layout.activity_main);
        WebView webView = (WebView) findViewById(R.id.webview);
        webView.setWebViewClient(new WebViewClient());
        Uri data = getIntent().getData();
        String str = "https://630e122590d67b94089c388984220cc3.ctf.hacker101.com/appRoot";
        String str2 = BuildConfig.FLAVOR;
        if (data != null) {
            str2 = data.toStri  ng().substring(28);
            str = str + str2;
        }
        if (!str.contains("?")) {
            str = str + "?";
        }
        try {
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
            messageDigest.update("s00p3rs3cr3tk3y".getBytes(StandardCharsets.UTF_8));
            messageDigest.update(str2.getBytes(StandardCharsets.UTF_8));
            webView.loadUrl(str + "&hash=" + String.format("%064x", new BigInteger(1, messageDigest.digest())));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }
}
```

Данные из интента являются строкой и первые 28 символов обрезаются, после чего добавляются к исходной url, далее проверяется, что полученная после слияния строка содержит в конце знак вопроса ('?') и добавляется в случае отсутствия. Далее идёт блок try..catch, в котором создаётся объект MessageDigest для хэширования строки алгоритмом SHA-256, добавляется соль "s00p3rs3cr3tk3y", затем добавляется получення до этого строка. Далее загружается страница по url, которая получается из строки, которая была создана немного ранее, и к ней прибавляется параметр hash, значение которого принимает 64 символа в шестнадцатеричном виде, который является рассчитанным по строке хэшем.

Откроем исходную url в браузере для поиска чего-нибудь интересного. Открывается точно такая же страница, что и при запуске приложения.

А вот при нажатии на ссылку flag перекидывает на другую страницу, однако самое интересное, что можно посмотреть url этой страницы и в конце добавляется "/flagBearer".

Исходный url: https://630e122590d67b94089c388984220cc3.ctf.hacker101.com/appRoot

URL после перехода: https://630e122590d67b94089c388984220cc3.ctf.hacker101.com/appRoot/flagBearer

Возможно этой части не хватает при расчёте хэша и открытия правильной страницы с флагом. Поэтому запустим приложение через Интент, в котором будет находиться строка с этим кусочком. Помним, что первые 28 символов просто удаляются, поэтому возьмём такую строку "0123456789012345678901234567/flagBearer". Для запуска MainActivity этого приложения с данной строкой воспользуемся командой adb. Команда будет выглядеть так: adb shell am start -n com.hacker101.level13/.MainActivity -d "0123456789012345678901234567/flagBearer"

После выполнения команды открывается приложение и открывается страница, которая содержит искомый флаг.
<details>
  <summary>Скриншот</summary>
  
  ![](/CTF7/5.png)
</details>

Для чтения целой строки, повернём эмулятор.
<details>
  <summary>Скриншот</summary>
  
  ![](/CTF7/6.png)
</details>

Флаг найден, задача решена.


### Oauthbreaker
Установим и откроем приложение, и можем увидеть только кнопку.
<details>
  <summary>Скриншот</summary>
  
  ![](/CTF7/7.png)
</details>

После нажатия на кнопку открывается браузер, на странице находится одна ссылка, на которую также можно нажать.
<details>
  <summary>Скриншот</summary>
  
  ![](/CTF7/8.png)
</details>

После нажатия на ссылку снова попадаем в приложение, но видим пустой экран, однако название Активити другое, следовательно это и есть другая Активити.
<details>
  <summary>Скриншот</summary>
  
  ![](/CTF7/9.png)
</details>

Попробуем посмотреть открываемую в браузере ссылку. Изначально она представляет собой такую строку "https://9f0e3288e0983a26d69d3ca8a3e15377.ctf.hacker101.com/oauth?redirect_url=oauth%3A%2F%2Ffinal%2Flogin&response_type=token&scope=all". Можно увидеть параметр redirect_url со значением "oauth://final/login".

Заменим значение параметра redirect_url на какой-нибудь сайт, например https://google.com ("https://" нужен, так как в оригинале есть "oauth://", которое имеет тот же смысл). URL будет таким: https://9f0e3288e0983a26d69d3ca8a3e15377.ctf.hacker101.com/oauth?redirect_url=https://google.com&response_type=token&scope=all


При перезагрузке страницы с изменённым URL открывается точно такая же страница, на которой присутствует та же ссылка. Перейдём по ней и можно увидеть, что открывется действительно главная страница Google, а сама ссылка содержит флаг. Полный url: https://www.google.com/?token=^FLAG^5bbe3795b78bfe5db6188cf2c40f3f85e5bf8fea259d08376e73535d6a02763b$FLAG$

Следовательно, таким образом нашли первый флаг.

Так как всё возможное с точки зрения пользовательского интерфейса сделали, следовательно пришло время посмотреть на приложению изнутри. Для этого откроем apk файл в jadx-gui.

В манифесте присутствуют две Активити, каждая из которых имеет intent-filter для определённой схемы данных и может открываться в качестве приложения по умолчанию при нажатии на ссылку в таком формате.
```xml
<application android:theme="@style/AppTheme" android:label="@string/app_name" android:icon="@mipmap/ic_launcher" android:allowBackup="true" android:supportsRtl="true" android:usesCleartextTraffic="true" android:roundIcon="@mipmap/ic_launcher_round" android:appComponentFactory="androidx.core.app.CoreComponentFactory">
    <activity android:name="com.hacker101.oauth.Browser">
        <intent-filter>
            <action android:name="android.intent.action.VIEW"/>
            <category android:name="android.intent.category.DEFAULT"/>
            <category android:name="android.intent.category.BROWSABLE"/>
            <data android:scheme="oauth" android:host="final" android:pathPrefix="/"/>
        </intent-filter>
    </activity>
    <activity android:name="com.hacker101.oauth.MainActivity">
        <intent-filter>
            <action android:name="android.intent.action.MAIN"/>
            <category android:name="android.intent.category.LAUNCHER"/>
        </intent-filter>
        <intent-filter>
            <action android:name="android.intent.action.VIEW"/>
            <category android:name="android.intent.category.DEFAULT"/>
            <category android:name="android.intent.category.BROWSABLE"/>
            <data android:scheme="oauth" android:host="login" android:pathPrefix="/"/>
        </intent-filter>
    </activity>
</application>
```

MainActivity, как можно увидеть по первому intent-filter внутри, является стартовой, поэтому интереса особого пока что она не представляет. Посмотрим на вторую Активити с названием Browser.

Здесь можно увидеть, что Активити, как и ожидалось, использует WebView для отображения информации и соответственно url для запросов веб-страниц. В методе onCreate во время настройки WebView можно увидеть метод addJavascriptInterface, который создаёт объект в глобальной области видимости веб-страницы, на подобие document, window, таким образом может быть использован в JavaScript во время работы со страницей по названию, которое указывается вторым аргументом, в данном случае iface.

Метод onCreate класс Browser.
```java
public void onCreate(Bundle bundle) {
    super.onCreate(bundle);
    setContentView(R.layout.activity_browser);
    String str = "https://c2ca46fbe19179750611e53295065d0f.ctf.hacker101.com/authed";
    try {
        Uri data = getIntent().getData();
        if (!(data == null || data.getQueryParameter("uri") == null)) {
            str = data.getQueryParameter("uri");
        }
    } catch (Exception unused) {
    }
    WebView webView = (WebView) findViewById(R.id.webview);
    webView.setWebViewClient(new SSLTolerentWebViewClient(webView));
    webView.getSettings().setJavaScriptEnabled(true);
    webView.addJavascriptInterface(new WebAppInterface(getApplicationContext()), "iface");
    webView.loadUrl(str);
}
```

Посмотрим на класс, который называется WebAppInterface. По сути единственным и примечательным для нас методом является метод getFlagPath. Во-первых, название говорит о том, что он связан с флагом, к тому же возвращает строку, во-вторых, он помечен аннотацией @JavascriptInterface, означающий то, что этот метод может быть вызван из JavaScript кода при работе с веб-страницей.
<details>
  <summary>Класс WebAppInterface</summary>

```java
class WebAppInterface {
    Context mContext;

    /* JADX INFO: Access modifiers changed from: package-private */
    public WebAppInterface(Context context) {
        this.mContext = context;
    }

    @JavascriptInterface
    public String getFlagPath() {
        int[] iArr = {174, 95, 10, 184, 102, 20, 194, 114, 29, 205, 126, 42, 213, 137, 49, 223, 141, 59, 239, 155, 70, 244, 162, 82, 253, 173, 94, 10, 182, 100, 18, 192, 110, 33, 201, 119, 43, 212, 133, 48, 222, 142, 57, 233, 154, 70, 247, 160, 83, 251, 169, 87, 5, 179, 97, 21, 190, 108, 26, 200, 121, 36, 212, 127, 45, 221, 142, 58, 235, 148, 71, 240, 158, 76, 250, 173, 85, 7, 178, 96, 16, 187, 107, 28, 200, 115, 33, 207, 131, 43, 223, 136, 54, 228, 151, 63, 237, 155, 73, 247, 165, 83, 7, 179, 94, 12, 186, 106, 21, 195, 113, 31, 205, 125, 46, 218, 133, 51, 231, 144, 65, 236, 154, 74, 245, 165, 86, 2, 179, 91, 9, 183, 101, 19, 193, 111, 35, 204, 122, 40, 214, 132, 50, 224, 147, 63, 234, 154, 69, 243, 163, 84, 0, 171, 95, 8, 182, 103, 18, 192, 110, 28, 202, 122, 37, 211, 129, 49, 226, 142, 63, 232, 153, 68, 242, 160, 80, 251, 171, 92, 8, 180, 98, 16, 190, 113, 29, 200, 118, 38, 209, 129, 50, 222, 137, 61, 233, 148, 68, 239, 157, 77, 254, 170, 86, 9, 177, 99, 14, 188, 108, 23, 199, 120, 36, 213, 126, 47, 218, 138, 53, 227, 147, 68, 240, 156, 79, 247, 165, 83, 1, 175, 97, 12, 188, 103, 21, 195, 115, 36, 208, 129, 42, 221, 134, 52, 226, 144, 62, 239, 154, 74, 245, 163, 83, 4, 176, 97, 10, 184, 107, 23, 194, 112, 32, 203, 123, 44, 216, 131, 49, 223, 141, 65, 234, 152, 70, 244, 167, 79, 3, 172, 93, 8, 184, 99, 17, 193, 114, 30, 207, 123, 38, 212, 132, 47, 223, 144, 60, 237, 149, 67, 241, 159, 83, 251, 169, 87, 5, 185, 98, 16, 190, 113, 26, 200, 118, 36, 213, 128, 48, 219, 137, 57, 234, 150, 71, 243, 158, 76, 252, 167, 87, 8, 180, 95, 13, 193, 106, 24, 198, 121, 33, 207, 131, 47, 218, 138, 53, 227, 147, 68, 240, 156, 79, 247, 165, 87, 2, 178, 93, 11, 185, 105, 26, 198, 119, 31, 205, 123, 47, 216, 134, 52, 226, 144, 62, 236, 154, 77, 246, 167, 82, 0, 174, 94, 9, 185, 106, 22, 193, 117, 33, 204, 122, 42, 213, 133, 54, 226, 141, 59, 233, 151, 75, 244, 162, 80, 254, 172, 90, 11, 182, 102, 17, 191, 111, 32, 204, 125, 41, 212, 130, 50, 221, 141, 62, 234, 149, 73, 245, 160, 80, 251, 169, 89, 10, 182, 97, 21, 190, 111, 26, 200, 120, 35, 211, 132, 48, 220, 143, 55, 233, 148, 68, 239, 157, 77, 254, 170, 85, 9, 178, 96, 14, 188, 111, 23, 203, 119, 34, 208, 128, 43, 219, 140, 56, 227, 145, 63, 237, 155, 79, 248, 171, 84, 2, 179, 94, 14, 185, 103, 23, 200, 116, 37, 209, 124, 42, 218, 133, 53, 230, 146, 67, 235, 153, 71, 245, 163, 81, 5, 174, 92, 10, 184, 102, 25, 193, 111, 29, 203, 127, 43, 214, 132, 50, 224, 142, 62, 233, 151, 69, 243, 163, 84, 0, 171, 95, 7, 187, 103, 18, 192, 112, 27, 203, 124, 40, 211, 129, 47, 221, 139, 57, 231, 155};
        String str = BuildConfig.FLAVOR;
        byte[] bArr = new byte[65536];
        int i = 0;
        while (i < iArr.length) {
            int i2 = i + 1;
            iArr[i] = (((iArr[i] + 256000) - i) - (i2 * 173)) % 256;
            i = i2;
        }
        int i3 = 0;
        int i4 = 0;
        while (i3 < iArr.length) {
            if (iArr[i3] == 3) {
                i4 = i4 == 65535 ? 0 : i4 + 1;
            } else if (iArr[i3] == 2) {
                i4 = i4 == 0 ? 65535 : i4 - 1;
            } else if (iArr[i3] == 0) {
                bArr[i4] = (byte) (bArr[i4] + 1);
            } else if (iArr[i3] == 1) {
                bArr[i4] = (byte) (bArr[i4] - 1);
            } else if (iArr[i3] == 6) {
                str = str + String.valueOf((char) bArr[i4]);
            } else if (iArr[i3] == 4 && bArr[i4] == 0) {
                int i5 = i3 + 1;
                int i6 = 0;
                while (true) {
                    if (i6 <= 0 && iArr[i5] == 5) {
                        break;
                    }
                    if (iArr[i5] == 4) {
                        i6++;
                    } else if (iArr[i5] == 5) {
                        i6--;
                    }
                    i5++;
                }
                i3 = i5;
            } else if (iArr[i3] == 5 && bArr[i4] != 0) {
                int i7 = i3 - 1;
                int i8 = 0;
                while (true) {
                    if (i8 <= 0 && iArr[i7] == 4) {
                        break;
                    }
                    if (iArr[i7] == 5) {
                        i8++;
                    } else if (iArr[i7] == 4) {
                        i8--;
                    }
                    i7--;
                }
                i3 = i7 - 1;
            }
            i3++;
        }
        return str + ".html";
    }
}
```
</details>

По сути этот метод можно легко и просто вызвать с помощью frida, но можно поиграть по правилам этого задания и попробовать получить флаг с помощью JS. Так и поступим.

В методе onCreate есть URL, который используется по умолчанию при отсутствии данных у Интента. В случае, если данные есть, то загружается именно страница, адрес которой получен из Интента. Для этого в переданной в Активити строке находится параметр uri и его значение записывается в переменную str. Из этого делаем вывод, что нужно передать в этом параметре такую страницу, которая вызовет метод в JS - iface.getFlagPath.

Также помним, что каждая из Активити приложения имеет интент-фильтры, которые содержат определённый контракт, по которому они открываются. Поэтому для теста того, что ссылка из uri действительно откроется воспользуемся adb и попробуем открыть Активити Browser. Для этого нужна такая команда: adb shell am start -d "oauth://final/?uri=https://google.com"

После запуска команды открывается страница Google, то есть всё отлично работает.
<details>
  <summary>Скриншот</summary>
  
  ![](/CTF7/10.png)
</details>

Так как создавать где-либо сайт это чуть дольше, чем хотелось бы, можно использовать локальный файл для загрузки в WebView. Единственное, так как у приложения нет доступов к общему хранилищу, то придётся положить файл в приватном каталоге приложения, что не является проблемой, так как используется эмулятор с root правами.

Но в начале нужно написать скрипт, который будет вызывать необходимый метод и отображать содержимое ответа. Назовём весь файл flag.html. Я добавил стили, так как на эмуляторе у меня обрезаются левая и правая части страницы, из-за чего флаг нельзя было прочитать целиком. В любом случае главное здесь то, что находится в теге script.
```html
<html>
<style>
    #result {
        width: 75%;
        margin-top: 50%;
        margin-left: auto;
        margin-right: auto;
        word-break: break-all;
    }
</style>

<body>
    <div id="result">
    </div>
</body>
<script>
    document.getElementById("result").innerText = iface.getFlagPath()
</script>

</html>
```

Для того, чтобы файл загрузить в нужную папку на устройстве, можно использовать команду adb push. Также обязательно надо перезапустить adb для получения root прав командой "adb root", если их по какой-то причине у adb нет. Итоговая команда будет такой: adb push "flag.html" "/data/data/com.hacker101.oauth/flag.html"

Осталось только отправить правильный Интент. Для этого поменяем значение uri на полный путь к файлу, при этом начало, а именно параметр scheme (это http, https, ftp или другие) должен быть file. То есть команда будет такой: adb shell am start -d "oauth://final/?uri=file:///data/data/com.hacker101.oauth/flag.html"

Данные, которые передаём в виде строки достаточно легко понять. oauth://final/ - это тот тип url, который открывается именно в Активити Browser этого приложения, далее параметр uri, который в Активити проверяется и оттуда берётся значение, далее file:// - стандартное написание схемы, затем /data/data/com.hacker101.oauth/flag.html - абсолютный путь к файлу в приватной директории.

При запуске команды открывается приложение и на экране можно увидеть длинное название html файла.
<details>
  <summary>Скриншот</summary>
  
  ![](/CTF7/11.png)
</details>

Скопируем, то есть перепишем :(, название и добавим к URL в браузере, откуда скачали apk файл при старте решения этого CTF на сайте hacker101.com. Откроем эту страницу и сразу видим искомый флаг.
<details>
  <summary>Скриншот</summary>
  
  ![](/CTF7/12.png)
</details>

Второй флаг найден, задание выполнено.

### Mobile Webdev
Как всегда установим и откроем приложение. Нас сразу встречает экран с двумя кнопками вверху, а также, как можно понять по скорости загрузки и внешнему виду, WebView, находящаяся под ними.
<details>
  <summary>Скриншот</summary>
  
  ![](/CTF7/13.png)
</details>

При нажатии на кнопку REFRESH ничего не происходит. А вот при нажатии на кнопку EDIT загружается другая веб-страница со списком файлов, которые можно нажать. В данном случае только один файл index.html.
<details>
  <summary>Скриншот</summary>
  
  ![](/CTF7/14.png)
</details>

Нажмём на единственный файл и нас сразу перебрасывает на другую страницу, в этот раз для редактирования содержимого файла.
<details>
  <summary>Скриншот</summary>
  
  ![](/CTF7/15.png)
</details>

Добавим текст.
<details>
  <summary>Скриншот</summary>
  
  ![](/CTF7/16.png)
</details>

Затем нажмём кнопку SAVE для сохранения. Получаем подтверждение этой операции.
<details>
  <summary>Скриншот</summary>
  
  ![](/CTF7/17.png)
</details>

По ссылке return возвращаемся на известную страницу со списком файлов для редактирования. При нажатии на index.html снова переходим на страницу редактирования. Также можно заметить, что правая кнопка имеет текст VIEW, а не EDIT, как было изначально. При нажатии на неё открывается главная страница, как это было при старте приложения, но уже с добавленным текстом.
<details>
  <summary>Скриншот</summary>
  
  ![](/CTF7/18.png)
</details>

Пришло время посмотреть код в jadx-gui, так как по большому счёту больше сделать здесь нечего.

В манифесте лежит всего лишь одна стандартная Активити.
```xml
<application android:theme="@style/AppTheme" android:label="@string/app_name" android:icon="@mipmap/ic_launcher" android:allowBackup="true" android:supportsRtl="true" android:usesCleartextTraffic="true" android:roundIcon="@mipmap/ic_launcher_round" android:appComponentFactory="androidx.core.app.CoreComponentFactory">
    <activity android:name="com.hacker101.webdev.MainActivity">
        <intent-filter>
            <action android:name="android.intent.action.MAIN"/>
            <category android:name="android.intent.category.LAUNCHER"/>
        </intent-filter>
    </activity>
</application>
```

Здесь также используется WebView, в принципе как и было понятно. Можно увидеть метод, который отвечает за обработку нажатий, который содержит два URL адреса.
```java
@Override // android.view.View.OnClickListener
public void onClick(View view) {
    int id = view.getId();
    if (id != R.id.edit) {
        if (id == R.id.refresh) {
            this.webView.reload();
        }
    } else if (this.editing.booleanValue()) {
        this.editButton.setText("Edit");
        this.webView.loadUrl("https://06fa1cd42590f9a715cb95259c15fb3b.ctf.hacker101.com/content/");
        this.editing = false;
    } else {
        this.editButton.setText("View");
        this.webView.loadUrl("https://06fa1cd42590f9a715cb95259c15fb3b.ctf.hacker101.com/edit.php");
        this.editing = true;
    }
}
```

В самом классе можно обнаружить интересные детали. Первая - это поле HmacKey. Вторая деталь - это метод Hmac без реализации.

```java
protected String HmacKey = "8c34bac50d9b096d41cafb53683b315690acf65a11b5f63250c61f7718fa1d1d";

protected String Hmac(byte[] bArr) throws Exception {
    throw new Exception("TODO: Implement this and expose to JS");
}
```

[HMAC](https://ru.wikipedia.org/wiki/HMAC) простыми словами это техника, при которой берётся кусок передаваемых данных, из него высчитывается хэш (по стандарту не самый стойкий MD5) с солью, которая изначально известна обеим сторонам, после чего хэш добавляется в эти данные и передаётся получателю.

Так как в коде есть метод, который должен был реализовать HMAC, значит есть передача данных. Так как в мобильном приложении есть кусочки, которые не реализованы, а само приложение по большей части работает через WebView, значит по логике такие же куски недоделанного кода могут быть и по ссылкам, которые представлены в приложении.

По ссылке "https://06fa1cd42590f9a715cb95259c15fb3b.ctf.hacker101.com/content/" в исходном коде страницы ничего не обнаружилось, только то, что это именно тот текст, который редактировался в приложении.

По ссылке "https://06fa1cd42590f9a715cb95259c15fb3b.ctf.hacker101.com/edit.php" обнаружился в коде комментарий с указанием адреса upload.php.

```html
<h1>Edit Contents</h1>
<!-- <a href="upload.php">Upload</a> -->
<ul>
<li><a href="edit.php?file=index.html">index.html</a></li>
</ul>
```

Перейдём по нему и видим форму для загрузки файла. Такое должно быть реализовано в приложении в том числе, а HMAC, скорее всего, должен был рассчитываться на основе загружаемого файла.
<details>
  <summary>Скриншот</summary>
  
  ![](/CTF7/19.png)
</details>

Из кода страницы понятно, что для загрузки требуется именно zip архив.Код выглядит таким образом.
```html
<h1>Upload Archive</h1>
<form action="upload.php" method="POST" enctype="multipart/form-data">
	<input type="file" name="file" accept=".zip">
	<input type="submit" value="Upload">
</form>
```

Попробуем создать zip архив и загрузить на сайт. В zip архив добавим файл test.txt с содержимым "1234567890", а сам архив назовём test.zip.

При отправке этого файла перебрасывает на страницу, в которой указано, что HMAC не правильный. Код этой страницы содержит исключительно строку, представленную на изображении, даже нет html тегов.
<details>
  <summary>Скриншот</summary>
  
  ![](/CTF7/20.png)
</details>

Скорее всего HMAC будет содержаться как поле ввода формы, так как JavaScript код полностью отсутствует на странице upload.php. Можно рассчитать HMAC в онлайн сервисе и подменить запрос в браузере с помощью Инструментов разработчика. А можно создать html файл, в который добавить ещё один input. Сделаем вторым способом.

Код файла с названием, например, upload.html, будет таким.
```html
<h1>Upload Archive</h1>
<form action="https://06fa1cd42590f9a715cb95259c15fb3b.ctf.hacker101.com/upload.php" method="POST" enctype="multipart/form-data">
	<input type="file" name="file" accept=".zip">
	<input type="text" name="hmac">
	<input type="submit" value="Upload">
</form>
```

Для расчёта HMAC воспользуемся очень удобным сайтом https://gchq.github.io/CyberChef/, в нём выберем найдём в списке слева HMAC, перетащим в центральный элемент, далее укажем Hashing function - MD5, в поле ключ вставим строку из кода приложения "8c34bac50d9b096d41cafb53683b315690acf65a11b5f63250c61f7718fa1d1d", в этом же поле укажем справа формат HEX. Далее кнопкой для импорта файла загрузим созданный архив с текстовым файлом и в итоге получим значение 4d92f2c93a9866a86d3c3f7f5a2a1665.
<details>
  <summary>Скриншот</summary>
  
  ![](/CTF7/21.png)
</details>

Откроем созданный upload.html, выберем архив и укажем рассчитанный HMAC.
<details>
  <summary>Скриншот</summary>
  
  ![](/CTF7/22.png)
</details>

Далее нажмём кнопку Upload и после небольшого ожидания получим результат, который содержит флаг и подсказку для получения второго флага.
```txt
Extracted to temp folder. TODO: Copy to content directory. ^FLAG^e83e6a42e011d14bca4963a3a67546b4615aced33e33cdbccbdba6d3772a2b03$FLAG$
```

Получение второго флага, а точнее того, как мыслить дальше, несмотря на подсказку, поставило немного в тупик, но благодаря интернету, да-да, всё стало понятно.

Оказывается, можно создать такие zip файлы, которые при распаковке в директории, извлекут файлы не в указанную директорию, а в директории выше, то есть более корневые и это может стать причиной какой-либо уязвимости. После недолгих поисков на Гитхабе был найден репозиторий, в котором описывалась данная уязвимость, проведено исследование и содержался пример такого файла (https://github.com/snyk/zip-slip-vulnerability/blob/master/archives/zip-slip.zip).

Скачаем этот файл, переименуем в test2.zip. Далее рассчитаем тем же способом HMAC и с помощью созданной веб-странички отправим его.
<details>
  <summary>Скриншоты</summary>
  
  ![](/CTF7/23.png)
  ![](/CTF7/24.png)
</details>

В результате открывается страница, содержащая оба флага.
```
Valid HMAC: ^FLAG^e83e6a42e011d14bca4963a3a67546b4615aced33e33cdbccbdba6d3772a2b03$FLAG$
Path traversal: ^FLAG^3157c1a0d1b0937f6fddc9c0fa53e21caeaf9875521b1d3623a98589595cd1af$FLAG$
```

Два флага найдены, это и все предыдущие задания решены.
