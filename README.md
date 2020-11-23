# Reverse Engineer Introduction &amp; Test

## Информация об инструментах.
  - Андроид версия 7.0
  - Micromax Q402+
  - Magisk v7.5.1
  - Android Studio 3.6.1
  - Frida 12.11.6
  - Recaf-2.12.0
  - Apktool 
  - Mitmproxy
  - Plugin for Android Studio (Smalidea v0.05)
  - decompiler (CFR, FernFlower, Procyon)
  
## Начальное состояние устройства.
  - Перепрошит на чисто, версия прошивки MMX_Q402+_RU_SW_V15_HW_V4.0_20180906
  - Установлено кастомное рекавери
  - Рутован Magisk
  - Поставлена Frida
  - Устройство подключено через mitmproxy, и upstream прокси.
   
## Анализ apk

### Задача
    Выявить правильное значение ключа

### Входные данные
    Подписанный `app.apk`.

### Среда для анализа
    Использую Android Studio, с плагином Smalidea в режиме "Profile or dbg apk.
    Также использую apktool для конвертации apk в jar.
    Через Magisk меняю "resetprop "ro.debuggable" 1"

### Анализ smali 

#### Хранение строк

    Класс example.com.crackme.i содержит основную логику проверки приложения.
    Строки прописаны статически и хранятся внутрии массивов.
    
 ```
 var1[0] = new byte[]{97, 110, 100, 114, 111, 105, 100, 46, 99, 111, 110, 116, 101, 110, 116, 46, 67, 111, 110, 116, 101, 120, 116}; //android.content.Context
 var1[1] = new byte[]{97, 110, 100, 114, 111, 105, 100, 46, 116, 101, 108, 101, 112, 104, 111, 110, 121, 46, 84, 101, 108, 101, 112, 104, 111, 110, 121, 77, 97, 110, 97, 103, 101, 114; //android.telephony.TelephonyManager
 ```
 
#### Хранение строк 


[## ВВОДНОЕ](./intro/)

[## ТЕСТОВОЕ](./test/)
