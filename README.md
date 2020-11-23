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
    Строки прописаны статически и хранятся внутри массивов.
    
 ```
 var1[0] = new byte[]{97, 110, 100, 114, 111, 105, 100, 46, 99, 111, 110, 116, 101, 110, 116, 46, 67, 111, 110, 116, 101, 120, 116}; //android.content.Context
 var1[1] = new byte[]{97, 110, 100, 114, 111, 105, 100, 46, 116, 101, 108, 101, 112, 104, 111, 110, 121, 46, 84, 101, 108, 101, 112, 104, 111, 110, 121, 77, 97, 110, 97, 103, 101, 114; //android.telephony.TelephonyManager
 ```
 
#### Вызовы методов

    Скрытое использование методов осуществляется через рефлексию. 
    Сначала идет принудительная загрузка класса через Class.forName,
    получение объекта  "Method" используя getDeclaredMethod() , и вызов invoke.
      
  ```
  var3 = Class.forName("android.content.Context");
  var4 = var3.getDeclaredMethod("getResources");
  Resources var57 = (Resources)var4.invoke("");//Resources.getResources
  ```

#### Проверка номера девайса

     Также есть проверка номера девайса, если номер девайса не "0000000000000000" , программа выдаст "KEY_INVALID"
     В случае, валидности вызовет System.exit(0).Без изменений, приложение находится изначально в нерабочем состоянии.
     Обходится все при помощи скрипта фриды, либо изменением resetprop.
     Но в любом случае также нужно вставлять кастомное goto до рабочего участка кода. 

  ```
   try {
        Object var63 = var62.invoke(var52); // получить номер девайса
        var2 = new String("0000000000000000");// 0000000000000000 
        
        if ((Boolean) var50.invoke(var63, var2)) { // "вызов equals для номера"
         var61.invoke(var3, 0); //выйти из программы exit 0
        }
        
   } catch (IllegalAccessException var24) {} 
     catch (InvocationTargetException var25) {}
   
   var46 = i.Status.KEY_INVALID;
   return var46; 
  ```
  
#### Проверка количества символов в строке

    Код удаляет все символы "-" затем приводит все в нижний регистр, далее считает общее количество символов 
    и сравнивает его с 16.Можно сделать вывод что у минимального ключа 16 символов, также о том что ключей 
    большое количество, ограниченное лишь вместимостью TextView.
    
  ```
   if (!(Boolean) var50.invoke(Integer.toString((Integer) var56.invoke(var0.replaceAll("-", "").toLowerCase(Locale.UK))), Integer.toString(16))) {
                                var46 = i.Status.KEY_INVALID;
                                return var46;
   }
                            
  ```

#### Основной момент проверки ключа

     Код дальше занимается манипуляцией с массивами, копированием один в другой и использованием алгоритма SHA-1 и AES.
     В конечном результате идет сравнение введенной строки с "3814606579781593".
     Также мне не дает покоя исключение Exception var11, которое бы тоже приводило к возвращению Status.KEY_GOOD.
     Проблема в том что я не придумал способа его вызвать, при этом не вызывать исключение раньше.
     
  ```
   try {
                    byte var7 = getbyte(123, l[5][0], l[0][2], l[0][1]); // 30
                    byte var8 = getbyte(321, l[0][1], l[5][0], l[0][2]); // 120
                    var2 = new String(l[10]); //SHA-1
                    byte[] var54 = Arrays.copyOf(MessageDigest.getInstance("SHA-1").digest(new byte[]{30, 2, 120}), 16); //
                    byte[] var55 = new byte[l[1].length + l[3].length]; // 11 + 9
                    //l[1] = [64, 118, -91, 90, 7, -17, -114, 118, -49, 31, -40]
                    //var55 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
                    System.arraycopy(l[1], 0, var55, 0, l[1].length);
                    //var55 = [64, 118, -91, 90, 7, -17, -114, 118, -49, 31, -40, 0, 0, 0, 0, 0, 0, 0, 0, 0]
                    System.arraycopy(l[3], 0, var55, l[1].length, l[3].length);
                    //var55 = [64, 118, -91, 90, 7, -17, -114, 118, -49, 31, -40, -70, -16, 42, -68, 127, 34, -66, -74, -102]
                    byte[] var60 = new byte[var55.length + 12];
                    //var60 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
                    System.arraycopy(var55, 0, var60, 0, var55.length);
                    //[64, 118, -91, 90, 7, -17, -114, 118, -49, 31, -40, -70, -16, 42, -68, 127, 34, -66, -74, -102, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
                    int var9 = var55.length;
                    // var9 = 20
                    System.arraycopy(new byte[]{122, 125, -19, 33, 69, 71, 112, -6, 36, 19, -90, 118}, 0, var60, var9, 12);
                    // var60 = [64, 118, -91, 90, 7, -17, -114, 118, -49, 31, -40, -70, -16, 42, -68, 127, 34, -66, -74, -102, 122, 125, -19, 33, 69, 71, 112, -6, 36, 19, -90, 118]
                    var0 = var0.replaceAll("-", "").toLowerCase(Locale.UK); //Убираем - из текста
                    var53 = new String(iiiilll(var54, var60)); //3814606579781593

                    if ((Boolean) var50.invoke(var0, var53)) {// сравниваем нашу строку с 3814606579781593
                        var46 = i.Status.KEY_GOOD;
                        return var46;
                    }
                } catch (NumberFormatException var10) {
                    var46 = i.Status.KEY_INVALID;
                    return var46;
                } catch (Exception var11) {
                    var46 = i.Status.KEY_GOOD;
                    return var46;
                }
  
  
  
  
   private static byte getbyte(int var0, byte var1, byte var2, byte var3) {
        int var6 = var1 % 25;
        int var7 = var2 % 3;
        byte var4;
        byte var5;
        if (var6 % 2 == 0) {
            var5 = (byte) (var0 >> var6 & 255 ^ (var0 >> var7 | var3));
            var4 = var5;
        } else {
            var5 = (byte) (var0 >> var6 & 255 ^ var0 >> var7 & var3);
            var4 = var5;
        }

        return var4;
    }
    
    
    private static byte[] iiiilll(byte[] var0, byte[] var1) throws Exception {
        SecretKeySpec var3 = new SecretKeySpec(var0, "AES");
        Cipher var2 = Cipher.getInstance("AES");

        return var4;
    }
    
    
    private static byte[] iiiilll(byte[] var0, byte[] var1) throws Exception {
        SecretKeySpec var3 = new SecretKeySpec(var0, "AES");
        Cipher var2 = Cipher.getInstance("AES");
        var2.init(2, var3);
        return var2.doFinal(var1);
    }
    
  ```
  
#### Вывод

     Apk фаил изначально не работоспособен, попыток связи в интернет не предпринимал.
     Ключ для изначальной версии приложения найден не был.
     При изменении apk был достигнут работоспособный вариант который хранится в папке decision.
     Для него есть множества ключей вида "3814606579781593" , "3-8-1-4-6-0-6-5-7-9-7-8-1-5-9-3" и тд
