Исправлена установка, которая могла останавливаться из-за нерабочей записи Spotify в `hosts`.

### Что сделано

- Сохранены запасные адреса из комплекта программы. В 0.1.0 они терялись, когда установщик находил другую запись Spotify в `hosts`. Теперь запасной адрес тоже проверяется по HTTPS и может заменить неотвечающий.
- Отчёт установки сохраняется в `data\setup-result.json`, включая неудачные попытки. Кнопка «Открыть журнал» показывает его и после незавершённой установки.
- Ошибка установки указывает неответивший домен. В `bootstrap\status.json` добавлены результаты проверки запасных адресов; промежуточные результаты сохраняются при раннем сбое.
- Версия системного curl проверяется до сетевых запросов. Отсутствие поддержки JSON теперь получает отдельное сообщение.

### Как установить

Скачайте **SpotiRoute.exe**, откройте его и нажмите **«Установить компонент»**. После ошибки 0.1.0 можно повторить установку новым EXE, сохранив папку данных и резервные копии.

Уже работающий фоновый компонент версия 0.1.1 автоматически не заменяет: простая замена EXE обновляет окно программы.

### Проверено

- [Сборка и 60 тестов](https://github.com/kappapr1der/spotiroute/actions/runs/42061779952) на GitHub; проверка вложенных файлов EXE.
- Сетевая проверка на Windows 11: для неотвечающего `143.20.64.192` найден `199.232.210.250` после загрузки двух разных обложек по HTTPS. Проверка выполнялась без записи в действующий `hosts`.

Требуются Windows 10/11, .NET Framework 4.8, Windows PowerShell 5.1 и curl 7.70+. Выпуск остаётся beta: полный цикл на чистой VM пока не проверен. EXE не подписан цифровым сертификатом; управляющий маршрут зависит от шлюза AstraCat.

[Скачать EXE](https://github.com/kappapr1der/spotiroute/releases/download/v0.1.1/SpotiRoute.exe) · [ZIP-архив](https://github.com/kappapr1der/spotiroute/releases/download/v0.1.1/SpotiRoute-0.1.1-win.zip) · [SHA256](https://github.com/kappapr1der/spotiroute/releases/download/v0.1.1/SHA256SUMS.txt) · [Изменения в коде](https://github.com/kappapr1der/spotiroute/compare/v0.1.0...v0.1.1)

### Диагностика таймаутов

Если установка останавливается на `i.scdn.co` с HTTP 0, можно собрать подробную проверку соединения: [скачать диагностику](https://github.com/kappapr1der/spotiroute/releases/download/v0.1.1/SpotiRoute-Diagnostics-0.1.1.zip), распаковать и запустить `Run-Diagnostics.cmd`. Рядом появится `SpotiRoute-Diagnostics.json`.

Пакет проверяет соединения и сохраняет отчёт. Права администратора не требуются; настройки сети и файл `hosts` не меняются. Исходники находятся в папке [`diagnostics`](https://github.com/kappapr1der/spotiroute/tree/main/diagnostics).
### Если не удаётся войти в Spotify

Для ошибки `accesspoint:37`, недоступных настроек прокси или чёрного окна настроек есть отдельная [диагностика входа](https://github.com/kappapr1der/spotiroute/releases/download/v0.1.1/SpotiRoute-Desktop-Diagnostics-0.1.1.zip). Распакуйте архив и запустите `Run-Desktop-Diagnostics.cmd` при открытом окне входа Spotify. Нужный файл — `SpotiRoute-Desktop-Diagnostics.json`.

В отчёт входят версия приложения, сводка режима прокси и проверки серверов входа. Логин, пароль, адрес прокси и токены из файла настроек не включаются. Программа ничего не меняет и не выполняет авторизацию. Исходники: [`desktop-diagnostics`](https://github.com/kappapr1der/spotiroute/tree/main/desktop-diagnostics).

### Если HTTPS доступен, но accesspoint:37 остаётся

Добавлена [проверка протокола access point](https://github.com/kappapr1der/spotiroute/releases/download/v0.1.1/SpotiRoute-AccessPoint-Diagnostics-0.1.1.zip). Распакуйте архив и запустите Run-AccessPoint-Diagnostics.cmd при работающей стратегии Zapret и открытом экране ошибки Spotify. Отчёт — SpotiRoute-AccessPoint-Diagnostics.json.

Проба отправляет начальный ClientHello и проверяет подпись ответа сервера Spotify. Вход в аккаунт не выполняется; файлы аккаунта не читаются. Проверено 16 случаев обработки пакетов и подписи, а также семь реальных соединений с access point на Windows PowerShell 5.1. Успех этой пробы подтверждает начальный ответ сервера, но не авторизацию официального клиента. Исходники: [accesspoint-diagnostics](https://github.com/kappapr1der/spotiroute/tree/main/accesspoint-diagnostics).
