# VPS Audit — Researcher Universe Labs

Улучшенный двуязычный Bash-скрипт для **аудита безопасности и состояния Debian/Ubuntu VPS**.

Проект основан на [`nuver-labs/vps-audit`](https://github.com/nuver-labs/vps-audit) и распространяется на условиях MIT License.

Текущая версия: **0.3.3**.

## Основные возможности

- двуязычный вывод: English + русский текст в скобках;
- read-only подход — скрипт не меняет SSH, firewall, Fail2Ban, пакеты или systemd;
- эффективная конфигурация SSH через `sshd -T`;
- проверка `PermitRootLogin`, парольной и ключевой аутентификации;
- проверка UFW, firewalld, nftables и iptables;
- раздельный анализ TCP listeners и UDP bound sockets с разделением loopback и сетевых bind-адресов;
- сворачивание последовательных UDP/TCP-портов в диапазоны в детальном отчёте;
- проверка Fail2Ban, CrowdSec и SSHGuard;
- проверка соответствия порта SSH jail'у Fail2Ban;
- проверка unattended-upgrades и `apt-daily-upgrade.timer`;
- раздельная оценка обычных и security-обновлений;
- анализ failed SSH logins за единое окно времени;
- поддержка `/etc/sudoers.d/` и sudo-rs;
- безопасный SUID scan в пределах корневой файловой системы (`find / -xdev`) с исключением хранилищ Docker/containerd/Snap и поддержкой merged-`/usr` aliases при проверке владельца через dpkg;
- health-показатели CPU, RAM и диска отдельно от security-оценки;
- анализ только реально опубликованных Docker host-портов (`->`), без смешивания с container-only `EXPOSE`, включая детальный блок отчёта;
- проверка `DOCKER-USER` при wildcard-публикациях и активном UFW;
- локальный отчёт с правами `0600`.

## Требования

Рекомендуемые системы:

- Debian 12/13;
- Ubuntu 22.04/24.04/26.04;
- root или `sudo` для полного набора проверок.

Большинство используемых утилит входят в стандартную установку. Отдельные проверки автоматически пропускаются или получают статус INFO/WARN, если нужной команды нет.

## Установка

```bash
curl -fsSLO https://raw.githubusercontent.com/vlwork/vps-audit-Researcher-Universe-Labs/main/vps-audit.sh
chmod +x vps-audit.sh
sudo ./vps-audit.sh
```

Или через `wget`:

```bash
wget https://raw.githubusercontent.com/vlwork/vps-audit-Researcher-Universe-Labs/main/vps-audit.sh
chmod +x vps-audit.sh
sudo ./vps-audit.sh
```

## Запуск

```bash
sudo ./vps-audit.sh
```

Скрипт создаст файл вида:

```text
vps-audit-report-YYYYMMDD_HHMMSS.txt
```

Права отчёта по умолчанию:

```text
0600
```

Это сделано намеренно: отчёт может содержать IP-адреса, открытые порты, названия сервисов и сведения о настройках безопасности.

## Статусы

| Статус | Русский смысл | Значение |
|---|---|---|
| `PASS` | НОРМА | Проверка успешно пройдена |
| `INFO` | ИНФО | Информационный результат |
| `WARN` | ВНИМАНИЕ | Требуется ручная проверка |
| `FAIL` | ОШИБКА | Обнаружена потенциально серьёзная проблема |

`FAIL` не следует автоматически исправлять без анализа контекста сервера.

## Read-only модель

Скрипт **не выполняет** автоматические изменения вроде:

```bash
apt update
apt upgrade
systemctl restart ...
ufw enable
iptables -A ...
nft add ...
sed -i ...
passwd
```

Основное локальное изменение — создание отчёта.

### Внешний запрос

По умолчанию для определения публичного IPv4 выполняется HTTPS-запрос к:

```text
https://api.ipify.org
```

Отключается в начале скрипта:

```bash
ENABLE_PUBLIC_IP_LOOKUP=false
```

## Отличия от upstream

По сравнению с исходным `nuver-labs/vps-audit` эта версия, среди прочего:

- не считает каждый listening socket публичным портом;
- разделяет TCP listeners и UDP bound sockets, чтобы большие WebRTC/VPN UDP-диапазоны не раздували TCP attack surface;
- не принимает простое наличие `Chain INPUT` в iptables за доказательство работающего firewall;
- не называет все доступные APT-обновления security updates;
- проверяет не только наличие `unattended-upgrades`, но и конфигурацию/таймер;
- использует effective SSH config;
- корректнее классифицирует `PermitRootLogin prohibit-password`;
- поддерживает `sudoers.d` и sudo-rs;
- не сканирует рекурсивно отдельные смонтированные файловые системы и common container/image stores при SUID-проверке;
- отличает Docker host publications от внутренних container-only портов и отдельно предупреждает о wildcard-публикациях;
- отделяет health metrics от security findings;
- содержит русские пояснения рядом с английскими результатами.

## Ограничения

- Основная цель — Debian/Ubuntu.
- Скрипт выполняет локальный аудит, а не внешний network scan. Listener на `0.0.0.0` ещё не означает, что порт реально достижим из Интернета: доступ может ограничивать firewall VPS-провайдера, NAT или upstream ACL.
- Для Docker скрипт отдельно показывает host-published ports. При классическом iptables backend активный UFW сам по себе не доказывает, что wildcard Docker publication ограничена; при наличии `DOCKER-USER` проверяется наличие пользовательских правил.
- Результаты являются вспомогательным аудитом и не заменяют ручной security review.

## Проверка синтаксиса

Перед запуском можно выполнить:

```bash
bash -n vps-audit.sh
```

## Upstream и лицензия

Исходный проект:

- https://github.com/nuver-labs/vps-audit
- автор исходной лицензии: Israel Abebe Kokiso
- лицензия: MIT

Эта версия является модифицированным вариантом исходного проекта. Copyright notice и текст MIT License сохранены в файле [`LICENSE`](LICENSE).
