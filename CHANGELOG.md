# Changelog

## 0.3.3

- Исправлена проверка владельца SUID-файлов на merged-`/usr` Debian/Ubuntu: учитываются эквивалентные пути `/bin` ↔ `/usr/bin`, `/sbin` ↔ `/usr/sbin`, `/lib` ↔ `/usr/lib` и `/lib64` ↔ `/usr/lib64` только когда соответствующий top-level каталог действительно является merged-`/usr` symlink.
- Детальный блок `Docker host-published ports` теперь выводит только mappings с `->` и не показывает рядом container-only `EXPOSE` записи того же контейнера.
- Устранён ложный SUID WARN для штатных файлов наподобие `fusermount3`, когда dpkg хранит исторический `/bin/...` путь, а filesystem scan возвращает `/usr/bin/...`.

## 0.3.2

- TCP listeners и UDP bound sockets теперь считаются и оцениваются раздельно.
- Последовательные порты в детальном network-отчёте сворачиваются в диапазоны, например `50000-50100/udp`.
- Docker `EXPOSE` больше не считается host publication: учитываются только mappings с `->`.
- Добавлена проверка wildcard Docker publications и состояния `DOCKER-USER` при активном UFW.
- SUID scan исключает common Docker/containerd/containers/LXC/Snap image stores и учитывает canonical path через `readlink -f`.
- Уменьшены ложные WARN для серверов с WebRTC, VPN и контейнерными образами.
- README обновлён для публичного репозитория `vlwork/vps-audit-Researcher-Universe-Labs`.

## 0.3.1

- Добавлен двуязычный English/Russian вывод.
- Переведены заголовки, статусы, названия проверок и пояснения.
- Сохранён английский текст для совместимости и однозначности терминов.

## 0.3.0

- Исправлена классификация listening/public ports.
- Добавлена обработка TCP и UDP listeners.
- Улучшена проверка UFW/firewalld/nftables/iptables.
- SSH-проверки переведены на effective configuration через `sshd -T`.
- Улучшена проверка Fail2Ban и соответствия SSH-порта jail'у.
- Разделены обычные и security APT updates.
- Улучшена проверка unattended-upgrades и apt timer.
- Добавлена поддержка sudoers.d и sudo-rs.
- SUID scan ограничен текущей файловой системой через `-xdev`.
- Health metrics отделены от security findings.
- Добавлен обзор Docker published ports.
- Отчёты создаются с безопасным umask и правами `0600`.
