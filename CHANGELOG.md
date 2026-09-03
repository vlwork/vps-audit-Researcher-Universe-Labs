# Changelog

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
