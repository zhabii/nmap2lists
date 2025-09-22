# nmap2lists

Парсит XML вывод Nmap и создает контрольные списки хостов по сервисам.
За основу взята идея Ройса Д. из книги "Исскуство на проникновение в сеть". Ознакомиться с оригинальным скриптом можно [здесь](https://github.com/R3dy/parsenmap)

## Установка

```bash
git clone https://github.com/zhabii/nmap2lists.git
cd nmap2lists
chmod +x nmap2lists.py
```
---
## Зависимости

- Python 3.6+
- Стандартные библиотеки Python (никаких дополнительных зависимостей)
---
## Использование 

```bash
nmap -sV 192.168.0.1/24 -oX full-sweep
python3 nmaparser.py --input full-sweep.xml --dir ./output
```

Пример вывода:
```plain
[*] Parsing /home/username/Pentest/target/discovery/services/quick-sweep.xml
[*] Found 2919 open ports on 1378 unique hosts
[*] Saving results to ./lists
[+] All ports saved to: lists/all_ports.txt
[+] All IPs saved to: lists/all_ips.txt
[+] ssh: 360 hosts saved to lists/ssh.txt
[+] windows_smb: 578 hosts saved to lists/windows_smb.txt
[+] rdp: 346 hosts saved to lists/rdp.txt
[+] vnc: 170 hosts saved to lists/vnc.txt
[+] web: 758 hosts saved to lists/web.txt
[+] mysql: 103 hosts saved to lists/mysql.txt
[+] dns: 2 hosts saved to lists/dns.txt

[*] Summary:
    dns: 2 hosts (0.1%)
    mysql: 103 hosts (7.5%)
    rdp: 346 hosts (25.1%)
    ssh: 360 hosts (26.1%)
    vnc: 170 hosts (12.3%)
    web: 758 hosts (55.0%)
    windows_smb: 578 hosts (41.9%)
[+] Done! Processed 1378 unique hosts.
```
---
## Контрольные списки 

| Категория   | Порты               | Сервисы                   |
| ----------- | ------------------- | ------------------------- |
| web         | 80, 443, 8080, 8443 | http, https               |
| ssh         | 22, 2222            | ssh                       |
| windows_smb | 139, 445            | microsoft-ds, netbios-ssn |
| ftp         | 21, 2121            | ftp                       |
| rdp         | 3389                | ms-wbt-server             |
| mssql       | 1433                | ms-sql-s                  |
| mysql       | 3306                | mysql                     |
| vnc         | 5800, 5900          | vnc                       |
| smtp        | 25, 465, 587        | smtp                      |
| dns         | 53                  | domain                    |
| snmp        | 161                 | snmp                      |

А также список (other для всех прочих портов)
