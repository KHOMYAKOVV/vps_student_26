import re
import socket
import hashlib


def extract_ip(log_line: str) -> str | None:
    """
    Кейс 1: Поиск IP-адреса в строке лога SSH.
    """
    if "Failed password" not in log_line:
        return None

    match = re.search(
        r"from\s+(\d{1,3}(?:\.\d{1,3}){3})",
        log_line
    )

    if match:
        return match.group(1)

    return None


def group_by_ip(log_lines: list[str]) -> dict[str, int]:
    """
    Кейс 2: Подсчет неудачных попыток входа по IP-адресам.
    """
    attacks: dict[str, int] = {}

    for line in log_lines:
        ip = extract_ip(line)

        if ip is not None:
            attacks[ip] = attacks.get(ip, 0) + 1

    return attacks


def detect_brute_force(
    ip_counts: dict[str, int],
    threshold: int = 5
) -> list[str]:
    """
    Кейс 3: Поиск IP-адресов с количеством попыток
    не меньше заданного порога.
    """
    alerts: list[str] = []

    for ip, count in ip_counts.items():
        if count >= threshold:
            alerts.append(ip)

    return alerts


def detect_suspicious_paths(log_line: str) -> bool:
    """
    Кейс 4: Поиск подозрительных сигнатур в веб-логах.
    """
    signatures = [
        "/etc/passwd",
        ".env",
        "wp-admin",
        "select+union",
        "union+select",
        "shell.php"
    ]

    log_line = log_line.lower()

    for signature in signatures:
        if signature in log_line:
            return True

    return False


def calculate_risk_score(
    brute_force_alerts: int,
    web_alerts: int
) -> str:
    """
    Кейс 5: Расчет уровня риска.
    """
    risk_score = brute_force_alerts * 3 + web_alerts

    if risk_score == 0:
        return "LOW"
    elif risk_score < 5:
        return "MEDIUM"
    else:
        return "HIGH"


def is_port_open(
    ip: str,
    port: int,
    timeout: float = 1.0
) -> bool:
    """
    Кейс 6: Проверка доступности TCP-порта.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            return result == 0

    except (socket.timeout, socket.error, OSError):
        return False


def get_file_hash(filepath: str) -> str:
    """
    Кейс 7: Вычисление SHA-256 хеша файла.
    """
    sha256_hash = hashlib.sha256()

    try:
        with open(filepath, "rb") as file:
            while True:
                block = file.read(4096)

                if not block:
                    break

                sha256_hash.update(block)

        return sha256_hash.hexdigest()

    except FileNotFoundError:
        return "FILE_NOT_FOUND"
