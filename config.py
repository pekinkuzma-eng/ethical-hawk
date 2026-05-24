import netifaces

def get_default_interface():
    """Автоматически находит активный сетевой интерфейс"""
    try:
        # Получаем интерфейс по умолчанию (через который идет интернет)
        gateways = netifaces.gateways()
        default_iface = gateways['default'][netifaces.AF_INET][1]
        if default_iface:
            return default_iface
    except:
        pass
    
    # Если не нашли через gateways, ищем первый интерфейс с IP (не loopback)
    for iface in netifaces.interfaces():
        if iface == 'lo':
            continue
        addrs = netifaces.ifaddresses(iface)
        if netifaces.AF_INET in addrs:
            return iface
    
    return 'eth0'  # fallback

INTERFACE = get_default_interface()

MAX_REQUESTS_PER_MINUTE = 30

BLOCK_SUSPICIOUS_IP = False

LOG_FILE = "logs/attacks.log"

DATABASE_PATH = "database/attacks.db"

print(f"[INFO] Using network interface: {INTERFACE}")
