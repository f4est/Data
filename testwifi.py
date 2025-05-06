from sjhvfywuvwwefw import is_admin, run_command


def get_current_wifi_and_nearby():
    """
    1) Определяет текущую подключённую Wi‑Fi-сеть (SSID) + пароль
    2) Сканирует ближайшие (видимые) Wi‑Fi-сети и собирает SSID / BSSID / Уровень сигнала
    
    Требует прав администратора, иначе пароль для текущей сети не будет отображён.
    """
    if not is_admin():
        return {
            "Error": "Admin rights required to access Wi-Fi information."
        }
    
    data = {}

    # --------------------------
    # 1) ТЕКУЩАЯ СЕТЬ + ПАРОЛЬ
    # --------------------------
    interfaces_output = run_command(["netsh", "wlan", "show", "interfaces"])
    current_ssid = None
    # Ищем строку вида "SSID            : MyNetwork"
    for line in interfaces_output.splitlines():
        line_strip = line.strip()
        if line_strip.lower().startswith("ssid") and "bssid" not in line_strip.lower():
            parts = line_strip.split(":", 1)
            if len(parts) > 1:
                current_ssid = parts[1].strip()
                break

    current_password = None
    if current_ssid:
        prof_output = run_command([
            "netsh", "wlan", "show", "profile",
            f"name={current_ssid}", "key=clear"
        ])
        for l in prof_output.splitlines():
            l_strip = l.strip().lower()
            # Ищем строчку с "Key Content" или "Содержимое ключа"
            if l_strip.startswith("key content") or "содержимое ключа" in l_strip:
                parts = l.split(":", 1)
                if len(parts) > 1:
                    current_password = parts[1].strip()
                    break
        
        data["Current Wi-Fi"] = {
            "SSID": current_ssid,
            "Password": current_password if current_password else "Not found"
        }
    else:
        data["Current Wi-Fi"] = {
            "SSID": "Not connected",
            "Password": "N/A"
        }
    
    # ----------------------------------
    # 2) СПИСОК ВИДИМЫХ (БЛИЖАЙШИХ) Wi-Fi
    # ----------------------------------
    # netsh wlan show networks mode=bssid
    networks_output = run_command(["netsh", "wlan", "show", "networks", "mode=bssid"])
    print(networks_output)
    nearby_networks = []
    current_net = {}
    
    # Логика парсинга: Когда начинаем новый "SSID", значит предыдущий блок можно добавить в список
    for line in networks_output.splitlines():
        line_strip = line.strip()

        # Строка вида "SSID 1 : MyNetwork"
        if line_strip.lower().startswith("ssid") and "bssid" not in line_strip.lower():
            # Если уже есть "current_net", сохраняем его
            if current_net:
                nearby_networks.append(current_net)
            current_net = {}
            parts = line_strip.split(":", 1)
            if len(parts) > 1:
                current_net["SSID"] = parts[1].strip()

        # Строка вида "BSSID 1 : xx:xx:xx:xx:xx:xx"
        elif line_strip.lower().startswith("bssid"):
            parts = line_strip.split(":", 1)
            if len(parts) > 1:
                # Собираем все BSSID в список
                current_net.setdefault("BSSIDs", []).append(parts[1].strip())

        # Строка вида "Signal : 63%"
        elif "signal" in line_strip.lower():
            parts = line_strip.split(":", 1)
            if len(parts) > 1:
                current_net["Signal"] = parts[1].strip()
    
    # Добавляем последний блок, если есть
    if current_net:
        nearby_networks.append(current_net)

    data["Nearby Networks"] = nearby_networks if nearby_networks else ["No nearby networks found"]
    
    return data


def get_all_saved_wifi():
    """
    Возвращает все сохранённые на русской Windows Wi-Fi сети (SSID) + пароль.
    Для каждой сети вызывается 'netsh wlan show profile name=... key=clear'.
    
    Требует прав администратора, иначе пароли не будут отображены.
    """
    if not is_admin():
        return {
            "Error": "Admin rights required to access Wi-Fi information."
        }

    saved_profiles_output = run_command(["netsh", "wlan", "show", "profiles"])
    saved_profiles = []
    # Ищем строки вида:
    #   "Все профили пользователей     : MyNetwork"
    #   "All User Profile     : MyNetwork"
    for line in saved_profiles_output.splitlines():
        line_strip = line.strip().lower()
        if (("all user profile" in line_strip or "все профили пользователей" in line_strip)
            and ":" in line):
            parts = line.split(":", 1)
            if len(parts) > 1:
                profile_name = parts[1].strip()
                saved_profiles.append(profile_name)

    # Для каждого профиля берём пароль
    results = []
    for prof in saved_profiles:
        prof_output = run_command([
            "netsh", "wlan", "show", "profile",
            f"name={prof}", "key=clear"
        ])
        pw = None
        for l in prof_output.splitlines():
            l_strip = l.strip().lower()
            if l_strip.startswith("key content") or "содержимое ключа" in l_strip:
                parts = l.split(":", 1)
                if len(parts) > 1:
                    pw = parts[1].strip()
                    break
                    
        results.append({
            "SSID": prof,
            "Password": pw if pw else "Not found"
        })
    
    if not results:
        return {"Saved Wi-Fi Networks": ["No saved networks found"]}
    else:
        return {"Saved Wi-Fi Networks": results}


print(get_all_saved_wifi())
print("+" * 40)
print(get_current_wifi_and_nearby())