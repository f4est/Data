def get_disk_usage():
    """
    Возвращает список строк с информацией о дисках.
    Если возникла ошибка с конкретным диском, он пропускается.
    """
    import psutil
    usage_info = []
    try:
        partitions = psutil.disk_partitions(all=False)
        for partition in partitions:
            try:
                usage = psutil.disk_usage(partition.mountpoint)
                total_gb = round(usage.total / (1024 ** 3), 2)
                free_gb = round(usage.free / (1024 ** 3), 2)
                usage_info.append(f"{partition.device}: Total: {total_gb} GB, Free: {free_gb} GB")
            except Exception:
                # Если возникает ошибка для конкретного диска, пропускаем его
                continue
        return usage_info
    except Exception as e:
        return [f"Disk Usage: Error occurred - {e}"]
    
print(get_disk_usage())