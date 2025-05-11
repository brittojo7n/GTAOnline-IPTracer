import psutil
import time

def find_gta_process():
    for proc in psutil.process_iter(['pid', 'name']):
        if proc.info['name'] and 'gta5.exe' in proc.info['name'].lower():
            return proc
    return None

def switch_to_solo_session():
    gta_proc = find_gta_process()
    if gta_proc:
        print(f"Suspending GTA5 process (PID: {gta_proc.pid})...")
        gta_proc.suspend()
        time.sleep(10)
        print("Resuming GTA5 process...")
        gta_proc.resume()
        print("Done.")
    else:
        print("GTA5 process not found.")

if __name__ == "__main__":
    switch_to_solo_session()
