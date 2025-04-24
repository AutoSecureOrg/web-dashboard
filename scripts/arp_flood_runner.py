from wifi_tool import auto_arp_replay_flood

if __name__ == "__main__":
    report = auto_arp_replay_flood(interface="wlan0")
    print(report)  # << Important: Print the entire report
