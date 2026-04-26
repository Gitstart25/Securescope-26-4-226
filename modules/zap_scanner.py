from zapv2 import ZAPv2
import time

ZAP_PROXY = "http://127.0.0.1:8080"


def run_zap_scan(target_url):
    """
    Runs OWASP ZAP scan and returns raw alerts
    """

    zap = ZAPv2(proxies={"http": ZAP_PROXY, "https": ZAP_PROXY})

    # Access the target
    zap.urlopen(target_url)
    time.sleep(2)

    # Spider scan
    scan_id = zap.spider.scan(target_url)
    while int(zap.spider.status(scan_id)) < 100:
        time.sleep(2)

    # Active scan
    ascan_id = zap.ascan.scan(target_url)
    while int(zap.ascan.status(ascan_id)) < 100:
        time.sleep(5)

    # Get alerts
    alerts = zap.core.alerts(baseurl=target_url)

    return alerts
