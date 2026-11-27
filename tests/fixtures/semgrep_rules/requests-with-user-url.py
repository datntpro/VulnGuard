import requests
def f(base, host, data):
    # ruleid: requests-with-user-url
    requests.get(base + host)
    # ruleid: requests-with-user-url
    requests.post(base + host, data=data)
    # ruleid: requests-with-user-url
    requests.get(f"http://{host}/x")
    # ok: requests-with-user-url
    requests.get("https://api.example.com/x")
    # ok: requests-with-user-url
    requests.get("https://api.example.com" + "/x")
