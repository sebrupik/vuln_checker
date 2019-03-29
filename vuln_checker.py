#!/usr/bin/env python3
import requests
import urllib3
import json
import csv
from config.cisco_apiconsole import CLIENT_ID, CLIENT_PASS


DEBUG = False
API_TOKEN_URL = "https://cloudsso2.cisco.com/as/token.oauth2"
PROXIES = {}
API_GET_ADVISORIES = "https://api.cisco.com/security/advisories/ios/?version={0}"
DETAIL_TEXT = "    ID {0} -- {1}\n      First fixed: {2}\n      Bug IDs: {3}\n"


def get_api_token(url):
    response = requests.post(url, verify=False, proxies=PROXIES, data={"grant_type": "client_credentials"},
                             headers={"Content-Type": "application/x-www-form-urlencoded"},
                             params={"client_id": CLIENT_ID, "client_secret": CLIENT_PASS})

    if response is not None:
        return json.loads(response.text)["access_token"]

    return None


def get_advisories_by_release(token, platform, ver):
    platform_dict = {"platform": platform, "release": ver, "advisories": []}
    requests.packages.urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    response = requests.get(API_GET_ADVISORIES.format(ver), verify=False, proxies=PROXIES,
                            headers={"Authorization": "Bearer {0}".format(token), "Accept": "application/json"})

    if response.status_code == 200:
        platform_dict["advisories"] = build_dictionary_relevant_advisories(json.loads(response.text)["advisories"])
        return platform_dict

    return {"platform": platform, "release": ver, "advisories": [], "state": "ERROR", "detail": response.status_code}


def build_dictionary_relevant_advisories(advisories):
    adv_list = []
    for adv in advisories:
        adv_dict = dict()
        adv_dict["advisory_id"] = adv["advisoryId"] if "advisoryId" in adv else "Unknown"
        adv_dict["advisory_title"] = adv["advisoryTitle"] if "advisoryTitle" in adv else "Unknown"
        adv_dict["bug_ids"] = adv["bugIDs"] if "bugIDs" in adv else "Unknown"
        adv_dict["first_fixed"] = adv["firstFixed"] if "firstFixed" in adv else "Unknown"
        adv_list.append(adv_dict)

    return adv_list


def load_csv(input_csv, token):
    psirt_list = []
    with open(input_csv, "r") as file:
        for device_row in csv.DictReader(file):
            psirt_list.append(get_advisories_by_release(token, device_row["platform"], device_row["ios_version"]))

    return psirt_list


def build_csv_dict(source_list):
    csv_dict = dict()

    platforms = dict()
    for p in source_list:
        platforms[p["platform"]] = False

    for item in source_list:
        for adv in item["advisories"]:
            if adv is not None:
                if adv["advisory_id"] not in csv_dict:
                    csv_dict[adv["advisory_id"]] = adv
                    csv_dict[adv["advisory_id"]]["affected_platforms"] = platforms.copy()

                csv_dict[adv["advisory_id"]]["affected_platforms"][item["platform"]] = True

    print(json.dumps(csv_dict, indent=2))
    return csv_dict, list(platforms.keys())


def write_to_csv(source_dict, platform_list):
    headernames = ["advisory_id", "advisory_title", "first_fixed", "bug_ids"] + platform_list

    with open("vuln_checker_output" + ".csv", "w", newline="") as csvfile:
        csvwriter = csv.writer(csvfile, delimiter=",")
        csvwriter.writerow(headernames)

        for adv in source_dict:
            print(adv)
            row = [source_dict[adv]["advisory_id"], source_dict[adv]["advisory_title"],
                   "/ ".join(source_dict[adv]["first_fixed"]), "/ ".join(source_dict[adv]["bug_ids"])]
            for p in platform_list:
                row.append(source_dict[adv]["affected_platforms"][p])

            csvwriter.writerow(row)


def print_advisories(source_dict, detail=True):
    for item in source_dict:
        print("Platform: {0}, Current release: {1}".format(item["platform"], item["release"]))
        print("  {0} advisories".format(len(item["advisories"])))
        if len(item["advisories"]) == 0:
            message = "ERROR encountered during lookup: {0}".format(item["detail"]) if item["state"] == "ERROR" \
                else "None found"

            print("    {0}".format(message))
        else:
            detail_t = ""
            fixed_releases = []
            for adv in item["advisories"]:
                if adv is not None:
                    detail_t = detail_t + DETAIL_TEXT.format(adv["advisory_id"], adv["advisory_title"],
                                                             ", ".join(adv["first_fixed"]), ", ".join(adv["bug_ids"]))
                    fixed_releases = fixed_releases + adv["first_fixed"]

            print("  Minimum suggested release: {0}".format(sorted(fixed_releases)[len(fixed_releases)-1]))
            if detail:
                print(detail_t)


def vuln_checker():
    psirt_list = load_csv("vuln_checker_input.csv", get_api_token("https://cloudsso.cisco.com/as/token.oauth2"))

    print_advisories(psirt_list, True)
    c_dict, p_list = build_csv_dict(psirt_list)
    write_to_csv(c_dict, p_list)


if __name__ == "__main__":
    vuln_checker()
