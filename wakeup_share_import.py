#!/usr/bin/env python3
import argparse
import json
import secrets
import sys
from pathlib import Path

import requests

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import wakeup_share_sim as sim


def default_apk():
    apks = sorted(Path.cwd().glob("*.apk"))
    if not apks and SCRIPT_DIR != Path.cwd():
        apks = sorted(SCRIPT_DIR.glob("*.apk"))
    return apks[0] if apks else None


def make_common_args(args, channel, public_token):
    return argparse.Namespace(
        area=args.area,
        screensize=args.screensize,
        cuid=args.cuid,
        city=args.city,
        abis=args.abis,
        channel=channel,
        app_bit=args.app_bit,
        device_id=args.device_id,
        public_token=public_token,
        adid=args.adid,
        province=args.province,
        app_id=args.app_id,
        download_type=args.download_type,
        sdk=args.sdk,
        device=args.device,
        brand=args.brand,
        operatorid=args.operatorid,
    )


def extract_antispam_sign_b(response_text):
    payload = json.loads(response_text)
    candidate = payload.get("data")
    if isinstance(candidate, dict):
        candidate = candidate.get("data")
    if not isinstance(candidate, str):
        result_obj = payload.get("result")
        candidate = result_obj.get("data") if isinstance(result_obj, dict) else None
    if not isinstance(candidate, str) or not candidate:
        raise ValueError(f"antispam response did not contain signB: {response_text}")
    return candidate, payload


def parse_json_or_text(text):
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return text


def post_or_raise(url, body, timeout, session, cuid, did, adid, dp_ticket=None):
    resp = sim.post_form(url, body, timeout, session=session, cuid=cuid, did=did, adid=adid, dp_ticket=dp_ticket)
    resp.raise_for_status()
    return resp


def main():
    parser = argparse.ArgumentParser(description="Import/decrypt a WakeUp share code without HAR-derived parameters.")
    parser.add_argument("--apk", default=str(default_apk()) if default_apk() else None)
    parser.add_argument("--cuid", default=None)
    parser.add_argument("--android-id", default=None, help="derive CUID as MD5_UPPER('com.baidu' + android_id) + '|0'")
    parser.add_argument("--random-android-id", action="store_true", help="generate a random 16-hex android_id and derive CUID")
    parser.add_argument("--code", required=True, help="share code")
    parser.add_argument("--api-host", default="https://api.wakeup.fun")
    parser.add_argument("--antispam-host", default="https://api.wakeup.fun")
    parser.add_argument("--resource-host", default="https://resourceserver.zybang.com")
    parser.add_argument("--timeout", type=float, default=15.0)
    parser.add_argument("--check-conf", action="store_true", help="also probe /wakeup/app/conf before share import")
    parser.add_argument("--register-did", action="store_true", help="call /userident/user/getdid and use its returned did")
    parser.add_argument("--verbose", action="store_true")

    parser.add_argument("--public-token", default=None, help="defaults to the APK embedded value")
    parser.add_argument("--operatorid", default="")
    parser.add_argument("--adid", default="")
    parser.add_argument("--did", default="")
    parser.add_argument("--dp-ticket", default=None, help="optional DProtect ticket; cannot be generated offline by this script")
    parser.add_argument("--sdk", default=35, type=int)
    parser.add_argument("--device", default="Pixel 7")
    parser.add_argument("--brand", default="google")
    parser.add_argument("--screensize", default="1080x2400")
    parser.add_argument("--screen", default=None, help="getdid screen field, defaults to reversing --screensize as WxH")
    parser.add_argument("--os-version", default="", help="Android release string used in getdid payload, e.g. 16")
    parser.add_argument("--oaid", default="")
    parser.add_argument("--language", default="zh")
    parser.add_argument("--country", default="CN")
    parser.add_argument("--typewriting", default="")
    parser.add_argument("--operator", default="", help="human readable carrier name used in getdid payload")
    parser.add_argument("--power-on-time", type=int, default=None)
    parser.add_argument("--first-install-time", type=int, default=0, help="used only for bad/empty android_id fallback")
    parser.add_argument("--memory", type=int, default=0)
    parser.add_argument("--hard-disk", type=int, default=0)
    parser.add_argument("--abis", default="arm64-v8a")
    parser.add_argument("--app-bit", default="64")
    parser.add_argument("--device-id", default="")
    parser.add_argument("--download-type", default="1")
    parser.add_argument("--app-id", default="wakeup")
    parser.add_argument("--province", default="")
    parser.add_argument("--city", default="")
    parser.add_argument("--area", default="")
    args = parser.parse_args()

    if not args.apk:
        raise SystemExit("No APK path given and no *.apk found.")
    if args.random_android_id:
        args.android_id = secrets.token_hex(8)
    cuid_source = "argument"
    if not args.cuid:
        if not args.android_id:
            raise SystemExit("Pass --cuid, --android-id, or --random-android-id.")
        args.cuid = sim.cuid_from_android_id(args.android_id, args.device, args.first_install_time)
        cuid_source = "android_id_random" if args.random_android_id else "android_id"
    adid_source = "argument"
    if not args.adid and args.android_id:
        args.adid = sim.adid_from_android_id(args.android_id, args.device, args.first_install_time)
        adid_source = "android_id_random" if args.random_android_id else "android_id"

    apk_path = Path(args.apk)
    manifest = sim.parse_manifest_info(apk_path)
    channel = sim.read_apk_text_entry(apk_path, "assets/channel")
    public_token = args.public_token or sim.read_public_token(apk_path)
    if not public_token:
        raise SystemExit("Could not find the APK embedded public token; pass --public-token explicitly.")

    signature_chars, cert_entry = sim.read_signature_chars(apk_path)
    sign_a, rand10, sign_a_plain = sim.make_sign_a(args.cuid, signature_chars)
    common_params = sim.make_common_params(make_common_args(args, channel, public_token), manifest)

    session = requests.Session()
    antispam_url = args.antispam_host.rstrip("/") + "/pluto/app/antispam"
    antispam = sim.build_antispam_request(sign_a, common_params)
    antispam_resp = post_or_raise(
        antispam_url,
        antispam["body"],
        args.timeout,
        session,
        args.cuid,
        args.did,
        args.adid,
        args.dp_ticket,
    )
    sign_b, antispam_payload = extract_antispam_sign_b(antispam_resp.text)
    antispam_token, sign_b_plain = sim.token_from_sign_b(sign_b, rand10)

    getdid_result = None
    if args.register_did:
        if not args.android_id:
            raise SystemExit("--register-did needs --android-id or --random-android-id for the getdid payload.")
        getdid_payload = sim.build_getdid_payload(
            android_id=args.android_id,
            did=args.did,
            oaid=args.oaid,
            app_id=args.app_id,
            os_version=args.os_version or str(args.sdk),
            language=args.language,
            typewriting=args.typewriting,
            power_on_time=args.power_on_time,
            operator=args.operator,
            country=args.country,
            brand=args.brand,
            model=args.device,
            memory=args.memory,
            hard_disk=args.hard_disk,
            uid="-1",
            screen=args.screen or sim.screen_for_getdid(args.screensize),
        )
        getdid = sim.build_getdid_request(getdid_payload, antispam_token, common_params)
        getdid_url = args.resource_host.rstrip("/") + "/userident/user/getdid"
        getdid_resp = post_or_raise(
            getdid_url,
            getdid["body"],
            args.timeout,
            session,
            args.cuid,
            args.did,
            args.adid,
            args.dp_ticket,
        )
        getdid_response = parse_json_or_text(getdid_resp.text)
        new_did = None
        if isinstance(getdid_response, dict):
            data = getdid_response.get("data")
            if isinstance(data, dict):
                new_did = data.get("did")
        if new_did:
            args.did = new_did
        getdid_result = {
            "url": getdid_url,
            "request_sign": getdid["sign"],
            "encrypted_param": getdid["param"],
            "decoded_param": getdid["decoded_param"],
            "response": getdid_response,
            "did": args.did,
        }

    conf_result = None
    if args.check_conf:
        conf = sim.build_conf_request(antispam_token, common_params)
        conf_url = args.api_host.rstrip("/") + "/wakeup/app/conf"
        conf_resp = post_or_raise(conf_url, conf["body"], args.timeout, session, args.cuid, args.did, args.adid, args.dp_ticket)
        conf_result = {
            "request_sign": conf["sign"],
            "response": parse_json_or_text(conf_resp.text),
        }

    share = sim.build_share_request(
        args.code,
        antispam_token,
        manifest["version_code"],
        common_params,
        did=args.did,
    )
    share_url = args.api_host.rstrip("/") + "/share_schedule/getv2"
    share_resp = post_or_raise(share_url, share["body"], args.timeout, session, args.cuid, args.did, args.adid, args.dp_ticket)
    share_payload = parse_json_or_text(share_resp.text)
    decrypted = sim.decrypt_response_data(share_resp.text, share["rc4_key"])

    output = {
        "ok": isinstance(share_payload, dict) and share_payload.get("errNo") == 0 and "error" not in decrypted,
        "apk": str(apk_path),
        "manifest": manifest,
        "channel": channel,
        "public_token_source": "argument" if args.public_token else "apk",
        "cert_entry": cert_entry,
        "signature_chars_md5": sim.md5_hex(signature_chars),
        "android_id": args.android_id,
        "cuid_source": cuid_source,
        "cuid": args.cuid,
        "adid_source": adid_source,
        "adid": args.adid,
        "did": args.did,
        "share_code": args.code,
        "antispam": {
            "sign_a_plain": sign_a_plain,
            "sign_a": sign_a,
            "sign_b": sign_b,
            "sign_b_plain_latin1": sign_b_plain.decode("latin1", "replace"),
            "token": antispam_token,
        },
        "share": {
            "request_sign": share["sign"],
            "encrypted_request_data": share["data"],
            "raw_response": share_payload,
            "decrypted_response": decrypted,
        },
    }
    if getdid_result is not None:
        output["getdid"] = getdid_result
    if conf_result is not None:
        output["conf"] = conf_result
    if args.verbose:
        output["common_params"] = common_params
        output["antispam_response"] = antispam_payload
        output["share_request_body"] = share["body"]

    print(json.dumps(output, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
