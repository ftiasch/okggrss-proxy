#!/usr/bin/env python
import os
import argparse
import logging
from typing import Optional
import requests
import argcomplete
import json

from lib import Parser, gen_clash_rules


logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)1.1s%(asctime)s.%(msecs)03d %(process)d %(filename)s:%(lineno)d] %(message)s",
    datefmt="%Y%m%d %H:%M:%S",
)


CLASH_RULES = (
    "direct",
    "proxy",
    "reject",
    "private",
    "apple",
    "icloud",
    "gfw",
    "tld-not-cn",
    "telegramcidr",
    "lancidr",
    "cncidr",
)


def down():
    def fetch(dst, src):
        logging.info("+%s" % (src))
        with open(f"run/{dst}.txt", "w") as f:
            f.write(requests.get(src).text)

    fetch("okgg", "https://rss.okggrss.top/link/3tddh0FHKbzOdLoE?mu=2")
    fetch("ww", "https://ww5271.xyz/rss/mEWrAf3/D7jmP8?net_type=TROJAN")
    fetch(
        "anti-ad",
        "https://raw.githubusercontent.com/privacy-protection-tools/anti-AD/master/adblock-for-dnsmasq.conf",
    )
    for f in ("accelerated-domains", "apple"):
        fetch(
            f,
            f"https://raw.githubusercontent.com/felixonmars/dnsmasq-china-list/master/{f}.china.conf",
        )
    for rs in CLASH_RULES:
        fetch(
            f"clash-{rs}",
            f"https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/{rs}.txt",
        )


def okgg_filter(name: str, _: dict) -> bool:
    if "AI" in name:
        return True
    return False


def ww_filter(name: str, __: dict) -> bool:
    if "JP" in name:
        return True
    return False


def select(nameserver: Optional[str] = None) -> Parser:
    parser = Parser(nameserver)
    parser.parse("okgg", okgg_filter)
    # parser.parse("ww", ww_filter)
    return parser


def clash_rules():
    """
    for gen.sh to read
    """
    print(" ".join(CLASH_RULES))


def gen():
    # with open(f"run/ad-block.json", "w") as f:
    #     json.dump(
    #         {"version": 1, "rules": gen_rules("anti-ad")},
    #         f,
    #         ensure_ascii=False,
    #         indent=2,
    #     )
    # with open(f"run/cn.json", "w") as f:
    #     json.dump(
    #         {
    #             "version": 1,
    #             "rules": [
    #                 {
    #                     "domain_suffix": [
    #                         ".apple.com",
    #                         ".icloud.com",
    #                         ".syncthing.net",
    #                         ".steamserver.net",  # https://github.com/Loyalsoldier/v2ray-rules-dat/issues/254
    #                     ]
    #                 }
    #             ]
    #             + gen_rules("accelerated-domains")
    #             + gen_rules("apple"),
    #         },
    #         f,
    #         ensure_ascii=False,
    #         indent=2,
    #     )
    for rs in CLASH_RULES:
        with open(f"run/clash-{rs}.json", "w") as f:
            json.dump(
                {"version": 1, "rules": gen_clash_rules(rs)},
                f,
                ensure_ascii=False,
                indent=2,
            )
    # ruleset
    rule_set = [
        {
            "type": "remote",
            "tag": "geoip-cn",
            "format": "binary",
            "url": "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs",
        }
    ]
    for rs in CLASH_RULES:
        cname = f"clash-{rs}"
        rule_set.append(
            {
                "type": "local",
                "tag": cname,
                "format": "binary",
                "path": f"/etc/sing-box/{cname}.srs",
            }
        )
    with open("run/rule_set.json", "w") as f:
        json.dump({"route": {"rule_set": rule_set}}, f, ensure_ascii=False, indent=2)
    # outbounds
    parser = select("223.5.5.5")
    with open("run/config.json", "w") as f:
        json.dump(parser.assemble(), f, ensure_ascii=False, indent=2)


def test():
    parser = select()
    print(
        json.dumps([o["tag"] for o in parser.outbounds], ensure_ascii=False, indent=2)
    )


def main():
    os.chdir(os.path.dirname(__file__) or ".")

    parser = argparse.ArgumentParser()
    argcomplete.autocomplete(parser)
    parser.add_argument(
        "func",
        choices=["clash_rules", "gen", "test", "down"],
        default="gen_dry_run",
    )
    args = parser.parse_args()
    globals().get(args.func)()


if __name__ == "__main__":
    main()
