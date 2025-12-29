"""Simple helper to query the ENISA EUVD API for product vulnerabilities.

The API is documented at https://euvd.enisa.europa.eu/apidoc. This module focuses on
searching for vulnerabilities related to a particular solution (for example
"wazuh"). It keeps the request logic small and dependency-free so it can be
used as a library or run as a standalone CLI.
"""

from __future__ import annotations

import json
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional


class EuvdClient:
    """Minimal EUVD API client.

    Parameters
    ----------
    base_url:
        Base API URL. The default matches the documented public endpoint.
    session:
        Optional :class:`urllib.request.OpenerDirector` if you want to reuse
        connections or inject custom handlers.
    """

    def __init__(
        self,
        base_url: str = "https://euvdservices.enisa.europa.eu/api",
        session: Optional[urllib.request.OpenerDirector] = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        # ``urllib.request`` uses an opener to issue requests. The default
        # opener is equivalent to calling ``urllib.request.urlopen`` directly,
        # but accepting an ``OpenerDirector`` here makes the class easy to test
        # or extend with custom handlers (proxies, caching, etc.).
        self.session = session or urllib.request.build_opener()

    def _headers(self) -> Dict[str, str]:
        return {
            "Accept": "application/json",
            "User-Agent": "OMSIndex-EUVD-Client/1.0 (+https://euvd.enisa.europa.eu/apidoc)",
        }

    def search_vulnerabilities(
        self,
        solution: Optional[str] = None,
        *,
        filter_field: str = "product",
        limit: int = 25,
        page: int = 1,
        filters: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        """Search for vulnerabilities related to ``solution``.

        Uses the public EUVD `/search` endpoint with a selectable filter
        (e.g. `product`, `vendor`, or `text`). Additional filters can be passed
        via `filters`. Paging uses a 1-based `page` parameter (default 1) and
        `size` up to 100 per request.
        """

        url = f"{self.base_url}/search"
        params: Dict[str, Any] = {"page": page, "size": limit}
        if filters:
            for key, value in filters.items():
                if value is not None:
                    params[key] = value
        if solution and filter_field not in params:
            params[filter_field] = solution
        query_string = urllib.parse.urlencode(params)
        request = urllib.request.Request(
            url=f"{url}?{query_string}",
            headers=self._headers(),
            method="GET",
        )

        try:
            with self.session.open(request, timeout=30) as response:
                payload: Dict[str, Any] = json.load(response)
        except urllib.error.HTTPError as exc:  # type: ignore[attr-defined]
            error_body = ""
            try:
                error_body = exc.read().decode("utf-8", errors="replace").strip()
            except Exception:
                pass
            detail = f" {error_body}" if error_body else ""
            raise RuntimeError(f"EUVD request failed with status {exc.code}: {exc.reason}.{detail}") from exc
        except urllib.error.URLError as exc:  # type: ignore[attr-defined]
            raise RuntimeError(f"EUVD request failed: {exc.reason}") from exc

        if "items" in payload:
            items = payload.get("items", [])
            if not isinstance(items, list):
                raise ValueError("Unexpected EUVD response format: 'items' is not a list")
            return items
        if "data" in payload:
            data = payload["data"]
            if not isinstance(data, list):
                raise ValueError("Unexpected EUVD response format: 'data' is not a list")
            return data
        raise ValueError("Unexpected EUVD response format: neither 'items' nor 'data' present")


def _format_entry(entry: Dict[str, Any]) -> str:
    vuln_id = entry.get("id") or entry.get("enisaid") or "<unknown>"
    title = entry.get("title") or entry.get("summary") or "No summary"
    severity = entry.get("baseScore") or entry.get("cvssScore") or entry.get("score")

    parts = [f"ID: {vuln_id}", f"Title: {title}"]
    if severity is not None:
        parts.append(f"CVSS 3.x: {severity}")
    return " | ".join(parts)


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Search vulnerabilities on ENISA EUVD")
    parser.add_argument(
        "solution",
        nargs="?",
        help="Value for the selected --filter (e.g. 'wazuh'); optional if other filters are set",
    )
    parser.add_argument("--limit", type=int, default=25, help="Number of results per page (default: 25)")
    parser.add_argument("--page", type=int, default=1, help="Result page to fetch (default: 1)")
    parser.add_argument(
        "--filter",
        dest="filter_field",
        choices=("product", "vendor", "text"),
        default="product",
        help="Search filter to use (default: product)",
    )
    parser.add_argument("--fromScore", type=float, help="Minimum CVSS score (0-10)")
    parser.add_argument("--toScore", type=float, help="Maximum CVSS score (0-10)")
    parser.add_argument("--fromEpss", type=float, help="Minimum EPSS score (0-100)")
    parser.add_argument("--toEpss", type=float, help="Maximum EPSS score (0-100)")
    parser.add_argument("--fromDate", help="Minimum publication date (YYYY-MM-DD)")
    parser.add_argument("--toDate", help="Maximum publication date (YYYY-MM-DD)")
    parser.add_argument("--fromUpdatedDate", help="Minimum updated date (YYYY-MM-DD)")
    parser.add_argument("--toUpdatedDate", help="Maximum updated date (YYYY-MM-DD)")
    parser.add_argument("--product", help="Product name filter")
    parser.add_argument("--vendor", help="Vendor name filter")
    parser.add_argument("--assigner", help="Assigner name filter")
    parser.add_argument("--text", help="Free-text search filter")
    parser.add_argument(
        "--exploited",
        choices=("true", "false"),
        help="Filter for known exploited vulnerabilities",
    )
    args = parser.parse_args()

    if not args.solution and not any(
        [
            args.fromScore,
            args.toScore,
            args.fromEpss,
            args.toEpss,
            args.fromDate,
            args.toDate,
            args.fromUpdatedDate,
            args.toUpdatedDate,
            args.product,
            args.vendor,
            args.assigner,
            args.text,
            args.exploited,
        ]
    ):
        parser.error("Provide a solution value or at least one filter (e.g. --product or --text).")

    client = EuvdClient()
    filters = {
        "fromScore": args.fromScore,
        "toScore": args.toScore,
        "fromEpss": args.fromEpss,
        "toEpss": args.toEpss,
        "fromDate": args.fromDate,
        "toDate": args.toDate,
        "fromUpdatedDate": args.fromUpdatedDate,
        "toUpdatedDate": args.toUpdatedDate,
        "product": args.product,
        "vendor": args.vendor,
        "assigner": args.assigner,
        "text": args.text,
        "exploited": args.exploited,
    }
    results = client.search_vulnerabilities(
        args.solution,
        filter_field=args.filter_field,
        limit=args.limit,
        page=args.page,
        filters=filters,
    )

    if not results:
        print("No vulnerabilities found.")
        return

    for entry in results:
        print(_format_entry(entry))


if __name__ == "__main__":
    main()
