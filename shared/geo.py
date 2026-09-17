"""Country-level visitor geo, resolved from the tunnel's own header.

Cloudflare stamps ``CF-IPCountry`` at the edge the same way it stamps
``CF-Connecting-IP``, and cloudflared is documented to forward both. This module
is the country counterpart of :mod:`shared.client_ip` and keeps the same
discipline: read the header, bound the value, never invent one.

Three deliberate limits:

* **Country only.** No city, no coordinates derived from the visitor's own
  address, no external lookup service, no GeoIP database, no new dependency. A
  country code is coarse enough to be defensible in an audit log; anything finer
  is a different decision with a licence and an update story attached.
* **No backfill.** Rows written before this existed stay ``NULL`` and are
  reported as ``Unknown``. Inferring a country for an old row from the IP would
  mean a lookup service, and it would be a guess presented as a record.
* **Failure is ``NULL``, never an error.** If the header never arrives (the
  premise this was designed against is unverified until it is seen on a live
  origin), every request stores ``NULL``, the aggregation returns a single
  ``Unknown`` bucket, and the page renders a sentence instead of a map. Nothing
  raises and nothing retries.

The centroid table is country-labelled points, not a density surface. Every
country is one dot, regardless of how many of its people visited, which is why
the audit page draws radius-scaled markers rather than a heat layer: heat over
centroids would render the shape of this table and imply per-visitor density that
the data does not contain.
"""

from __future__ import annotations

import math
import re
from typing import Any

from starlette.requests import Request

#: Ordered by trustworthiness for this deployment. Cloudflare sets exactly one of
#: these; the tuple exists so a second source can be added without moving the
#: call sites, the same shape as :data:`shared.client_ip._VISITOR_HEADERS`.
COUNTRY_HEADERS = ("CF-IPCountry",)

#: Values Cloudflare uses to mean "not a country", which must not be stored as if
#: they were one. `XX` is the documented unknown, `T1` is a Tor exit.
COUNTRY_SENTINELS = ("XX", "T1")

#: Exactly two uppercase letters. Lowercase is rejected rather than upper-cased:
#: Cloudflare never sends it, so a lowercase value did not come from Cloudflare.
_COUNTRY_RE = re.compile(r"^[A-Z]{2}$")

#: The aggregation the audit page's dropdown offers, in display order.
GEO_MODES = ("views", "visitors", "gated", "blocked")
DEFAULT_GEO_MODE = "views"

#: Actions that count as "blocked" for the `blocked` mode. The vocabulary belongs
#: to the gate; these are the three it writes when a request is turned away.
BLOCKED_ACTIONS = ("deny", "access_code_fail", "access_code_rate_limited")

#: The bucket a row with no country falls into. It has no centroid and is never a
#: marker; it is reported in the text summary so a NULL is visible rather than
#: silently dropped from a total.
UNKNOWN_CC = "Unknown"

#: Marker radius bounds, in pixels, for the audit map.
MIN_RADIUS = 4.0
MAX_RADIUS = 26.0


def normalize_country(value: Any) -> str | None:
    """A header or payload value as a storable country code, or ``None``.

    Surrounding whitespace is stripped because header values can carry it; case
    is not normalized because only uppercase arrives from Cloudflare. Anything
    that is not two uppercase letters, and anything on the sentinel list, is
    ``None``: a stored value is a claim about a real country.
    """
    if value is None:
        return None
    text = str(value).strip()
    if not _COUNTRY_RE.match(text):
        return None
    if text in COUNTRY_SENTINELS:
        return None
    return text


def get_country(request: Request) -> str | None:
    """The visitor's country from the first header that carries one."""
    for header in COUNTRY_HEADERS:
        country = normalize_country(request.headers.get(header))
        if country:
            return country
    return None


def centroid(cc: str | None) -> tuple[float, float] | None:
    """The ``(lat, lon)`` point for a country code, or ``None`` if unknown."""
    entry = COUNTRY_INFO.get(str(cc or "").strip().upper())
    if entry is None:
        return None
    return (entry[0], entry[1])


def country_name(cc: str | None) -> str:
    """The display name for a country code, falling back to the code itself.

    The fallback is deliberate: a code Cloudflare sends that this table does not
    carry is still a real country, so it is shown as the code rather than
    renamed to ``Unknown``, which is reserved for a NULL.
    """
    code = str(cc or "").strip().upper()
    if not code:
        return UNKNOWN_CC
    entry = COUNTRY_INFO.get(code)
    return entry[2] if entry else code


def marker_radius(count: int, max_count: int) -> float:
    """Marker radius for a count, scaled by area rather than by length.

    Area grows with the square of the radius, so a radius proportional to
    ``sqrt(count)`` gives a circle whose area is proportional to the count. A
    linear radius would exaggerate the top country by its square.

    The result is ``MIN_RADIUS`` to ``MAX_RADIUS`` along that square root, so the
    busiest country always lands on the maximum and a country with a tiny share
    stays just above the floor rather than shrinking to nothing: the floor is
    what keeps a single visit visible, and it is only reached at a count of zero,
    which returns 0 so no marker is drawn.
    """
    if count <= 0 or max_count <= 0:
        return 0.0
    share = min(1.0, count / max_count)
    return round(MIN_RADIUS + (MAX_RADIUS - MIN_RADIUS) * math.sqrt(share), 1)


def build_points(counts: list[tuple[str | None, int]]) -> list[dict[str, Any]]:
    """Turn ``(country, count)`` pairs into map points, joining in the centroids.

    Pure and database-free so the aggregation can be unit-tested without a
    browser or a server: the SQL only produces counts per country, and every
    presentation decision (ordering, share, radius, the unknown bucket) is made
    here.

    A country with no centroid in the table keeps its entry with ``lat``/``lon``
    ``None``, so it counts in the totals and appears in the text summary while
    being skipped by the marker layer. The unknown bucket is appended only when
    rows actually lacked a country, and always last.
    """
    known: list[dict[str, Any]] = []
    unknown = 0
    for cc, count in counts:
        count = int(count or 0)
        if count <= 0:
            continue
        if cc is None:
            unknown += count
            continue
        point = centroid(cc)
        known.append(
            {
                "cc": str(cc).upper(),
                "name": country_name(cc),
                "count": count,
                "lat": point[0] if point else None,
                "lon": point[1] if point else None,
            }
        )

    known.sort(key=lambda p: (-p["count"], p["name"]))
    total = sum(p["count"] for p in known) + unknown
    max_count = max((p["count"] for p in known), default=0)
    for point in known:
        point["share"] = round(point["count"] / total, 4) if total else 0.0
        point["radius"] = marker_radius(point["count"], max_count)

    if unknown:
        known.append(
            {
                "cc": None,
                "name": UNKNOWN_CC,
                "count": unknown,
                "lat": None,
                "lon": None,
                "share": round(unknown / total, 4) if total else 0.0,
                "radius": 0.0,
            }
        )
    return known


def plot_points(points: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Only the points a map can draw, so the marker layer never sees a null."""
    return [p for p in points if p.get("lat") is not None and p.get("lon") is not None]


def summarize(points: list[dict[str, Any]], limit: int = 5) -> str:
    """A sentence naming the biggest countries, for the text fallback.

    The map carries the data visually, so the same numbers have to exist as text:
    a screen reader, a failed tile fetch and an export all need the answer
    without the picture.
    """
    if not points:
        return "No country data recorded yet."
    head = ", ".join(f"{p['name']} {p['count']}" for p in points[:limit])
    rest = len(points) - limit
    if rest > 0:
        return f"{head}, and {rest} more."
    return f"{head}."


def totals(points: list[dict[str, Any]]) -> int:
    """The sum of every bucket, including the unknown one."""
    return sum(int(p.get("count") or 0) for p in points)


#: Country label points: ``CC -> (latitude, longitude, display name)``.
#:
#: One point per country, sourced from a public country-centroid table and
#: rounded to two decimals. It is a static table in this file on purpose: a
#: GeoIP database would be a licence, an update cadence and a large artifact in
#: the image, and an external API would send visitor addresses to a third party,
#: which contradicts the privacy posture the country-only design exists to keep.
COUNTRY_INFO: dict[str, tuple[float, float, str]] = {
    "AD": (42.5, 1.6, "Andorra"),
    "AE": (24.0, 54.0, "United Arab Emirates"),
    "AF": (33.0, 65.0, "Afghanistan"),
    "AG": (17.05, -61.8, "Antigua and Barbuda"),
    "AI": (18.25, -63.17, "Anguilla"),
    "AL": (41.0, 20.0, "Albania"),
    "AM": (40.0, 45.0, "Armenia"),
    "AN": (12.25, -68.75, "Netherlands Antilles"),
    "AO": (-12.5, 18.5, "Angola"),
    "AQ": (-90.0, 0.0, "Antarctica"),
    "AR": (-34.0, -64.0, "Argentina"),
    "AS": (-14.33, -170.0, "American Samoa"),
    "AT": (47.33, 13.33, "Austria"),
    "AU": (-27.0, 133.0, "Australia"),
    "AW": (12.5, -69.97, "Aruba"),
    "AX": (60.12, 19.9, "Aland Islands"),
    "AZ": (40.5, 47.5, "Azerbaijan"),
    "BA": (44.0, 18.0, "Bosnia and Herzegovina"),
    "BB": (13.17, -59.53, "Barbados"),
    "BD": (24.0, 90.0, "Bangladesh"),
    "BE": (50.83, 4.0, "Belgium"),
    "BF": (13.0, -2.0, "Burkina Faso"),
    "BG": (43.0, 25.0, "Bulgaria"),
    "BH": (26.0, 50.55, "Bahrain"),
    "BI": (-3.5, 30.0, "Burundi"),
    "BJ": (9.5, 2.25, "Benin"),
    "BL": (17.9, -62.83, "Saint Barthelemy"),
    "BM": (32.33, -64.75, "Bermuda"),
    "BN": (4.5, 114.67, "Brunei"),
    "BO": (-17.0, -65.0, "Bolivia"),
    "BQ": (12.18, -68.23, "Bonaire, Sint Eustatius and Saba"),
    "BR": (-10.0, -55.0, "Brazil"),
    "BS": (24.25, -76.0, "Bahamas"),
    "BT": (27.5, 90.5, "Bhutan"),
    "BV": (-54.43, 3.4, "Bouvet Island"),
    "BW": (-22.0, 24.0, "Botswana"),
    "BY": (53.0, 28.0, "Belarus"),
    "BZ": (17.25, -88.75, "Belize"),
    "CA": (60.0, -95.0, "Canada"),
    "CC": (-12.5, 96.83, "Cocos (Keeling) Islands"),
    "CD": (0.0, 25.0, "Congo, the Democratic Republic of the"),
    "CF": (7.0, 21.0, "Central African Republic"),
    "CG": (-1.0, 15.0, "Congo"),
    "CH": (47.0, 8.0, "Switzerland"),
    "CI": (8.0, -5.0, "Ivory Coast"),
    "CK": (-21.23, -159.77, "Cook Islands"),
    "CL": (-30.0, -71.0, "Chile"),
    "CM": (6.0, 12.0, "Cameroon"),
    "CN": (35.0, 105.0, "China"),
    "CO": (4.0, -72.0, "Colombia"),
    "CR": (10.0, -84.0, "Costa Rica"),
    "CU": (21.5, -80.0, "Cuba"),
    "CV": (16.0, -24.0, "Cape Verde"),
    "CW": (12.17, -68.97, "Curacao"),
    "CX": (-10.5, 105.67, "Christmas Island"),
    "CY": (35.0, 33.0, "Cyprus"),
    "CZ": (49.75, 15.5, "Czech Republic"),
    "DE": (51.0, 9.0, "Germany"),
    "DJ": (11.5, 43.0, "Djibouti"),
    "DK": (56.0, 10.0, "Denmark"),
    "DM": (15.42, -61.33, "Dominica"),
    "DO": (19.0, -70.67, "Dominican Republic"),
    "DZ": (28.0, 3.0, "Algeria"),
    "EC": (-2.0, -77.5, "Ecuador"),
    "EE": (59.0, 26.0, "Estonia"),
    "EG": (27.0, 30.0, "Egypt"),
    "EH": (24.5, -13.0, "Western Sahara"),
    "ER": (15.0, 39.0, "Eritrea"),
    "ES": (40.0, -4.0, "Spain"),
    "ET": (8.0, 38.0, "Ethiopia"),
    "FI": (64.0, 26.0, "Finland"),
    "FJ": (-18.0, 175.0, "Fiji"),
    "FK": (-51.75, -59.0, "Falkland Islands (Malvinas)"),
    "FM": (6.92, 158.25, "Micronesia, Federated States of"),
    "FO": (62.0, -7.0, "Faroe Islands"),
    "FR": (46.0, 2.0, "France"),
    "GA": (-1.0, 11.75, "Gabon"),
    "GB": (54.0, -2.0, "United Kingdom"),
    "GD": (12.12, -61.67, "Grenada"),
    "GE": (42.0, 43.5, "Georgia"),
    "GF": (4.0, -53.0, "French Guiana"),
    "GG": (49.5, -2.56, "Guernsey"),
    "GH": (8.0, -2.0, "Ghana"),
    "GI": (36.18, -5.37, "Gibraltar"),
    "GL": (72.0, -40.0, "Greenland"),
    "GM": (13.47, -16.57, "Gambia"),
    "GN": (11.0, -10.0, "Guinea"),
    "GP": (16.25, -61.58, "Guadeloupe"),
    "GQ": (2.0, 10.0, "Equatorial Guinea"),
    "GR": (39.0, 22.0, "Greece"),
    "GS": (-54.5, -37.0, "South Georgia and the South Sandwich Islands"),
    "GT": (15.5, -90.25, "Guatemala"),
    "GU": (13.47, 144.78, "Guam"),
    "GW": (12.0, -15.0, "Guinea-Bissau"),
    "GY": (5.0, -59.0, "Guyana"),
    "HK": (22.25, 114.17, "Hong Kong"),
    "HM": (-53.1, 72.52, "Heard Island and McDonald Islands"),
    "HN": (15.0, -86.5, "Honduras"),
    "HR": (45.17, 15.5, "Croatia"),
    "HT": (19.0, -72.42, "Haiti"),
    "HU": (47.0, 20.0, "Hungary"),
    "ID": (-5.0, 120.0, "Indonesia"),
    "IE": (53.0, -8.0, "Ireland"),
    "IL": (31.5, 34.75, "Israel"),
    "IM": (54.23, -4.55, "Isle of Man"),
    "IN": (20.0, 77.0, "India"),
    "IO": (-6.0, 71.5, "British Indian Ocean Territory"),
    "IQ": (33.0, 44.0, "Iraq"),
    "IR": (32.0, 53.0, "Iran, Islamic Republic of"),
    "IS": (65.0, -18.0, "Iceland"),
    "IT": (42.83, 12.83, "Italy"),
    "JE": (49.21, -2.13, "Jersey"),
    "JM": (18.25, -77.5, "Jamaica"),
    "JO": (31.0, 36.0, "Jordan"),
    "JP": (36.0, 138.0, "Japan"),
    "KE": (1.0, 38.0, "Kenya"),
    "KG": (41.0, 75.0, "Kyrgyzstan"),
    "KH": (13.0, 105.0, "Cambodia"),
    "KI": (1.42, 173.0, "Kiribati"),
    "KM": (-12.17, 44.25, "Comoros"),
    "KN": (17.33, -62.75, "Saint Kitts and Nevis"),
    "KP": (40.0, 127.0, "Korea, Democratic People's Republic of"),
    "KR": (37.0, 127.5, "South Korea"),
    "KW": (29.34, 47.66, "Kuwait"),
    "KY": (19.5, -80.5, "Cayman Islands"),
    "KZ": (48.0, 68.0, "Kazakhstan"),
    "LA": (18.0, 105.0, "Lao People's Democratic Republic"),
    "LB": (33.83, 35.83, "Lebanon"),
    "LC": (13.88, -61.13, "Saint Lucia"),
    "LI": (47.17, 9.53, "Liechtenstein"),
    "LK": (7.0, 81.0, "Sri Lanka"),
    "LR": (6.5, -9.5, "Liberia"),
    "LS": (-29.5, 28.5, "Lesotho"),
    "LT": (56.0, 24.0, "Lithuania"),
    "LU": (49.75, 6.17, "Luxembourg"),
    "LV": (57.0, 25.0, "Latvia"),
    "LY": (25.0, 17.0, "Libya"),
    "MA": (32.0, -5.0, "Morocco"),
    "MC": (43.73, 7.4, "Monaco"),
    "MD": (47.0, 29.0, "Moldova, Republic of"),
    "ME": (42.0, 19.0, "Montenegro"),
    "MF": (18.08, -63.06, "Saint Martin (French part)"),
    "MG": (-20.0, 47.0, "Madagascar"),
    "MH": (9.0, 168.0, "Marshall Islands"),
    "MK": (41.83, 22.0, "Macedonia, the former Yugoslav Republic of"),
    "ML": (17.0, -4.0, "Mali"),
    "MM": (22.0, 98.0, "Myanmar"),
    "MN": (46.0, 105.0, "Mongolia"),
    "MO": (22.17, 113.55, "Macao"),
    "MP": (15.2, 145.75, "Northern Mariana Islands"),
    "MQ": (14.67, -61.0, "Martinique"),
    "MR": (20.0, -12.0, "Mauritania"),
    "MS": (16.75, -62.2, "Montserrat"),
    "MT": (35.83, 14.58, "Malta"),
    "MU": (-20.28, 57.55, "Mauritius"),
    "MV": (3.25, 73.0, "Maldives"),
    "MW": (-13.5, 34.0, "Malawi"),
    "MX": (23.0, -102.0, "Mexico"),
    "MY": (2.5, 112.5, "Malaysia"),
    "MZ": (-18.25, 35.0, "Mozambique"),
    "NA": (-22.0, 17.0, "Namibia"),
    "NC": (-21.5, 165.5, "New Caledonia"),
    "NE": (16.0, 8.0, "Niger"),
    "NF": (-29.03, 167.95, "Norfolk Island"),
    "NG": (10.0, 8.0, "Nigeria"),
    "NI": (13.0, -85.0, "Nicaragua"),
    "NL": (52.5, 5.75, "Netherlands"),
    "NO": (62.0, 10.0, "Norway"),
    "NP": (28.0, 84.0, "Nepal"),
    "NR": (-0.53, 166.92, "Nauru"),
    "NU": (-19.03, -169.87, "Niue"),
    "NZ": (-41.0, 174.0, "New Zealand"),
    "OM": (21.0, 57.0, "Oman"),
    "PA": (9.0, -80.0, "Panama"),
    "PE": (-10.0, -76.0, "Peru"),
    "PF": (-15.0, -140.0, "French Polynesia"),
    "PG": (-6.0, 147.0, "Papua New Guinea"),
    "PH": (13.0, 122.0, "Philippines"),
    "PK": (30.0, 70.0, "Pakistan"),
    "PL": (52.0, 20.0, "Poland"),
    "PM": (46.83, -56.33, "Saint Pierre and Miquelon"),
    "PN": (-24.7, -127.4, "Pitcairn"),
    "PR": (18.25, -66.5, "Puerto Rico"),
    "PS": (32.0, 35.25, "Palestinian Territory, Occupied"),
    "PT": (39.5, -8.0, "Portugal"),
    "PW": (7.5, 134.5, "Palau"),
    "PY": (-23.0, -58.0, "Paraguay"),
    "QA": (25.5, 51.25, "Qatar"),
    "RE": (-21.1, 55.6, "Reunion"),
    "RO": (46.0, 25.0, "Romania"),
    "RS": (44.0, 21.0, "Serbia"),
    "RU": (60.0, 100.0, "Russian Federation"),
    "RW": (-2.0, 30.0, "Rwanda"),
    "SA": (25.0, 45.0, "Saudi Arabia"),
    "SB": (-8.0, 159.0, "Solomon Islands"),
    "SC": (-4.58, 55.67, "Seychelles"),
    "SD": (15.0, 30.0, "Sudan"),
    "SE": (62.0, 15.0, "Sweden"),
    "SG": (1.37, 103.8, "Singapore"),
    "SH": (-15.93, -5.7, "Saint Helena, Ascension and Tristan da Cunha"),
    "SI": (46.0, 15.0, "Slovenia"),
    "SJ": (78.0, 20.0, "Svalbard and Jan Mayen"),
    "SK": (48.67, 19.5, "Slovakia"),
    "SL": (8.5, -11.5, "Sierra Leone"),
    "SM": (43.77, 12.42, "San Marino"),
    "SN": (14.0, -14.0, "Senegal"),
    "SO": (10.0, 49.0, "Somalia"),
    "SR": (4.0, -56.0, "Suriname"),
    "SS": (8.0, 30.0, "South Sudan"),
    "ST": (1.0, 7.0, "Sao Tome and Principe"),
    "SV": (13.83, -88.92, "El Salvador"),
    "SX": (18.03, -63.05, "Sint Maarten (Dutch part)"),
    "SY": (35.0, 38.0, "Syrian Arab Republic"),
    "SZ": (-26.5, 31.5, "Swaziland"),
    "TC": (21.75, -71.58, "Turks and Caicos Islands"),
    "TD": (15.0, 19.0, "Chad"),
    "TF": (-43.0, 67.0, "French Southern Territories"),
    "TG": (8.0, 1.17, "Togo"),
    "TH": (15.0, 100.0, "Thailand"),
    "TJ": (39.0, 71.0, "Tajikistan"),
    "TK": (-9.0, -172.0, "Tokelau"),
    "TL": (-8.55, 125.52, "Timor-Leste"),
    "TM": (40.0, 60.0, "Turkmenistan"),
    "TN": (34.0, 9.0, "Tunisia"),
    "TO": (-20.0, -175.0, "Tonga"),
    "TR": (39.0, 35.0, "Turkey"),
    "TT": (11.0, -61.0, "Trinidad and Tobago"),
    "TV": (-8.0, 178.0, "Tuvalu"),
    "TW": (23.5, 121.0, "Taiwan"),
    "TZ": (-6.0, 35.0, "Tanzania, United Republic of"),
    "UA": (49.0, 32.0, "Ukraine"),
    "UG": (1.0, 32.0, "Uganda"),
    "UM": (19.28, 166.6, "United States Minor Outlying Islands"),
    "US": (38.0, -97.0, "United States"),
    "UY": (-33.0, -56.0, "Uruguay"),
    "UZ": (41.0, 64.0, "Uzbekistan"),
    "VA": (41.9, 12.45, "Holy See (Vatican City State)"),
    "VC": (13.25, -61.2, "St. Vincent and the Grenadines"),
    "VE": (8.0, -66.0, "Venezuela"),
    "VG": (18.5, -64.5, "Virgin Islands, British"),
    "VI": (18.33, -64.83, "Virgin Islands, U.S."),
    "VN": (16.0, 106.0, "Vietnam"),
    "VU": (-16.0, 167.0, "Vanuatu"),
    "WF": (-13.3, -176.2, "Wallis and Futuna"),
    "WS": (-13.58, -172.33, "Samoa"),
    "XK": (42.58, 21.0, "Kosovo"),
    "YE": (15.0, 48.0, "Yemen"),
    "YT": (-12.83, 45.17, "Mayotte"),
    "ZA": (-29.0, 24.0, "South Africa"),
    "ZM": (-15.0, 30.0, "Zambia"),
    "ZW": (-20.0, 30.0, "Zimbabwe"),
}
