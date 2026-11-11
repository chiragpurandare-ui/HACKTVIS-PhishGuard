import ipaddress
import socket
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup


# Safety limits
REQUEST_TIMEOUT = 8
MAX_RESPONSE_SIZE = 2 * 1024 * 1024  # 2 MB
MAX_REDIRECTS = 3


def is_private_or_internal_host(hostname):
    """Block localhost, loopback, private and reserved addresses."""

    if not hostname:
        return True

    hostname = hostname.lower().strip()

    blocked_names = {
        "localhost",
        "localhost.localdomain",
        "ip6-localhost",
        "ip6-loopback",
    }

    if hostname in blocked_names or hostname.endswith(".local"):
        return True

    try:
        ip = ipaddress.ip_address(hostname)

        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        )

    except ValueError:
        pass

    # Resolve hostname and check returned addresses
    try:
        addresses = socket.getaddrinfo(
            hostname,
            None,
            type=socket.SOCK_STREAM
        )

        for address in addresses:
            ip_text = address[4][0]

            try:
                ip = ipaddress.ip_address(ip_text)

                if (
                    ip.is_private
                    or ip.is_loopback
                    or ip.is_link_local
                    or ip.is_reserved
                    or ip.is_multicast
                    or ip.is_unspecified
                ):
                    return True

            except ValueError:
                continue

    except socket.gaierror:
        return True

    return False


def validate_url(url):
    """Validate URL before making a request."""

    parsed = urlparse(url)

    if parsed.scheme not in {"http", "https"}:
        return False, "Only HTTP and HTTPS URLs are allowed."

    if not parsed.hostname:
        return False, "URL does not contain a valid hostname."

    if is_private_or_internal_host(parsed.hostname):
        return False, "Private or internal hosts are blocked."

    return True, None


def safe_fetch(url):
    """
    Fetch webpage using safety limits.

    JavaScript is NOT executed.
    Forms are NOT submitted.
    """

    valid, error = validate_url(url)

    if not valid:
        return None, error

    session = requests.Session()

    session.headers.update({
        "User-Agent": (
            "HACKTVIS-PhishGuard/1.0 "
            "(Defensive Security Scanner)"
        )
    })

    current_url = url

    try:

        for _ in range(MAX_REDIRECTS + 1):

            valid, error = validate_url(current_url)

            if not valid:
                return None, error

            response = session.get(
                current_url,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=False,
                stream=True
            )

            # Handle redirects ourselves
            if response.status_code in {
                301,
                302,
                303,
                307,
                308
            }:

                location = response.headers.get("Location")

                response.close()

                if not location:
                    return None, "Redirect without Location header."

                current_url = urljoin(
                    current_url,
                    location
                )

                continue

            content_type = response.headers.get(
                "Content-Type",
                ""
            ).lower()

            if "text/html" not in content_type:
                response.close()

                return None, (
                    "Target did not return an HTML page."
                )

            chunks = []
            total_size = 0

            for chunk in response.iter_content(
                chunk_size=8192
            ):

                if not chunk:
                    continue

                total_size += len(chunk)

                if total_size > MAX_RESPONSE_SIZE:
                    response.close()

                    return None, (
                        "Response exceeded the 2 MB safety limit."
                    )

                chunks.append(chunk)

            response.close()

            content = b"".join(chunks)

            encoding = response.encoding or "utf-8"

            html = content.decode(
                encoding,
                errors="replace"
            )

            return {
                "requested_url": url,
                "final_url": current_url,
                "status_code": response.status_code,
                "content_type": content_type,
                "html": html,
            }, None

        return None, "Too many redirects."

    except requests.RequestException as exc:

        return None, f"Request failed: {exc}"

def check_robots_txt(page_url):
    """Check whether the website has a robots.txt file."""

    parsed = urlparse(page_url)

    if not parsed.scheme or not parsed.hostname:
        return 0

    robots_url = (
        f"{parsed.scheme}://{parsed.netloc}/robots.txt"
    )

    try:
        response = requests.get(
            robots_url,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=False,
            stream=True
        )

        content_type = response.headers.get(
            "Content-Type",
            ""
        ).lower()

        status = response.status_code
        response.close()

        if status == 200 and (
            "text" in content_type
            or "plain" in content_type
            or content_type == ""
        ):
            return 1

    except requests.RequestException:
        pass

    return 0

def analyze_html(html, page_url):
    """Extract static HTML features."""

    soup = BeautifulSoup(
        html,
        "lxml"
    )

    lines = html.splitlines()

    # -----------------------------
    # Basic HTML statistics
    # -----------------------------

    line_of_code = len(lines)

    largest_line_length = max(
        (len(line) for line in lines),
        default=0
    )

    # -----------------------------
    # Title
    # -----------------------------

    title_tag = soup.find("title")

    has_title = int(
        title_tag is not None
        and bool(title_tag.get_text(strip=True))
    )

    title = (
        title_tag.get_text(" ", strip=True)
        if title_tag
        else ""
    )

    # -----------------------------
    # Favicon
    # -----------------------------

    favicon = False

    for link in soup.find_all("link"):

        rel = link.get("rel", [])

        if isinstance(rel, list):
            rel_text = " ".join(rel).lower()
        else:
            rel_text = str(rel).lower()

        if "icon" in rel_text:
            favicon = True
            break

    # -----------------------------
    # Responsive design
    # -----------------------------

    viewport = soup.find(
        "meta",
        attrs={
            "name": lambda value:
            value and value.lower() == "viewport"
        }
    )

    is_responsive = int(
        viewport is not None
    )

    # -----------------------------
    # Description
    # -----------------------------

    description = soup.find(
        "meta",
        attrs={
            "name": lambda value:
            value and value.lower() == "description"
        }
    )

    has_description = int(
        description is not None
        and bool(description.get("content", "").strip())
    )

    # -----------------------------
    # Frames
    # -----------------------------

    no_of_iframe = len(
        soup.find_all("iframe")
    )

    # -----------------------------
    # Forms
    # -----------------------------

    forms = soup.find_all("form")

    has_external_form_submit = 0

    parsed_page = urlparse(page_url)
    robots = check_robots_txt(page_url)

    for form in forms:

        action = form.get("action", "").strip()

        if not action:
            continue

        absolute_action = urljoin(
            page_url,
            action
        )

        parsed_action = urlparse(
            absolute_action
        )

        if (
            parsed_action.hostname
            and parsed_page.hostname
            and parsed_action.hostname.lower()
            != parsed_page.hostname.lower()
        ):
            has_external_form_submit = 1
            break

    # -----------------------------
    # Social networks
    # -----------------------------

    social_domains = [
        "facebook.com",
        "instagram.com",
        "twitter.com",
        "x.com",
        "linkedin.com",
        "youtube.com",
        "tiktok.com"
    ]

    has_social_net = 0

    for link in soup.find_all("a", href=True):

        href = link["href"].lower()

        if any(
            domain in href
            for domain in social_domains
        ):
            has_social_net = 1
            break

    # -----------------------------
    # Submit buttons
    # -----------------------------

    has_submit_button = 0

    for element in soup.find_all(
        ["button", "input"]
    ):

        element_type = element.get(
            "type",
            ""
        ).lower()

        value = element.get(
            "value",
            ""
        ).lower()

        text = element.get_text(
            " ",
            strip=True
        ).lower()

        if (
            element_type == "submit"
            or "submit" in value
            or "submit" in text
        ):
            has_submit_button = 1
            break

    # -----------------------------
    # Hidden fields
    # -----------------------------

    has_hidden_fields = int(
        soup.find(
            "input",
            attrs={
                "type": lambda value:
                value and value.lower() == "hidden"
            }
        ) is not None
    )

    # -----------------------------
    # Password field
    # -----------------------------

    has_password_field = int(
        soup.find(
            "input",
            attrs={
                "type": lambda value:
                value and value.lower() == "password"
            }
        ) is not None
    )

    # -----------------------------
    # Images
    # -----------------------------

    no_of_image = len(
        soup.find_all("img")
    )

    # -----------------------------
    # CSS
    # -----------------------------

    no_of_css = len(
        soup.find_all("link", rel=lambda value:
            value and "stylesheet" in str(value).lower()
        )
    )

    no_of_css += len(
        soup.find_all("style")
    )

    # -----------------------------
    # JavaScript
    # -----------------------------

    no_of_js = len(
        soup.find_all("script")
    )

    # -----------------------------
    # Links
    # -----------------------------

    no_of_self_ref = 0
    no_of_external_ref = 0
    no_of_empty_ref = 0

    for tag in soup.find_all(
        ["a", "link", "script", "img", "iframe"]
    ):

        attribute = (
            "href"
            if tag.name in ["a", "link"]
            else "src"
        )

        reference = tag.get(
            attribute,
            None
        )

        if reference is None:
            continue

        reference = reference.strip()

        if not reference or reference == "#":
            no_of_empty_ref += 1
            continue

        absolute_ref = urljoin(
            page_url,
            reference
        )

        parsed_ref = urlparse(
            absolute_ref
        )

        if not parsed_ref.hostname:
            no_of_self_ref += 1
            continue

        if (
            parsed_ref.hostname.lower()
            == parsed_page.hostname.lower()
        ):
            no_of_self_ref += 1
        else:
            no_of_external_ref += 1

    return {
        "LineOfCode": line_of_code,
        "LargestLineLength": largest_line_length,
        "HasTitle": has_title,
        "Title": title,
        "HasFavicon": int(favicon),
         "Robots": robots,
         "IsResponsive": is_responsive,
        "HasDescription": has_description,
        "NoOfiFrame": no_of_iframe,
        "HasExternalFormSubmit": has_external_form_submit,
        "HasSocialNet": has_social_net,
        "HasSubmitButton": has_submit_button,
        "HasHiddenFields": has_hidden_fields,
        "HasPasswordField": has_password_field,
        "NoOfImage": no_of_image,
        "NoOfCSS": no_of_css,
        "NoOfJS": no_of_js,
        "NoOfSelfRef": no_of_self_ref,
        "NoOfExternalRef": no_of_external_ref,
        "NoOfEmptyRef": no_of_empty_ref,
    }


def analyze_website(url):
    """Complete safe website analysis."""

    result, error = safe_fetch(url)

    if error:
        return {
            "success": False,
            "error": error
        }

    html_features = analyze_html(
        result["html"],
        result["final_url"]
    )

    return {
        "success": True,
        "requested_url": result["requested_url"],
        "final_url": result["final_url"],
        "status_code": result["status_code"],
        "content_type": result["content_type"],
        "features": html_features
    }


if __name__ == "__main__":

    url = input(
        "Enter URL to analyze: "
    ).strip()

    if not url:
        print("No URL entered.")
        raise SystemExit(1)

    result = analyze_website(url)

    print("\n================================")
    print("HACKTVIS PhishGuard Website Analyzer")
    print("================================")

    if not result["success"]:
        print("Analysis failed:")
        print(result["error"])
        raise SystemExit(1)

    print(f"Final URL: {result['final_url']}")
    print(f"HTTP Status: {result['status_code']}")
    print(f"Content Type: {result['content_type']}")

    print("\nWebsite Features:")

    for key, value in result["features"].items():
        print(f"{key}: {value}")
