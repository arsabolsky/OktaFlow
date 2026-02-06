# AI is crazy...I'm impressed. lol

import asyncio
import base64
import hashlib
import json
import logging
import os
import random
import string
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlparse

import httpx
from dotenv import load_dotenv
from rich.console import Console
from rich.logging import RichHandler
from rich.padding import Padding
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table

load_dotenv()

# --- Configuration & UI ---
logging.basicConfig(
    level="INFO",
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(markup=True, show_path=False)],
)
log = logging.getLogger("rich")

console = Console()
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.82 Safari/537.36"
MAX_RETRIES = 3
LOG_DELAY = 0.5


# --- Presentation Helpers ---
class Presenter:
    state = {}

    @staticmethod
    def clear():
        os.system("cls" if os.name == "nt" else "clear")

    @staticmethod
    def update_state(key: str, value: Any):
        # Truncate long strings for display
        if isinstance(value, str) and len(value) > 30:
            Presenter.state[key] = value[:27] + "..."
        else:
            Presenter.state[key] = value

    @staticmethod
    def log_json(data: Any, title: str):
        """Pretty prints a JSON object to the console with truncated strings."""

        def truncate_recursive(obj):
            if isinstance(obj, dict):
                return {k: truncate_recursive(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [truncate_recursive(i) for i in obj]
            elif isinstance(obj, str) and len(obj) > 50:
                return obj[:47] + "..."
            return obj

        truncated_data = truncate_recursive(data)
        console.print(
            Panel(
                json.dumps(truncated_data, indent=2),
                title=f"[bold cyan]{title}[/]",
                border_style="cyan",
                expand=False,
            )
        )
        print()

    @staticmethod
    def step(title: str, description: str, code: str):
        Presenter.clear()

        # Title
        console.rule(f"[bold blue]{title}[/]")
        print()

        # Session State Panel
        if Presenter.state:
            table = Table(box=None, show_header=False, padding=(0, 2))
            table.add_column("Key", style="bold magenta")
            table.add_column("Value", style="yellow")

            for k, v in Presenter.state.items():
                table.add_row(f"{k}:", str(v))

            console.print(
                Panel(
                    table,
                    title="[bold magenta]Session State (The Journey)[/]",
                    border_style="magenta",
                    expand=False,
                )
            )
            print()

        # Description
        console.print(Padding(f"[italic]{description}[/]", (0, 2)))
        print()

        # Code Snippet
        if code:
            syntax = Syntax(
                code, "python", theme="monokai", line_numbers=True, word_wrap=True
            )
            console.print(
                Panel(
                    syntax, title="[bold green]Code to Execute[/]", border_style="green"
                )
            )

        # Prompt
        console.print("\n[bold yellow blink]Press Enter to execute...[/]", end="")
        input()
        print()
        console.rule("[bold red]Live Logs[/]")
        print()

    @staticmethod
    def end_step():
        print()
        console.print(
            "[bold yellow blink]Step complete. Press Enter to continue...[/]", end=""
        )
        input()


# --- Data Structures ---
@dataclass
class Env:
    working_path: str
    church_username: str
    church_password: str


@dataclass
class BearerTokenClaims:
    mission_id: str


@dataclass
class BearerToken:
    token: str
    claims: BearerTokenClaims

    @classmethod
    def from_base64(
        cls, b64_token: str, mission_id: Optional[str] = None
    ) -> "BearerToken":
        try:
            _, payload_b64, _ = b64_token.split(".")
            payload_b64 += "=" * (-len(payload_b64) % 4)
            payload_json = base64.b64decode(payload_b64).decode("utf-8")
            claims_data = json.loads(payload_json)

            if not mission_id:
                mission_id = (
                    claims_data.get("missionId")
                    or claims_data.get("mission_id")
                    or claims_data.get("mvo", {}).get("mid")
                )

            if not mission_id:
                raise ValueError(
                    "Could not find mission_id in token claims or response body"
                )

            claims = BearerTokenClaims(mission_id=str(mission_id))
            return cls(token=b64_token, claims=claims)
        except Exception as e:
            raise ValueError(f"Failed to decode bearer token: {e}") from e


class ChurchClient:
    def __init__(self, env: Env):
        self.env = env
        self.working_path = Path(env.working_path)
        self.bearer_token: Optional[BearerToken] = None
        self._cookie_jar = httpx.Cookies()
        self.http_client: Optional[httpx.AsyncClient] = None

    @classmethod
    async def create(cls, env: Env) -> "ChurchClient":
        instance = cls(env)
        await instance._init_clients()
        return instance

    async def _log_request_safe(self, request: httpx.Request):
        await asyncio.sleep(LOG_DELAY)
        log.info(f"[cyan]Request:[/cyan] {request.method} {request.url}")

    async def _log_response_safe(self, response: httpx.Response):
        await asyncio.sleep(LOG_DELAY)
        status_color = "green" if response.status_code < 400 else "red"
        log.info(
            f"[bold {status_color}]Response:[/bold {status_color}] {response.status_code} {response.url}"
        )

    async def _init_clients(self):
        self.http_client = httpx.AsyncClient(
            headers={"User-Agent": USER_AGENT},
            cookies=self._cookie_jar,
            timeout=60.0,
            follow_redirects=True,
            event_hooks={
                "request": [self._log_request_safe],
                "response": [self._log_response_safe],
            },
        )

    async def login(self) -> BearerToken:
        Presenter.step(
            "Stage 1: Security Setup (PKCE)",
            "Authentication starts on the client. We use Proof Key for Code Exchange (PKCE) to prevent code interception.\n\n"
            "1. [bold cyan]code_verifier[/]: A random secret password created just for this session.\n"
            "2. [bold cyan]code_challenge[/]: A hashed version of that secret.\n\n"
            "We will send the [italic]hash[/] to Okta now, and reveal the [italic]secret[/] later. If anyone intercepts our login code, they can't use it without this secret.",
            """
def generate_code_challenge(verifier):
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b'=').decode()

code_verifier = generate_random_string(64)
code_challenge = generate_code_challenge(code_verifier)""",
        )

        if self.http_client:
            self.http_client.cookies.clear()

        # --- PKCE Generation ---
        def generate_random_string(length: int) -> str:
            return "".join(
                random.choices(string.ascii_letters + string.digits, k=length)
            )

        def generate_code_challenge(verifier: str) -> str:
            digest = hashlib.sha256(verifier.encode()).digest()
            return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()

        log.info("Generating PKCE and security parameters")
        code_verifier = generate_random_string(64)
        code_challenge = generate_code_challenge(code_verifier)
        state = generate_random_string(32)
        nonce = generate_random_string(32)

        Presenter.update_state("code_verifier", code_verifier)
        Presenter.update_state("code_challenge", code_challenge)
        Presenter.update_state("oauth_state", state)

        Presenter.end_step()

        # ---------------------------------------------------------

        Presenter.step(
            "Stage 2: Triggering the Authentication Flow",
            "We visit the Referral Manager website. The server sees we are not logged in and replies with a [bold]302 Redirect[/] to Okta's login page.\n\n"
            "Critically, this redirect URL contains our [bold cyan]client_id[/], [bold cyan]scope[/], and the [bold cyan]code_challenge[/] we just generated.\n"
            "We capture this URL to begin the handshake.",
            """
# Use http_client but don't follow redirects to capture the Location header
redirect_res = await self.http_client.get(
    "https://referralmanager.churchofjesuschrist.org/", 
    follow_redirects=False
)
location_url = redirect_res.headers.get("location")""",
        )

        log.info("Visiting referralmanager.churchofjesuschrist.org to capture redirect")
        redirect_res = await self.http_client.get(
            "https://referralmanager.churchofjesuschrist.org/", follow_redirects=False
        )
        location_url = redirect_res.headers.get("location")
        if not location_url:
            raise Exception("Failed to get initial redirect location")
        log.info(f"Got redirect location: {location_url}")

        # Analyze params
        parsed = urlparse(location_url)
        params = parse_qs(parsed.query)
        flat_params = {k: v[0] for k, v in params.items()}
        Presenter.log_json(
            flat_params, "Analyzed Redirect Parameters (Payload to Okta)"
        )

        Presenter.update_state("location_url", location_url)

        log.info(f"Following redirect to: {location_url}")
        await self.http_client.get(location_url)

        Presenter.end_step()

        # ---------------------------------------------------------

        Presenter.step(
            "Stage 3: Handshake with Okta",
            "Now we talk directly to Okta's API to start the login session.\n\n"
            "1. [bold cyan]/interact[/]: We send the parameters from the redirect URL (including our [bold]code_challenge[/]) to get an [bold cyan]interaction_handle[/].\n"
            "2. [bold cyan]/introspect[/]: We send that handle back to 'open' the transaction. Okta returns a [bold cyan]stateHandle[/]—a temporary ID that tracks our progress through the login form.",
            """
# /interact
interact_res = await self.http_client.post(
    ".../interact",
    data={ "client_id": "...", "code_challenge": ... }
)
interaction_handle = interact_res.json().get("interaction_handle")""",
        )

        # Step 3: /interact
        log.info("Calling /interact to get interactionHandle")
        interact_res = await self.http_client.post(
            "https://id.churchofjesuschrist.org/oauth2/default/v1/interact",
            data={
                "client_id": "0oaodd1guy51rqnJo357",
                "scope": "openid profile offline_access",
                "redirect_uri": "https://referralmanager.churchofjesuschrist.org/login",
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
                "state": state,
                "nonce": nonce,
            },
        )
        interaction_handle = interact_res.json().get("interaction_handle")
        if not interaction_handle:
            raise Exception(f"/interact call failed. Response: {interact_res.text}")

        Presenter.update_state("interaction_handle", interaction_handle)

        # Step 4: /introspect
        log.info("Calling /introspect with interactionHandle")
        introspect_res = await self.http_client.post(
            "https://id.churchofjesuschrist.org/idp/idx/introspect",
            json={"interactionHandle": interaction_handle},
        )
        state_handle = introspect_res.json().get("stateHandle")
        if not state_handle:
            raise Exception(f"/introspect call failed. Response: {introspect_res.text}")

        Presenter.update_state("state_handle", state_handle)

        Presenter.end_step()

        # ---------------------------------------------------------

        Presenter.step(
            "Stage 4: Identity & Challenge",
            "We use the [bold cyan]stateHandle[/] to step through the login form via API:\n\n"
            "1. [bold cyan]/identify[/]: We send the username. Okta confirms and lists available auth methods.\n"
            "2. [bold cyan]/challenge[/]: We select the 'Password' authenticator.\n"
            "3. [bold cyan]/answer[/]: We send the password.\n\n"
            "If successful, the [bold]stateHandle[/] is updated to indicate a 'success' status.",
            """
# Identify
await self.http_client.post(
    ".../identify",
    json={"stateHandle": state_handle, "identifier": self.env.church_username},
)

# Challenge Answer (Password)
await self.http_client.post(
    ".../challenge/answer",
    json={
        "stateHandle": state_handle,
        "credentials": {"passcode": self.env.church_password},
    },
)""",
        )

        # Step 5: /identify (send username)
        log.info("Sending the username")
        identify_res = await self.http_client.post(
            "https://id.churchofjesuschrist.org/idp/idx/identify",
            json={"stateHandle": state_handle, "identifier": self.env.church_username},
        )
        identify_data = identify_res.json()
        state_handle = identify_data.get("stateHandle")
        if not state_handle:
            raise Exception(f"/identify call failed. Response: {identify_data}")

        Presenter.update_state("state_handle", state_handle)

        # Step 6: Find password authenticator
        authenticators = identify_data.get("authenticators", {}).get("value", [])
        password_authenticator_id = next(
            (
                auth.get("id")
                for auth in authenticators
                if auth.get("type") == "password"
            ),
            None,
        )
        if not password_authenticator_id:
            raise Exception("No password authenticator found")

        # Step 7: /challenge
        log.info("Challenging the password authenticator")
        challenge_res = await self.http_client.post(
            "https://id.churchofjesuschrist.org/idp/idx/challenge",
            json={
                "authenticator": {"id": password_authenticator_id},
                "stateHandle": state_handle,
            },
        )
        state_handle = challenge_res.json().get("stateHandle")
        if not state_handle:
            raise Exception(f"/challenge call failed. Response: {challenge_res.text}")

        Presenter.update_state("state_handle", state_handle)

        # Step 8: /challenge/answer (send password)
        log.info("Sending the password")
        await self.http_client.post(
            "https://id.churchofjesuschrist.org/idp/idx/challenge/answer",
            json={
                "stateHandle": state_handle,
                "credentials": {"passcode": self.env.church_password},
            },
        )

        Presenter.end_step()

        # ---------------------------------------------------------

        Presenter.step(
            "Stage 5: The Critical Fix (Returning Home)",
            "Okta has verified us! Now we must return to the app.\n\n"
            "The app expects us to hit the original Redirect URI, but with a twist: we manually append [bold cyan]okta=true[/].\n\n"
            "This flag tells the Church's server: 'I have finished talking to Okta, please validate my session state now.'\n"
            "We must preserve the other parameters like `state` so the server knows which session we are resuming.",
            """
# The Fix
if location_url:
    # Use copy_add_param to preserve existing params
    authorize_url = httpx.URL(location_url).copy_add_param("okta", "true")
    
    await self.http_client.get(authorize_url)""",
        )

        # Step 9: /authorize with okta=true
        log.info("Calling /authorize using location URL with okta=true")
        if location_url:
            authorize_url = httpx.URL(location_url).copy_add_param("okta", "true")
            Presenter.update_state("authorize_url", str(authorize_url))
            await self.http_client.get(authorize_url)
        else:
            log.warning("Location URL was empty, skipping /authorize call")

        Presenter.end_step()

        # ---------------------------------------------------------

        Presenter.step(
            "Stage 6: Exchanging for the Bearer Token",
            "We call the app's [bold cyan]/services/auth[/] endpoint.\n\n"
            "The server checks our session cookies (which were set during the previous redirect steps) and verifies we are logged in.\n"
            "It issues a [bold green]Bearer Token[/] (JWT). This token contains our [bold cyan]missionId[/], which defines which data we are allowed to see.",
            """
token_res = await self.http_client.get(
    ".../services/auth", ...
)
token = token_res.json().get("token")
mission_id = token_res.json().get("missionId")""",
        )

        # Step 10: Get the bearer token
        log.info("Getting the bearer token")
        token_res = await self.http_client.get(
            "https://referralmanager.churchofjesuschrist.org/services/auth",
            headers={"Accept": "application/json"},
        )
        token_res.raise_for_status()
        token_data = token_res.json()
        token_str = token_data.get("token")
        mission_id = token_data.get("missionId")

        if not token_str:
            raise Exception(f"Failed to get final token. Response: {token_res.text}")

        # Filtered View of Response
        filtered_response = {
            "missionId": mission_id,
            "orgName": token_data.get("orgName"),
            "token": token_str[:20] + "..." if token_str else None,
        }
        Presenter.log_json(filtered_response, "Final Auth Response (Filtered)")

        token = BearerToken.from_base64(token_str, mission_id=mission_id)
        self.bearer_token = token

        Presenter.update_state("mission_id", token.claims.mission_id)
        Presenter.update_state("bearer_token", token.token)

        log.info(
            f"[bold green]Success![/] Got Token for Mission ID: {token.claims.mission_id}"
        )

        Presenter.end_step()

        return token

    async def get_people_list(self) -> List[Dict[str, Any]]:
        # Ensure we are logged in before presenting the next step
        if not self.bearer_token:
            await self.login()

        Presenter.step(
            "Stage 7: Fetching Mission Data",
            f"We now have the Keys to the Kingdom.\n\n"
            f"We make a GET request to the People API, using the [bold cyan]missionId: {self.bearer_token.claims.mission_id}[/].\n"
            "We pass the token in the `Authorization` header.\n"
            "This returns the full database of people for that mission. We will parse it and redact sensitive info for display.",
            """
res = await self.http_client.get(
    f".../mission/{mission_id}...", 
    headers={"Authorization": f"Bearer {token}"}
)
redacted_sample = redact_pii(people_list[0])""",
        )

        log.info("Getting the people list from referral manager")
        for i in range(MAX_RETRIES):
            try:
                url = (
                    f"https://referralmanager.churchofjesuschrist.org/services/people/mission/"
                    f"{self.bearer_token.claims.mission_id}?includeDroppedPersons=true"
                )
                res = await self.http_client.get(
                    url, headers={"Authorization": f"Bearer {self.bearer_token.token}"}
                )
                res.raise_for_status()
                log.info("Download complete. Parsing JSON...")
                people_list = res.json()

                # Handle dictionary response wrapper if present
                if isinstance(people_list, dict) and "persons" in people_list:
                    people_list = people_list["persons"]

                log.info(f"Received {len(people_list)} people from referral manager")

                if people_list:
                    # Redact PII and filter for "Interesting" data
                    def simplify_and_redact(p):
                        # Fields we definitely want to show to prove we have the data
                        interesting_keys = [
                            "firstName",
                            "lastName",
                            "address",
                            "missionName",
                            "zoneName",
                            "districtName",
                            "areaName",
                            "orgName",
                            "phone",
                            "phoneHome",
                            "phoneMobile",
                            "phoneWork",
                            "phoneOther",
                            "email",
                            "referralStatusName",
                            "createDate",
                            "statusDate",
                        ]

                        pii_fields = {
                            "firstName",
                            "lastName",
                            "address",
                            "phone",
                            "phoneHome",
                            "phoneMobile",
                            "phoneWork",
                            "phoneOther",
                            "email",
                        }

                        simplified = {}
                        for k in interesting_keys:
                            if k not in p:
                                continue

                            v = p[k]

                            # Redact if it has a value and is PII
                            if k in pii_fields and v:
                                val = "[REDACTED]"
                            else:
                                val = v

                            # Make dates readable
                            if isinstance(val, int) and val > 1000000000000:
                                try:
                                    val = time.strftime(
                                        "%Y-%m-%d", time.gmtime(val / 1000.0)
                                    )
                                except:
                                    pass

                            simplified[k] = val
                        return simplified

                    sample = simplify_and_redact(people_list[0])
                    console.print(
                        Panel(
                            json.dumps(sample, indent=2),
                            title="[bold cyan]Simplified Sample (Contact & Location Data)[/]",
                            border_style="blue",
                            expand=False,
                        )
                    )

                Presenter.end_step()

                return people_list
            except (
                httpx.RequestError,
                httpx.HTTPStatusError,
                json.JSONDecodeError,
                ValueError,
            ) as e:
                log.warning(f"Getting people list failed (try {i + 1}): {e}")
                # If it failed, maybe our token expired? Try logging in again if we have retries left
                if i < MAX_RETRIES - 1:
                    log.info("Re-authenticating...")
                    await self.login()

        raise Exception("Max retries exceeded for get_people_list")


async def main():
    # Setup
    load_dotenv()
    env = Env(
        working_path=".",
        church_username=os.environ.get("CHURCH_USERNAME", "your_username"),
        church_password=os.environ.get("CHURCH_PASSWORD", "your_password"),
    )

    if env.church_username == "your_username":
        console.print(
            "[bold red]Please set your CHURCH_USERNAME and CHURCH_PASSWORD environment variables.[/]"
        )
        return

    try:
        # Create Client
        client = await ChurchClient.create(env)

        # Run Flow
        people = await client.get_people_list()

        log.info(f"Successfully fetched {len(people)} items/people.")

    except Exception:
        console.print_exception()


if __name__ == "__main__":
    asyncio.run(main())
