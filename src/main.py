import asyncio
import base64
import hashlib
import json
import logging
import os
import random
import string
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv

load_dotenv()


import httpx
from rich.logging import RichHandler

# --- Basic Configuration ---
logging.basicConfig(
    level="INFO", format="%(message)s", datefmt="[%X]", handlers=[RichHandler()]
)
log = logging.getLogger("rich")

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.82 Safari/537.36"
MAX_RETRIES = 3


# --- Data Structures (Inferred from Rust code) ---
@dataclass
class Env:
    """Configuration dataclass, similar to Rust's env::Env."""

    working_path: str
    church_username: str
    church_password: str


@dataclass
class BearerTokenClaims:
    """Claims decoded from the JWT bearer token."""

    mission_id: str


@dataclass
class BearerToken:
    """Represents the bearer token and its claims."""

    token: str
    claims: BearerTokenClaims

    @classmethod
    def from_base64(
        cls, b64_token: str, mission_id: Optional[str] = None
    ) -> "BearerToken":
        """Decodes the JWT to extract claims without verifying the signature."""
        try:
            _, payload_b64, _ = b64_token.split(".")
            payload_b64 += "=" * (-len(payload_b64) % 4)  # Add padding
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
    """
    A Python client to interact with the Church's Referral Manager services.
    This is an asynchronous translation of the original Rust code.
    """

    def __init__(self, env: Env):
        self.env = env
        self.working_path = Path(env.working_path)
        self.bearer_token: Optional[BearerToken] = None
        self._cookie_jar = httpx.Cookies()
        self.http_client: Optional[httpx.AsyncClient] = None

    @classmethod
    async def create(cls, env: Env) -> "ChurchClient":
        """Async factory to create and initialize the client."""
        instance = cls(env)
        await instance._init_clients()
        return instance

    async def _log_request(self, request: httpx.Request):
        await request.aread()
        log.info(f"Request: {request.method} {request.url}")
        if request.content:
            log.info(
                f"Request Body: {request.content.decode('utf-8', errors='replace')}"
            )

    async def _log_response(self, response: httpx.Response):
        await response.aread()
        log.info(f"Response: {response.status_code} {response.url}")
        log.info(f"Response Body: {response.text}")

    async def _init_clients(self):
        """Initializes the httpx clients in an async context."""
        self.http_client = httpx.AsyncClient(
            headers={"User-Agent": USER_AGENT},
            cookies=self._cookie_jar,
            timeout=60.0,
            follow_redirects=True,
            event_hooks={
                "request": [self._log_request],
                "response": [self._log_response],
            },
        )

    async def login(self) -> BearerToken:
        log.info("Logging into referral manager")
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

        # Step 1: Visit referral manager to get redirect
        log.info("Visiting referralmanager.churchofjesuschrist.org to capture redirect")
        # Use http_client but don't follow redirects to capture the Location header
        redirect_res = await self.http_client.get(
            "https://referralmanager.churchofjesuschrist.org/", follow_redirects=False
        )
        location_url = redirect_res.headers.get("location")
        if not location_url:
            raise Exception(
                "Failed to get initial redirect location from referralmanager"
            )
        log.info(f"Got redirect location: {location_url}")

        # Step 2: Follow the redirect
        log.info(f"Following redirect to: {location_url}")
        await self.http_client.get(location_url)

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

        # Step 4: /introspect
        log.info("Calling /introspect with interactionHandle")
        introspect_res = await self.http_client.post(
            "https://id.churchofjesuschrist.org/idp/idx/introspect",
            json={"interactionHandle": interaction_handle},
        )
        state_handle = introspect_res.json().get("stateHandle")
        if not state_handle:
            raise Exception(f"/introspect call failed. Response: {introspect_res.text}")

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

        # Step 8: /challenge/answer (send password)
        log.info("Sending the password")
        await self.http_client.post(
            "https://id.churchofjesuschrist.org/idp/idx/challenge/answer",
            json={
                "stateHandle": state_handle,
                "credentials": {"passcode": self.env.church_password},
            },
        )

        # Step 9: /authorize with okta=true
        log.info("Calling /authorize using location URL with okta=true")
        if location_url:
            authorize_url = httpx.URL(location_url).copy_add_param("okta", "true")
            await self.http_client.get(authorize_url)
        else:
            log.warning("Location URL was empty, skipping /authorize call")

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

        token = BearerToken.from_base64(token_str, mission_id=mission_id)
        self.bearer_token = token

        return token

    async def get_people_list(self) -> List[Dict[str, Any]]:
        log.info("Getting the people list from referral manager")
        for i in range(MAX_RETRIES):
            if not self.bearer_token:
                await self.login()
            try:
                # print(self.bearer_token)
                url = (
                    f"https://referralmanager.churchofjesuschrist.org/services/people/mission/"
                    f"{self.bearer_token.claims.mission_id}?includeDroppedPersons=true"
                )
                res = await self.http_client.get(
                    url, headers={"Authorization": f"Bearer {self.bearer_token.token}"}
                )
                res.raise_for_status()
                people_list = res.json()
                log.info(f"Received {len(people_list)} people from referral manager")
                return people_list
            except (
                httpx.RequestError,
                httpx.HTTPStatusError,
                json.JSONDecodeError,
                ValueError,
            ) as e:
                log.warning(f"Getting people list failed (try {i + 1}): {e}")
                self.bearer_token = None  # Force re-login
        raise Exception("Max retries exceeded for get_people_list")

    # Additional methods like get_person_timeline can be added here following the same pattern.


async def main():
    """Example usage of the ChurchClient."""
    # IMPORTANT: Replace with your actual credentials or load from a secure source
    load_dotenv()
    env = Env(
        working_path=".",
        church_username=os.environ.get("CHURCH_USERNAME", "your_username"),
        church_password=os.environ.get("CHURCH_PASSWORD", "your_password"),
    )

    if env.church_username == "your_username":
        log.error(
            "Please set your CHURCH_USERNAME and CHURCH_PASSWORD environment variables."
        )
        return

    try:
        client = await ChurchClient.create(env)

        log.info("Fetching people list...")
        # Direct call to get_people_list, no caching
        people = await client.get_people_list()

        log.info(f"Successfully fetched {len(people)} people.")
        if people:
            log.info("First person in list:")
            log.info(people[0])

    except Exception as e:
        log.error(f"An error occurred: {e}", exc_info=True)


if __name__ == "__main__":
    asyncio.run(main())
