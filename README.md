# OktaFlow - Interactive Authentication Demo

This repository contains two primary Python scripts: a "production-like" client and an interactive, educational presentation tool. Both are designed to reverse-engineer and demonstrate the Okta authentication flow used by the Church's Referral Manager.

## Purpose

The primary goal of `OktaFlow` is to educate and demonstrate the hidden mechanics of modern web authentication. By slowing down the OAuth 2.0 process and inspecting the traffic step-by-step, we can understand:

1.  **PKCE Security:** How `code_verifier` and `code_challenge` prevent interception attacks.
2.  **OAuth Handshakes:** The specific API calls (`/interact`, `/introspect`, `/identify`, `/challenge`) that establish a trusted session.
3.  **State Management:** How session state is maintained between the Identity Provider (Okta) and the Service Provider (Referral Manager).
4.  **The "Critical Fix":** Identifying and handling non-standard requirements (like the `okta=true` flag) that are often undocumented but essential for programmatic access.

## Files Overview

### 1. `src/main.py` (The Interactive Presentation)

This is the core educational tool. It is a highly polished, interactive CLI application that guides the user through the authentication flow one step at a time.

**Key Features:**

- **Narrative Walkthrough:** Pauses at 7 key stages to explain _what_ is happening and _why_.
- **Visual Journey:** A "Session State" panel tracks critical parameters (`stateHandle`, `code_verifier`, `mission_id`) as they are generated and passed between systems.
- **Traffic Inspection:** Displays snippets of real JSON responses, allowing you to see the "authenticator" lists and tokens returned by the server.
- **Safety First:** Automatically redacts PII (Personally Identifiable Information) from the final output, making it safe for live demos.
- **Compact UI:** Uses the `rich` library to present complex data in clean, readable tables and panels.

### 2. `src/main_cli_presentation.py` (The "Production" Logic)

This file likely contains the initial or alternative version of the logic, focusing on the functional implementation of the client without the heavy interactive pauses and educational panels of `main.py`. It serves as a reference for how to implement the client in a real-world scenario (e.g., for data scraping or automation) once the flow is understood.

## Prerequisites

- Python 3.14+
- `uv` (recommended) or `pip` for dependency management.

## Setup

1.  **Clone the repository:**

    ```bash
    git clone <repository-url>
    cd OktaFlow
    ```

2.  **Install dependencies:**

    ```bash
    uv sync
    # OR
    pip install -r requirements.txt
    ```

3.  **Configure Environment:**
    Create a `.env` file in the root directory with your credentials:
    ```env
    CHURCH_USERNAME=your_username
    CHURCH_PASSWORD=your_password
    ```

## Usage

**To run the Interactive Presentation (Recommended):**

```bash
uv run src/main.py
# OR
python src/main.py
```

Follow the on-screen prompts. Press `Enter` to advance through each stage of the authentication flow.

**To run the Standard Client Logic:**

```bash
uv run src/main_cli_presentation.py
# OR
python src/main_cli_presentation.py
```

## The Authentication Flow (7 Stages)

The interactive script breaks the complex OAuth dance into 7 digestible stages:

1.  **Initialization & PKCE:** We generate a cryptographic secret (`code_verifier`) and its hash (`code_challenge`) to secure the exchange.
2.  **Initial Redirect:** We hit the application to capture the redirect URL, which contains our client context.
3.  **OAuth Handshake:** We exchange the context for an `interaction_handle` and then "open" the transaction with Okta to get a `stateHandle`.
4.  **Identity & Challenge:** We prove who we are (`/identify`) and prove we know the secret (`/challenge` with password).
5.  **The Fix:** We manually construct the return URL with `okta=true`, signaling to the application that we have successfully authenticated.
6.  **Token Acquisition:** The application verifies our session and issues a Bearer Token (JWT) containing our permissions (`missionId`).
7.  **Data Fetch:** We use the token to access the protected People API, downloading and displaying the data (with PII redacted).

## Meta: The AI Factor

We started with a Rust script that I worked on while serving as an office Elder for the Florida Tallahasse Mission and I was able to quickly turn the logic I previously created in Rust into asynchronous Python using Gemini. I then had a weird whacky idea that I could demostrate the principals and content I'm talking about on my slides with a interactive presentation client. Gemini with 10 or 15 prompts got it down. Considering how last minute I've been working on this I'm super grateful. Very cool but also scary... 🤦‍♂️

## Disclaimer

This tool is for educational and research purposes only. Ensure you have authorization before interacting with any APIs. PII redaction is implemented for demonstration safety, but always handle credentials and data with care.
