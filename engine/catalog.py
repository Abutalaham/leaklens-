"""Human-readable knowledge about each finding type: label, category, why it is
risky and what to do. Base scores live in config.BASE_SCORES (configurable)."""
from config import BASE_SCORES

_ROTATE = ("Revoke or rotate it now (assume it is compromised if the file was already shared), "
           "then load it from an environment variable or secrets manager. Redacting a copy does "
           "not make an already-leaked secret safe.")
_PII = ("Remove it, or replace it with a placeholder, unless the recipient genuinely needs it. "
        "Share the minimum personal data necessary.")

_T = {
    "PRIVATE_KEY": ("Private key", "Credential", "Private keys prove identity; anyone holding one can impersonate the owner or decrypt data.", _ROTATE),
    "AWS_ACCESS_KEY": ("AWS access key ID", "Credential", "Matches the AWS access-key format and can identify an account that attackers probe.", _ROTATE),
    "AWS_SECRET_KEY": ("AWS secret access key", "Credential", "Paired with an access key ID it grants programmatic access to AWS resources.", _ROTATE),
    "GITHUB_TOKEN": ("GitHub token", "Credential", "Matches a GitHub token format; can grant repository or account access.", _ROTATE),
    "GOOGLE_API_KEY": ("Google API key", "Credential", "Matches the Google API key format; can incur cost or expose data.", _ROTATE),
    "SLACK_TOKEN": ("Slack token", "Credential", "Matches a Slack token format; can read or post in workspaces.", _ROTATE),
    "STRIPE_KEY": ("Stripe live key", "Credential", "Live payment keys can move money or expose customer data.", _ROTATE),
    "SENDGRID_KEY": ("SendGrid API key", "Credential", "Can send email as your domain.", _ROTATE),
    "OPENAI_STYLE_KEY": ("'sk-' style API key", "Credential", "Matches the common 'sk-' secret-key format used by AI API providers; usage is billed to the owner.", _ROTATE),
    "NPM_TOKEN": ("npm token", "Credential", "Can publish packages as the owner.", _ROTATE),
    "HUGGINGFACE_TOKEN": ("Hugging Face token", "Credential", "Can read or write models and datasets.", _ROTATE),
    "JWT": ("JSON Web Token", "Credential", "A JWT may be a live session or API token until it expires.", "Check whether it is still valid, revoke the session or key if so, and avoid pasting tokens into shared files."),
    "AUTH_HEADER": ("Authorization header value", "Credential", "A Bearer/Basic value is a ready-to-use credential.", _ROTATE),
    "CONNECTION_STRING": ("Password in connection string", "Credential", "The URL embeds a username and password for a service.", _ROTATE),
    "GENERIC_CREDENTIAL": ("Hardcoded credential", "Credential", "A credential-named variable is assigned a literal value.", _ROTATE),
    "TWILIO_KEY": ("Twilio API key", "Credential", "Matches Twilio API key format; grants access to send SMS and trigger voice calls.", _ROTATE),
    "DISCORD_TOKEN": ("Discord bot token", "Credential", "Matches Discord bot token structure; grants control over connected Discord bot.", _ROTATE),
    "GITLAB_PAT": ("GitLab token", "Credential", "Matches GitLab Personal Access Token format; grants repository or CI/CD access.", _ROTATE),
    "SUPABASE_KEY": ("Supabase key", "Credential", "Matches Supabase JWT token format; grants direct database access.", _ROTATE),
    "POSTMAN_KEY": ("Postman API key", "Credential", "Matches Postman key format; grants access to private workspaces and mocks.", _ROTATE),
    "DIGITALOCEAN_TOKEN": ("DigitalOcean token", "Credential", "Matches DigitalOcean personal access token; can manipulate cloud infrastructure.", _ROTATE),
    "HEROKU_KEY": ("Heroku API key", "Credential", "Matches Heroku API key format; can access apps, configs, and add-ons.", _ROTATE),
    "CREDIT_CARD": ("Payment card number", "Personal data", "Passes the Luhn checksum and a card-network prefix check.", "Remove it. Never share full card numbers; if real, tell the card issuer."),
    "AADHAAR": ("Aadhaar number", "Personal data", "A 12-digit number that passes the Verhoeff checksum used by Aadhaar.", _PII),
    "SSN": ("US Social Security number", "Personal data", "Matches the SSN format and basic validity rules.", _PII),
    "PAN": ("PAN (India tax ID)", "Personal data", "Matches the Indian Permanent Account Number format.", _PII),
    "EMAIL": ("Email address", "Personal data", "Email addresses identify people and enable phishing or spam.", _PII),
    "PHONE": ("Phone number", "Personal data", "Phone numbers identify people and enable spam or SIM-swap attempts.", _PII),
    "IP_ADDRESS": ("IP address", "Network", "May reveal infrastructure or location.", "Remove it if it is not needed by the reader."),
    "INTERNAL_IP": ("Internal IP address", "Network", "Reveals private network layout.", "Remove or generalise internal addresses before sharing."),
    "SUSPECTED_SENSITIVE": ("Suspected sensitive value (ML)", "Credential", "The ML classifier judged this line likely to contain a secret or personal value, but no deterministic rule matched. Treat as a hint to review.", "Review the line manually; redact it if it is real."),
    "METADATA_GPS": ("GPS location in metadata", "Metadata", "Embedded coordinates can reveal where a photo was taken (often a home or workplace).", "Strip metadata before sharing. LeakLens always removes it from the sanitised copy."),
    "METADATA_AUTHOR": ("Author / owner in metadata", "Metadata", "Names or owners embedded in file metadata can identify a person.", "Strip metadata before sharing. LeakLens removes it from the sanitised copy."),
    "METADATA_DEVICE": ("Device / capture info in metadata", "Metadata", "Camera model and timestamps help fingerprint a device or timeline.", "Strip metadata before sharing."),
    "METADATA_SOFTWARE": ("Software info in metadata", "Metadata", "Reveals the tools used to create the file.", "Usually harmless; stripped from the sanitised copy."),
    "METADATA_DOCINFO": ("Document info in metadata", "Metadata", "Title, subject or keywords may reveal internal project names.", "Review and strip if sensitive."),
}

# Concrete impact if the value is real and already exposed. Shown on finding cards.
# Each entry names the systems or data an attacker could reach — not a generic "rotate it".
BLAST_RADIUS = {
    "PRIVATE_KEY": "Whoever holds the key can impersonate the owner: SSH or TLS client login, code signing, or decryption of data protected by the matching public key.",
    "AWS_ACCESS_KEY": "Identifies an IAM principal. Paired with the secret key it unlocks that principal's AWS APIs (S3, EC2, IAM, and whatever else the policy allows).",
    "AWS_SECRET_KEY": "With the access key ID, this grants programmatic AWS access: S3 object read/write, EC2 and Lambda control, IAM changes, and any other action in the key's policy.",
    "GITHUB_TOKEN": "Repository read or write, Actions secrets, packages, and — for broader PATs — private repos, org membership, and workflow dispatch.",
    "GOOGLE_API_KEY": "Calls against whichever Google APIs the key is allowed to use (Maps, YouTube, Cloud), billed to the owning project. Unrestricted keys can run up quota and invoice cost.",
    "SLACK_TOKEN": "Workspace access under the token's scopes: channel history, files, user directory, and posting messages as the app or user.",
    "STRIPE_KEY": "Live secret keys can create charges and refunds, read customers and payouts, and act on connected accounts — direct movement of money and cardholder data.",
    "SENDGRID_KEY": "Send mail as the verified domain, and read stats plus suppression lists. Attackers can phish from an address recipients already trust.",
    "OPENAI_STYLE_KEY": "Billable model calls on the owning account. Org or project keys may also read stored files, assistants, and fine-tuning data.",
    "NPM_TOKEN": "Publish, unpublish, or modify packages under the account — a supply-chain path into every app that installs those packages.",
    "HUGGINGFACE_TOKEN": "Read or overwrite private models and datasets, and spend Inference Endpoints or API quota on the account.",
    "JWT": "Until it expires, the token can call whatever APIs its claims allow: session takeover, user impersonation, or service-to-service access.",
    "AUTH_HEADER": "A ready-to-replay credential. The next request that sends this header acts with the original caller's privileges on that API.",
    "CONNECTION_STRING": "Database login with the embedded user: read, change, or drop data, and often a path to other secrets stored in the same database.",
    "GENERIC_CREDENTIAL": "Treated as full access to the service named by the variable (password, token, or API key) until you confirm it is a dummy.",
    "TWILIO_KEY": "Send SMS and voice calls, read message logs, and incur per-message charges on the Twilio project.",
    "DISCORD_TOKEN": "Control the bot: read guild messages, manage channels and roles the bot can touch, and post as that bot.",
    "GITLAB_PAT": "Repository contents, container registry, and CI/CD variables — those variables often hold further cloud and deploy secrets.",
    "SUPABASE_KEY": "PostgREST and database access as the key's role. A service-role key bypasses row-level security and sees every row.",
    "POSTMAN_KEY": "Private collections, environments (which often store more secrets), mocks, and monitors in the workspace.",
    "DIGITALOCEAN_TOKEN": "Account infrastructure: Droplets, volumes, DNS, firewalls, and billing actions the token's scopes allow.",
    "HEROKU_KEY": "Apps, dynos, add-ons, and config vars. Config vars commonly contain database URLs and third-party API keys.",
    "CREDIT_CARD": "Card-not-present purchases until the issuer blocks the number. The PAN plus expiry or CVV is enough for many merchants.",
    "AADHAAR": "Indian national identity number. Exposure supports identity fraud and fraudulent KYC against the holder.",
    "SSN": "US identity number used for credit applications, tax filing, and benefits fraud against the person it belongs to.",
    "PAN": "Indian tax identity. Exposure supports fraudulent tax or financial KYC in that person's name.",
    "EMAIL": "Identifies a person and is the usual reset channel for their other accounts: phishing, spam, and account-recovery attacks.",
    "PHONE": "Identifies a person and enables spam, voice-phishing, and social engineering toward a SIM swap.",
    "IP_ADDRESS": "Points at a host or network. Public addresses help attackers map infrastructure and aim scans or exploits.",
    "INTERNAL_IP": "Reveals private addressing (RFC1918). That map is what an attacker uses after they get a foothold inside the network.",
    "SUSPECTED_SENSITIVE": "No specific rule matched. If the line is a real secret, impact is whatever that secret unlocks — credential use or personal-data exposure.",
    "METADATA_GPS": "Latitude and longitude of where the photo was taken, often a home or workplace, which can identify a person from a single image.",
    "METADATA_AUTHOR": "Names the person embedded as author or owner, linking the file to a real identity even after the visible content is redacted.",
    "METADATA_DEVICE": "Camera model and capture time fingerprint a device and a timeline, which can tie several files to one person.",
    "METADATA_SOFTWARE": "Names the applications that produced the file. Low direct harm; still useful for profiling the author's toolchain.",
    "METADATA_DOCINFO": "Title, subject, or keywords can leak unreleased project names, customer names, or internal document classifications.",
}


def known_types():
    return list(_T)

PROVIDER_MAP = {
    "AWS_ACCESS_KEY": "AWS",
    "AWS_SECRET_KEY": "AWS",
    "GITHUB_TOKEN": "GitHub",
    "GOOGLE_API_KEY": "Google Cloud",
    "SLACK_TOKEN": "Slack",
    "STRIPE_KEY": "Stripe",
    "SENDGRID_KEY": "SendGrid",
    "OPENAI_STYLE_KEY": "OpenAI / LLM",
    "NPM_TOKEN": "npm",
    "HUGGINGFACE_TOKEN": "Hugging Face",
    "TWILIO_KEY": "Twilio",
    "DISCORD_TOKEN": "Discord",
    "GITLAB_PAT": "GitLab",
    "SUPABASE_KEY": "Supabase",
    "POSTMAN_KEY": "Postman",
    "DIGITALOCEAN_TOKEN": "DigitalOcean",
    "HEROKU_KEY": "Heroku",
    "PRIVATE_KEY": "Cryptography",
    "CONNECTION_STRING": "Database",
    "AUTH_HEADER": "HTTP Auth",
    "JWT": "Auth Token",
}


def info(t):
    label, cat, why, action = _T.get(t, (t, "General", "Potential sensitive information", _ROTATE))
    base = BASE_SCORES.get(t, 50)
    provider = PROVIDER_MAP.get(t, "Generic")
    blast = BLAST_RADIUS.get(
        t,
        "Impact depends on the service this value unlocks. If it is a real credential, the holder can act as the account that owns it.",
    )
    return {
        "label": label, "category": cat, "why": why, "action": action,
        "base": base, "provider": provider, "blast_radius": blast,
    }


def short_label(t):
    return t
