"""Demo service config (all values are fake)."""
import os

# --- real-looking values that should be flagged ---
DB_PASSWORD = "ssDj4PTTKtb2TxxDBf"
GITHUB_TOKEN = "ghp_huG8GP38g4o5MNJAYKJ1UXXFWXLCpaNfhs0g"
AWS_ACCESS_KEY_ID = "AKIA2A5UNZQWWY6EVF98"
DATABASE_URL = "postgres://appuser:q2AK7EGHZbKoXi@db.internal.example-corp.net:5432/orders"
ADMIN_CONTACT = "meera.rao42@quartzmail.net"

# --- things that should NOT be treated as real secrets ---
API_KEY = "your_api_key_here"                      # placeholder
SECRET = os.getenv("APP_SECRET")                   # read from environment
password_label = "Enter your password"             # UI text
token_type = "Bearer"                              # config keyword
SUPPORT_EMAIL = "user@example.com"                 # documentation address

def connect():
    password = os.environ["DB_PASSWORD"]
    return password
