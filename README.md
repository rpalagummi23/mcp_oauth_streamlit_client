# ❄️ Snowflake MCP Client with OAuth

**Copyright (c) 2025 Snowflake Inc. All rights reserved.**

**WARRANTY: 
THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.**


**Author:** Ram Palagummi  

---

## About This Project

This project provides a **Streamlit-based MCP (Model Context Protocol) client** that connects to Snowflake MCP servers using **OAuth 2.0 Authorization Code Flow with PKCE**.

### What It Does

- **Authenticates users** via Snowflake's OAuth security integration
- **Generates access tokens** after successful authentication
- **Connects to Snowflake MCP servers** to execute natural language queries
- **Supports role-based access control** by passing a user role during authentication

### How OAuth Integration Works

1. **User initiates login** → Client generates PKCE code verifier and challenge
2. **Redirects to Snowflake** → User authenticates with Snowflake credentials
3. **Authorization code returned** → Snowflake redirects back with an authorization code
4. **Token exchange** → Client exchanges the code for an access token
5. **MCP server access** → Access token is used to authenticate API calls to the MCP server

### Role-Based Access Control

The `ROLE` configuration parameter controls which Snowflake role is used when accessing the MCP server. This role:
- Is passed in the OAuth scope as `session:role:<ROLE_NAME>`
- Determines what data and operations the user can access
- Must have appropriate grants on the MCP server and underlying data

**Note:** If no role is specified, Snowflake uses the user's default role at the time of authentication.

---

## ⚙️ Snowflake Setup Required

### Step 1: Create MCP Server

Create an MCP server in Snowflake with appropriate tools configured:

```sql
CREATE MCP SERVER <your_mcp_server_name> FROM SPECIFICATION $$
tools:
  - title: "Your Tool Title"
    name: "your_tool_name"
    identifier: "<database>.<schema>.<tool_identifier>"
    type: "<TOOL_TYPE>"
    description: "Description of what this tool does"
$$;
```

For detailed instructions on creating MCP servers and configuring tools, refer to the [Snowflake MCP Server Documentation](https://docs.snowflake.com/en/user-guide/mcp-servers).

### Step 2: Create Security Integration (Sample code below)
(For more information, see the [Snowflake Security Integration Documentation](https://docs.snowflake.com/en/sql-reference/sql/create-security-integration-oauth-snowflake).)

```sql
CREATE OR REPLACE SECURITY INTEGRATION mcp_client_oauth
  TYPE = OAUTH
  ENABLED = TRUE
  OAUTH_CLIENT = CUSTOM
  OAUTH_CLIENT_TYPE = 'CONFIDENTIAL'
  OAUTH_REDIRECT_URI = 'http://localhost:8501'
  OAUTH_ALLOW_NON_TLS_REDIRECT_URI = TRUE
  OAUTH_REFRESH_TOKEN_VALIDITY = 86400 
  BLOCKED_ROLES_LIST = ('ACCOUNTADMIN', 'SECURITYADMIN');
```

### Step 3: Get OAuth Credentials

```sql
SELECT SYSTEM$SHOW_OAUTH_CLIENT_SECRETS('STREAMLIT_MCP_OAUTH');
```

This returns:
```json
{
  "OAUTH_CLIENT_SECRET_2": "...",
  "OAUTH_CLIENT_SECRET": "...",
  "OAUTH_CLIENT_ID": "..."
}
```

### Step 4: Create .env Configuration File

Copy `.env.example` to `.env` and update with your values:

```bash
cp .env.example .env
```

Edit `.env` with your configuration:

```env
# Snowflake Account Details
ACCOUNT_HOSTNAME=myorg-myaccount.snowflakecomputing.com
DATABASE=MY_DATABASE
SCHEMA=MY_SCHEMA
MCP_SERVER_NAME=MY_MCP_SERVER
ROLE=MY_ROLE

# OAuth Security Integration credentials
# Get these by running: SELECT SYSTEM$SHOW_OAUTH_CLIENT_SECRETS('YOUR_INTEGRATION_NAME');
OAUTH_CLIENT_ID=your_oauth_client_id
OAUTH_CLIENT_SECRET=your_oauth_client_secret

# Redirect URI - Must match OAUTH_REDIRECT_URI in your security integration
REDIRECT_URI=http://localhost:8501
```

### Step 5: Grant Permissions

```sql
-- Grant usage on integration. You may provide any name for the integration 
GRANT USAGE ON INTEGRATION mcp_client_oauth TO ROLE <your_role>;

-- Grant access to MCP server
GRANT USAGE ON DATABASE <your_database> TO ROLE <your_role>;
GRANT USAGE ON SCHEMA <your_database>.<your_schema> TO ROLE <your_role>;
GRANT USAGE ON MCP SERVER <your_database>.<your_schema>.<your_mcp_server> TO ROLE <your_role>;
```

---

## 🚀 Running the MCP Client OAuth App

### Set Up Virtual Environment (Recommended):

```bash
python -m venv venv

source venv/bin/activate

pip install -r requirements.txt
```

### Run the App:

```bash
streamlit run mcp_client_oauth.py
```

### Use the App:

1. Click **"🔐 Login with Snowflake"** in the sidebar
2. You'll be redirected to Snowflake login page
3. Enter your Snowflake username and password
4. Grant permissions
5. You'll be redirected back to the app with a valid token
6. Start querying your data!

---

## 🔄 OAuth Flow Diagram

```
User clicks "Login"
     ↓
Streamlit generates PKCE code_verifier & code_challenge
     ↓
Redirects to: https://account.snowflakecomputing.com/oauth/authorize
     ↓
User logs in with Snowflake credentials
     ↓
Snowflake redirects back: http://localhost:8501?code=xxx&state=yyy
     ↓
Streamlit exchanges code for access_token
     ↓
Streamlit uses access_token to call MCP server
     ↓
✅ Authenticated!
```

---

## 📊 OAuth Authorization Code Flow Benefits

| Feature | Description |
|---------|-------------|
| **Setup** | Requires OAuth security integration |
| **User Login** | Required (Snowflake login) |
| **Token Expiry** | Session-based (hours) |
| **Security** | Dynamic per-user tokens |
| **Role Control** | Pass role via OAuth scope |

---

## 🎯 When to Use This Approach

### Use `mcp_client_oauth.py` if:
- ✅ Multi-user application where each user authenticates themselves
- ✅ You need role-based access control to MCP servers
- ✅ You want proper OAuth security with dynamic tokens
- ✅ Session-based tokens are acceptable

---

## 🐛 Troubleshooting OAuth

### "Invalid redirect_uri"
- Ensure `OAUTH_REDIRECT_URI` in security integration matches `REDIRECT_URI` in app
- For localhost, use exactly: `http://localhost:8501`
- For deployed apps, use your actual domain

### "invalid_grant" during token exchange
- Check that CLIENT_ID and CLIENT_SECRET match the security integration
- Verify the security integration is ENABLED
- Ensure OAUTH_CLIENT_TYPE is 'CONFIDENTIAL'

### "Token expired"
- OAuth tokens are session-based and expire
- Click "Logout" and "Login" again to get a fresh token

### Can't authenticate
- Verify user has permissions on the security integration
- Check that BLOCKED_ROLES_LIST doesn't include your role
- Ensure account-level MCP features are enabled

---

## 💡 Why Authorization Code Flow?

**Authorization Code Flow** is required for Snowflake MCP servers because:
- User-interactive authentication ensures proper identity verification
- Browser-based login leverages Snowflake's existing authentication mechanisms
- `grant_type=authorization_code` is the supported method for MCP server access
- PKCE (Proof Key for Code Exchange) adds additional security against code interception

---

## 🔒 Security Notes

1. **Never commit OAuth secrets to git**
2. **Use environment variables for production**
3. **REDIRECT_URI must use HTTPS in production** (not http)
4. **Tokens are stored in Streamlit session** (not persisted)
5. **Users must re-login when session expires**

---

## 🎉 Success!

If everything is set up correctly:
1. Click "Login with Snowflake"
2. Authenticate with your Snowflake credentials
3. Get redirected back with ✅ "Successfully authenticated!"
4. Start querying your MCP server with natural language!

