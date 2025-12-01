# Copyright (c) 2025 Snowflake Inc. All rights reserved.

import streamlit as st
import httpx
import asyncio
import hashlib
import base64
import secrets
import json
import os
import tempfile
from urllib.parse import urlencode, parse_qs, urlparse
from typing import Optional, Dict, Any
import pandas as pd
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Page configuration
st.set_page_config(
    page_title="Snowflake MCP Agent - OAuth",
    page_icon="❄️",
    layout="wide"
)

# ============================================================
# CONFIGURATION - Loaded from environment variables (.env file)
# ============================================================
ACCOUNT_HOSTNAME = os.getenv("ACCOUNT_HOSTNAME")
DATABASE = os.getenv("DATABASE")
SCHEMA = os.getenv("SCHEMA")
MCP_SERVER_NAME = os.getenv("MCP_SERVER_NAME")
ROLE = os.getenv("ROLE")

# OAuth Security Integration credentials (from SYSTEM$SHOW_OAUTH_CLIENT_SECRETS)
OAUTH_CLIENT_ID = os.getenv("OAUTH_CLIENT_ID")
OAUTH_CLIENT_SECRET = os.getenv("OAUTH_CLIENT_SECRET")
REDIRECT_URI = os.getenv("REDIRECT_URI", "http://localhost:8501")

# Validate required configuration
_required_vars = ["ACCOUNT_HOSTNAME", "DATABASE", "SCHEMA", "MCP_SERVER_NAME", "ROLE", "OAUTH_CLIENT_ID", "OAUTH_CLIENT_SECRET"]
_missing_vars = [var for var in _required_vars if not os.getenv(var)]
if _missing_vars:
    st.error(f"❌ Missing required environment variables: {', '.join(_missing_vars)}")
    st.info("💡 Copy `.env.example` to `.env` and update with your values.")
    st.stop()

# Construct MCP URL
MCP_URL = f"https://{ACCOUNT_HOSTNAME}/api/v2/databases/{DATABASE}/schemas/{SCHEMA}/mcp-servers/{MCP_SERVER_NAME}"

# OAuth endpoints
AUTHORIZE_URL = f"https://{ACCOUNT_HOSTNAME}/oauth/authorize"
TOKEN_URL = f"https://{ACCOUNT_HOSTNAME}/oauth/token-request"

# Temporary storage for OAuth state (to persist across redirects)
OAUTH_STATE_DIR = os.path.join(tempfile.gettempdir(), 'streamlit_oauth')
os.makedirs(OAUTH_STATE_DIR, exist_ok=True)
# ============================================================


def save_oauth_state(state: str, code_verifier: str):
    """Save OAuth state to file to persist across redirects"""
    import time
    state_file = os.path.join(OAUTH_STATE_DIR, f"{state}.json")
    with open(state_file, 'w') as f:
        json.dump({'code_verifier': code_verifier, 'timestamp': time.time()}, f)


def load_oauth_state(state: str) -> Optional[str]:
    """Load OAuth state from file"""
    state_file = os.path.join(OAUTH_STATE_DIR, f"{state}.json")
    if os.path.exists(state_file):
        try:
            with open(state_file, 'r') as f:
                data = json.load(f)
                # Clean up file after reading
                os.remove(state_file)
                return data.get('code_verifier')
        except:
            return None
    return None


def generate_pkce_pair():
    """Generate PKCE code verifier and challenge"""
    code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')
    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode('utf-8')).digest()
    ).decode('utf-8').rstrip('=')
    return code_verifier, code_challenge


def get_authorization_url(state: str, code_challenge: str) -> str:
    """Generate OAuth authorization URL"""
    params = {
        'client_id': OAUTH_CLIENT_ID,
        'redirect_uri': REDIRECT_URI,
        'response_type': 'code',
        'state': state,
        'code_challenge': code_challenge,
        'code_challenge_method': 'S256',
        'scope': f'session:role:{ROLE}'
    }
    return f"{AUTHORIZE_URL}?{urlencode(params)}"


async def exchange_code_for_token(code: str, code_verifier: str) -> Optional[str]:
    """Exchange authorization code for access token"""
    try:
        async with httpx.AsyncClient(verify=False, timeout=30.0) as client:
            data = {
                'grant_type': 'authorization_code',
                'code': code,
                'redirect_uri': REDIRECT_URI,
                'client_id': OAUTH_CLIENT_ID,
                'client_secret': OAUTH_CLIENT_SECRET,
                'code_verifier': code_verifier
            }
            
            response = await client.post(
                TOKEN_URL,
                data=data,
                headers={'Content-Type': 'application/x-www-form-urlencoded'}
            )
            
            if response.status_code == 200:
                token_data = response.json()
                return token_data.get('access_token')
            else:
                st.error(f"Token exchange failed: {response.status_code}")
                st.error(f"Response: {response.text}")
                return None
                
    except Exception as e:
        st.error(f"Error exchanging code: {str(e)}")
        return None


async def call_mcp_tool(access_token: str, tool_name: str, arguments: Dict[str, Any]) -> Optional[Dict]:
    """Call MCP tool with access token"""
    try:
        async with httpx.AsyncClient(verify=False, timeout=120.0) as client:
            headers = {
                'Authorization': f'Bearer {access_token}',
                'Content-Type': 'application/json'
            }
            
            payload = {
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {
                    "name": tool_name,
                    "arguments": arguments
                },
                "id": 1
            }
            
            response = await client.post(MCP_URL, json=payload, headers=headers)
            
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 401:
                st.error("Token expired. Please re-authenticate.")
                return None
            else:
                st.error(f"MCP call failed: {response.status_code} - {response.text}")
                return None
                
    except Exception as e:
        st.error(f"Error calling MCP: {str(e)}")
        return None


def format_query_result(result: Dict) -> None:
    """Format and display query results"""
    try:
        if 'result' in result:
            content = result['result']
            
            # Handle new response format with content array
            if 'content' in content and isinstance(content['content'], list):
                for content_item in content['content']:
                    if content_item.get('type') == 'text':
                        try:
                            # Parse the JSON string inside text
                            text_data = json.loads(content_item['text'])
                            
                            # Check if it has result_set (SQL execution results)
                            if 'result_set' in text_data:
                                result_set = text_data['result_set']
                                
                                if 'data' in result_set and result_set['data']:
                                    st.subheader("📊 Query Results")
                                    
                                    # Get column names from metadata
                                    columns = [col['name'] for col in result_set['resultSetMetaData']['rowType']]
                                    data = result_set['data']
                                    
                                    # Display as table
                                    df = pd.DataFrame(data, columns=columns)
                                    st.dataframe(df, use_container_width=True)
                                    
                                    # Display row count
                                    st.success(f"✅ Total rows: {len(data)}")
                                else:
                                    st.warning("Query executed successfully but returned no results.")
                                return
                            
                            # Check if it has statement (SQL generation)
                            elif 'statement' in text_data:
                                st.subheader("Generated SQL Query")
                                st.code(text_data['statement'], language='sql')
                                return
                        except json.JSONDecodeError:
                            st.error("Failed to parse response")
                            st.text(content_item['text'])
            
            # Handle old format - SQL execution results
            elif isinstance(content, dict) and 'result_set' in content:
                result_set = content['result_set']
                
                if 'data' in result_set and result_set['data']:
                    st.subheader("📊 Query Results")
                    
                    # Get column names from metadata
                    columns = [col['name'] for col in result_set['resultSetMetaData']['rowType']]
                    data = result_set['data']
                    
                    # Display as table
                    df = pd.DataFrame(data, columns=columns)
                    st.dataframe(df, use_container_width=True)
                    
                    # Display row count
                    st.success(f"✅ Total rows: {len(data)}")
                else:
                    st.warning("Query executed successfully but returned no results.")
            
            # Handle old format - SQL statement
            elif isinstance(content, dict) and 'statement' in content:
                st.subheader("Generated SQL Query")
                st.code(content['statement'], language='sql')
            
            else:
                # Display raw result if format is unknown
                st.warning("Unknown response format:")
                st.json(content)
        else:
            st.json(result)
            
    except Exception as e:
        st.error(f"Error formatting results: {str(e)}")
        st.json(result)


def initialize_session_state():
    """Initialize session state"""
    if 'messages' not in st.session_state:
        st.session_state.messages = []
    if 'access_token' not in st.session_state:
        st.session_state.access_token = None
    if 'oauth_state' not in st.session_state:
        st.session_state.oauth_state = None
    if 'code_verifier' not in st.session_state:
        st.session_state.code_verifier = None


def main():
    """Main application"""
    initialize_session_state()
    
    # Custom CSS
    st.markdown("""
        <style>
        .main-header {
            font-size: 2.5rem;
            font-weight: bold;
            color: #29B5E8;
            margin-bottom: 1rem;
        }
        .sub-header {
            font-size: 1.2rem;
            color: #666;
            margin-bottom: 2rem;
        }
        </style>
    """, unsafe_allow_html=True)
    
    # Header
    st.markdown('<div class="main-header">❄️ Snowflake MCP Agent</div>', unsafe_allow_html=True)
    # st.markdown('<div class="sub-header">OAuth Authorization Code Flow - Just like Claude!</div>', unsafe_allow_html=True)
    
    # Check for OAuth callback
    query_params = st.query_params
    
    if 'code' in query_params and 'state' in query_params:
        code = query_params['code']
        state_from_callback = query_params['state']
        
        # Try to load state from file first (more reliable than session state)
        code_verifier = load_oauth_state(state_from_callback)
        
        # Also check session state as fallback
        stored_state = st.session_state.get('oauth_state')
        if not code_verifier:
            code_verifier = st.session_state.get('code_verifier')
        
        # If we have code_verifier, we can proceed
        if code_verifier:
            with st.spinner("Exchanging authorization code for access token..."):
                access_token = asyncio.run(
                    exchange_code_for_token(code, code_verifier)
                )
                
                if access_token:
                    st.session_state.access_token = access_token
                    # Clear OAuth state
                    st.session_state.oauth_state = None
                    st.session_state.code_verifier = None
                    st.success("✅ Successfully authenticated!")
                    # Clear query params
                    st.query_params.clear()
                    st.rerun()
                else:
                    st.error("❌ Token exchange failed - check credentials")
        else:
            # Code verifier not found - just clear params without showing error
            st.query_params.clear()
            # Don't rerun immediately to avoid loop - let the page render normally
            pass
    
    # Sidebar
    with st.sidebar:
        st.header("⚙️ Authentication")
        
        if st.session_state.access_token:
            st.success("✅ Authenticated")
            st.info(f"Token: {st.session_state.access_token[:20]}...")
            
            if st.button("🔓 Logout", use_container_width=True):
                st.session_state.access_token = None
                st.session_state.messages = []
                st.rerun()
        else:
            st.warning("⚠️ Not authenticated")
            
            if st.button("🔐 Login with Snowflake", use_container_width=True):
                # Generate PKCE pair
                code_verifier, code_challenge = generate_pkce_pair()
                state = secrets.token_urlsafe(32)
                
                # Save to file for persistence across redirects
                save_oauth_state(state, code_verifier)
                
                # Also store in session as backup
                st.session_state.oauth_state = state
                st.session_state.code_verifier = code_verifier
                st.session_state.oauth_in_progress = True
                
                # Generate authorization URL
                auth_url = get_authorization_url(state, code_challenge)
                
                # Redirect to Snowflake
                st.info("🔄 Redirecting to Snowflake login...")
                
                # Use st.markdown with meta refresh (stays in same tab)
                st.markdown(
                    f'<meta http-equiv="refresh" content="1;url={auth_url}">',
                    unsafe_allow_html=True
                )
                
                # Also add a manual link without target blank
                st.markdown(
                    f'<a href="{auth_url}" style="text-decoration: none;"><button style="padding: 10px 20px; background-color: #29B5E8; color: white; border: none; border-radius: 5px; cursor: pointer;">Click here if not redirected</button></a>',
                    unsafe_allow_html=True
                )
                
                st.stop()
        
        st.divider()
        
        if st.button("🗑️ Clear Chat", use_container_width=True):
            st.session_state.messages = []
            st.rerun()
        
        st.divider()
        st.markdown("### 💡 Example Queries")
        st.markdown("""
        - Show me sales trends by category
        - What are the top 10 products?
        - Compare Q1 vs Q2 sales
        - Show monthly revenue for 2025
        """)
    
    # Main chat interface
    st.subheader("💬 Ask Just Like Snowflake Intelligence!")
    
    # Display chat history
    for message in st.session_state.messages:
        with st.chat_message(message["role"]):
            st.markdown(message["content"])
            if "data" in message:
                format_query_result(message["data"])
    
    # Chat input
    if prompt := st.chat_input("Ask a question about your data..."):
        if not st.session_state.access_token:
            st.error("⚠️ Please authenticate first using the sidebar.")
            return
        
        # Add user message
        st.session_state.messages.append({"role": "user", "content": prompt})
        with st.chat_message("user"):
            st.markdown(prompt)
        
        # Process query
        with st.chat_message("assistant"):
            with st.spinner("Analyzing your query..."):
                # Step 1: Query analyst
                analyst_result = asyncio.run(
                    call_mcp_tool(
                        st.session_state.access_token,
                        "sales-and-marketing-analyst",
                        {"message": prompt}
                    )
                )
                
                if analyst_result and 'result' in analyst_result:
                    result_data = analyst_result['result']
                    
                    # Handle new response format with content array
                    if 'content' in result_data and isinstance(result_data['content'], list):
                        for content_item in result_data['content']:
                            if content_item.get('type') == 'text':
                                try:
                                    # Parse the JSON string inside text
                                    text_data = json.loads(content_item['text'])
                                    if 'statement' in text_data:
                                        sql_statement = text_data['statement']
                                        st.subheader("Generated SQL Query")
                                        st.code(sql_statement, language='sql')
                                        
                                        # Step 2: Execute SQL
                                        with st.spinner("Executing query..."):
                                            exec_result = asyncio.run(
                                                call_mcp_tool(
                                                    st.session_state.access_token,
                                                    "sql_exec_tool",
                                                    {"sql": sql_statement}
                                                )
                                            )
                                            
                                            if exec_result:
                                                format_query_result(exec_result)
                                                st.session_state.messages.append({
                                                    "role": "assistant",
                                                    "content": "Here are the results:",
                                                    "data": exec_result
                                                })
                                            else:
                                                st.error("Failed to execute query")
                                        break
                                except json.JSONDecodeError:
                                    st.error("Failed to parse response")
                                    st.text(content_item['text'])
                    # Handle old format (direct statement)
                    elif isinstance(result_data, dict) and 'statement' in result_data:
                        sql_statement = result_data['statement']
                        st.subheader("Generated SQL Query")
                        st.code(sql_statement, language='sql')
                        
                        # Step 2: Execute SQL
                        with st.spinner("Executing query..."):
                            exec_result = asyncio.run(
                                call_mcp_tool(
                                    st.session_state.access_token,
                                    "sql_exec_tool",
                                    {"sql": sql_statement}
                                )
                            )
                            
                            if exec_result:
                                format_query_result(exec_result)
                                st.session_state.messages.append({
                                    "role": "assistant",
                                    "content": "Here are the results:",
                                    "data": exec_result
                                })
                            else:
                                st.error("Failed to execute query")
                    else:
                        st.error("Unexpected response format")
                        st.json(analyst_result)
                else:
                    st.error("Failed to generate query")


if __name__ == "__main__":
    main()

