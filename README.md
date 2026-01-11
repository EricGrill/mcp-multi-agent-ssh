# MCP Multi-Agent SSH

Stateful SSH connections for Claude Code via MCP (Model Context Protocol).

## Features

- **Persistent Connections**: SSH connections stay open for 10 minutes of inactivity, eliminating reconnection overhead
- **Encrypted Credential Storage**: Credentials stored per-host with AES-256-GCM encryption
- **Auto-Reconnect**: Transparently reconnects when connections expire or drop
- **SFTP Support**: Upload, download, and list files on remote servers
- **NPX or Docker**: Easy installation via npx or Docker

## Quick Start

### Using NPX

```bash
npx mcp-multi-agent-ssh
```

### Using Docker

```bash
docker run -it --rm \
  -v ~/.mcp-multi-agent-ssh:/root/.mcp-multi-agent-ssh \
  -e MCP_SSH_MASTER_PASSWORD=your-password \
  mcp-multi-agent-ssh
```

## Claude Code Setup

Add to your Claude Code MCP configuration (`~/.claude/claude_desktop_config.json`):

### NPX Method

```json
{
  "mcpServers": {
    "ssh": {
      "command": "npx",
      "args": ["mcp-multi-agent-ssh"],
      "env": {
        "MCP_SSH_MASTER_PASSWORD": "your-master-password"
      }
    }
  }
}
```

### Docker Method

```json
{
  "mcpServers": {
    "ssh": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm",
        "-v", "~/.mcp-multi-agent-ssh:/root/.mcp-multi-agent-ssh",
        "-e", "MCP_SSH_MASTER_PASSWORD",
        "mcp-multi-agent-ssh"
      ],
      "env": {
        "MCP_SSH_MASTER_PASSWORD": "your-master-password"
      }
    }
  }
}
```

## Tools Reference

### Connection Management

| Tool | Description |
|------|-------------|
| `ssh_connect` | Connect to an SSH server. Stores credentials for future use. |
| `ssh_disconnect` | Close connection to a specific host. |
| `ssh_list_connections` | List all active connections with idle time. |

### Command Execution

| Tool | Description |
|------|-------------|
| `ssh_exec` | Run a command on a remote server. Auto-connects if needed. |

### File Operations (SFTP)

| Tool | Description |
|------|-------------|
| `sftp_upload` | Upload a local file to a remote server. |
| `sftp_download` | Download a file from a remote server. |
| `sftp_list` | List files in a remote directory. |

### Credential Management

| Tool | Description |
|------|-------------|
| `ssh_list_credentials` | List hosts with stored credentials. |
| `ssh_delete_credentials` | Remove stored credentials for a host. |

## Examples

### Connect and Run Commands

```
User: Connect to my server at example.com as user "deploy" with password "secret123"

Claude: [calls ssh_connect with host="example.com", username="deploy", password="secret123"]
Connected! Credentials saved for future use.

User: What's the disk usage?

Claude: [calls ssh_exec with host="example.com", command="df -h"]
Filesystem      Size  Used Avail Use% Mounted on
/dev/sda1       100G   45G   55G  45% /
...
```

### Transfer Files

```
User: Upload my config file to the server

Claude: [calls sftp_upload with host="example.com", local_path="/home/user/config.yml", remote_path="/etc/app/config.yml"]
Uploaded 2.3 KB to /etc/app/config.yml
```

### Auto-Reconnect

After 10 minutes of inactivity, connections automatically close. On the next command, the server reconnects using stored credentials:

```
[mcp-multi-agent-ssh] Connection to example.com:22 expired after 10 minutes of inactivity

User: Check the server status

Claude: [calls ssh_exec with host="example.com", command="systemctl status app"]
[Automatically reconnects using stored credentials]
● app.service - My Application
   Active: active (running)
...
```

## Security

### Credential Storage

- Credentials are stored in `~/.mcp-multi-agent-ssh/credentials.enc`
- Encrypted with AES-256-GCM
- Master password derived using PBKDF2 (100,000 iterations)
- File permissions set to 600 (owner read/write only)

### Master Password

The master password is required to encrypt/decrypt stored credentials:

1. **Environment Variable** (recommended for automation):
   ```bash
   export MCP_SSH_MASTER_PASSWORD="your-password"
   ```

2. **Interactive Prompt**: If not set, you'll be prompted on first run.

### Host Key Verification

Currently, host key verification is disabled for simplicity. For production use with sensitive servers, consider forking and enabling strict host key checking.

## Development

### Prerequisites

- Python 3.10+
- Node.js 18+ (for NPX launcher)

### Local Setup

```bash
# Clone the repository
git clone https://github.com/ericgrill/mcp-multi-agent-ssh.git
cd mcp-multi-agent-ssh

# Create virtual environment
python -m venv venv
source venv/bin/activate  # or `venv\Scripts\activate` on Windows

# Install in development mode
pip install -e ".[dev]"

# Run tests
pytest
```

### Project Structure

```
mcp-multi-agent-ssh/
├── src/mcp_multi_agent_ssh/
│   ├── __init__.py
│   ├── server.py          # MCP server entry point
│   ├── connection_pool.py # SSH connection management
│   ├── credentials.py     # Encrypted credential storage
│   └── types.py           # Pydantic models
├── bin/
│   └── launcher.js        # NPX launcher script
├── tests/
├── Dockerfile
├── docker-compose.yml
├── package.json
├── pyproject.toml
└── README.md
```

## Troubleshooting

### "Master password required" error

Set the `MCP_SSH_MASTER_PASSWORD` environment variable or run interactively.

### "Python 3.10+ not found"

Install Python 3.10 or later from https://www.python.org/

### Connection timeouts

- Check network connectivity to the SSH server
- Verify the port is correct (default: 22)
- Ensure firewall rules allow SSH connections

### "Failed to decrypt credentials"

This usually means the master password is incorrect. If you've forgotten it, delete `~/.mcp-multi-agent-ssh/credentials.enc` and `~/.mcp-multi-agent-ssh/salt` to start fresh (you'll need to re-enter all credentials).

## License

MIT
