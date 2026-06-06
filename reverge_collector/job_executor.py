"""
Job Executor — handles ad-hoc CollectorJob tasks.

Each job_type maps to a handler function that receives the parsed args
dict and returns a result dict with output_text, exit_code, output_type.
Handlers cover shell execution, file read/write, directory listing, and
Python script execution.
"""

import base64
import json
import logging
import os
import subprocess
import tempfile

import requests

logger = logging.getLogger(__name__)

# Cap on output returned to the server (64 KB).
_MAX_OUTPUT = 65536


# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------


def execute_shell(args: dict) -> dict:
    """Run a shell command and capture combined stdout+stderr.

    The command may be supplied as a raw string (``command``) or, to avoid
    deep shell/JSON quote escaping, as base64 via ``command_b64``. When both
    are present ``command_b64`` wins.
    """
    timeout = args.get('timeout', 300)
    command_b64 = args.get('command_b64')
    if command_b64:
        try:
            command = base64.b64decode(command_b64, validate=True).decode('utf-8')
        except Exception as e:
            return {
                'output_text': '[ERROR] invalid command_b64: %s' % e,
                'exit_code': -1,
                'output_type': 'text',
            }
    else:
        command = args.get('command', '')
    try:
        proc = subprocess.run(
            command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
        )
        output = proc.stdout.decode('utf-8', errors='replace')
        if len(output) > _MAX_OUTPUT:
            output = output[:_MAX_OUTPUT] + '\n[output truncated]'
        return {
            'output_text': output if output else '(no output)',
            'exit_code': proc.returncode,
            'output_type': 'text',
        }
    except subprocess.TimeoutExpired:
        return {
            'output_text': '[ERROR] command timed out after %ds' % timeout,
            'exit_code': -1,
            'output_type': 'text',
        }
    except Exception as e:
        return {
            'output_text': '[ERROR] %s' % e,
            'exit_code': -1,
            'output_type': 'text',
        }


def execute_python(args: dict) -> dict:
    """Write a Python script to a temp file, execute it, return output.

    The script may be supplied as a raw string (``script``) or, to avoid
    deep JSON/quote escaping, as base64 via ``script_b64``. When both are
    present ``script_b64`` wins.
    """
    timeout = args.get('timeout', 300)
    script_b64 = args.get('script_b64')
    if script_b64:
        try:
            script = base64.b64decode(script_b64, validate=True).decode('utf-8')
        except Exception as e:
            return {
                'output_text': '[ERROR] invalid script_b64: %s' % e,
                'exit_code': -1,
                'output_type': 'text',
            }
    else:
        script = args.get('script', '')
    fd, script_path = tempfile.mkstemp(suffix='.py')
    try:
        with os.fdopen(fd, 'w') as f:
            f.write(script)
        proc = subprocess.run(
            ['python3', script_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
        )
        output = proc.stdout.decode('utf-8', errors='replace')
        if len(output) > _MAX_OUTPUT:
            output = output[:_MAX_OUTPUT] + '\n[output truncated]'
        return {
            'output_text': output if output else '(no output)',
            'exit_code': proc.returncode,
            'output_type': 'text',
        }
    except subprocess.TimeoutExpired:
        return {
            'output_text': '[ERROR] script timed out after %ds' % timeout,
            'exit_code': -1,
            'output_type': 'text',
        }
    except Exception as e:
        return {
            'output_text': '[ERROR] %s' % e,
            'exit_code': -1,
            'output_type': 'text',
        }
    finally:
        try:
            os.unlink(script_path)
        except OSError:
            pass


def execute_file_upload(args: dict) -> dict:
    """Decode base64 content and write to remote_path on the collector."""
    remote_path = args.get('remote_path', '')
    content_b64 = args.get('content_b64', '')
    try:
        parent = os.path.dirname(os.path.abspath(remote_path))
        os.makedirs(parent, exist_ok=True)
        data = base64.b64decode(content_b64)
        with open(remote_path, 'wb') as f:
            f.write(data)
        return {
            'output_text': 'wrote %d bytes to %s' % (len(data), remote_path),
            'exit_code': 0,
            'output_type': 'text',
        }
    except Exception as e:
        return {
            'output_text': '[ERROR] %s' % e,
            'exit_code': -1,
            'output_type': 'text',
        }


def execute_file_download(args: dict) -> dict:
    """Read a file and return it as base64 blob + text preview."""
    remote_path = args.get('remote_path', '')
    max_size = 16 * 1024 * 1024  # 16 MB cap
    try:
        with open(remote_path, 'rb') as f:
            data = f.read(max_size)
        return {
            'output_text': data.decode('utf-8', errors='replace')[:_MAX_OUTPUT],
            'output_blob_b64': base64.b64encode(data).decode(),
            'exit_code': 0,
            'output_type': 'binary',
        }
    except FileNotFoundError:
        return {
            'output_text': '[ERROR] file not found: %s' % remote_path,
            'exit_code': -1,
            'output_type': 'text',
        }
    except Exception as e:
        return {
            'output_text': '[ERROR] %s' % e,
            'exit_code': -1,
            'output_type': 'text',
        }


def execute_directory_list(args: dict) -> dict:
    """List directory contents."""
    path = args.get('path', '.')
    try:
        entries = []
        for entry in sorted(os.scandir(path), key=lambda e: (e.is_file(), e.name)):
            kind = '[d]' if entry.is_dir() else '[f]'
            try:
                size = '  (%d bytes)' % entry.stat().st_size if entry.is_file() else ''
            except OSError:
                size = ''
            entries.append('%s %s%s' % (kind, entry.name, size))
        output = '\n'.join(entries) if entries else '(empty directory)'
        return {
            'output_text': output,
            'exit_code': 0,
            'output_type': 'text',
        }
    except FileNotFoundError:
        return {
            'output_text': '[ERROR] directory not found: %s' % path,
            'exit_code': -1,
            'output_type': 'text',
        }
    except Exception as e:
        return {
            'output_text': '[ERROR] %s' % e,
            'exit_code': -1,
            'output_type': 'text',
        }


def execute_http_request(args: dict) -> dict:
    """Make a single HTTP request and return status, headers, and body.

    Covers the common case where a test needs one HTTP call without the
    boilerplate of a full Python script. A completed request returns
    exit_code 0 regardless of HTTP status (a 404/500 is still a successful
    round-trip); only transport-level failures (connection refused,
    timeout, invalid URL) return exit_code -1.
    """
    url = args.get('url', '')
    if not url:
        return {
            'output_text': '[ERROR] url is required',
            'exit_code': -1,
            'output_type': 'text',
        }
    method = str(args.get('method', 'GET')).upper()
    headers = args.get('headers') or {}
    body_b64 = args.get('body_b64')
    if body_b64:
        try:
            body = base64.b64decode(body_b64, validate=True)
        except Exception as e:
            return {
                'output_text': '[ERROR] invalid body_b64: %s' % e,
                'exit_code': -1,
                'output_type': 'text',
            }
    else:
        body = args.get('body')
    timeout = args.get('timeout', 30)
    verify = args.get('verify', False)
    try:
        resp = requests.request(
            method=method,
            url=url,
            headers=headers,
            data=body,
            timeout=timeout,
            verify=verify,
        )
        header_lines = '\n'.join('%s: %s' % (k, v) for k, v in resp.headers.items())
        output = 'HTTP %d %s\n%s\n\n%s' % (
            resp.status_code,
            resp.reason or '',
            header_lines,
            resp.text,
        )
        if len(output) > _MAX_OUTPUT:
            output = output[:_MAX_OUTPUT] + '\n[output truncated]'
        return {
            'output_text': output,
            'exit_code': 0,
            'output_type': 'text',
        }
    except Exception as e:
        return {
            'output_text': '[ERROR] %s' % e,
            'exit_code': -1,
            'output_type': 'text',
        }


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------

HANDLERS = {
    'shell': execute_shell,
    'python': execute_python,
    'file_upload': execute_file_upload,
    'file_download': execute_file_download,
    'directory_list': execute_directory_list,
    'http_request': execute_http_request,
}


def run_job(job_type: str, args_json) -> dict:
    """Execute a job and return the result dict.

    Args:
        job_type: One of the keys in HANDLERS.
        args_json: Either a JSON string or an already-parsed dict.

    Returns:
        dict with output_text, exit_code, output_type (and optionally
        output_blob_b64 for file downloads).
    """
    handler = HANDLERS.get(job_type)
    if not handler:
        return {
            'output_text': 'Unknown job_type: %s. Valid types: %s'
            % (job_type, ', '.join(sorted(HANDLERS))),
            'exit_code': -1,
            'output_type': 'text',
        }
    try:
        args = json.loads(args_json) if isinstance(args_json, str) else args_json
    except json.JSONDecodeError as e:
        return {
            'output_text': 'Invalid args JSON: %s' % e,
            'exit_code': -1,
            'output_type': 'text',
        }
    return handler(args)
