"""
PlaywrightInteract — scripted browser interaction for authenticated
exploitation and DOM-level verification.

Unlike httpx / feroxbuster / nuclei (static HTTP probes) or a JS-aware
crawler, this tool is a *step executor*: one invocation drives a real
Chromium browser through a small, structured action sequence
(``navigate`` / ``fill`` / ``click`` / ``submit`` / ``wait`` /
``screenshot``), returns the resulting page state, and round-trips the
full session bundle (cookies + localStorage + sessionStorage) so the
next invocation can pick up where this one left off.

Invocation parameters (JSON — see ``schema`` section of the project
wiki for the full spec):

    {
      "action": "navigate" | "click" | "fill" | "submit" | "wait"
                 | "screenshot",
      "url":              "https://…",          # navigate only
      "selector":         "css-selector",       # click / fill / submit
      "value":            "string",             # fill only
      "actions":          [ {…}, {…} ],         # compound; overrides action
      "state_in":         { cookies, localStorage, sessionStorage, origin },
      "wait_until":       "load" | "domcontentloaded" | "networkidle" | "commit",
      "timeout":          int seconds,
      "extract":          ["text","forms","links","network","console","html"],
      "ignore_https_errors": bool,
      "user_agent":       "override",
      "headers":          {"X-Auth": "…"}
    }

Output is a single JSON blob written to ``get_output_path`` and then
emitted as a ``CollectionModuleOutput`` record by ``parse_output``.
"""

import asyncio
import base64
import json
import logging
import os
from typing import Any, Dict, List, Optional

from reverge_collector import data_model, scan_utils
from reverge_collector.tool_spec import ToolSpec


logger = logging.getLogger(__name__)


# Synthetic module name used to parent the CollectionModuleOutput records
# this tool produces.  Makes it easy to filter by "playwright interactions"
# without colliding with the Nuclei/Metasploit module namespaces.
PLAYWRIGHT_MODULE_NAME = 'playwright_session'

# Cap the html/text payloads to keep the agent's context from blowing up.
_MAX_HTML_BYTES = 500 * 1024   # 500 KiB
_MAX_TEXT_BYTES = 100 * 1024   # 100 KiB

_ALLOWED_ACTIONS = (
    'navigate', 'click', 'fill', 'submit', 'wait', 'screenshot',
)
_ALLOWED_WAIT_UNTIL = ('load', 'domcontentloaded', 'networkidle', 'commit')
_DEFAULT_EXTRACT = ('text', 'forms', 'links', 'network', 'console')
_NETWORK_RESOURCE_TYPES = ('xhr', 'fetch')


# ---------------------------------------------------------------------------
# ToolSpec subclass
# ---------------------------------------------------------------------------


class PlaywrightInteract(ToolSpec):

    name = 'playwright_interact'
    description = (
        'Scripted browser interaction via Playwright for authenticated '
        'exploitation and DOM-level verification. Drives Chromium through '
        'a structured action sequence (navigate/fill/click/submit/wait/'
        'screenshot), returns page state, and round-trips cookies + '
        'localStorage + sessionStorage so the next invocation can resume '
        'the session. Read-only: no raw page.evaluate(), no off-schema '
        'JavaScript execution. Input JSON goes in args; full result JSON '
        'is stored as a CollectionModuleOutput.'
    )
    project_url = 'https://playwright.dev/python/'
    tags = ['browser', 'interactive', 'auth-flow', 'exploit-verify']
    collector_type = data_model.CollectorType.ACTIVE.value
    scan_order = 20
    # Structured JSON goes in args.  Default is a no-op "wait 0" so the
    # scan can be scheduled and then driven via job-specific args.
    args = '{"action":"wait","timeout":1}'
    input_records = [
        data_model.ServerRecordType.PORT,
        data_model.ServerRecordType.HTTP_ENDPOINT_DATA,
    ]
    output_records = [
        data_model.ServerRecordType.COLLECTION_MODULE,
        data_model.ServerRecordType.COLLECTION_MODULE_OUTPUT,
    ]

    def get_output_path(self, scan_input) -> str:
        return get_output_path(scan_input)

    def execute_scan(self, scan_input) -> None:
        execute_scan(scan_input)

    def parse_output(self, output_path: str, scan_input) -> list:
        return parse_playwright_output(
            output_path,
            scan_input,
        ) or []


# ---------------------------------------------------------------------------
# Parameter validation
# ---------------------------------------------------------------------------


def _validate_params(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Normalise the invocation params dict.  Raises ValueError on bad input."""
    if not isinstance(raw, dict):
        raise ValueError('params must be a JSON object')

    actions_field = raw.get('actions')
    single_action = raw.get('action')

    if actions_field is not None and single_action is not None:
        raise ValueError('set exactly one of `action` or `actions`, not both')
    if actions_field is None and single_action is None:
        raise ValueError('missing `action` (or `actions`)')

    if actions_field is not None:
        if not isinstance(actions_field, list) or not actions_field:
            raise ValueError('`actions` must be a non-empty list')
        steps = [_validate_step(s) for s in actions_field]
    else:
        steps = [_validate_step(raw)]

    state_in = raw.get('state_in')
    if state_in is not None and not isinstance(state_in, dict):
        raise ValueError('`state_in` must be an object or null')

    extract_raw = raw.get('extract') or list(_DEFAULT_EXTRACT)
    if not isinstance(extract_raw, list):
        raise ValueError('`extract` must be a list')
    extract = [e for e in extract_raw
               if e in ('text', 'forms', 'links', 'network',
                        'console', 'html')]

    wait_until = raw.get('wait_until', 'networkidle')
    if wait_until not in _ALLOWED_WAIT_UNTIL:
        raise ValueError(f'`wait_until` must be one of {_ALLOWED_WAIT_UNTIL}')

    timeout = int(raw.get('timeout', 15))
    if not (1 <= timeout <= 120):
        raise ValueError('`timeout` must be between 1 and 120 seconds')

    return {
        'steps': steps,
        'state_in': state_in,
        'wait_until': wait_until,
        'timeout': timeout,
        'extract': extract,
        'ignore_https_errors': bool(raw.get('ignore_https_errors', False)),
        'user_agent': raw.get('user_agent') or None,
        'headers': raw.get('headers') or {},
    }


def _validate_step(step: Dict[str, Any]) -> Dict[str, Any]:
    action = step.get('action')
    if action not in _ALLOWED_ACTIONS:
        raise ValueError(
            f'unknown action {action!r}; must be one of {_ALLOWED_ACTIONS}')

    clean = {'action': action}
    if action == 'navigate':
        url = step.get('url')
        if not isinstance(url, str) or not url:
            raise ValueError('`navigate` requires `url`')
        if not (url.startswith('http://') or url.startswith('https://')):
            raise ValueError('`url` scheme must be http or https')
        clean['url'] = url
    elif action in ('click', 'fill', 'submit'):
        selector = step.get('selector')
        if not isinstance(selector, str) or not selector:
            raise ValueError(f'`{action}` requires `selector`')
        clean['selector'] = selector
        if action == 'fill':
            value = step.get('value')
            if not isinstance(value, str):
                raise ValueError('`fill` requires `value` (string)')
            clean['value'] = value
    elif action == 'wait':
        # Optional explicit wait in seconds; caps at 30 so the agent can't
        # pin a browser context.
        clean['seconds'] = min(int(step.get('seconds') or 2), 30)
    # screenshot takes no extra fields.
    return clean


def _redacted_value(selector: str, value: str) -> str:
    """Mask password-ish values so ``action_trace`` is safe to retain."""
    lowered = selector.lower()
    if ('password' in lowered
            or 'pwd' in lowered
            or 'input[type=password]' in lowered):
        return '***'
    return value


# ---------------------------------------------------------------------------
# Async runner
# ---------------------------------------------------------------------------


async def _run_async(params: Dict[str, Any]) -> Dict[str, Any]:
    try:
        from playwright.async_api import async_playwright  # noqa: PLC0415
    except ImportError as exc:
        raise RuntimeError(
            "Playwright is not installed on this collector. Install with: "
            "`pip install playwright && playwright install chrome`."
        ) from exc

    extract = params['extract']
    timeout_ms = params['timeout'] * 1000
    wait_until = params['wait_until']
    state_in = params['state_in'] or {}

    network_log: List[Dict[str, Any]] = []
    console_log: List[Dict[str, Any]] = []
    alerts_log: List[str] = []
    action_trace: List[Dict[str, Any]] = []

    result: Dict[str, Any] = {
        'ok': False,
        'error': None,
        'url': None,
        'status': None,
        'title': None,
        'content': {'text': None, 'forms': None, 'links': None, 'html': None},
        'network': [],
        'console': [],
        'alerts': [],
        'state_out': None,
        'timing': {'elapsed_ms': 0, 'actions': 0},
        'action_trace': action_trace,
        'screenshot_b64': None,
    }

    import time as _time
    t0 = _time.monotonic()

    async with async_playwright() as pw:
        launch_kwargs: Dict[str, Any] = {'headless': True}
        launch_kwargs['channel'] = 'chrome'
        try:
            browser = await pw.chromium.launch(**launch_kwargs)
        except Exception as exc:
            logger.info(
                "PlaywrightInteract: system Chrome unavailable (%s); "
                "falling back to bundled chromium", exc,
            )
            launch_kwargs.pop('channel', None)
            browser = await pw.chromium.launch(**launch_kwargs)

        ctx_kwargs: Dict[str, Any] = {}
        if params['ignore_https_errors']:
            ctx_kwargs['ignore_https_errors'] = True
        if params['user_agent']:
            ctx_kwargs['user_agent'] = params['user_agent']
        if params['headers']:
            ctx_kwargs['extra_http_headers'] = params['headers']

        context = await browser.new_context(**ctx_kwargs)
        page = await context.new_page()

        # --- Wire up observation hooks ---
        if 'network' in extract:
            def _on_response(resp):
                try:
                    req = resp.request
                    if req.resource_type not in _NETWORK_RESOURCE_TYPES:
                        return
                    network_log.append({
                        'url': resp.url,
                        'method': req.method,
                        'status': resp.status,
                        'resource_type': req.resource_type,
                    })
                except Exception:
                    pass
            page.on('response', _on_response)

        if 'console' in extract:
            def _on_console(msg):
                try:
                    if msg.type in ('error', 'warning'):
                        console_log.append({
                            'level': msg.type,
                            'text': (msg.text or '')[:2048],
                        })
                except Exception:
                    pass
            page.on('console', _on_console)

        # Auto-dismiss dialogs so a rogue alert() from an XSS PoC doesn't
        # block the page — but record that they fired.
        async def _on_dialog(dialog):
            try:
                alerts_log.append(
                    f'{dialog.type}: {(dialog.message or "")[:1024]}')
                await dialog.dismiss()
            except Exception:
                pass
        page.on('dialog', _on_dialog)

        try:
            # --- Restore session state BEFORE any navigation ---
            if state_in.get('cookies'):
                try:
                    await context.add_cookies(state_in['cookies'])
                except Exception as exc:
                    logger.warning(
                        "PlaywrightInteract: could not add_cookies: %s", exc)

            # localStorage / sessionStorage require us to already be on
            # the right origin.  If state_in carries an origin, navigate
            # there first (about:blank is useless) and then seed storage.
            storage_in = {
                'localStorage': state_in.get('localStorage') or {},
                'sessionStorage': state_in.get('sessionStorage') or {},
            }
            origin = state_in.get('origin')
            if origin and (storage_in['localStorage']
                           or storage_in['sessionStorage']):
                try:
                    await page.goto(origin, wait_until='commit',
                                    timeout=timeout_ms)
                    await _seed_storage(page, origin, storage_in)
                except Exception as exc:
                    logger.warning(
                        "PlaywrightInteract: could not seed storage at "
                        "%s: %s", origin, exc)

            # --- Execute action sequence ---
            for step in params['steps']:
                step_entry: Dict[str, Any] = {'action': step['action'],
                                              'ok': False}
                try:
                    if step['action'] == 'navigate':
                        step_entry['url'] = step['url']
                        resp = await page.goto(
                            step['url'],
                            wait_until=wait_until, timeout=timeout_ms)
                        if resp is not None:
                            step_entry['status'] = resp.status
                    elif step['action'] == 'fill':
                        step_entry['selector'] = step['selector']
                        step_entry['value'] = _redacted_value(
                            step['selector'], step['value'])
                        await page.fill(step['selector'], step['value'],
                                        timeout=timeout_ms)
                    elif step['action'] == 'click':
                        step_entry['selector'] = step['selector']
                        await page.click(step['selector'],
                                         timeout=timeout_ms)
                        # After click wait for settle — click often triggers
                        # navigation or async renders.
                        try:
                            await page.wait_for_load_state(
                                wait_until, timeout=timeout_ms)
                        except Exception:
                            pass
                    elif step['action'] == 'submit':
                        step_entry['selector'] = step['selector']
                        # `submit` on a form element, or trigger on the
                        # element's form if a sibling/input was selected.
                        await page.evaluate(
                            "sel => { const el = document.querySelector(sel); "
                            "if (!el) throw new Error('no element ' + sel); "
                            "const form = el.tagName === 'FORM' "
                            "  ? el "
                            "  : el.closest('form'); "
                            "if (!form) throw new Error('no parent form for ' + sel); "
                            "form.requestSubmit ? form.requestSubmit() "
                            "  : form.submit(); }",
                            step['selector'],
                        )
                        try:
                            await page.wait_for_load_state(
                                wait_until, timeout=timeout_ms)
                        except Exception:
                            pass
                        step_entry['status'] = None
                    elif step['action'] == 'wait':
                        await asyncio.sleep(step['seconds'])
                    elif step['action'] == 'screenshot':
                        png = await page.screenshot(full_page=False,
                                                    type='png')
                        result['screenshot_b64'] = base64.b64encode(
                            png).decode('ascii')
                    step_entry['ok'] = True
                except Exception as exc:
                    step_entry['error'] = str(exc)[:1024]
                    action_trace.append(step_entry)
                    raise
                action_trace.append(step_entry)

            # --- Harvest page state ---
            result['url'] = page.url
            try:
                result['title'] = (await page.title()) or ''
            except Exception:
                result['title'] = ''

            if 'text' in extract:
                try:
                    text = await page.evaluate(
                        "() => document.body ? document.body.innerText : ''")
                    if text and len(text) > _MAX_TEXT_BYTES:
                        text = text[:_MAX_TEXT_BYTES] + '\n…[truncated]'
                    result['content']['text'] = text
                except Exception:
                    pass

            if 'html' in extract:
                try:
                    html = await page.content()
                    truncated = False
                    if html and len(html) > _MAX_HTML_BYTES:
                        html = html[:_MAX_HTML_BYTES]
                        truncated = True
                    result['content']['html'] = html
                    if truncated:
                        result['content']['html_truncated'] = True
                except Exception:
                    pass

            if 'forms' in extract:
                try:
                    forms = await page.evaluate(_EXTRACT_FORMS_JS)
                    result['content']['forms'] = forms
                except Exception:
                    pass

            if 'links' in extract:
                try:
                    links = await page.evaluate(_EXTRACT_LINKS_JS)
                    result['content']['links'] = links[:500]
                except Exception:
                    pass

            # Last-response status if the final step was a navigation.
            last_nav = next(
                (s for s in reversed(action_trace)
                 if s.get('action') in ('navigate', 'click', 'submit')
                 and 'status' in s),
                None,
            )
            if last_nav:
                result['status'] = last_nav['status']

            # --- Harvest session state for round-trip ---
            result['state_out'] = await _harvest_state(context, page)

            result['ok'] = True

        except Exception as exc:
            result['error'] = str(exc)[:2048]
        finally:
            result['network'] = network_log
            result['console'] = console_log
            result['alerts'] = alerts_log
            result['timing']['elapsed_ms'] = int(
                (_time.monotonic() - t0) * 1000)
            result['timing']['actions'] = len(action_trace)
            try:
                await context.close()
            except Exception:
                pass
            try:
                await browser.close()
            except Exception:
                pass

    return result


# Extraction helpers run inside the page — kept as module constants so
# they don't get rebuilt per call.
_EXTRACT_FORMS_JS = """
() => Array.from(document.querySelectorAll('form')).slice(0, 50).map(f => ({
    selector: f.id ? `form#${f.id}` :
              (f.name ? `form[name="${f.name}"]` : 'form'),
    action: f.action || null,
    method: (f.method || 'GET').toUpperCase(),
    inputs: Array.from(f.querySelectorAll('input,select,textarea'))
        .slice(0, 50)
        .map(i => ({
            name: i.name || null,
            type: i.type || i.tagName.toLowerCase(),
            value: i.type === 'password' ? '' : (i.value || '')
        }))
}))
"""

_EXTRACT_LINKS_JS = """
() => Array.from(document.querySelectorAll('a[href]'))
    .map(a => ({
        href: a.href,
        text: (a.innerText || '').trim().slice(0, 200)
    }))
    .filter(l => l.href && l.href.length < 2048)
"""


async def _seed_storage(page, origin: str,
                        storage: Dict[str, Dict[str, str]]) -> None:
    """Seed localStorage/sessionStorage for the given origin."""
    for store_name in ('localStorage', 'sessionStorage'):
        by_origin = storage.get(store_name) or {}
        entries = by_origin.get(origin) or {}
        if not entries:
            continue
        await page.evaluate(
            "({store, items}) => { "
            "const s = window[store]; "
            "for (const [k, v] of Object.entries(items)) s.setItem(k, v); "
            "}",
            {'store': store_name, 'items': entries},
        )


async def _harvest_state(context, page) -> Dict[str, Any]:
    """Pull cookies + localStorage + sessionStorage for round-trip."""
    cookies: List[Dict[str, Any]] = []
    try:
        cookies = await context.cookies()
    except Exception as exc:
        logger.warning("PlaywrightInteract: could not read cookies: %s", exc)

    origin = None
    storage: Dict[str, Dict[str, Dict[str, str]]] = {
        'localStorage': {},
        'sessionStorage': {},
    }
    try:
        origin_url = page.url
        if origin_url and origin_url != 'about:blank':
            from urllib.parse import urlparse
            p = urlparse(origin_url)
            origin = f'{p.scheme}://{p.netloc}'
            snapshot = await page.evaluate(
                "() => ({"
                "  localStorage: Object.fromEntries("
                "    Array.from({length: localStorage.length}, "
                "      (_, i) => [localStorage.key(i), "
                "                 localStorage.getItem(localStorage.key(i))])),"
                "  sessionStorage: Object.fromEntries("
                "    Array.from({length: sessionStorage.length}, "
                "      (_, i) => [sessionStorage.key(i), "
                "                 sessionStorage.getItem(sessionStorage.key(i))])),"
                "})"
            )
            if snapshot.get('localStorage'):
                storage['localStorage'][origin] = snapshot['localStorage']
            if snapshot.get('sessionStorage'):
                storage['sessionStorage'][origin] = snapshot['sessionStorage']
    except Exception as exc:
        logger.warning(
            "PlaywrightInteract: could not read web storage: %s", exc)

    return {
        'cookies': cookies,
        'localStorage': storage['localStorage'],
        'sessionStorage': storage['sessionStorage'],
        'origin': origin,
    }


# ---------------------------------------------------------------------------
# Public entry point — usable from either the ToolSpec runner or a direct
# MCP tool wrapper.
# ---------------------------------------------------------------------------


def run_browser_interact(params: Dict[str, Any]) -> Dict[str, Any]:
    """Synchronous entry point: validate params, run playwright, return blob."""
    try:
        clean = _validate_params(params)
    except ValueError as exc:
        return {
            'ok': False,
            'error': f'invalid params: {exc}',
            'url': None, 'status': None, 'title': None,
            'content': {}, 'network': [], 'console': [], 'alerts': [],
            'state_out': None,
            'action_trace': [],
            'timing': {'elapsed_ms': 0, 'actions': 0},
        }
    try:
        return asyncio.run(_run_async(clean))
    except Exception as exc:
        logger.error("PlaywrightInteract: execution failed: %s", exc,
                     exc_info=True)
        return {
            'ok': False,
            'error': f'execution failed: {exc}',
            'url': None, 'status': None, 'title': None,
            'content': {}, 'network': [], 'console': [], 'alerts': [],
            'state_out': None,
            'action_trace': [],
            'timing': {'elapsed_ms': 0, 'actions': 0},
        }


# ---------------------------------------------------------------------------
# Scheduler entry points (ToolSpec plumbing)
# ---------------------------------------------------------------------------


def get_output_path(scan_input) -> str:
    scan_id = scan_input.id
    tool_name = scan_input.current_tool.name
    dir_path = scan_utils.init_tool_folder(tool_name, 'outputs', scan_id)
    return dir_path + os.path.sep + 'playwright_result.json'


def execute_scan(scan_input) -> None:
    output_file_path = get_output_path(scan_input)
    if os.path.exists(output_file_path):
        logger.debug(
            "PlaywrightInteract output %s already exists; skipping",
            output_file_path)
        return

    args_str = scan_input.current_tool.args or '{}'
    try:
        params = json.loads(args_str)
    except json.JSONDecodeError as exc:
        result = {
            'ok': False,
            'error': f'args must be JSON: {exc}',
        }
    else:
        result = run_browser_interact(params)

    # Always write the output file so _run_import has something to parse,
    # even on failure — the error message becomes part of the record.
    with open(output_file_path, 'w') as fh:
        json.dump(result, fh)


# ---------------------------------------------------------------------------
# Output parser — JSON blob → CollectionModuleOutput
# ---------------------------------------------------------------------------


def _pick_target_port_id(scan_input) -> Optional[str]:
    """Pick a representative port_id for the CollectionModuleOutput record.

    If the scan scope has exactly one host:port, use that.  Otherwise
    fall back to the first one — the record is primarily about the
    session step, not the port.
    """
    try:
        port_map = scan_input.scan_data.host_port_obj_map
        for entry in port_map.values():
            port_obj = entry.get('port_obj')
            if port_obj and port_obj.id:
                return port_obj.id
    except Exception:
        pass
    return None


def parse_playwright_output(output_file: str, scan_input) -> List[Any]:
    if not os.path.exists(output_file) or os.path.getsize(output_file) == 0:
        return []

    try:
        with open(output_file, 'r') as fh:
            blob = json.load(fh)
    except Exception as exc:
        logger.warning(
            "PlaywrightInteract: could not parse output %s: %s",
            output_file, exc)
        return []

    tool_instance_id = scan_input.current_tool_instance_id
    port_id = _pick_target_port_id(scan_input)

    module_obj = data_model.CollectionModule()
    module_obj.collection_tool_instance_id = tool_instance_id
    module_obj.name = PLAYWRIGHT_MODULE_NAME

    output_obj = data_model.CollectionModuleOutput(parent_id=module_obj.id)
    output_obj.collection_tool_instance_id = tool_instance_id
    output_obj.output = json.dumps(blob)
    output_obj.port_id = port_id

    return [module_obj, output_obj]
