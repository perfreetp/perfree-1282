import os
import re
import json
import copy
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from .crypto import encrypt_value, decrypt_value, is_encrypted, mask_value


DEFAULT_ENVS = ["dev", "test", "prod"]
STORE_FILENAME = "envmgr.json"
DEFAULT_PROFILE = "default"


def _get_store_path(project_path: Optional[Path] = None) -> Path:
    if project_path:
        return project_path / ".envmgr" / STORE_FILENAME
    current = Path.cwd()
    for parent in [current] + list(current.parents):
        candidate = parent / ".envmgr" / STORE_FILENAME
        if candidate.exists():
            return candidate
    return current / ".envmgr" / STORE_FILENAME


def _empty_profile(envs: List[str] = None) -> dict:
    envs = envs or DEFAULT_ENVS
    environments = {}
    for env_name in envs:
        environments[env_name] = {
            "variables": {},
            "created_at": datetime.now().isoformat(),
        }
    default = envs[0] if envs else "dev"
    return {
        "default_env": default,
        "current_env": default,
        "environments": environments,
        "audit_log": [],
        "last_snapshot": None,
        "required_vars": [],
    }


class EnvStore:
    def __init__(self, path: Optional[Path] = None):
        self.path = Path(path) if path else _get_store_path()
        self._data = None

    @property
    def data(self) -> dict:
        if self._data is None:
            self._load()
        return self._data

    def _load(self):
        if self.path.exists():
            with open(self.path, "r", encoding="utf-8") as f:
                raw = json.load(f)
            self._data = self._migrate(raw)
        else:
            self._data = self._empty_store()

    def _empty_store(self) -> dict:
        return {
            "version": "2.0",
            "project": "",
            "current_profile": DEFAULT_PROFILE,
            "profiles": {
                DEFAULT_PROFILE: _empty_profile(),
            },
        }

    def _migrate(self, raw: dict) -> dict:
        if "profiles" in raw and isinstance(raw.get("profiles"), dict):
            if "version" not in raw:
                raw["version"] = "2.0"
            if "current_profile" not in raw:
                raw["current_profile"] = DEFAULT_PROFILE
            return raw

        profile = {
            "default_env": raw.get("default_env", "dev"),
            "current_env": raw.get("current_env", "dev"),
            "environments": raw.get("environments", {}),
            "audit_log": raw.get("audit_log", []),
            "last_snapshot": raw.get("last_snapshot"),
            "required_vars": raw.get("required_vars", []),
        }
        return {
            "version": "2.0",
            "project": raw.get("project", ""),
            "current_profile": DEFAULT_PROFILE,
            "profiles": {
                DEFAULT_PROFILE: profile,
            },
        }

    def save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(self._data, f, indent=2, ensure_ascii=False)

    def _profile(self, name: Optional[str] = None) -> dict:
        target = name or self.data.get("current_profile", DEFAULT_PROFILE)
        if target not in self.data["profiles"]:
            raise ValueError(f"Profile 不存在: {target}")
        return self.data["profiles"][target]

    # ============ Profile Management ============

    def init_project(self, project_name: str, envs: List[str] = None, profile: str = DEFAULT_PROFILE):
        self._data = self._empty_store()
        self._data["project"] = project_name
        self._data["current_profile"] = profile
        self._data["profiles"] = {profile: _empty_profile(envs)}
        self._record_audit("init", f"初始化项目: {project_name}, 环境: {', '.join(envs or DEFAULT_ENVS)}", profile=profile)
        self.save()

    def is_initialized(self) -> bool:
        return self.path.exists() and bool(self.data.get("project"))

    def list_profiles(self) -> List[str]:
        return list(self.data.get("profiles", {}).keys())

    def get_current_profile(self) -> str:
        return self.data.get("current_profile", DEFAULT_PROFILE)

    def switch_profile(self, name: str):
        if name not in self.data["profiles"]:
            raise ValueError(f"Profile 不存在: {name}")
        old = self.data["current_profile"]
        self.data["current_profile"] = name
        self.save()

    def create_profile(self, name: str, copy_from: Optional[str] = None, envs: List[str] = None):
        if name in self.data["profiles"]:
            raise ValueError(f"Profile 已存在: {name}")
        if copy_from:
            if copy_from not in self.data["profiles"]:
                raise ValueError(f"源 Profile 不存在: {copy_from}")
            self.data["profiles"][name] = copy.deepcopy(self.data["profiles"][copy_from])
            self.data["profiles"][name]["audit_log"] = []
            self.data["profiles"][name]["last_snapshot"] = None
        else:
            self.data["profiles"][name] = _empty_profile(envs)
        self._record_audit("profile_create", f"创建 profile: {name}" + (f" (从 {copy_from} 复制)" if copy_from else ""), profile=name)
        self.save()

    def delete_profile(self, name: str):
        if name not in self.data["profiles"]:
            raise ValueError(f"Profile 不存在: {name}")
        if len(self.data["profiles"]) <= 1:
            raise ValueError("至少保留一个 Profile")
        del self.data["profiles"][name]
        if self.data["current_profile"] == name:
            self.data["current_profile"] = self.list_profiles()[0]
        self.save()

    # ============ Environment Management ============

    def list_envs(self, profile: Optional[str] = None) -> List[str]:
        return list(self._profile(profile).get("environments", {}).keys())

    def get_current_env(self, profile: Optional[str] = None) -> str:
        return self._profile(profile).get("current_env", "dev")

    def get_default_env(self, profile: Optional[str] = None) -> str:
        return self._profile(profile).get("default_env", "dev")

    def set_default_env(self, env_name: str, profile: Optional[str] = None):
        p = self._profile(profile)
        if env_name not in p["environments"]:
            raise ValueError(f"环境不存在: {env_name}")
        p["default_env"] = env_name
        self._record_audit("set_default", f"设置默认环境: {env_name}", profile=profile)
        self.save()

    def switch_env(self, env_name: str, profile: Optional[str] = None):
        p = self._profile(profile)
        if env_name not in p["environments"]:
            raise ValueError(f"环境不存在: {env_name}")
        old = p["current_env"]
        p["current_env"] = env_name
        self._record_audit("switch", f"切换环境: {old} -> {env_name}", profile=profile)
        self.save()

    def add_env(self, env_name: str, copy_from: Optional[str] = None, profile: Optional[str] = None):
        p = self._profile(profile)
        if env_name in p["environments"]:
            raise ValueError(f"环境已存在: {env_name}")
        new_env = {
            "variables": {},
            "created_at": datetime.now().isoformat(),
        }
        if copy_from and copy_from in p["environments"]:
            new_env["variables"] = copy.deepcopy(p["environments"][copy_from]["variables"])
        p["environments"][env_name] = new_env
        self._record_audit("add_env", f"添加环境: {env_name}" + (f" (从{copy_from}复制)" if copy_from else ""), profile=profile)
        self.save()

    def remove_env(self, env_name: str, profile: Optional[str] = None):
        p = self._profile(profile)
        if env_name not in p["environments"]:
            raise ValueError(f"环境不存在: {env_name}")
        if len(p["environments"]) <= 1:
            raise ValueError("至少保留一个环境")
        del p["environments"][env_name]
        if p["current_env"] == env_name:
            p["current_env"] = self.list_envs(profile)[0]
        if p["default_env"] == env_name:
            p["default_env"] = self.list_envs(profile)[0]
        self._record_audit("remove_env", f"删除环境: {env_name}", profile=profile)
        self.save()

    # ============ Variable Management ============

    def get_variables(self, env_name: Optional[str] = None, decrypt: bool = False, profile: Optional[str] = None) -> Dict[str, dict]:
        p = self._profile(profile)
        env = env_name or self.get_current_env(profile)
        if env not in p["environments"]:
            raise ValueError(f"环境不存在: {env}")
        vars_dict = p["environments"][env]["variables"]
        if decrypt:
            result = {}
            for k, v in vars_dict.items():
                v_copy = copy.deepcopy(v)
                if v_copy.get("secret") and is_encrypted(v_copy.get("value", "")):
                    v_copy["value"] = decrypt_value(v_copy["value"])
                result[k] = v_copy
            return result
        return copy.deepcopy(vars_dict)

    def set_variable(self, key: str, value: str, secret: bool = False,
                     required: bool = False, env_name: Optional[str] = None,
                     skip_snapshot: bool = False, profile: Optional[str] = None):
        p = self._profile(profile)
        env = env_name or self.get_current_env(profile)
        if env not in p["environments"]:
            raise ValueError(f"环境不存在: {env}")

        existing_keys = p["environments"][env]["variables"].keys()
        key_lower = key.lower()
        for existing in existing_keys:
            if existing != key and existing.lower() == key_lower:
                raise ValueError(
                    f"大小写冲突: '{key}' 与已存在变量 '{existing}' 等价"
                )

        if not skip_snapshot:
            self._snapshot(profile)
        old_value = None
        if key in p["environments"][env]["variables"]:
            old_var = p["environments"][env]["variables"][key]
            old_value = old_var.get("value", "")
            if old_var.get("secret") and is_encrypted(old_value):
                old_value = decrypt_value(old_value)
        stored_value = encrypt_value(value) if secret else value
        p["environments"][env]["variables"][key] = {
            "value": stored_value,
            "secret": secret,
            "required": required,
            "updated_at": datetime.now().isoformat(),
        }
        if required and key not in p.get("required_vars", []):
            p.setdefault("required_vars", []).append(key)
        action = "update" if old_value is not None else "set"
        self._record_audit(action, f"[{env}] {key} = {'***' if secret else value}", profile=profile)
        if not skip_snapshot:
            self.save()

    def get_variable(self, key: str, env_name: Optional[str] = None, profile: Optional[str] = None) -> Optional[str]:
        p = self._profile(profile)
        env = env_name or self.get_current_env(profile)
        if env not in p["environments"]:
            raise ValueError(f"环境不存在: {env}")
        var = p["environments"][env]["variables"].get(key)
        if var is None:
            return None
        value = var.get("value", "")
        if var.get("secret") and is_encrypted(value):
            return decrypt_value(value)
        return value

    def unset_variable(self, key: str, env_name: Optional[str] = None, profile: Optional[str] = None) -> bool:
        p = self._profile(profile)
        env = env_name or self.get_current_env(profile)
        if env not in p["environments"]:
            raise ValueError(f"环境不存在: {env}")
        if key not in p["environments"][env]["variables"]:
            return False
        self._snapshot(profile)
        del p["environments"][env]["variables"][key]
        self._record_audit("unset", f"[{env}] 删除变量: {key}", profile=profile)
        self.save()
        return True

    # ============ Import / Preview ============

    def preview_import(self, file_path: str, env_name: Optional[str] = None,
                       secret_keys: Optional[List[str]] = None, profile: Optional[str] = None):
        p = self._profile(profile)
        env = env_name or self.get_current_env(profile)
        secret_keys = set(secret_keys or [])
        if env not in p["environments"]:
            raise ValueError(f"环境不存在: {env}")
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"文件不存在: {file_path}")

        pending = []
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                if not key:
                    continue
                is_secret = key in secret_keys or any(
                    kw in key.lower() for kw in ["password", "secret", "token", "key", "api_key"]
                )
                pending.append((key, value, is_secret))

        existing_keys = set(p["environments"][env]["variables"].keys())
        pending_keys_lower = {}
        conflicts = []
        added = []
        updated = []
        skipped = []

        for key, value, is_secret in pending:
            kl = key.lower()
            conflict_with = None
            for existing in existing_keys:
                if existing != key and existing.lower() == kl:
                    conflict_with = existing
                    break
            if conflict_with:
                conflicts.append((key, conflict_with))
                continue
            if kl in pending_keys_lower and pending_keys_lower[kl] != key:
                conflicts.append((key, pending_keys_lower[kl]))
                continue
            pending_keys_lower[kl] = key

            if key in existing_keys:
                old_var = p["environments"][env]["variables"][key]
                old_value = old_var.get("value", "")
                if old_var.get("secret") and is_encrypted(old_value):
                    old_value = decrypt_value(old_value)
                if old_value == value:
                    skipped.append((key, value, is_secret))
                else:
                    updated.append((key, old_value, value, is_secret))
            else:
                added.append((key, value, is_secret))

        return {
            "added": added,
            "updated": updated,
            "skipped": skipped,
            "conflicts": conflicts,
            "pending": [(k, v, s) for k, v, s in pending if not any(c[0] == k for c in conflicts)],
        }

    def import_env_file(self, file_path: str, env_name: Optional[str] = None,
                        secret_keys: Optional[List[str]] = None, profile: Optional[str] = None):
        result = self.preview_import(file_path, env_name, secret_keys, profile)
        if result["conflicts"]:
            parts = ", ".join(f"{k}<->{c}" for k, c in result["conflicts"])
            raise ValueError(f"导入失败: 大小写冲突 ({parts})")

        p = self._profile(profile)
        env = env_name or self.get_current_env(profile)
        self._snapshot(profile)
        count = 0
        for key, value, is_secret in result["pending"]:
            self.set_variable(key, value, secret=is_secret, env_name=env, skip_snapshot=True, profile=profile)
            count += 1
        self._record_audit("import", f"[{env}] 从 {Path(file_path).name} 导入 {count} 个变量", profile=profile)
        self.save()
        return count

    # ============ Export ============

    def export_shell(self, env_name: Optional[str] = None, decrypt: bool = True,
                     expand: bool = True, profile: Optional[str] = None) -> str:
        env = env_name or self.get_current_env(profile)
        variables = self.get_variables(env, decrypt=decrypt, profile=profile)
        if expand:
            variables = self._expand_variables(variables)
        lines = []
        for key in sorted(variables.keys()):
            val = variables[key].get("value", "")
            val_escaped = val.replace("'", "'\\''")
            lines.append(f"export {key}='{val_escaped}'")
        return "\n".join(lines) + "\n"

    def export_dotenv(self, env_name: Optional[str] = None, decrypt: bool = True,
                      expand: bool = True, profile: Optional[str] = None) -> str:
        env = env_name or self.get_current_env(profile)
        variables = self.get_variables(env, decrypt=decrypt, profile=profile)
        if expand:
            variables = self._expand_variables(variables)
        lines = []
        for key in sorted(variables.keys()):
            val = variables[key].get("value", "")
            val_escaped = val.replace('"', '\\"')
            lines.append(f'{key}="{val_escaped}"')
        return "\n".join(lines) + "\n"

    # ============ Utils ============

    def _expand_variables(self, variables: Dict[str, dict]) -> Dict[str, dict]:
        result = copy.deepcopy(variables)
        plain_values = {k: v.get("value", "") for k, v in result.items()}
        max_iter = 10
        for _ in range(max_iter):
            changed = False
            for key in result:
                val = plain_values[key]
                new_val = val
                def _replace(match):
                    nonlocal changed
                    var_name = match.group(1) or match.group(2)
                    if var_name in plain_values and plain_values[var_name] != val:
                        changed = True
                        return plain_values[var_name]
                    return match.group(0)
                new_val = re.sub(r'\$\{([A-Za-z_][A-Za-z0-9_]*)\}', _replace, new_val)
                new_val = re.sub(r'\$([A-Za-z_][A-Za-z0-9_]*)', _replace, new_val)
                if new_val != val:
                    plain_values[key] = new_val
            if not changed:
                break
        for key in result:
            result[key]["value"] = plain_values[key]
        return result

    def diff_envs(self, env_a: str, env_b: str, profile: Optional[str] = None) -> Tuple[Dict[str, dict], Dict[str, dict], Dict[str, Tuple[str, str, bool]]]:
        vars_a = self.get_variables(env_a, decrypt=True, profile=profile)
        vars_b = self.get_variables(env_b, decrypt=True, profile=profile)
        keys_a = set(vars_a.keys())
        keys_b = set(vars_b.keys())
        only_a = {k: vars_a[k] for k in keys_a - keys_b}
        only_b = {k: vars_b[k] for k in keys_b - keys_a}
        different = {}
        for k in keys_a & keys_b:
            va = vars_a[k].get("value", "")
            vb = vars_b[k].get("value", "")
            if va != vb:
                is_secret = vars_a[k].get("secret", False) or vars_b[k].get("secret", False)
                different[k] = (va, vb, is_secret)
        return only_a, only_b, different

    def check_required(self, env_name: Optional[str] = None, profile: Optional[str] = None) -> List[str]:
        p = self._profile(profile)
        env = env_name or self.get_current_env(profile)
        required = p.get("required_vars", [])
        variables = self.get_variables(env, decrypt=False, profile=profile)
        missing = []
        for key in required:
            if key not in variables or not variables[key].get("value"):
                missing.append(key)
        return missing

    def detect_conflicts(self, env_name: Optional[str] = None, profile: Optional[str] = None) -> List[str]:
        variables = self.get_variables(env_name, decrypt=False, profile=profile)
        lower_map = {}
        conflicts = []
        for key in variables:
            lower_key = key.lower()
            if lower_key in lower_map:
                conflicts.append((lower_map[lower_key], key))
            else:
                lower_map[lower_key] = key
        return [f"{a} <-> {b}" for a, b in conflicts]

    def get_required_vars(self, profile: Optional[str] = None) -> List[str]:
        return list(self._profile(profile).get("required_vars", []))

    def set_required(self, key: str, required: bool = True, profile: Optional[str] = None):
        p = self._profile(profile)
        req = p.setdefault("required_vars", [])
        if required and key not in req:
            req.append(key)
        elif not required and key in req:
            req.remove(key)
        self.save()

    # ============ Snapshot / Rollback ============

    def _snapshot(self, profile: Optional[str] = None):
        p = self._profile(profile)
        p["last_snapshot"] = copy.deepcopy({
            "environments": p.get("environments", {}),
            "default_env": p.get("default_env"),
            "current_env": p.get("current_env"),
            "required_vars": p.get("required_vars", []),
        })

    def rollback(self, profile: Optional[str] = None) -> bool:
        p = self._profile(profile)
        if not p.get("last_snapshot"):
            return False
        snap = p["last_snapshot"]
        p["environments"] = copy.deepcopy(snap["environments"])
        p["default_env"] = snap["default_env"]
        p["current_env"] = snap["current_env"]
        p["required_vars"] = snap["required_vars"]
        p["last_snapshot"] = None
        self._record_audit("rollback", "回滚到上一个快照", profile=profile)
        self.save()
        return True

    # ============ Audit Log ============

    def get_audit_log(self, limit: int = 0, env: Optional[str] = None,
                      key: Optional[str] = None, action: Optional[str] = None,
                      since: Optional[str] = None, until: Optional[str] = None,
                      profile: Optional[str] = None) -> List[dict]:
        p = self._profile(profile)
        log = p.get("audit_log", [])
        filtered = []
        for entry in log:
            ts = entry.get("timestamp", "")
            if since and ts < since:
                continue
            if until and ts > until:
                continue
            if action and entry.get("action") != action:
                continue
            detail = entry.get("detail", "")
            if env and f"[{env}]" not in detail and not detail.startswith(env + " "):
                # detail like "[dev] KEY = val" or "切换环境: dev -> test"
                pass_env = False
                if env and f"[{env}]" in detail:
                    pass_env = True
                elif env and re.search(rf"\b{re.escape(env)}\b", detail):
                    pass_env = True
                if not pass_env and env:
                    continue
            if key and key not in detail:
                continue
            filtered.append(entry)
        return filtered[-limit:] if limit > 0 else filtered

    def export_audit_report(self, decrypt_secrets: bool = False, profile: Optional[str] = None, **filters) -> str:
        entries = self.get_audit_log(profile=profile, **filters)
        lines = [
            "# envmgr 审计报告",
            f"# 项目: {self.data.get('project', '')}",
            f"# Profile: {profile or self.get_current_profile()}",
            f"# 生成时间: {datetime.now().isoformat()}",
            f"# 记录总数: {len(entries)}",
            "",
            "| 时间 | 操作 | 详情 |",
            "|------|------|------|",
        ]
        for e in entries:
            detail = e.get("detail", "")
            if not decrypt_secrets:
                detail = re.sub(r'(\S+)\s*=\s*([^\s][^\s]*)', lambda m: f"{m.group(1)} = {'***' if any(kw in m.group(1).lower() for kw in ['password','secret','token','key','api_key']) else m.group(2)}", detail)
            lines.append(f"| {e.get('timestamp','')} | {e.get('action','')} | {detail} |")
        return "\n".join(lines) + "\n"

    def _record_audit(self, action: str, detail: str, profile: Optional[str] = None):
        p = self._profile(profile)
        p.setdefault("audit_log", []).append({
            "timestamp": datetime.now().isoformat(),
            "action": action,
            "detail": detail,
        })

    # ============ Template ============

    def generate_template(self, profile: Optional[str] = None) -> str:
        envs = self.list_envs(profile)
        p = self._profile(profile)
        all_vars: Dict[str, dict] = {}
        for env in envs:
            for k, v in p["environments"][env]["variables"].items():
                if k not in all_vars:
                    all_vars[k] = copy.deepcopy(v)
        required = set(p.get("required_vars", []))

        secret_vars = []
        required_vars = []
        regular_vars = []
        for k in sorted(all_vars.keys()):
            v = all_vars[k]
            entry = (k, v.get("value", ""), v.get("secret", False))
            if k in required:
                required_vars.append(entry)
            elif v.get("secret"):
                secret_vars.append(entry)
            else:
                regular_vars.append(entry)

        lines = [
            "# ============================================",
            "# 环境变量配置模板",
            f"# 项目: {self.data.get('project', '')}",
            f"# Profile: {profile or self.get_current_profile()}",
            f"# 可用环境: {', '.join(envs)}",
            "# ============================================",
            "",
        ]

        if required_vars:
            lines.append("# [1/3] 必填变量 (必须填写, 缺失会阻止 exec)")
            lines.append("")
            for key, value, _ in required_vars:
                is_secret = all_vars[key].get("secret", False)
                sample = "<必填>" if not value else (mask_value(value, secret=True) if is_secret else value)
                lines.append(f"# {key}")
                lines.append(f"#   类型: {'敏感 (加密存储)' if is_secret else '普通'}")
                lines.append(f"#   示例值: {sample}")
                lines.append(f"{key}=")
                lines.append("")

        if secret_vars:
            lines.append("# [2/3] 敏感变量 (非必填, 但会加密存储)")
            lines.append("")
            for key, value, _ in secret_vars:
                sample = mask_value(value, secret=True) if value else "<请输入>"
                lines.append(f"# {key}  (敏感, 加密保存, 输出时脱敏)")
                lines.append(f"#   示例值: {sample}")
                lines.append(f"{key}=")
                lines.append("")

        if regular_vars:
            lines.append("# [3/3] 常规变量 (有默认值, 可按需修改)")
            lines.append("")
            for key, value, _ in regular_vars:
                val_display = value if value else ""
                lines.append(f"# {key}")
                lines.append(f"#   默认值: {val_display}")
                lines.append(f"{key}={val_display}")
                lines.append("")

        lines.append("# ============================================")
        lines.append("# 使用说明:")
        lines.append("#   envmgr import <文件>   # 批量导入")
        lines.append("#   envmgr set KEY VALUE   # 单个设置")
        lines.append("#   envmgr switch <env>    # 切换环境")
        lines.append("#   envmgr exec -- <cmd>   # 带环境执行命令")
        lines.append("# ============================================")
        lines.append("")
        return "\n".join(lines)

    # ============ Clean ============

    def clean_unused(self, keep_env: Optional[str] = None, profile: Optional[str] = None) -> List[str]:
        keep_env = keep_env or self.get_default_env(profile)
        p = self._profile(profile)
        if keep_env not in p["environments"]:
            raise ValueError(f"环境不存在: {keep_env}")
        keep_keys = set(p["environments"][keep_env]["variables"].keys())
        removed = []
        self._snapshot(profile)
        for env_name, env_data in p["environments"].items():
            if env_name == keep_env:
                continue
            for key in list(env_data["variables"].keys()):
                if key not in keep_keys:
                    del env_data["variables"][key]
                    removed.append(f"{env_name}.{key}")
        if removed:
            self._record_audit("clean", f"清理未使用变量: {len(removed)} 个", profile=profile)
            self.save()
        return removed
