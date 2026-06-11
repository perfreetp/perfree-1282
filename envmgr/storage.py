import os
import json
import copy
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from .crypto import encrypt_value, decrypt_value, is_encrypted


DEFAULT_ENVS = ["dev", "test", "prod"]
STORE_FILENAME = "envmgr.json"


def _get_store_path(project_path: Optional[Path] = None) -> Path:
    if project_path:
        return project_path / ".envmgr" / STORE_FILENAME
    current = Path.cwd()
    for parent in [current] + list(current.parents):
        candidate = parent / ".envmgr" / STORE_FILENAME
        if candidate.exists():
            return candidate
    return current / ".envmgr" / STORE_FILENAME


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
                self._data = json.load(f)
        else:
            self._data = self._empty_store()

    def _empty_store(self) -> dict:
        return {
            "version": "1.0",
            "project": "",
            "default_env": "dev",
            "current_env": "dev",
            "environments": {},
            "audit_log": [],
            "last_snapshot": None,
            "required_vars": [],
        }

    def save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(self._data, f, indent=2, ensure_ascii=False)

    def init_project(self, project_name: str, envs: List[str] = None):
        self._data = self._empty_store()
        self._data["project"] = project_name
        envs = envs or DEFAULT_ENVS
        for env_name in envs:
            self._data["environments"][env_name] = {
                "variables": {},
                "created_at": datetime.now().isoformat(),
            }
        self._data["default_env"] = envs[0] if envs else "dev"
        self._data["current_env"] = self._data["default_env"]
        self._record_audit("init", f"初始化项目: {project_name}, 环境: {', '.join(envs)}")
        self.save()

    def is_initialized(self) -> bool:
        return self.path.exists() and bool(self.data.get("project"))

    def list_envs(self) -> List[str]:
        return list(self.data.get("environments", {}).keys())

    def get_current_env(self) -> str:
        return self.data.get("current_env", "dev")

    def get_default_env(self) -> str:
        return self.data.get("default_env", "dev")

    def set_default_env(self, env_name: str):
        if env_name not in self.data["environments"]:
            raise ValueError(f"环境不存在: {env_name}")
        self.data["default_env"] = env_name
        self._record_audit("set_default", f"设置默认环境: {env_name}")
        self.save()

    def switch_env(self, env_name: str):
        if env_name not in self.data["environments"]:
            raise ValueError(f"环境不存在: {env_name}")
        old = self.data["current_env"]
        self.data["current_env"] = env_name
        self._record_audit("switch", f"切换环境: {old} -> {env_name}")
        self.save()

    def add_env(self, env_name: str, copy_from: Optional[str] = None):
        if env_name in self.data["environments"]:
            raise ValueError(f"环境已存在: {env_name}")
        new_env = {
            "variables": {},
            "created_at": datetime.now().isoformat(),
        }
        if copy_from and copy_from in self.data["environments"]:
            new_env["variables"] = copy.deepcopy(
                self.data["environments"][copy_from]["variables"]
            )
        self.data["environments"][env_name] = new_env
        self._record_audit("add_env", f"添加环境: {env_name}" + (f" (从{copy_from}复制)" if copy_from else ""))
        self.save()

    def remove_env(self, env_name: str):
        if env_name not in self.data["environments"]:
            raise ValueError(f"环境不存在: {env_name}")
        if len(self.data["environments"]) <= 1:
            raise ValueError("至少保留一个环境")
        del self.data["environments"][env_name]
        if self.data["current_env"] == env_name:
            self.data["current_env"] = self.list_envs()[0]
        if self.data["default_env"] == env_name:
            self.data["default_env"] = self.list_envs()[0]
        self._record_audit("remove_env", f"删除环境: {env_name}")
        self.save()

    def get_variables(self, env_name: Optional[str] = None, decrypt: bool = False) -> Dict[str, dict]:
        env = env_name or self.get_current_env()
        if env not in self.data["environments"]:
            raise ValueError(f"环境不存在: {env}")
        vars_dict = self.data["environments"][env]["variables"]
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
                     required: bool = False, env_name: Optional[str] = None):
        env = env_name or self.get_current_env()
        if env not in self.data["environments"]:
            raise ValueError(f"环境不存在: {env}")
        self._snapshot()
        old_value = None
        if key in self.data["environments"][env]["variables"]:
            old_var = self.data["environments"][env]["variables"][key]
            old_value = old_var.get("value", "")
            if old_var.get("secret") and is_encrypted(old_value):
                old_value = decrypt_value(old_value)
        stored_value = encrypt_value(value) if secret else value
        self.data["environments"][env]["variables"][key] = {
            "value": stored_value,
            "secret": secret,
            "required": required,
            "updated_at": datetime.now().isoformat(),
        }
        if required and key not in self.data.get("required_vars", []):
            self.data.setdefault("required_vars", []).append(key)
        action = "update" if old_value is not None else "set"
        self._record_audit(action, f"[{env}] {key} = {'***' if secret else value}")
        self.save()

    def get_variable(self, key: str, env_name: Optional[str] = None) -> Optional[str]:
        env = env_name or self.get_current_env()
        if env not in self.data["environments"]:
            raise ValueError(f"环境不存在: {env}")
        var = self.data["environments"][env]["variables"].get(key)
        if var is None:
            return None
        value = var.get("value", "")
        if var.get("secret") and is_encrypted(value):
            return decrypt_value(value)
        return value

    def unset_variable(self, key: str, env_name: Optional[str] = None) -> bool:
        env = env_name or self.get_current_env()
        if env not in self.data["environments"]:
            raise ValueError(f"环境不存在: {env}")
        if key not in self.data["environments"][env]["variables"]:
            return False
        self._snapshot()
        del self.data["environments"][env]["variables"][key]
        self._record_audit("unset", f"[{env}] 删除变量: {key}")
        self.save()
        return True

    def import_env_file(self, file_path: str, env_name: Optional[str] = None,
                        secret_keys: Optional[List[str]] = None):
        env = env_name or self.get_current_env()
        secret_keys = set(secret_keys or [])
        if env not in self.data["environments"]:
            raise ValueError(f"环境不存在: {env}")
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"文件不存在: {file_path}")
        self._snapshot()
        count = 0
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
                self.set_variable(key, value, secret=is_secret, env_name=env)
                count += 1
        self._record_audit("import", f"[{env}] 从 {path.name} 导入 {count} 个变量")
        self.save()
        return count

    def export_shell(self, env_name: Optional[str] = None, decrypt: bool = True,
                     expand: bool = True) -> str:
        env = env_name or self.get_current_env()
        variables = self.get_variables(env, decrypt=decrypt)
        if expand:
            variables = self._expand_variables(variables)
        lines = []
        for key in sorted(variables.keys()):
            val = variables[key].get("value", "")
            val_escaped = val.replace("'", "'\\''")
            lines.append(f"export {key}='{val_escaped}'")
        return "\n".join(lines) + "\n"

    def export_dotenv(self, env_name: Optional[str] = None, decrypt: bool = True,
                      expand: bool = True) -> str:
        env = env_name or self.get_current_env()
        variables = self.get_variables(env, decrypt=decrypt)
        if expand:
            variables = self._expand_variables(variables)
        lines = []
        for key in sorted(variables.keys()):
            val = variables[key].get("value", "")
            val_escaped = val.replace('"', '\\"')
            lines.append(f'{key}="{val_escaped}"')
        return "\n".join(lines) + "\n"

    def _expand_variables(self, variables: Dict[str, dict]) -> Dict[str, dict]:
        result = copy.deepcopy(variables)
        plain_values = {k: v.get("value", "") for k, v in result.items()}
        import re
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

    def diff_envs(self, env_a: str, env_b: str) -> Tuple[Dict[str, dict], Dict[str, dict], Dict[str, Tuple[str, str]]]:
        vars_a = self.get_variables(env_a, decrypt=True)
        vars_b = self.get_variables(env_b, decrypt=True)
        keys_a = set(vars_a.keys())
        keys_b = set(vars_b.keys())
        only_a = {k: vars_a[k] for k in keys_a - keys_b}
        only_b = {k: vars_b[k] for k in keys_b - keys_a}
        different = {}
        for k in keys_a & keys_b:
            va = vars_a[k].get("value", "")
            vb = vars_b[k].get("value", "")
            if va != vb:
                different[k] = (va, vb)
        return only_a, only_b, different

    def check_required(self, env_name: Optional[str] = None) -> List[str]:
        env = env_name or self.get_current_env()
        required = self.data.get("required_vars", [])
        variables = self.get_variables(env, decrypt=False)
        missing = []
        for key in required:
            if key not in variables or not variables[key].get("value"):
                missing.append(key)
        return missing

    def detect_conflicts(self, env_name: Optional[str] = None) -> List[str]:
        env = env_name or self.get_current_env()
        variables = self.get_variables(env, decrypt=False)
        lower_map = {}
        conflicts = []
        for key in variables:
            lower_key = key.lower()
            if lower_key in lower_map:
                conflicts.append((lower_map[lower_key], key))
            else:
                lower_map[lower_key] = key
        return [f"{a} <-> {b}" for a, b in conflicts]

    def get_required_vars(self) -> List[str]:
        return list(self.data.get("required_vars", []))

    def set_required(self, key: str, required: bool = True):
        req = self.data.setdefault("required_vars", [])
        if required and key not in req:
            req.append(key)
        elif not required and key in req:
            req.remove(key)
        self.save()

    def _snapshot(self):
        self.data["last_snapshot"] = copy.deepcopy({
            "environments": self.data.get("environments", {}),
            "default_env": self.data.get("default_env"),
            "current_env": self.data.get("current_env"),
            "required_vars": self.data.get("required_vars", []),
        })

    def rollback(self) -> bool:
        if not self.data.get("last_snapshot"):
            return False
        snap = self.data["last_snapshot"]
        self.data["environments"] = copy.deepcopy(snap["environments"])
        self.data["default_env"] = snap["default_env"]
        self.data["current_env"] = snap["current_env"]
        self.data["required_vars"] = snap["required_vars"]
        self.data["last_snapshot"] = None
        self._record_audit("rollback", "回滚到上一个快照")
        self.save()
        return True

    def get_audit_log(self, limit: int = 20) -> List[dict]:
        log = self.data.get("audit_log", [])
        return log[-limit:] if limit > 0 else log

    def _record_audit(self, action: str, detail: str):
        self.data.setdefault("audit_log", []).append({
            "timestamp": datetime.now().isoformat(),
            "action": action,
            "detail": detail,
        })

    def generate_template(self) -> str:
        envs = self.list_envs()
        all_keys = set()
        for env in envs:
            all_keys.update(self.data["environments"][env]["variables"].keys())
        required = self.data.get("required_vars", [])
        lines = [
            "# 环境变量配置模板",
            f"# 项目: {self.data.get('project', '')}",
            f"# 可用环境: {', '.join(envs)}",
            "",
            "# 必填变量:",
        ]
        for key in sorted(required):
            lines.append(f"#   - {key}")
        lines.append("")
        lines.append("# 使用方法:")
        lines.append("#   envmgr set KEY value  # 设置变量")
        lines.append("#   envmgr switch dev     # 切换到开发环境")
        lines.append("#   envmgr exec -- cmd    # 带环境执行命令")
        lines.append("")
        return "\n".join(lines) + "\n"

    def clean_unused(self, keep_env: Optional[str] = None) -> List[str]:
        keep_env = keep_env or self.get_default_env()
        if keep_env not in self.data["environments"]:
            raise ValueError(f"环境不存在: {keep_env}")
        keep_keys = set(self.data["environments"][keep_env]["variables"].keys())
        removed = []
        self._snapshot()
        for env_name, env_data in self.data["environments"].items():
            if env_name == keep_env:
                continue
            for key in list(env_data["variables"].keys()):
                if key not in keep_keys:
                    del env_data["variables"][key]
                    removed.append(f"{env_name}.{key}")
        if removed:
            self._record_audit("clean", f"清理未使用变量: {len(removed)} 个")
            self.save()
        return removed
