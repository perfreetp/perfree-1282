import os
import sys
import argparse
import subprocess
from pathlib import Path

from .storage import EnvStore
from .crypto import mask_value, is_encrypted


def _profile_header(store: EnvStore) -> str:
    return f"[Profile: {store.get_current_profile()}]"


def cmd_init(args, store: EnvStore):
    if store.is_initialized() and not args.force:
        print("错误: 当前目录已初始化。使用 --force 覆盖。")
        return 1
    envs = args.environments or ["dev", "test", "prod"]
    store.init_project(args.project, envs=envs, profile=args.profile or "default")
    print(f"✅ 项目 '{args.project}' 已初始化")
    print(f"   配置文件: {store.path}")
    print(f"   Profile: {store.get_current_profile()}")
    print(f"   环境: {', '.join(envs)}")
    print(f"   默认环境: {store.get_default_env()}")
    return 0


def cmd_profile(args, store: EnvStore):
    if not store.is_initialized():
        print("错误: 未初始化。请先运行 'envmgr init'")
        return 1
    action = getattr(args, "profile_action", "list")
    try:
        if action == "list":
            profiles = store.list_profiles()
            current = store.get_current_profile()
            print("可用 Profiles:")
            for p in profiles:
                marker = " <-- 当前" if p == current else ""
                print(f"  - {p}{marker}")
            return 0
        if action == "switch":
            store.switch_profile(args.name)
            print(f"🔀 已切换到 Profile: {args.name}")
            return 0
        if action == "create":
            store.create_profile(args.name, copy_from=args.copy_from, envs=args.environments)
            print(f"✅ Profile '{args.name}' 已创建" + (f" (从 {args.copy_from} 复制)" if args.copy_from else ""))
            return 0
        if action == "delete":
            if not args.yes:
                confirm = input(f"确认删除 Profile '{args.name}'? [y/N] ").strip().lower()
                if confirm not in ("y", "yes"):
                    print("已取消")
                    return 1
            store.delete_profile(args.name)
            print(f"🗑️  Profile '{args.name}' 已删除")
            return 0
    except ValueError as e:
        print(f"错误: {e}")
        return 1
    return 0


def cmd_list(args, store: EnvStore):
    if not store.is_initialized():
        print("错误: 未初始化。请先运行 'envmgr init'")
        return 1

    if args.profiles:
        return cmd_profile(argparse.Namespace(profile_action="list"), store)

    if args.environments:
        envs = store.list_envs(profile=args.profile)
        current = store.get_current_env(profile=args.profile)
        default = store.get_default_env(profile=args.profile)
        print(f"{_profile_header(store)} 可用环境:")
        for env in envs:
            marker = ""
            if env == current:
                marker += " <-- 当前"
            if env == default:
                marker += " [默认]"
            print(f"  - {env}{marker}")
        return 0

    target_env = args.env or store.get_current_env(profile=args.profile)
    try:
        variables = store.get_variables(target_env, decrypt=args.decrypt, profile=args.profile)
    except ValueError as e:
        print(f"错误: {e}")
        return 1

    print(f"{_profile_header(store)} 环境: {target_env}")
    if not variables:
        print("  (无变量)")
        return 0

    required_set = set(store.get_required_vars(profile=args.profile))
    max_key_len = max(len(k) for k in variables.keys())
    for key in sorted(variables.keys()):
        var = variables[key]
        value = var.get("value", "")
        secret = var.get("secret", False)
        required = key in required_set

        if not args.decrypt and secret:
            display_val = mask_value(value, secret=True)
        else:
            display_val = value

        flags = []
        if secret:
            flags.append("🔒")
        if required:
            flags.append("✓")
        flag_str = f" [{''.join(flags)}]" if flags else ""

        print(f"  {key.ljust(max_key_len)} = {display_val}{flag_str}")

    if args.check:
        missing = store.check_required(target_env, profile=args.profile)
        if missing:
            print(f"\n⚠️  缺失必填变量: {', '.join(missing)}")
        else:
            print(f"\n✅ 所有必填变量已设置")
    return 0


def cmd_set(args, store: EnvStore):
    if not store.is_initialized():
        print("错误: 未初始化。请先运行 'envmgr init'")
        return 1
    try:
        store.set_variable(
            args.key, args.value,
            secret=args.secret,
            required=args.required,
            env_name=args.env,
            profile=args.profile,
        )
    except ValueError as e:
        print(f"错误: {e}")
        return 1
    env = args.env or store.get_current_env(profile=args.profile)
    secret_str = " [加密]" if args.secret else ""
    print(f"{_profile_header(store)} ✅ [{env}] {args.key} = {'***' if args.secret else args.value}{secret_str}")
    return 0


def cmd_get(args, store: EnvStore):
    if not store.is_initialized():
        print("错误: 未初始化。请先运行 'envmgr init'")
        return 1
    try:
        variables = store.get_variables(args.env, decrypt=args.decrypt, profile=args.profile)
    except ValueError as e:
        print(f"错误: {e}")
        return 1

    if args.key not in variables:
        if not args.quiet:
            print(f"变量 '{args.key}' 不存在")
        return 1

    var = variables[args.key]
    value = var.get("value", "")
    is_secret = var.get("secret", False)

    if args.expand:
        try:
            all_vars_plain = store.get_variables(args.env, decrypt=True, profile=args.profile)
            expanded = store._expand_variables(all_vars_plain)
            value = expanded.get(args.key, {}).get("value", value)
        except Exception:
            pass

    if is_secret and not args.decrypt:
        value = mask_value(value, secret=True)

    if args.raw:
        sys.stdout.write(value)
    else:
        print(value)
    return 0


def cmd_unset(args, store: EnvStore):
    if not store.is_initialized():
        print("错误: 未初始化。请先运行 'envmgr init'")
        return 1
    try:
        removed = store.unset_variable(args.key, env_name=args.env, profile=args.profile)
    except ValueError as e:
        print(f"错误: {e}")
        return 1
    env = args.env or store.get_current_env(profile=args.profile)
    if removed:
        print(f"{_profile_header(store)} 🗑️  [{env}] 已删除 {args.key}")
    else:
        print(f"变量 '{args.key}' 不存在")
    return 0 if removed else 1


def cmd_switch(args, store: EnvStore):
    if not store.is_initialized():
        print("错误: 未初始化。请先运行 'envmgr init'")
        return 1
    try:
        store.switch_env(args.environment, profile=args.profile)
    except ValueError as e:
        print(f"错误: {e}")
        return 1
    print(f"{_profile_header(store)} 🔄 已切换到环境: {args.environment}")
    return 0


def cmd_diff(args, store: EnvStore):
    if not store.is_initialized():
        print("错误: 未初始化。请先运行 'envmgr init'")
        return 1

    env_a = args.env_a or store.get_current_env(profile=args.profile)
    env_b = args.env_b or store.get_default_env(profile=args.profile)
    if env_a == env_b:
        print("错误: 两个环境相同")
        return 1

    try:
        only_a, only_b, different = store.diff_envs(env_a, env_b, profile=args.profile)
    except ValueError as e:
        print(f"错误: {e}")
        return 1

    print(f"{_profile_header(store)} 比较 {env_a} vs {env_b}")
    print("=" * 40)

    reveal = args.decrypt

    if only_a:
        print(f"\n  仅存在于 {env_a}:")
        for k in sorted(only_a.keys()):
            v = only_a[k].get("value", "")
            if only_a[k].get("secret") and not reveal:
                v = mask_value(v, secret=True)
            print(f"    + {k} = {v}")

    if only_b:
        print(f"\n  仅存在于 {env_b}:")
        for k in sorted(only_b.keys()):
            v = only_b[k].get("value", "")
            if only_b[k].get("secret") and not reveal:
                v = mask_value(v, secret=True)
            print(f"    + {k} = {v}")

    if different:
        print(f"\n  值不同:")
        for k in sorted(different.keys()):
            va, vb, is_secret = different[k]
            if is_secret and not reveal:
                va = mask_value(va, secret=True)
                vb = mask_value(vb, secret=True)
            print(f"    ~ {k}")
            print(f"        {env_a}: {va}")
            print(f"        {env_b}: {vb}")

    if not only_a and not only_b and not different:
        print("\n  两个环境完全相同")

    return 0


def _parse_env_file(path: str) -> dict:
    result = {}
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key:
                result[key] = value
    return result


def cmd_exec(args, store: EnvStore):
    if not store.is_initialized():
        print("错误: 未初始化。请先运行 'envmgr init'")
        return 1
    if not args.command:
        print("错误: 请指定要执行的命令")
        return 1

    target_env = args.env or store.get_current_env(profile=args.profile)
    try:
        variables = store.get_variables(target_env, decrypt=True, profile=args.profile)
    except ValueError as e:
        print(f"错误: {e}")
        return 1

    if not args.no_expand:
        variables = store._expand_variables(variables)

    env = os.environ.copy()
    for key, var in variables.items():
        env[key] = var.get("value", "")

    if args.env_file:
        for ef in args.env_file:
            if not Path(ef).exists():
                print(f"错误: 临时环境文件不存在: {ef}")
                return 1
            extra = _parse_env_file(ef)
            env.update(extra)

    if args.override:
        for ov in args.override:
            if "=" in ov:
                k, _, v = ov.partition("=")
                env[k] = v

    missing = store.check_required(target_env, profile=args.profile)
    if missing and not args.force:
        print(f"⚠️  缺失必填变量: {', '.join(missing)}")
        print("   使用 --force 强制执行")
        return 1

    cmd = args.command
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    if isinstance(cmd, list):
        cmd_str = " ".join(f'"{c}"' if " " in c else c for c in cmd)
    else:
        cmd_str = cmd
    try:
        result = subprocess.run(cmd_str, env=env, shell=True)
        return result.returncode
    except FileNotFoundError as e:
        print(f"错误: {e}")
        return 127


def cmd_import(args, store: EnvStore):
    if not store.is_initialized():
        print("错误: 未初始化。请先运行 'envmgr init'")
        return 1
    try:
        result = store.preview_import(
            args.file,
            env_name=args.env,
            secret_keys=args.secret_keys.split(",") if args.secret_keys else None,
            profile=args.profile,
        )
    except (FileNotFoundError, ValueError) as e:
        print(f"错误: {e}")
        return 1

    env = args.env or store.get_current_env(profile=args.profile)
    added = len(result["added"])
    updated = len(result["updated"])
    skipped = len(result["skipped"])
    conflicts = len(result["conflicts"])

    print(f"{_profile_header(store)} 导入预览: {Path(args.file).name} -> {env}")
    print(f"  新增:   {added} 个")
    print(f"  覆盖:   {updated} 个")
    print(f"  跳过:   {skipped} 个 (值相同)")
    if conflicts:
        print(f"  冲突:   {conflicts} 个")
        for k, c in result["conflicts"]:
            print(f"    - {k} <-> {c}")

    if args.preview or args.dry_run:
        if added:
            print(f"\n  新增变量:")
            for k, v, s in result["added"]:
                display = mask_value(v, secret=True) if s else v
                print(f"    + {k} = {display}" + (" 🔒" if s else ""))
        if updated:
            print(f"\n  覆盖变量:")
            for k, old_v, new_v, s in result["updated"]:
                old_d = mask_value(old_v, secret=True) if s else old_v
                new_d = mask_value(new_v, secret=True) if s else new_v
                print(f"    ~ {k}: {old_d} -> {new_d}" + (" 🔒" if s else ""))
        if skipped:
            print(f"\n  跳过变量 (值未变):")
            for k, v, s in result["skipped"]:
                print(f"    = {k}")
        if args.dry_run:
            print(f"\n📋 dry-run: 未写入任何变更")
        return 0

    if conflicts:
        print("\n❌ 存在冲突，导入已终止")
        return 1

    if not args.yes:
        try:
            confirm = input("\n确认导入? [y/N] ").strip().lower()
        except EOFError:
            confirm = "n"
        if confirm not in ("y", "yes"):
            print("已取消")
            return 1

    try:
        count = store.import_env_file(
            args.file,
            env_name=args.env,
            secret_keys=args.secret_keys.split(",") if args.secret_keys else None,
            profile=args.profile,
        )
    except ValueError as e:
        print(f"错误: {e}")
        return 1

    print(f"📥 已从 {args.file} 导入 {count} 个变量到 {env} 环境")
    return 0


def cmd_export(args, store: EnvStore):
    if not store.is_initialized():
        print("错误: 未初始化。请先运行 'envmgr init'")
        return 1
    try:
        if args.format == "shell":
            output = store.export_shell(
                env_name=args.env,
                decrypt=not args.encrypted,
                expand=not args.no_expand,
                profile=args.profile,
            )
        else:
            output = store.export_dotenv(
                env_name=args.env,
                decrypt=not args.encrypted,
                expand=not args.no_expand,
                profile=args.profile,
            )
    except ValueError as e:
        print(f"错误: {e}")
        return 1

    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
        print(f"📤 已导出到 {args.output}")
    else:
        sys.stdout.write(output)
    return 0


def cmd_rollback(args, store: EnvStore):
    if not store.is_initialized():
        print("错误: 未初始化。请先运行 'envmgr init'")
        return 1
    if store.rollback(profile=args.profile):
        print(f"{_profile_header(store)} ⏪ 已回滚到上一个快照")
        return 0
    else:
        print("没有可回滚的快照")
        return 1


def cmd_log(args, store: EnvStore):
    if not store.is_initialized():
        print("错误: 未初始化。请先运行 'envmgr init'")
        return 1

    logs = store.get_audit_log(
        limit=args.limit,
        env=args.env,
        key=args.key,
        action=args.action,
        since=args.since,
        until=args.until,
        profile=args.profile,
    )

    if args.export:
        report = store.export_audit_report(
            decrypt_secrets=args.decrypt,
            profile=args.profile,
            limit=args.limit,
            env=args.env,
            key=args.key,
            action=args.action,
            since=args.since,
            until=args.until,
        )
        if args.export == "-":
            sys.stdout.write(report)
        else:
            Path(args.export).write_text(report, encoding="utf-8")
            print(f"📝 审计报告已导出到: {args.export}")
        return 0

    if not logs:
        print("暂无操作记录 (或筛选后无匹配)")
        return 0

    print(f"{_profile_header(store)} 操作日志 ({len(logs)} 条)")
    if any([args.env, args.key, args.action, args.since, args.until]):
        filters = []
        if args.env:
            filters.append(f"环境={args.env}")
        if args.key:
            filters.append(f"变量={args.key}")
        if args.action:
            filters.append(f"操作={args.action}")
        if args.since:
            filters.append(f"起始={args.since}")
        if args.until:
            filters.append(f"截止={args.until}")
        print(f"  筛选条件: {', '.join(filters)}")
    print()

    for entry in logs:
        ts = entry.get("timestamp", "")[:19]
        action = entry.get("action", "").ljust(14)
        detail = entry.get("detail", "")
        if not args.decrypt:
            import re
            detail = re.sub(
                r'(\S+)\s*=\s*(\S+)',
                lambda m: f"{m.group(1)} = {'***' if any(kw in m.group(1).lower() for kw in ['password', 'secret', 'token', 'key', 'api_key']) else m.group(2)}",
                detail,
            )
        print(f"  {ts}  {action}  {detail}")
    return 0


def cmd_template(args, store: EnvStore):
    if args.generate:
        if not store.is_initialized():
            print("错误: 未初始化。请先运行 'envmgr init'")
            return 1
        output = store.generate_template(profile=args.profile)
        if args.output:
            Path(args.output).write_text(output, encoding="utf-8")
            print(f"📝 模板已生成: {args.output}")
        else:
            sys.stdout.write(output)
        return 0

    sample = """# ============================================
# envmgr 示例 .env 模板
# ============================================

# [1/3] 必填变量 (必须填写, 缺失会阻止 exec)

# DB_HOST
#   类型: 普通
#   示例值: localhost
DB_HOST=
# DB_USER
#   类型: 普通
#   示例值: admin
DB_USER=
# DB_PASSWORD
#   类型: 敏感 (加密存储)
#   示例值: ****************
DB_PASSWORD=

# [2/3] 敏感变量 (非必填, 但会加密存储)

# API_KEY  (敏感, 加密保存, 输出时脱敏)
#   示例值: ************
API_KEY=
# SECRET_TOKEN  (敏感, 加密保存, 输出时脱敏)
#   示例值: ************
SECRET_TOKEN=

# [3/3] 常规变量 (有默认值, 可按需修改)

# APP_NAME
#   默认值: MyApplication
APP_NAME=MyApplication
# APP_ENV
#   默认值: development
APP_ENV=development
# DEBUG
#   默认值: true
DEBUG=true

# ============================================
# 使用说明:
#   envmgr import <文件>   # 批量导入
#   envmgr set KEY VALUE   # 单个设置
#   envmgr switch <env>    # 切换环境
#   envmgr exec -- <cmd>   # 带环境执行命令
# ============================================
"""
    if args.output:
        Path(args.output).write_text(sample, encoding="utf-8")
        print(f"📝 示例模板已生成: {args.output}")
    else:
        sys.stdout.write(sample)
    return 0


def cmd_clean(args, store: EnvStore):
    if not store.is_initialized():
        print("错误: 未初始化。请先运行 'envmgr init'")
        return 1
    try:
        removed = store.clean_unused(keep_env=args.keep_env, profile=args.profile)
    except ValueError as e:
        print(f"错误: {e}")
        return 1
    if removed:
        print(f"{_profile_header(store)} 🧹 已清理 {len(removed)} 个未使用变量:")
        for item in removed:
            print(f"  - {item}")
    else:
        print("没有需要清理的变量")
    return 0


def cmd_default(args, store: EnvStore):
    if not store.is_initialized():
        print("错误: 未初始化。请先运行 'envmgr init'")
        return 1
    if args.environment:
        try:
            store.set_default_env(args.environment, profile=args.profile)
        except ValueError as e:
            print(f"错误: {e}")
            return 1
        print(f"{_profile_header(store)} ✅ 默认环境已设置为: {args.environment}")
        return 0
    else:
        print(f"{_profile_header(store)} 默认环境: {store.get_default_env(profile=args.profile)}")
        return 0


def cmd_required(args, store: EnvStore):
    if not store.is_initialized():
        print("错误: 未初始化。请先运行 'envmgr init'")
        return 1
    if args.add:
        store.set_required(args.add, required=True, profile=args.profile)
        print(f"{_profile_header(store)} ✅ '{args.add}' 已标记为必填")
        return 0
    elif args.remove:
        store.set_required(args.remove, required=False, profile=args.profile)
        print(f"{_profile_header(store)} ✅ '{args.remove}' 已取消必填")
        return 0
    else:
        required = store.get_required_vars(profile=args.profile)
        if required:
            print(f"{_profile_header(store)} 必填变量:")
            for key in sorted(required):
                print(f"  - {key}")
        else:
            print("暂无必填变量")
        return 0


def cmd_env_add(args, store: EnvStore):
    if not store.is_initialized():
        print("错误: 未初始化。请先运行 'envmgr init'")
        return 1
    try:
        store.add_env(args.name, copy_from=args.copy_from, profile=args.profile)
    except ValueError as e:
        print(f"错误: {e}")
        return 1
    print(f"{_profile_header(store)} ✅ 环境 '{args.name}' 已创建")
    return 0


def cmd_env_remove(args, store: EnvStore):
    if not store.is_initialized():
        print("错误: 未初始化。请先运行 'envmgr init'")
        return 1
    try:
        store.remove_env(args.name, profile=args.profile)
    except ValueError as e:
        print(f"错误: {e}")
        return 1
    print(f"{_profile_header(store)} 🗑️  环境 '{args.name}' 已删除")
    return 0


def _add_profile_arg(p: argparse.ArgumentParser):
    p.add_argument("-p", "--profile", help="指定 Profile (默认使用当前 Profile)")


def main():
    parser = argparse.ArgumentParser(
        prog="envmgr",
        description="环境变量管家 - 多 Profile、多环境配置管理工具",
    )
    subparsers = parser.add_subparsers(dest="command", help="可用命令")

    p_init = subparsers.add_parser("init", help="初始化项目")
    p_init.add_argument("project", help="项目名称")
    p_init.add_argument("-e", "--environments", nargs="+", help="环境名称列表")
    p_init.add_argument("-p", "--profile", default="default", help="初始 Profile 名称 (默认: default)")
    p_init.add_argument("-f", "--force", action="store_true", help="强制覆盖现有配置")
    p_init.set_defaults(func=cmd_init)

    p_profile = subparsers.add_parser("profile", help="Profile 管理 (list/switch/create/delete)")
    profile_sub = p_profile.add_subparsers(dest="profile_action")
    p_profile.set_defaults(profile_action="list")

    p_pl = profile_sub.add_parser("list", help="列出所有 Profile")
    p_pl.set_defaults(func=cmd_profile)

    p_ps = profile_sub.add_parser("switch", help="切换当前 Profile")
    p_ps.add_argument("name", help="Profile 名称")
    p_ps.set_defaults(func=cmd_profile)

    p_pc = profile_sub.add_parser("create", help="创建新 Profile")
    p_pc.add_argument("name", help="Profile 名称")
    p_pc.add_argument("--copy-from", help="从现有 Profile 复制")
    p_pc.add_argument("-e", "--environments", nargs="+", help="环境列表 (不使用 --copy-from 时)")
    p_pc.set_defaults(func=cmd_profile)

    p_pd = profile_sub.add_parser("delete", help="删除 Profile")
    p_pd.add_argument("name", help="Profile 名称")
    p_pd.add_argument("-y", "--yes", action="store_true", help="跳过确认")
    p_pd.set_defaults(func=cmd_profile)

    p_list = subparsers.add_parser("list", help="列出变量、环境或 Profile")
    _add_profile_arg(p_list)
    p_list.add_argument("-e", "--env", help="指定环境")
    p_list.add_argument("-d", "--decrypt", action="store_true", help="显示解密后的值")
    p_list.add_argument("-c", "--check", action="store_true", help="检查必填项")
    p_list.add_argument("--environments", action="store_true", help="列出所有环境")
    p_list.add_argument("--profiles", action="store_true", help="列出所有 Profile")
    p_list.set_defaults(func=cmd_list)

    p_set = subparsers.add_parser("set", help="设置变量")
    _add_profile_arg(p_set)
    p_set.add_argument("key", help="变量名")
    p_set.add_argument("value", help="变量值")
    p_set.add_argument("-e", "--env", help="指定环境")
    p_set.add_argument("-s", "--secret", action="store_true", help="标记为敏感值（加密存储）")
    p_set.add_argument("-r", "--required", action="store_true", help="标记为必填")
    p_set.set_defaults(func=cmd_set)

    p_get = subparsers.add_parser("get", help="获取变量值")
    _add_profile_arg(p_get)
    p_get.add_argument("key", help="变量名")
    p_get.add_argument("-e", "--env", help="指定环境")
    p_get.add_argument("-r", "--raw", action="store_true", help="原始输出（无换行）")
    p_get.add_argument("-q", "--quiet", action="store_true", help="安静模式")
    p_get.add_argument("-x", "--expand", action="store_true", help="展开变量引用")
    p_get.add_argument("-d", "--decrypt", action="store_true", help="敏感变量输出明文（默认脱敏）")
    p_get.set_defaults(func=cmd_get)

    p_unset = subparsers.add_parser("unset", help="删除变量")
    _add_profile_arg(p_unset)
    p_unset.add_argument("key", help="变量名")
    p_unset.add_argument("-e", "--env", help="指定环境")
    p_unset.set_defaults(func=cmd_unset)

    p_switch = subparsers.add_parser("switch", help="切换当前环境")
    _add_profile_arg(p_switch)
    p_switch.add_argument("environment", help="环境名称")
    p_switch.set_defaults(func=cmd_switch)

    p_diff = subparsers.add_parser("diff", help="比较两个环境")
    _add_profile_arg(p_diff)
    p_diff.add_argument("env_a", nargs="?", help="环境A")
    p_diff.add_argument("env_b", nargs="?", help="环境B")
    p_diff.add_argument("-d", "--decrypt", action="store_true", help="敏感变量显示明文（默认脱敏）")
    p_diff.set_defaults(func=cmd_diff)

    p_exec = subparsers.add_parser("exec", help="带环境执行命令")
    _add_profile_arg(p_exec)
    p_exec.add_argument("-e", "--env", help="指定环境")
    p_exec.add_argument("-o", "--override", action="append", help="临时覆盖变量 KEY=VALUE")
    p_exec.add_argument("--env-file", action="append", help="从 .env 文件临时叠加变量 (不写入配置)")
    p_exec.add_argument("-f", "--force", action="store_true", help="忽略必填项检查")
    p_exec.add_argument("--no-expand", action="store_true", help="不展开变量引用")
    p_exec.add_argument("command", nargs=argparse.REMAINDER, help="要执行的命令")
    p_exec.set_defaults(func=cmd_exec)

    p_import = subparsers.add_parser("import", help="从 .env 文件导入")
    _add_profile_arg(p_import)
    p_import.add_argument("file", help=".env 文件路径")
    p_import.add_argument("-e", "--env", help="目标环境")
    p_import.add_argument("-s", "--secret-keys", help="指定为敏感的键名（逗号分隔）")
    p_import.add_argument("--preview", action="store_true", help="仅预览变更，不写入")
    p_import.add_argument("--dry-run", action="store_true", help="预览变更详情，不写入")
    p_import.add_argument("-y", "--yes", action="store_true", help="跳过确认")
    p_import.set_defaults(func=cmd_import)

    p_export = subparsers.add_parser("export", help="导出环境变量")
    _add_profile_arg(p_export)
    p_export.add_argument("-e", "--env", help="指定环境")
    p_export.add_argument("-f", "--format", choices=["shell", "dotenv"], default="shell",
                          help="输出格式 (默认: shell)")
    p_export.add_argument("-o", "--output", help="输出文件")
    p_export.add_argument("--encrypted", action="store_true", help="保留加密值")
    p_export.add_argument("--no-expand", action="store_true", help="不展开变量引用")
    p_export.set_defaults(func=cmd_export)

    p_rollback = subparsers.add_parser("rollback", help="回滚上次变更")
    _add_profile_arg(p_rollback)
    p_rollback.set_defaults(func=cmd_rollback)

    p_log = subparsers.add_parser("log", help="查看操作日志 / 导出审计报告")
    _add_profile_arg(p_log)
    p_log.add_argument("-n", "--limit", type=int, default=0, help="显示条数 (0=全部)")
    p_log.add_argument("--env", help="按环境筛选")
    p_log.add_argument("--key", help="按变量名筛选")
    p_log.add_argument("--action", help="按操作类型筛选 (set/unset/switch/import/...)")
    p_log.add_argument("--since", help="起始时间 (ISO 格式, 如 2026-06-11T10:00)")
    p_log.add_argument("--until", help="截止时间 (ISO 格式)")
    p_log.add_argument("-d", "--decrypt", action="store_true", help="报告中显示敏感变量明文 (默认脱敏)")
    p_log.add_argument("--export", metavar="FILE", help="导出审计报告 (使用 - 输出到 stdout)")
    p_log.set_defaults(func=cmd_log)

    p_template = subparsers.add_parser("template", help="生成配置模板")
    _add_profile_arg(p_template)
    p_template.add_argument("-g", "--generate", action="store_true", help="基于当前 Profile 分组生成")
    p_template.add_argument("-o", "--output", help="输出文件")
    p_template.set_defaults(func=cmd_template)

    p_clean = subparsers.add_parser("clean", help="清理未使用变量")
    _add_profile_arg(p_clean)
    p_clean.add_argument("--keep-env", help="以此环境为基准保留变量")
    p_clean.set_defaults(func=cmd_clean)

    p_default = subparsers.add_parser("default", help="查看或设置默认环境")
    _add_profile_arg(p_default)
    p_default.add_argument("environment", nargs="?", help="环境名称")
    p_default.set_defaults(func=cmd_default)

    p_required = subparsers.add_parser("required", help="管理必填变量")
    _add_profile_arg(p_required)
    p_required.add_argument("--add", help="添加为必填")
    p_required.add_argument("--remove", help="取消必填")
    p_required.set_defaults(func=cmd_required)

    p_env_add = subparsers.add_parser("env-add", help="添加新环境")
    _add_profile_arg(p_env_add)
    p_env_add.add_argument("name", help="环境名称")
    p_env_add.add_argument("--copy-from", help="从现有环境复制")
    p_env_add.set_defaults(func=cmd_env_add)

    p_env_remove = subparsers.add_parser("env-remove", help="删除环境")
    _add_profile_arg(p_env_remove)
    p_env_remove.add_argument("name", help="环境名称")
    p_env_remove.set_defaults(func=cmd_env_remove)

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        return 1

    store = EnvStore()
    return args.func(args, store)


if __name__ == "__main__":
    sys.exit(main())
