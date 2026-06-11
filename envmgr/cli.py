import os
import sys
import argparse
import subprocess
from pathlib import Path

from .storage import EnvStore
from .crypto import mask_value, is_encrypted, decrypt_value


def cmd_init(args, store: EnvStore):
    if store.is_initialized() and not args.force:
        print("错误: 当前目录已初始化。使用 --force 覆盖。")
        return 1
    envs = args.environments or ["dev", "test", "prod"]
    store.init_project(args.project, envs=envs)
    print(f"✅ 项目 '{args.project}' 已初始化")
    print(f"   配置文件: {store.path}")
    print(f"   环境: {', '.join(envs)}")
    print(f"   默认环境: {store.get_default_env()}")
    return 0


def cmd_list(args, store: EnvStore):
    if not store.is_initialized():
        print("错误: 未初始化。请先运行 'envmgr init'")
        return 1

    if args.environments:
        envs = store.list_envs()
        current = store.get_current_env()
        default = store.get_default_env()
        print("可用环境:")
        for env in envs:
            marker = ""
            if env == current:
                marker += " <-- 当前"
            if env == default:
                marker += " [默认]"
            print(f"  - {env}{marker}")
        return 0

    target_env = args.env or store.get_current_env()
    try:
        variables = store.get_variables(target_env, decrypt=args.decrypt)
    except ValueError as e:
        print(f"错误: {e}")
        return 1

    print(f"环境: {target_env}")
    if not variables:
        print("  (无变量)")
        return 0

    required_set = set(store.get_required_vars())
    max_key_len = max(len(k) for k in variables.keys())
    for key in sorted(variables.keys()):
        var = variables[key]
        value = var.get("value", "")
        secret = var.get("secret", False)
        required = key in required_set

        if not args.decrypt and secret and is_encrypted(value):
            display_val = mask_value("?" * 12, secret=True)
        else:
            display_val = mask_value(value, secret=secret and not args.decrypt)

        flags = []
        if secret:
            flags.append("🔒")
        if required:
            flags.append("✓")
        flag_str = f" [{''.join(flags)}]" if flags else ""

        print(f"  {key.ljust(max_key_len)} = {display_val}{flag_str}")

    if args.check:
        missing = store.check_required(target_env)
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
        )
    except ValueError as e:
        print(f"错误: {e}")
        return 1
    env = args.env or store.get_current_env()
    secret_str = " [加密]" if args.secret else ""
    print(f"✅ [{env}] {args.key} = {'***' if args.secret else args.value}{secret_str}")
    return 0


def cmd_get(args, store: EnvStore):
    if not store.is_initialized():
        print("错误: 未初始化。请先运行 'envmgr init'")
        return 1
    try:
        value = store.get_variable(args.key, env_name=args.env)
    except ValueError as e:
        print(f"错误: {e}")
        return 1
    if value is None:
        if not args.quiet:
            print(f"变量 '{args.key}' 不存在")
        return 1

    if args.expand:
        try:
            variables = store.get_variables(args.env, decrypt=True)
            variables = store._expand_variables(variables)
            value = variables.get(args.key, {}).get("value", value)
        except Exception:
            pass

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
        removed = store.unset_variable(args.key, env_name=args.env)
    except ValueError as e:
        print(f"错误: {e}")
        return 1
    env = args.env or store.get_current_env()
    if removed:
        print(f"🗑️  [{env}] 已删除 {args.key}")
    else:
        print(f"变量 '{args.key}' 不存在")
    return 0 if removed else 1


def cmd_switch(args, store: EnvStore):
    if not store.is_initialized():
        print("错误: 未初始化。请先运行 'envmgr init'")
        return 1
    try:
        store.switch_env(args.environment)
    except ValueError as e:
        print(f"错误: {e}")
        return 1
    print(f"🔄 已切换到环境: {args.environment}")
    return 0


def cmd_diff(args, store: EnvStore):
    if not store.is_initialized():
        print("错误: 未初始化。请先运行 'envmgr init'")
        return 1

    env_a = args.env_a or store.get_current_env()
    env_b = args.env_b or store.get_default_env()
    if env_a == env_b:
        print("错误: 两个环境相同")
        return 1

    try:
        only_a, only_b, different = store.diff_envs(env_a, env_b)
    except ValueError as e:
        print(f"错误: {e}")
        return 1

    print(f"比较 {env_a} vs {env_b}")
    print("=" * 40)

    if only_a:
        print(f"\n  仅存在于 {env_a}:")
        for k in sorted(only_a.keys()):
            v = only_a[k].get("value", "")
            if only_a[k].get("secret") and is_encrypted(v):
                v = "********"
            elif only_a[k].get("secret"):
                v = mask_value(v, secret=True)
            print(f"    + {k} = {v}")

    if only_b:
        print(f"\n  仅存在于 {env_b}:")
        for k in sorted(only_b.keys()):
            v = only_b[k].get("value", "")
            if only_b[k].get("secret") and is_encrypted(v):
                v = "********"
            elif only_b[k].get("secret"):
                v = mask_value(v, secret=True)
            print(f"    + {k} = {v}")

    if different:
        print(f"\n  值不同:")
        for k in sorted(different.keys()):
            va, vb = different[k]
            print(f"    ~ {k}")
            print(f"        {env_a}: {va}")
            print(f"        {env_b}: {vb}")

    if not only_a and not only_b and not different:
        print("\n  两个环境完全相同")

    return 0


def cmd_exec(args, store: EnvStore):
    if not store.is_initialized():
        print("错误: 未初始化。请先运行 'envmgr init'")
        return 1
    if not args.command:
        print("错误: 请指定要执行的命令")
        return 1

    target_env = args.env or store.get_current_env()
    try:
        variables = store.get_variables(target_env, decrypt=True)
    except ValueError as e:
        print(f"错误: {e}")
        return 1

    if not args.no_expand:
        variables = store._expand_variables(variables)

    env = os.environ.copy()
    for key, var in variables.items():
        env[key] = var.get("value", "")

    if args.override:
        for ov in args.override:
            if "=" in ov:
                k, _, v = ov.partition("=")
                env[k] = v

    missing = store.check_required(target_env)
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
        count = store.import_env_file(
            args.file,
            env_name=args.env,
            secret_keys=args.secret_keys.split(",") if args.secret_keys else None,
        )
    except (FileNotFoundError, ValueError) as e:
        print(f"错误: {e}")
        return 1
    env = args.env or store.get_current_env()
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
            )
        else:
            output = store.export_dotenv(
                env_name=args.env,
                decrypt=not args.encrypted,
                expand=not args.no_expand,
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
    if store.rollback():
        print("⏪ 已回滚到上一个快照")
        return 0
    else:
        print("没有可回滚的快照")
        return 1


def cmd_log(args, store: EnvStore):
    if not store.is_initialized():
        print("错误: 未初始化。请先运行 'envmgr init'")
        return 1
    logs = store.get_audit_log(limit=args.limit)
    if not logs:
        print("暂无操作记录")
        return 0
    for entry in logs:
        ts = entry.get("timestamp", "")[:19]
        action = entry.get("action", "").ljust(10)
        detail = entry.get("detail", "")
        print(f"  {ts}  {action}  {detail}")
    return 0


def cmd_template(args, store: EnvStore):
    if args.generate:
        if not store.is_initialized():
            print("错误: 未初始化。请先运行 'envmgr init'")
            return 1
        output = store.generate_template()
        if args.output:
            Path(args.output).write_text(output, encoding="utf-8")
            print(f"📝 模板已生成: {args.output}")
        else:
            sys.stdout.write(output)
        return 0

    sample = """# 示例 .env 模板
# 复制为 .env 并填入实际值

# 数据库配置
DB_HOST=localhost
DB_PORT=5432
DB_NAME=myapp
DB_USER=admin
DB_PASSWORD=your_password_here

# API 配置
API_BASE_URL=https://api.example.com
API_KEY=your_api_key_here

# 应用配置
APP_NAME=MyApp
APP_ENV=development
DEBUG=true
LOG_LEVEL=info

# 第三方服务
REDIS_URL=redis://localhost:6379/0
S3_BUCKET=my-bucket
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
        removed = store.clean_unused(keep_env=args.keep_env)
    except ValueError as e:
        print(f"错误: {e}")
        return 1
    if removed:
        print(f"🧹 已清理 {len(removed)} 个未使用变量:")
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
            store.set_default_env(args.environment)
        except ValueError as e:
            print(f"错误: {e}")
            return 1
        print(f"✅ 默认环境已设置为: {args.environment}")
        return 0
    else:
        print(f"默认环境: {store.get_default_env()}")
        return 0


def cmd_required(args, store: EnvStore):
    if not store.is_initialized():
        print("错误: 未初始化。请先运行 'envmgr init'")
        return 1
    if args.add:
        store.set_required(args.add, required=True)
        print(f"✅ '{args.add}' 已标记为必填")
        return 0
    elif args.remove:
        store.set_required(args.remove, required=False)
        print(f"✅ '{args.remove}' 已取消必填")
        return 0
    else:
        required = store.get_required_vars()
        if required:
            print("必填变量:")
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
        store.add_env(args.name, copy_from=args.copy_from)
    except ValueError as e:
        print(f"错误: {e}")
        return 1
    print(f"✅ 环境 '{args.name}' 已创建")
    return 0


def cmd_env_remove(args, store: EnvStore):
    if not store.is_initialized():
        print("错误: 未初始化。请先运行 'envmgr init'")
        return 1
    try:
        store.remove_env(args.name)
    except ValueError as e:
        print(f"错误: {e}")
        return 1
    print(f"🗑️  环境 '{args.name}' 已删除")
    return 0


def main():
    parser = argparse.ArgumentParser(
        prog="envmgr",
        description="环境变量管家 - 管理多项目多环境配置",
    )
    subparsers = parser.add_subparsers(dest="command", help="可用命令")

    p_init = subparsers.add_parser("init", help="初始化项目")
    p_init.add_argument("project", help="项目名称")
    p_init.add_argument("-e", "--environments", nargs="+", help="环境名称列表")
    p_init.add_argument("-f", "--force", action="store_true", help="强制覆盖现有配置")
    p_init.set_defaults(func=cmd_init)

    p_list = subparsers.add_parser("list", help="列出变量或环境")
    p_list.add_argument("-e", "--env", help="指定环境")
    p_list.add_argument("-d", "--decrypt", action="store_true", help="显示解密后的值")
    p_list.add_argument("-c", "--check", action="store_true", help="检查必填项")
    p_list.add_argument("--environments", action="store_true", help="列出所有环境")
    p_list.set_defaults(func=cmd_list)

    p_set = subparsers.add_parser("set", help="设置变量")
    p_set.add_argument("key", help="变量名")
    p_set.add_argument("value", help="变量值")
    p_set.add_argument("-e", "--env", help="指定环境")
    p_set.add_argument("-s", "--secret", action="store_true", help="标记为敏感值（加密存储）")
    p_set.add_argument("-r", "--required", action="store_true", help="标记为必填")
    p_set.set_defaults(func=cmd_set)

    p_get = subparsers.add_parser("get", help="获取变量值")
    p_get.add_argument("key", help="变量名")
    p_get.add_argument("-e", "--env", help="指定环境")
    p_get.add_argument("-r", "--raw", action="store_true", help="原始输出（无换行）")
    p_get.add_argument("-q", "--quiet", action="store_true", help="安静模式")
    p_get.add_argument("-x", "--expand", action="store_true", help="展开变量引用")
    p_get.set_defaults(func=cmd_get)

    p_unset = subparsers.add_parser("unset", help="删除变量")
    p_unset.add_argument("key", help="变量名")
    p_unset.add_argument("-e", "--env", help="指定环境")
    p_unset.set_defaults(func=cmd_unset)

    p_switch = subparsers.add_parser("switch", help="切换当前环境")
    p_switch.add_argument("environment", help="环境名称")
    p_switch.set_defaults(func=cmd_switch)

    p_diff = subparsers.add_parser("diff", help="比较两个环境")
    p_diff.add_argument("env_a", nargs="?", help="环境A")
    p_diff.add_argument("env_b", nargs="?", help="环境B")
    p_diff.set_defaults(func=cmd_diff)

    p_exec = subparsers.add_parser("exec", help="带环境执行命令")
    p_exec.add_argument("-e", "--env", help="指定环境")
    p_exec.add_argument("-o", "--override", action="append", help="临时覆盖变量 KEY=VALUE")
    p_exec.add_argument("-f", "--force", action="store_true", help="忽略必填项检查")
    p_exec.add_argument("--no-expand", action="store_true", help="不展开变量引用")
    p_exec.add_argument("command", nargs=argparse.REMAINDER, help="要执行的命令")
    p_exec.set_defaults(func=cmd_exec)

    p_import = subparsers.add_parser("import", help="从 .env 文件导入")
    p_import.add_argument("file", help=".env 文件路径")
    p_import.add_argument("-e", "--env", help="目标环境")
    p_import.add_argument("-s", "--secret-keys", help="指定为敏感的键名（逗号分隔）")
    p_import.set_defaults(func=cmd_import)

    p_export = subparsers.add_parser("export", help="导出环境变量")
    p_export.add_argument("-e", "--env", help="指定环境")
    p_export.add_argument("-f", "--format", choices=["shell", "dotenv"], default="shell",
                          help="输出格式 (默认: shell)")
    p_export.add_argument("-o", "--output", help="输出文件")
    p_export.add_argument("--encrypted", action="store_true", help="保留加密值")
    p_export.add_argument("--no-expand", action="store_true", help="不展开变量引用")
    p_export.set_defaults(func=cmd_export)

    p_rollback = subparsers.add_parser("rollback", help="回滚上次变更")
    p_rollback.set_defaults(func=cmd_rollback)

    p_log = subparsers.add_parser("log", help="查看操作日志")
    p_log.add_argument("-n", "--limit", type=int, default=20, help="显示条数")
    p_log.set_defaults(func=cmd_log)

    p_template = subparsers.add_parser("template", help="生成配置模板")
    p_template.add_argument("-g", "--generate", action="store_true", help="基于当前项目生成")
    p_template.add_argument("-o", "--output", help="输出文件")
    p_template.set_defaults(func=cmd_template)

    p_clean = subparsers.add_parser("clean", help="清理未使用变量")
    p_clean.add_argument("--keep-env", help="以此环境为基准保留变量")
    p_clean.set_defaults(func=cmd_clean)

    p_default = subparsers.add_parser("default", help="查看或设置默认环境")
    p_default.add_argument("environment", nargs="?", help="环境名称")
    p_default.set_defaults(func=cmd_default)

    p_required = subparsers.add_parser("required", help="管理必填变量")
    p_required.add_argument("--add", help="添加为必填")
    p_required.add_argument("--remove", help="取消必填")
    p_required.set_defaults(func=cmd_required)

    p_env_add = subparsers.add_parser("env-add", help="添加新环境")
    p_env_add.add_argument("name", help="环境名称")
    p_env_add.add_argument("--copy-from", help="从现有环境复制")
    p_env_add.set_defaults(func=cmd_env_add)

    p_env_remove = subparsers.add_parser("env-remove", help="删除环境")
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
