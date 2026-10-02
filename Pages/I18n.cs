namespace NasAuth.Pages;

/// <summary>
/// 极简 i18n：英文原文当 key，zh 字典查不到就原样返回英文（fallback 安全）。
/// 语言按请求协商（?lang= > cookie > Accept-Language），存 AsyncLocal —— SSR 模板全是
/// static 方法，不想把 lang 参数穿透每一层调用。中间件见 Program.cs。
/// </summary>
public static class I18n
{
    public const string CookieName = "nas_auth_lang";

    private static readonly AsyncLocal<string?> _lang = new();

    /// <summary>"en" / "zh"。</summary>
    public static string Lang
    {
        get => _lang.Value ?? "en";
        set => _lang.Value = value == "zh" ? "zh" : "en";
    }

    public static bool IsZh => Lang == "zh";

    /// <summary>翻译：zh 模式查字典，缺译/EN 模式原样返回。</summary>
    public static string T(string en) => IsZh && Zh.TryGetValue(en, out var v) ? v : en;

    /// <summary>带参翻译（{0} 占位）。</summary>
    public static string T(string en, params object[] args) => string.Format(T(en), args);

    private static readonly Dictionary<string, string> Zh = new(StringComparer.Ordinal)
    {
        // ---- 通用 ----
        ["Sign in"] = "登录",
        ["Username"] = "用户名",
        ["Password"] = "密码",
        ["Authorize"] = "授权",
        ["Back to sign-in"] = "返回登录页",
        ["Back to sign-in (password)"] = "返回登录页（可用密码登录）",
        ["Use a different account"] = "换个账号",
        ["Choose another Google account"] = "选择其他 Google 账号",
        ["Choose another Microsoft account"] = "选择其他微软账号",
        ["Back to /account"] = "返回 /account",

        // ---- 系统：密码登录运行时开关 ----
        ["Password login"] = "密码登录",
        ["Enabled"] = "已启用",
        ["Disabled"] = "已停用",
        ["No external sign-in provider is configured, so password login is forced on (lockout protection)."] =
            "未配置任何外部登录 provider，密码登录被强制开启（防锁死保护）。",
        ["Following the container config (<code>Auth__PasswordLogin__Enabled</code> = {0})."] =
            "当前跟随容器配置（<code>Auth__PasswordLogin__Enabled</code> = {0}）。",
        ["Runtime override active; the container config (<code>Auth__PasswordLogin__Enabled</code> = {0}) is being ignored."] =
            "运行时覆盖已生效；容器配置（<code>Auth__PasswordLogin__Enabled</code> = {0}）被忽略。",
        ["Takes effect immediately, no restart. Typical use: keep password login off in config, enable it here temporarily, then restore. Password hashes stay in the database as a break-glass fallback."] =
            "立即生效，无需重启。典型用法：配置里常关密码登录，需要时在这里临时开启，用完恢复。密码 hash 留库作 break-glass 兜底。",
        ["Disable password login"] = "停用密码登录",
        ["Enable password login temporarily"] = "临时开启密码登录",
        ["Restore: follow config"] = "恢复跟随配置",
        ["Password login enabled (runtime override)"] = "密码登录已开启（运行时覆盖）",
        ["Password login disabled (runtime override)"] = "密码登录已停用（运行时覆盖）",
        ["Runtime override cleared; following the container config again"] = "已清除运行时覆盖，恢复跟随容器配置",
        ["Unknown action"] = "未知操作",

        // ---- 登录 / consent ----
        ["Sign in to nas-auth"] = "登录 nas-auth",
        ["Continue with Google"] = "通过 Google 继续",
        ["Continue with Microsoft"] = "通过 Microsoft 继续",
        ["Sign in with password"] = "使用密码登录",
        ["Signed out"] = "已退出登录",
        ["Username or password is incorrect"] = "用户名或密码不正确",
        ["Password sign-in is disabled"] = "密码登录已停用",
        ["<strong>{0}</strong> wants to access your <strong>{1}</strong>"] =
            "<strong>{0}</strong> 请求访问你的 <strong>{1}</strong>",
        ["Review the permissions below and sign in to authorize."] = "请确认以下权限并登录以完成授权。",
        ["Authorize as {0}"] = "以 {0} 身份授权",
        // 2026-09-29 consent 防钓鱼：显示回调去向 + DCR 自报名字未核实
        ["After you authorize, you will be sent to <strong>{0}</strong>."] = "授权后将跳转到 <strong>{0}</strong>。",
        ["After you authorize, you will be sent back to an app running on this computer (<strong>{0}</strong>)."] =
            "授权后将跳回这台电脑上运行的应用（<strong>{0}</strong>）。",
        ["After you authorize, you will be handed to the app that opens <strong>{0}</strong> links."] =
            "授权后将交给打开 <strong>{0}</strong> 链接的应用。",
        ["Unverified app"] = "未核实的应用",
        ["The name <strong>{0}</strong> was supplied by the app itself and has not been verified. Only continue if you just started connecting this app yourself."] =
            "名字「<strong>{0}</strong>」是这个应用自己报的，nas-auth 无法核实。只有在你本人刚刚发起连接这个应用时才继续。",
        ["Your session has expired. Please sign in again."] = "会话已过期，请重新登录。",
        ["Your account is not authorized for this resource (or the requested scopes exceed your grant). Ask an administrator to grant it under Users → Resources."] =
            "你的账号未被授权使用该资源（或请求的 scope 超出授予范围）。请联系管理员在「用户管理 → 资源授权」里授予。",
        ["This account must change its password first. Please go to /login, change your password, then return to this page to authorize."] =
            "该账号需要先修改密码。请先到 /login 登录并完成改密，再回到本页授权。",

        // ---- 外部登录结果页 ----
        ["Your account"] = "你的账号",
        ["Waiting for approval"] = "等待管理员批准",
        ["{0} ({1}) has been registered and is awaiting administrator approval."] =
            "{0}（{1}）已登记，正在等待管理员批准。",
        ["You will be able to sign in once an administrator approves this account. Nothing else is required from you right now."] =
            "管理员批准后即可登录。现在不需要你做任何其他操作。",
        ["Account bound"] = "账号绑定成功",
        ["External account <code>{0}</code> is now bound to user <code>{1}</code>."] =
            "外部账号 <code>{0}</code> 已绑定到用户 <code>{1}</code>。",
        ["You can sign in with this external account from now on. If this is not the user you expected, unbind it immediately."] =
            "之后可以直接用这个外部账号登录。如果绑定的用户不是你预期的，请立即解绑。",
        ["External sign-in failed"] = "外部登录失败",
        ["Access denied"] = "拒绝访问",
        ["This external account is not allowed to sign in."] = "该外部账号不允许登录。",
        ["No external sign-in result found. Please start over from the sign-in page."] =
            "未找到外部登录结果，请从登录页重新发起。",
        ["Unknown provider."] = "未知的身份提供方。",
        ["The identity provider did not return a stable subject."] = "身份提供方未返回稳定的 subject 标识。",
        ["The identity provider returned an error or the sign-in was cancelled. Please try again from the sign-in page."] =
            "身份提供方返回错误或登录被取消。请从登录页重试。",
        ["Binding failed"] = "绑定失败",
        ["Your session changed during the binding flow. Please sign in and try again."] =
            "绑定过程中会话发生了变化。请重新登录后再试。",

        // ---- 强制改密 ----
        ["Please change your password"] = "请修改密码",
        ["Account <code>{0}</code> is currently using a temporary password. Please set a new one to continue."] =
            "账号 <code>{0}</code> 正在使用临时密码，请设置新密码后继续。",
        ["New password must be at least 8 characters"] = "新密码至少 8 个字符",
        ["Passwords do not match"] = "两次输入的密码不一致",
        ["New password must differ from the temporary password"] = "新密码不能与临时密码相同",
        ["New password"] = "新密码",
        ["Confirm"] = "确认密码",
        ["Set password"] = "设置密码",
        ["Password updated"] = "密码已更新",
        ["Password change not required"] = "当前不需要修改密码",

        // ---- Dashboard 菜单 / 标题 ----
        ["Users"] = "用户管理",
        ["Approvals"] = "待批申请",
        ["Clients"] = "客户端",
        ["System"] = "系统",

        // ---- 我的授权 ----
        ["Authorized applications"] = "已授权应用",
        ["OAuth grants issued for your account. Revoking deletes the refresh tokens; issued access tokens remain valid until they expire."] =
            "你的账号签发过的 OAuth 授权。吊销会删除 refresh token；已签发的 access token 在到期前仍然有效。",
        ["No authorized applications yet. When an MCP client (such as Claude) completes an OAuth flow, grants appear here."] =
            "还没有已授权的应用。MCP 客户端（如 Claude）完成 OAuth 流程后会出现在这里。",
        ["Application"] = "应用",
        ["Resource"] = "资源",
        ["Scopes"] = "权限",
        ["Last active"] = "最近活跃",
        ["Revoke"] = "吊销",
        ["Missing parameters"] = "缺少参数",
        ["Revoked {0} refresh token(s)"] = "已吊销 {0} 个 refresh token",

        // ---- 账号绑定 ----
        ["External identities"] = "外部身份",
        ["External accounts bound to this user can sign in directly. Binding requires an active session and writes the identity as active immediately (no approval round-trip)."] =
            "绑定到本用户的外部账号可以直接登录。绑定要求当前已有活跃会话，绑定即生效（不走审批）。",
        ["No external identities bound yet."] = "还没有绑定外部账号。",
        ["Provider"] = "提供方",
        ["Account"] = "账号",
        ["Status"] = "状态",
        ["Bound"] = "绑定时间",
        ["Unbind"] = "解绑",
        ["Bind Google account"] = "绑定 Google 账号",
        ["Bind Microsoft account"] = "绑定 Microsoft 账号",
        ["Binding not found"] = "未找到该绑定",
        ["Unbound {0} account"] = "已解绑 {0} 账号",
        ["Change password"] = "修改密码",
        ["Current password"] = "当前密码",
        ["Update password"] = "更新密码",
        ["Current password is incorrect"] = "当前密码不正确",

        // ---- 用户管理 ----
        ["Create user"] = "新建用户",
        ["Share the temporary password with the user; they must change it on first sign-in."] =
            "把临时密码交给该用户；首次登录会强制改密。",
        ["letters, digits, . _ -"] = "字母、数字、. _ -",
        ["Temporary password"] = "临时密码",
        ["≥ 8 chars"] = "≥ 8 个字符",
        ["Create"] = "创建",
        ["Role"] = "角色",
        ["Created"] = "创建时间",
        ["admin"] = "管理员",
        ["user"] = "用户",
        ["you"] = "本人",
        ["must change password"] = "需改密",
        ["active"] = "正常",
        ["Reset"] = "重置",
        ["Delete"] = "删除",
        ["new temporary password"] = "新临时密码",
        ["Username is required"] = "用户名必填",
        ["Username may only contain letters, digits, . _ -, length 1-32"] =
            "用户名只能包含字母、数字、. _ -，长度 1-32",
        ["Temporary password must be at least 8 characters"] = "临时密码至少 8 个字符",
        // ---- §十四 统一账号中心：邮箱 / 按用户的密码登录 / 锁定 ----
        ["Email"] = "邮箱",
        ["email"] = "邮箱",
        ["password"] = "密码",
        ["Save"] = "保存",
        ["Saved {0}"] = "已保存 {0}",
        ["Invalid email address"] = "邮箱格式不对",
        ["Allow password sign-in"] = "允许密码登录",
        ["This is the master switch. With it on, only users whose \"Allow password sign-in\" is checked (Users page) can sign in with a password."] =
            "这里是总闸。打开后，也只有在「用户管理」里勾了「允许密码登录」的用户能用密码登录。",
        ["Password sign-in"] = "密码登录",
        ["sent to apps as the email claim"] = "作为 email 发给各应用",
        ["locked until {0}"] = "锁定至 {0}",
        ["Too many failed attempts. This account is temporarily locked; try again in {0} minutes."] =
            "失败次数过多，账号已临时锁定，请 {0} 分钟后再试。",
        ["Email is what apps (e.g. Immich) use to match this person to their own account — set it to the email of their account in that app. Accounts that sign in with Google / Microsoft should usually have password sign-in turned off."] =
            "邮箱用于让各应用（如 Immich）把这个人对应到应用里的账号 —— 填他在那个应用里的账号邮箱。用 Google / 微软登录的账号一般应关闭密码登录。",
        ["Username {0} already exists"] = "用户名 {0} 已存在",
        ["Created user {0}; must change password on first sign-in"] =
            "已创建用户 {0}；首次登录需修改密码",
        ["Cannot delete yourself"] = "不能删除自己",
        ["User does not exist"] = "用户不存在",
        ["Cannot delete an admin"] = "不能删除管理员",
        ["Deleted user {0}"] = "已删除用户 {0}",
        ["Delete user {0}? All of their refresh tokens will be revoked."] =
            "删除用户 {0}？其全部 refresh token 都会被吊销。",
        ["Reset password for {0}; they must change it on next sign-in"] =
            "已重置 {0} 的密码；下次登录需修改",

        // ---- 资源授权编辑 ----
        ["Per-resource maximum scopes for this user. Unchecking every scope of a resource removes the grant entirely; /authorize and token refresh then deny that resource for this user. Resources marked \"admins only\" use the administrator's own credentials upstream and can only be granted to admins."] =
            "该用户在每个资源上的最大 scope。某个资源全部不勾 = 整体撤销授权；之后 /authorize 与 token 刷新都会拒绝该用户访问此资源。标「仅管理员」的资源在上游用的是管理员自己的凭据，只能授给管理员。",
        ["Save grants"] = "保存授权",
        ["Back to users"] = "返回用户列表",
        ["Grants saved"] = "授权已保存",
        ["Nickname"] = "昵称",
        ["Avatar"] = "头像",
        ["Upload"] = "上传",
        ["Upload avatar"] = "上传头像",
        ["Nickname & avatar"] = "昵称与头像",
        ["Use a linked account"] = "用已绑定账号的",
        ["Use this avatar"] = "用这个头像",
        ["Use this name"] = "用这个名字",
        ["Profile saved"] = "资料已保存",
        ["Avatar updated"] = "头像已更新",
        ["Avatar removed"] = "头像已去掉",
        ["Choose an image file"] = "请选择一张图片",
        ["Image is larger than 2 MB"] = "图片超过 2 MB",
        ["Only PNG, JPEG or WebP images are accepted"] = "只支持 PNG、JPEG、WebP 图片",
        ["Nothing to copy from that account yet; sign in with it once first"] = "那个账号还没有可用的头像 / 名字，先用它登录一次",
        ["Your nickname and avatar are what apps (Gitea, Immich, Open WebUI…) show. Your username can't be changed: apps use it to recognise you. Grafana and Open WebUI pick up changes the next time you sign in to them; Gitea updates the avatar on next sign-in; Immich and ezBookkeeping only take them when the account is first created."] = "昵称和头像就是各应用（Gitea、Immich、Open WebUI…）里显示的。用户名不能改：各应用靠它认你。改了之后，Grafana、Open WebUI 下次登录时更新；Gitea 下次登录时更新头像；Immich、ezBookkeeping 只在首次建号时取一次。",
        ["≥ 8 chars; only when password sign-in is allowed"] = "≥ 8 位；仅允许密码登录时需要",
        ["Pre-bind sign-in email"] = "预绑定登录邮箱",
        ["optional; first Google / Outlook sign-in with it binds here"] = "可选；首次用它登录 Google / 微软即绑定到此用户",
        ["Pre-bound emails"] = "预绑定邮箱",
        ["Added"] = "添加时间",
        ["Remove"] = "移除",
        ["Add pre-bound email"] = "添加预绑定邮箱",
        ["Pre-bound email: the first time someone signs in with this email, that account is bound to this user directly without going through approvals. Used once, then removed. Requires the provider to vouch for the email: Google must report it as verified; for a personal Microsoft account it must be the sign-in name. Otherwise it still goes to approvals."] = "预绑定邮箱：第一次有人用这个邮箱登录时，直接绑到本用户，不进待批；用一次即删。前提是登录服务商能证明他拥有这个邮箱：Google 要标记为已验证；微软个人账号要求它就是登录名。否则仍进待批。",
        ["User id {0} belonged to a deleted user and can't be reused: apps still map it to that person's accounts"] = "用户 id {0} 属于已删除的用户，不能复用：各应用仍按它对应那个人的账号",
        ["Created user {0}, but {1} is already pre-bound to another user"] = "已建用户 {0}，但 {1} 已预绑定给别的用户",
        ["Created user {0} (external sign-in only)"] = "已建用户 {0}（仅外部登录）",
        ["{0} is already pre-bound"] = "{0} 已被预绑定",
        ["Pre-bound {0}"] = "已预绑定 {0}",
        ["Pre-bound email not found"] = "找不到这条预绑定邮箱",
        ["Removed pre-bound {0}"] = "已移除预绑定 {0}",

        // ---- 2026-09-29 Basecoat 改版：用户编辑页 / 侧边栏 / 登录页 ----
        ["User · {0}"] = "用户 · {0}",
        ["Profile"] = "基本信息",
        ["Resource grants"] = "资源授权",
        ["admins only"] = "仅管理员",
        ["Reset password"] = "重置密码",
        ["Delete user"] = "删除用户",
        ["Revokes all of their refresh tokens and removes their external identities and resource grants. Cannot be undone."] =
            "吊销其全部 refresh token，并删除其外部身份绑定与资源授权。不可撤销。",
        ["Allowed"] = "允许",
        ["Off"] = "关闭",
        ["Administration"] = "管理",
        ["Sign out"] = "退出登录",
        ["Menu"] = "菜单",
        ["One account for all your NAS apps"] = "一个账号，登录 NAS 上的所有应用",
        ["or use another account"] = "或换个账号",

        // ---- 2026-09-29 个人中心 / 管理后台拆分、会话、审计（§十六）----
        ["Personal"] = "个人中心",
        ["Admin"] = "管理后台",
        ["Overview"] = "概览",
        ["Admin overview"] = "管理概览",
        ["Authorized apps"] = "已授权应用",
        ["Sign-in & security"] = "登录与安全",
        ["Apps & resources"] = "应用与资源",
        ["Audit log"] = "审计日志",
        ["My account"] = "我的账号",
        ["Sign-in methods"] = "登录方式",
        ["Latest sign-in"] = "最近一次登录",
        ["Revoke own grant"] = "吊销自己的授权",
        ["Unbind own external account"] = "解绑自己的外部账号",
        ["Change own password"] = "修改自己的密码",
        ["Set password after reset"] = "重置后设置密码",
        ["Sign out other devices"] = "退出其他设备",
        ["Edit user"] = "编辑用户",
        ["Reset user password"] = "重置用户密码",
        ["Edit resource grants"] = "编辑资源授权",
        ["Revoke user's grant"] = "吊销用户的授权",
        ["Revoke all user's grants"] = "吊销用户全部授权",
        ["Unbind user's external account"] = "解绑用户的外部账号",
        ["Force sign-out"] = "强制下线",
        ["Approve request"] = "批准申请",
        ["Reject request"] = "拒绝申请",
        ["Delete client"] = "删除客户端",
        ["Password login switch"] = "密码登录开关",
        ["Rotate JWT key"] = "轮换 JWT 密钥",
        ["Member since"] = "注册时间",
        ["Apps I can use"] = "我能用的应用",
        ["App"] = "应用",
        ["What the administrator has opened for your account. Whether an app is actually connected is under Authorized apps."] =
            "管理员给你的账号开通的应用。是否真的连上了，看「已授权应用」。",
        ["No apps have been opened for you yet. Ask the administrator."] = "还没有给你开通任何应用，找管理员。",
        ["Changing the password also signs you out on all other devices."] = "改密码会同时退出你在其他设备上的登录。",
        ["Password updated; other devices have been signed out"] = "密码已更新；其他设备上的登录已退出",
        ["Sessions"] = "登录会话",
        ["A nas-auth sign-in lasts 30 days and renews while in use. If you signed in on someone else's computer, sign out everywhere else here; this browser stays signed in. Apps you authorized keep working — revoke them under Authorized apps."] =
            "nas-auth 登录有效 30 天、用着会自动续期。在别人电脑上登过又忘了退出，就在这里退出其他所有设备，当前这个浏览器不受影响。已授权给应用的访问不受影响，要断开去「已授权应用」吊销。",
        ["Sign out of all other devices"] = "退出其他所有设备",
        ["Sign out of all other devices?"] = "确定退出其他所有设备上的登录？",
        ["Signed out of all other devices"] = "已退出其他所有设备",
        ["Recent sign-ins"] = "最近登录",
        ["Includes failed attempts. Kept for 90 days."] = "包含失败的尝试。保留 90 天。",
        ["No sign-in records yet."] = "还没有登录记录。",
        ["Time"] = "时间",
        ["Method"] = "方式",
        ["Result"] = "结果",
        ["Note"] = "备注",
        ["Success"] = "成功",
        ["Failed"] = "失败",
        ["Accounts"] = "用户",
        ["{0} admin(s)"] = "其中管理员 {0}",
        ["Needs review"] = "待处理",
        ["All clear"] = "无待办",
        ["Active grants"] = "活跃授权",
        ["user × app × resource"] = "按 用户 × 应用 × 资源 计",
        ["{0} preset · {1} DCR"] = "预置 {0} · 自助注册 {1}",
        ["Sign-ins (24h)"] = "24 小时登录",
        ["{0} failed"] = "失败 {0} 次",
        ["No failures"] = "无失败",
        ["Recent events"] = "最近事件",
        ["View all"] = "查看全部",
        ["Manage"] = "管理",
        ["Revoking deletes the refresh tokens; issued access tokens remain valid until they expire."] =
            "吊销会删除 refresh token；已签发的 access token 在过期前仍然有效。",
        ["Revoke all"] = "全部吊销",
        ["Revoke all grants of {0}?"] = "确定吊销 {0} 的全部授权？",
        ["Unbind this external account?"] = "确定解绑这个外部账号？",
        ["Sign-ins & sessions"] = "登录与会话",
        ["Signing out ends every nas-auth browser session of this user. Apps they already authorized keep working until revoked above."] =
            "强制下线会结束该用户在所有浏览器里的 nas-auth 登录。已授权给应用的访问不受影响，要断开在上面吊销。",
        ["Sign out on all devices"] = "强制下线（所有设备）",
        ["Sign {0} out on all devices?"] = "确定让 {0} 在所有设备上下线？",
        ["{0} has been signed out on all devices"] = "{0} 已在所有设备上下线",
        ["To sign yourself out elsewhere, use Sign-in & security"] = "要退出自己在其他设备上的登录，请用「登录与安全」页",
        ["Use \"Change password\" under Sign-in & security for your own password"] = "修改自己的密码请用「登录与安全」页",
        ["Set a temporary password; they must change it on next sign-in. Their current sessions end immediately."] =
            "设一个临时密码，对方下次登录时必须修改；对方当前的登录立即失效。",
        ["Resource catalog"] = "资源",
        ["From resources.json (read-only; edit the file and restart to change). Users = accounts granted this resource under Users → Resource grants."] =
            "来自 resources.json（只读，改文件后重启生效）。开通用户数 = 在「用户 → 资源授权」里开了这个资源的账号数。",
        ["Granted users"] = "开通用户数",
        ["Mode"] = "接入方式",
        ["Proxy (token translation)"] = "代理（令牌翻译）",
        ["Direct JWT"] = "直接验 JWT",
        ["No resources."] = "没有资源。",
        ["Preset clients come from clients.preset.json; DCR ones registered themselves (e.g. Claude, Grok). DCR clients unused for 30 days with no live grants are cleaned up automatically; delete one here to cut it off now."] =
            "预置客户端来自 clients.preset.json；自助注册（DCR）的是应用自己注册的（如 Claude、Grok）。自助注册的客户端 30 天没用且没有有效授权会被自动清理；要立刻切断就在这里删。",
        ["created {0}"] = "创建于 {0}",
        ["Delete client {0}? Its grants are revoked; the app must register again."] = "确定删除客户端 {0}？它的授权会被吊销，应用需要重新注册。",
        ["Deleted client {0} and its grants"] = "已删除客户端 {0} 及其授权",
        ["Only dynamically registered (DCR) clients can be deleted"] = "只能删除自助注册（DCR）的客户端",
        ["Event"] = "事件",
        ["Events"] = "事件",
        ["User"] = "用户",
        ["Detail"] = "详情",
        ["No events."] = "没有事件。",
        ["All"] = "全部",
        ["Sign-ins"] = "登录",
        ["Authorization"] = "授权",
        ["Tokens"] = "令牌",
        ["Token"] = "令牌",
        ["Token revocation"] = "令牌吊销",
        ["Account actions"] = "账号 / 管理操作",
        ["Account action"] = "账号操作",
        ["Client registration"] = "客户端注册",
        ["Proxy denied"] = "代理拒绝",
        ["Password sign-in"] = "密码登录",
        ["External sign-in"] = "外部登录",
        ["Failures only"] = "只看失败",
        ["Filter"] = "筛选",
        ["Kept for 90 days; shows the latest 300 matches. High-volume proxy forwarding is only in the container log."] =
            "保留 90 天，显示最近 300 条。高频的代理转发只在容器日志里。",

        // ---- 待批申请 ----
        ["Pending requests"] = "待批申请",
        ["External sign-in attempts waiting for approval. Approve binds the identity to an existing user, or creates a new user (external sign-in only, no usable password). Checked resources are granted with their full scopes; fine-tune later under Users → Resources."] =
            "等待批准的外部登录申请。批准 = 绑定到现有用户，或新建用户（仅外部登录，无可用密码）。勾选的资源按全量 scope 授予，之后可在「用户管理 → 资源授权」细调。",
        ["Nothing pending."] = "没有待批申请。",
        ["requested {0}"] = "申请于 {0}",
        ["Bind to existing user"] = "绑定到现有用户",
        ["— select —"] = "— 选择 —",
        ["… or create new user id"] = "…或新建用户 id",
        ["leave empty to bind existing"] = "留空表示绑定现有用户",
        ["Approve"] = "批准",
        ["Reject"] = "拒绝",
        ["Rejected"] = "已拒绝",
        ["Kept on record so repeated sign-in attempts stay rejected instead of re-appearing as pending."] =
            "记录保留：重复登录尝试会继续被拒绝，而不是再次出现在待批列表。",
        ["None."] = "无。",
        ["Requested"] = "申请时间",
        ["Select an existing user or enter a new user id"] = "请选择现有用户或填写新用户 id",
        ["Approved: {0} identity bound to {1}"] = "已批准：{0} 身份绑定到 {1}",
        ["Rejected; the record is kept so repeat attempts stay blocked"] =
            "已拒绝；记录保留，重复申请会继续被拦",
        ["User id may only contain letters, digits, . _ -, length 1-32"] =
            "用户 id 只能包含字母、数字、. _ -，长度 1-32",
        ["Request is no longer pending"] = "该申请已不在待批状态",

        // ---- 客户端 ----
        ["OAuth clients"] = "OAuth 客户端",
        ["No clients."] = "没有客户端。",
        ["Client"] = "客户端",
        ["Type"] = "类型",
        ["Auth method"] = "认证方式",
        ["Redirect URIs"] = "回调地址",
        ["Last used"] = "最近使用",
        ["preset"] = "预置",

        // ---- 系统 ----
        ["JWT signing key rotation"] = "JWT 签名密钥轮换",
        ["Generates a new random key and stages the current key as Previous. After generating, manually update <code>Jwt__SigningKey__Current</code> / <code>Jwt__SigningKey__Previous</code> in the deployment environment (e.g. <code>.env</code>) and restart nas-auth and every resource server that shares the key."] =
            "生成一把新随机密钥，并把当前密钥转入 Previous。生成后需手动更新部署环境（如 <code>.env</code>）里的 <code>Jwt__SigningKey__Current</code> / <code>Jwt__SigningKey__Previous</code>，并重启 nas-auth 与所有共享该密钥的资源服务器。",
        ["Generate new key"] = "生成新密钥",
        ["Access token signing key (RS256)"] = "Access token 签名密钥（RS256）",
        ["Access tokens and id_tokens are signed with the RSA key in <code>oidc_rs256_current.pem</code> (next to auth.db); resource servers verify them via <code>/.well-known/jwks.json</code>."] =
            "access token 与 id_token 都用 <code>oidc_rs256_current.pem</code>（auth.db 同目录）里的 RSA 私钥签，资源服务器通过 <code>/.well-known/jwks.json</code> 取公钥验签。",
        ["To rotate: rename <code>oidc_rs256_current.pem</code> to <code>oidc_rs256_previous.pem</code> (replacing the old one), then restart nas-auth; a new current key is generated on startup. The previous key stays in JWKS, so outstanding tokens keep validating until they expire."] =
            "轮换：把 <code>oidc_rs256_current.pem</code> 改名为 <code>oidc_rs256_previous.pem</code>（覆盖旧的），重启 nas-auth，启动时自动生成新的 current。previous 仍留在 JWKS 里，在途 token 到期前照常能验。",
        ["Keep the previous key for at least the access-token lifetime ({0} days) before deleting it or rotating again, otherwise outstanding access tokens stop validating."] =
            "previous 至少保留一个 access token 寿命（{0} 天）再删或再次轮换，否则在途的 access token 会全部验签失败。",
        ["Legacy HS256 keys (<code>Jwt__SigningKey__*</code>) are still configured and only used to validate tokens issued before the switch to RS256, and only tokens expiring by <code>Jwt__LegacyHs256NotAfter</code> = {0}. After that they are all rejected; remove the keys."] =
            "仍配置着遗留 HS256 密钥（<code>Jwt__SigningKey__*</code>），只用来验切到 RS256 之前签出的 token，且只收 exp 不晚于 <code>Jwt__LegacyHs256NotAfter</code> = {0} 的；过了这个时间一律拒绝，届时移除密钥。",
        ["Access tokens are signed with RS256; no HS256 key was generated. To rotate the RSA key, follow the steps on this page."] =
            "access token 已改用 RS256 签名，未生成 HS256 密钥。轮换 RSA 密钥请按本页步骤操作。",
        ["Audit log"] = "审计日志",
        ["New key generated and stored in the SQLite settings table at jwt.signing_key.pending_current. Steps: 1) extract it with sqlite3 → set it as Jwt__SigningKey__Current in the deployment environment (e.g. .env); 2) move the previous Current to Jwt__SigningKey__Previous; 3) restart nas-auth and every resource server that shares the key."] =
            "新密钥已生成并存入 SQLite settings 表（jwt.signing_key.pending_current）。步骤：1）用 sqlite3 取出 → 写入部署环境（如 .env）的 Jwt__SigningKey__Current；2）原 Current 挪到 Jwt__SigningKey__Previous；3）重启 nas-auth 与所有共享该密钥的资源服务器。",
    };
}
