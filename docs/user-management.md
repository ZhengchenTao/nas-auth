# User management

Administrators use `/admin/users` to find and manage local accounts. External directory lookup in the creation form searches the upstream directory; the list search searches accounts already stored in Auth.

## Find an existing account

- Search by part of a display name, username, stable user ID or email. Whitespace is trimmed, ASCII letters are case-insensitive, and non-Latin text matches literal substrings. This does not add phonetic, spelling-correction or directory-wide search.
- Select active, disabled or deleted identities. The state tabs show totals across the deployment; the result footer shows the count matching the current filters.
- Active accounts can be filtered by administrator or regular-user role. These are Auth administration roles, not downstream application roles. Disabled accounts have their administrator role removed.
- Choose 25, 50 or 100 rows per page. Filtering starts at page one; pagination preserves filters. Out-of-range pages clamp to the last available page. Accounts with equal creation timestamps have a stable ID tie-breaker.
- Disabled accounts retain searchable profile details. Deleted identities retain only their reserved account ID, so their search is by ID. Restored identities appear once in their current state.

Search text is bounded to 128 characters and treated as literal data, including `%`, `_` and quotes. Queries, counts and page rows are read from one SQLite snapshot. This bounds response size; substring searches still scan the matching account data and are intended for small deployments.

## Onboarding and recovery

For an external identity, search a configured directory or create a verified-email binding, then select application access when available. A password account has a separate creation form. Never give an old reserved username to a different person: use the original-identity restoration flow only for the same person.

Auth application access controls admission. Configured [account provisioning](account-provisioning.md) can precreate an application account; roles, teams and data permissions remain managed in that application. A grant and successful account synchronization are distinct states.

Disabling revokes Auth sign-in credentials. Restoring an identity does not restore the old administrator role or grants. Application-owned sessions and local holds follow the integration's documented behavior; see [operations](operations.md) and [the provisioning contract](account-provisioning.md).

## User groups

Open **User groups** in the admin sidebar to create a group. Find existing active accounts by name, username or email and add them as members. On the group page, select applications, preview the changes, then save. The preview shows affected members and any account provisioning changes.

A user can join multiple groups. Effective access combines direct grants and grants from every group. Removing one source preserves access granted by another. Open a user's **Grant sources** section to see where each grant came from. Administrator-only resources are excluded from group assignment.

Adding or removing a member applies the group's current grants immediately in Auth. Configured provisioning tracks the resulting access changes asynchronously. Disabling an account removes its memberships. A group can be deleted after its members have been removed.

## 用户管理

`/admin/users` 的列表搜索用于查找已进入 Auth 的账号；创建表单中的人员目录搜索用于查找外部目录，两者范围不同。

支持按部分姓名、用户名、固定用户 ID、邮箱查找，按正常、停用、已删除身份切换，正常账号可再筛选管理员或普通用户。页签数字是全站各状态总数，表格底部是当前筛选结果数量。每页可显示 25、50、100 条，翻页保留搜索条件。

停用账号仍可按保留的姓名和邮箱查找；已删除身份仅保留原 ID，只支持按 ID 查找。没有拼音、错字纠正或全公司目录搜索。旧身份只能恢复给原来的人，不能交给新人；恢复不会自动还原管理员权限和应用准入。


## 用户组

从管理后台的「用户组」新建组，搜索已有正常账号并添加成员。勾选应用后先预览，再保存。预览会列出受影响的成员和已配置的账号下发变化。

用户可以加入多个组。有效准入合并个人授权及所在各组的授权。移除一项授权后，其他来源仍然有效。用户详情的「授权来源」会列出个人和各组授予的权限。仅管理员可用的资源不参与组授权。

加入或移除成员时，Auth 立即重新计算准入，已配置的账号下发异步处理。停用账号会移除组成员关系。组清空成员后可删除。


## Reuse a sign-in name

In the password account form, open **Reuse a deleted username** and confirm that any matching application bindings have been checked. A different person receives a fresh subject and starts with no application grants. Auth keeps the retired subject for original-person recovery. Applications that match by email or a separate identity field still require a binding check. If the name is already in use, the earlier identity cannot be restored under that name.

## 复用登录名

在密码账号表单展开「复用已删除的用户名」，确认已检查可能匹配的应用账号。新人使用新的身份标识，创建后单独配置应用准入。Auth 保留旧标识供原人恢复。按邮箱或其他字段匹配的应用仍需核对绑定。用户名已被占用时，旧身份不能以该用户名恢复。
