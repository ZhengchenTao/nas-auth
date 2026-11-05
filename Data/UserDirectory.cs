namespace NasAuth.Data;

public sealed record UserDirectoryFilter(string Query, string View, string Role, int Page, int PageSize)
{
    public static UserDirectoryFilter Normalize(string? query = null, string? view = null, string? role = null,
        int page = 1, int pageSize = 25)
    {
        var q = query?.Trim() ?? "";
        if (q.Length > 128) q = q[..128];
        var state = view is "disabled" or "deleted" ? view : "active";
        return new(q, state, state == "active" && role is "admin" or "member" ? role : "all",
            Math.Max(1, page), pageSize is 25 or 50 or 100 ? pageSize : 25);
    }
}

public sealed record UserDirectoryPage(UserDirectoryFilter Filter, IReadOnlyList<UserRow> Users,
    IReadOnlyList<string> DeletedIds, long Total, long ActiveCount, long DisabledCount, long DeletedCount)
{
    public long PageCount => Math.Max(1, (Total + Filter.PageSize - 1) / Filter.PageSize);
    public long First => Total == 0 ? 0 : (long)(Filter.Page - 1) * Filter.PageSize + 1;
    public long Last => Math.Min(Total, First + Filter.PageSize - 1);
}
