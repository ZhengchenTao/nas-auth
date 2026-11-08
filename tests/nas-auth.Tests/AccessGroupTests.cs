using Microsoft.Extensions.Logging.Abstractions;
using NasAuth.Config;
using NasAuth.Data;
using NasAuth.Data.Repositories;
using NasAuth.Services;
using Xunit;

namespace NasAuth.Tests;

public sealed class AccessGroupTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "access-groups-" + Guid.NewGuid().ToString("N"));
    private readonly UserRepository _users;
    private readonly UserResourceRepository _resources;
    private readonly AccessGroupService _groups;
    private readonly ProvisioningService _provisioning;

    public AccessGroupTests()
    {
        Directory.CreateDirectory(_dir);
        var resources = Path.Combine(_dir, "resources.json");
        File.WriteAllText(resources, """
            [
              {"aud":"photos","resource_url":"https://photos.example.test/","display_name":"Photos","scopes":["read","share"]},
              {"aud":"media","resource_url":"https://media.example.test/","display_name":"Media","scopes":["play"]},
              {"aud":"private","resource_url":"https://private.example.test/","display_name":"Private","scopes":["read"],"admin_only":true}
            ]
            """);
        var auth = new AuthOptions
        {
            Database = "Data Source=" + Path.Combine(_dir, "auth.db") + ";Pooling=False",
            Issuer = "https://auth.example.test", ResourcesPath = resources
        };
        var catalog = new ResourceCatalog(auth, NullLogger<ResourceCatalog>.Instance);
        var options = new ProvisioningOptions
        {
            Applications = new()
            {
                ["photos"] = new() { Name = "Photos", RequiredResources = new() { ["photos"] = ["read"] } },
                ["media"] = new() { Name = "Media", RequiredResources = new() { ["media"] = ["play"] } }
            }
        };
        var db = new AuthDb(auth);
        db.EnsureCreated();
        _users = new(db);
        _resources = new(db);
        _groups = new(db, catalog, options);
        _provisioning = new(db, auth, options, catalog);
        _users.Upsert("admin", "admin", "opaque", true);
        _users.Create("alex", "alex", "opaque", false);
        _users.Create("sam", "sam", "opaque", false);
    }

    [Fact]
    public void EffectiveScopesCombineGroupsAndDirectGrantsWithoutCopyingEither()
    {
        var family = _groups.Create("Family")!;
        var friends = _groups.Create("Friends")!;
        Assert.Null(_groups.Create("family"));
        Assert.True(_groups.ChangeMember(family, "alex", true));
        Assert.True(_groups.ChangeMember(friends, "alex", true));
        _resources.Upsert("alex", "photos", "share");
        Save(family, ["provisioned:photos"]);
        Save(friends, ["provisioned:photos"]);

        Assert.True(_resources.IsAllowed("alex", "photos", ["read", "share"]));
        Assert.Single(_resources.ListByUser("alex"));
        Assert.Equal("share", _resources.ListByUser("alex")[0].scopes);
        Assert.Equal(3, _groups.Sources("alex").Count);
        Assert.Equal(1, _resources.CountByAud()["photos"]);
        Assert.True(_groups.ChangeMember(family, "alex", false));
        Assert.True(_resources.IsAllowed("alex", "photos", ["read", "share"]));
        Assert.True(_groups.ChangeMember(friends, "alex", false));
        Assert.False(_resources.IsAllowed("alex", "photos", ["read"]));
        Assert.True(_resources.IsAllowed("alex", "photos", ["share"]));
    }

    [Fact]
    public void PreviewDoesNotSaveAndRejectsChangesToTheReviewedMembership()
    {
        var group = _groups.Create("Family")!;
        Assert.True(_groups.ChangeMember(group, "alex", true));
        var first = _groups.ChangeGrants(group, ["provisioned:photos"], null, out var saved)!;
        Assert.False(saved);
        Assert.Equal("alex", Assert.Single(first.Changes).UserId);
        Assert.False(_resources.IsAllowed("alex", "photos", ["read"]));
        Assert.True(_groups.ChangeMember(group, "sam", true));
        var updated = _groups.ChangeGrants(group, ["provisioned:photos"], first.Stamp, out saved)!;
        Assert.False(saved);
        Assert.NotEqual(first.Stamp, updated.Stamp);
        Assert.Equal(2, updated.Changes.Count);
        _groups.ChangeGrants(group, ["provisioned:photos"], updated.Stamp, out saved);
        Assert.True(saved);
        Assert.True(_resources.IsAllowed("sam", "photos", ["read"]));
        Assert.DoesNotContain(_groups.Applications(), a => a.Grants.ContainsKey("private"));
        Assert.Null(_groups.ChangeGrants(group, ["resource:private"], null, out _));
    }

    [Fact]
    public void GroupChangesOnlyProvisionAppsWhoseEffectiveAccessChanges()
    {
        var group = _groups.Create("Family")!;
        _resources.Upsert("alex", "media", "play");
        _provisioning.Initialize();
        Assert.True(_groups.ChangeMember(group, "alex", true));
        Save(group, ["provisioned:photos"]);
        _provisioning.CaptureChanges();
        var initial = Assert.Single(_provisioning.List("alex"));
        Assert.Equal("photos", initial.application_id);
        Assert.Equal(1, initial.enabled);

        _resources.Upsert("alex", "photos", "read");
        _provisioning.CaptureChanges();
        Assert.True(_groups.ChangeMember(group, "alex", false));
        _provisioning.CaptureChanges();
        Assert.Equal(initial.revision, _provisioning.List("alex").Single(r => r.application_id == "photos").revision);
        _resources.Delete("alex", "photos");
        _provisioning.CaptureChanges();
        Assert.Equal(0, _provisioning.List("alex").Single(r => r.application_id == "photos").enabled);
    }

    [Fact]
    public void DisableAndRestoreNeverRestoreGroupAccess()
    {
        var group = _groups.Create("Family")!;
        Assert.True(_groups.ChangeMember(group, "alex", true));
        Save(group, ["provisioned:photos"]);
        Assert.False(_groups.DeleteEmpty(group));
        Assert.True(_users.Disable("admin", "alex", "admin"));
        Assert.False(_groups.ChangeMember(group, "alex", true));
        Assert.True(_users.RestoreIdentity("admin", "alex", false, "opaque", false, null));
        Assert.Empty(_groups.Memberships("alex"));
        Assert.False(_resources.IsAllowed("alex", "photos", ["read"]));
        Assert.True(_groups.DeleteEmpty(group));
    }

    private void Save(string id, string[] applications)
    {
        var preview = _groups.ChangeGrants(id, applications, null, out _)!;
        _groups.ChangeGrants(id, applications, preview.Stamp, out var saved);
        Assert.True(saved);
    }

    public void Dispose() => Directory.Delete(_dir, true);
}
