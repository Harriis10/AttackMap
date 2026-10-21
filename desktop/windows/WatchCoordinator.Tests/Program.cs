using AttackMap.NativeSpike;
using System.Collections.Concurrent;

int checks=0;void Check(bool value,string name){if(!value)throw new Exception(name);checks++;}
var now=DateTimeOffset.Parse("2026-10-21T00:00:00Z");
var model=new RepositoryWatchState("repo",7,TimeSpan.FromSeconds(1));
Check(model.TakeDue(now)==null,"explicit enabling does not auto scan");
model.Changed(now);model.Changed(now.AddMilliseconds(400));
Check(model.TakeDue(now.AddSeconds(1))==null,"burst resets debounce");
var request=model.TakeDue(now.AddMilliseconds(1400));
Check(request is {Epoch:7,FullRescan:true,EventsUncertain:false},"single due request identity");
for(int i=0;i<20;i++)model.Changed(now.AddSeconds(2));
Check(model.TakeDue(now.AddSeconds(4))==null&&model.Pending,"active scan never overlaps and retains burst");
model.Complete();Check(model.TakeDue(now.AddSeconds(4))!=null&&model.TakeDue(now.AddSeconds(5))==null,"exactly one followup");
model.Changed(now.AddSeconds(5),true);model.Complete(true);
Check(model.EventsUncertain,"successful old scan cannot clear later overflow");
Check(model.TakeDue(now.AddSeconds(7))?.EventsUncertain==true,"overflow forces full uncertain request");
model.Complete(true);Check(!model.EventsUncertain,"successful full recovery clears earlier uncertainty");
model.Changed(now.AddSeconds(8));model.Stop();Check(!model.Pending&&model.TakeDue(now.AddSeconds(10))==null,"cancel/off clears pending");

string testBase=Path.GetFullPath(args.FirstOrDefault()??Path.GetTempPath());
string testRoot=Path.GetFullPath(Path.Combine(testBase,"watch-"+Guid.NewGuid().ToString("N")));
Directory.CreateDirectory(testRoot);
try
{
    string repo=Path.Combine(testRoot,"repo žluťoučký"),other=Path.Combine(testRoot,"other"),output=Path.Combine(repo,"generated");
    Directory.CreateDirectory(repo);Directory.CreateDirectory(other);Directory.CreateDirectory(output);
    Check(RepositoryWatchCoordinator.ShouldIgnore(repo,Path.Combine(repo,"node_modules","a.js"),new[]{output}),"Node deps ignored");
    Check(RepositoryWatchCoordinator.ShouldIgnore(repo,Path.Combine(repo,".git","index"),new[]{output}),"git ignored");
    Check(RepositoryWatchCoordinator.ShouldIgnore(repo,Path.Combine(output,"generation","report.json"),new[]{output}),"owned output subtree ignored");
    Check(!RepositoryWatchCoordinator.ShouldIgnore(repo,Path.Combine(repo,"reports","source.js"),new[]{output}),"unmarked source directory not suppressed by name");
    string marked=Path.Combine(repo,"legacy");Directory.CreateDirectory(marked);File.WriteAllText(Path.Combine(marked,".attackmap-output"),"generated");
    Check(RepositoryWatchCoordinator.ShouldIgnore(repo,Path.Combine(marked,"old.json"),new[]{output}),"legacy marker ignored");
    File.WriteAllText(Path.Combine(marked,"artifact-manifest.json"),"{}");
    Check(!RepositoryWatchCoordinator.ShouldIgnore(repo,Path.Combine(marked,"source.js"),new[]{output}),"modern output marker cannot hide added user source");
    using var watch=new RepositoryWatchCoordinator();
    Check(!watch.Start(Path.Combine(testRoot,"missing"))&&!watch.Enabled&&watch.Notice.Contains("manual"),"missing root explicit limitation");
    if(OperatingSystem.IsWindows())
    {
        var received=new ConcurrentQueue<RepositoryWatchRequest>();
        watch.ScanRequested+=received.Enqueue;
        Check(watch.Start(repo,new[]{output},TimeSpan.FromMilliseconds(150)),"actual Win32 watcher starts");
        long firstEpoch=watch.Epoch;
        async Task AwaitCount(int count)
        {var until=DateTime.UtcNow.AddSeconds(8);while(received.Count<count&&DateTime.UtcNow<until)await Task.Delay(40);Check(received.Count==count,$"actual request count {count}, got {received.Count}");}
        string source=Path.Combine(repo,"source.js");File.WriteAllText(source,"one");await AwaitCount(1);
        Check(received.TryPeek(out var first)&&watch.IsCurrent(first),"real request matches current root/epoch");
        File.AppendAllText(source,"two");File.AppendAllText(source,"three");await Task.Delay(500);
        Check(received.Count==1&&watch.Pending,"real edits during scan held as one followup");watch.ScanCompleted(firstEpoch);await AwaitCount(2);
        File.Move(source,Path.Combine(repo,"renamed.js"));watch.ScanCompleted(firstEpoch);await AwaitCount(3);
        File.Delete(Path.Combine(repo,"renamed.js"));watch.ScanCompleted(firstEpoch);await AwaitCount(4);
        watch.ScanCompleted(firstEpoch);File.WriteAllText(Path.Combine(output,"report.json"),"owned output");await Task.Delay(450);
        Check(received.Count==4&&!watch.Pending,"real owned publication does not loop");
        watch.SetScanRunning(true);File.WriteAllText(Path.Combine(repo,"pending.js"),"pending");await Task.Delay(400);Check(watch.Pending,"pending before switch");
        Check(watch.Start(other,Array.Empty<string>(),TimeSpan.FromMilliseconds(150)),"repo switch restarts subscription");
        Check(!watch.IsCurrent(first!)&&!watch.Pending,"switch invalidates old epoch/pending");
        watch.ScanCompleted(firstEpoch);File.WriteAllText(Path.Combine(repo,"after-switch.js"),"old root");await Task.Delay(400);Check(received.Count==4,"old root subscription disposed");
        File.WriteAllText(Path.Combine(other,"new.js"),"new root");await AwaitCount(5);
        var deferred=received.Last();watch.Requeue(deferred);
        Check(watch.Pending,"busy action requeues an already admitted filesystem change");
        await AwaitCount(6);Check(watch.IsCurrent(received.Last()),"deferred request retains current repository identity");
        watch.Stop();File.WriteAllText(Path.Combine(other,"after-stop.js"),"stop");await Task.Delay(400);
        Check(!watch.Enabled&&!watch.Pending&&received.Count==6,"stop leaves no subscription or pending callback");
        watch.Dispose();Check(!watch.Enabled,"close disposal idempotent");
    }
    else Console.WriteLine("SKIP actual Windows filesystem matrix: requires Windows");
}
finally
{
    // Test-created GUID directory only; never scan or modify user repositories.
    if(!testRoot.StartsWith(Path.TrimEndingDirectorySeparator(testBase)+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase)||!System.Text.RegularExpressions.Regex.IsMatch(Path.GetFileName(testRoot),"^watch-[a-f0-9]{32}$"))throw new IOException("Refusing cleanup outside test-owned GUID directory");
    if(Directory.Exists(testRoot))Directory.Delete(testRoot,true);
}
Console.WriteLine($"PASS {checks} watch policy/filesystem checks; no engine, GUI or model calls");
